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
// These POST/ACK controls begin with an initialized durable store. A freshly
// allocated store still owes its initial checkpoint and is correctly held by
// the reason-independent history gate until that receipt is consumed.
fn p2a_initialize_custody(support: &Path) {
    use crate::snapshots::claude_request_money as money;
    money::store::reload_for_test(support).unwrap();
    money::store::with_ledger_for_test(support, |ledger| {
        assert!(money::store::checkpoint_for_test(support, ledger));
    })
    .unwrap();
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
        let _replay_guard =
            unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
        p2a_initialize_custody(&support);
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
        // Money keys use the scanner's index key, the discovered path under
        // the configured root. It is not canonicalized: on macOS $TMPDIR is
        // /var/... while canonicalize() yields /private/var/...
        let transcript = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
        assert!(transcript.is_file());
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
        } else if ledger_fault {
            // The fault, then recovery: the restart finds the never-written
            // shard missing (indistinguishable from a lost one), so custody
            // reloads damaged and refuses admission until its rebuild and a
            // clean telemetry sweep finish. Bounded; it must then accept.
            6
        } else if ack_save_fault {
            4 // Failed ACK save, immediate hold, exact replay, then selected/debt convergence.
        } else {
            1
        };
        let _reset = P2aConflictReset;
        // Only the ledger-fault case stops early, once recovery accepted.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut recovered = false;
        for cycle in 0..cycles {
            if recovered {
                break;
            }
            // A failed local ACK save leaves an unknown outcome. Prove it
            // stays held both immediately and beyond the thirty-minute probe
            // deadline: elapsed time cannot turn an unknown ACK into proof.
            let _clock = money::PageClockForTest::new(
                &support,
                now + if ack_save_fault {
                    match cycle {
                        0 => 0,
                        1 => 1,
                        2 => 300,
                        _ => 301,
                    }
                } else {
                    cycle as u64 * 1801
                },
            );
            let recovering =
                ledger_fault && cycle > 0 && money::store::recovering_for_test(&support);
            let paused = money::adoption_paused(&support, &ScanIndex::load(&index_path).unwrap());
            if conflict && cycle == 1 {
                let saved = ScanIndex::load(&index_path).unwrap();
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision == 3));
                // No physical change or adoption remains: only this durable
                // external-evidence obligation can select the file again.
                money::store::with_ledger_for_test(&support, |ledger| {
                    assert_eq!(ledger.insert(dirty.clone(), crate::snapshots::claude_request_census::ClaudeRequestCensusRecord::money_debt([9; 32], 0)),
                        crate::snapshots::claude_request_census::ClaudeRequestCensusInsert::Stored);
                    // A due-only external-evidence obligation must cross the
                    // real custody barrier before the re-offer/CAS experiment.
                    assert!(money::store::checkpoint_for_test(&support, ledger));
                }).unwrap();
            }
            let mut attempts = 0;
            let mut retained_progress = None;
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
                });
                let frame = match frame {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break (Ok(()), retained_progress.expect("resumed progress path")),
                    Err(error)
                        if error
                            .to_string()
                            .contains("request money scheduling checkpoint pending") =>
                    {
                        money::store::flush();
                        continue;
                    }
                    Err(error) => {
                        break (
                            Err(error),
                            retained_progress.expect("resumed progress path"),
                        )
                    }
                };
                let (preparation, index, scan) =
                    collect_native_preparation_with_rotation(frame, false);
                assert!(index.request_money_live_revision());
                if ack_save_fault && (1..=2).contains(&cycle) {
                    assert!(
                        !index.request_money_adoption_paused(),
                        "UNKNOWN cannot veto the entire context"
                    );
                    assert!(
                        unknown_recovery::blocked_file(
                            &support,
                            &transcript.to_string_lossy(),
                            None
                        ),
                        "the uncertain batch retains its contributing file"
                    );
                    assert!(
                        scan.snapshots.iter().all(|item| item.source_file_fingerprint.as_deref()
                            .is_some_and(|fp| index.claude_history_emission_held(fp).is_some())),
                        "every locally retained body remains UNKNOWN-held before finish's emission veto"
                    );
                }

                if ledger_fault && recovering {
                    assert!(
                        index.request_money_adoption_paused(),
                        "uncertain ACK/custody recovery must retain the history pause"
                    );
                    assert!(
                        !money::adoption_probe_due(&support, &index),
                        "unknown ACK/recovery cannot use a known-outcome probe"
                    );
                    assert!(
                        scan.snapshots.iter().all(|item| {
                            item.source_file_fingerprint
                                .as_deref()
                                .is_some_and(|fingerprint| {
                                    index.claude_history_emission_held(fingerprint).is_some()
                                })
                        }),
                        "local recovery parses must remain vetoed at emission"
                    );
                } else if !(ack_save_fault && (1..=2).contains(&cycle)) {
                    assert!(!scan.snapshots.is_empty(),
                        "admitted selector must re-read the owed revision: {outcome:?}, conflict={conflict}, ledger_fault={ledger_fault}, ack_save_fault={ack_save_fault}, cycle={cycle}");
                }
                let progress_path = preparation.upload_progress_path.clone();
                retained_progress = Some(progress_path.clone());
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
                    if ledger_fault && cycle == 0 {
                        break (result, progress_path);
                    }
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
            } else if ack_save_fault && (1..=2).contains(&cycle) {
                assert!(
                    result.is_ok(),
                    "paused retry completes its local work: {result:?}"
                );
                assert!(
                    unknown_recovery::active_for_test(&support)
                        .iter()
                        .any(|attempt| !attempt.ack_saved
                            && attempt.entities.iter().any(|entity| entity
                                .files
                                .iter()
                                .any(|file| file == transcript.to_string_lossy().as_ref())))
                        == (cycle == 1),
                    "only a durable covering replay ACK ends the batch-scoped UNKNOWN hold"
                );
                assert_eq!(
                    server.offered.lock().unwrap().len(),
                    if cycle == 1 { 1 } else { 2 },
                    "only the due immutable replay can resolve the uncertain ACK"
                );
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3));
                assert!(
                    money::money_due(&support, &transcript.to_string_lossy(), u64::MAX),
                    "a held retry cannot retire the uncertain ACK debt"
                );
                let offered = server.offered.lock().unwrap();
                let fp = offered[0]["snapshot_fingerprint"].as_str().unwrap();
                if cycle == 1 {
                    assert!(
                        !saved.accepted_snapshot_fingerprint_recorded(fp),
                        "an uncertain local ACK must not become a selected acceptance"
                    );
                } else {
                    let progress = SnapshotUploadProgress::load(
                        &progress_path,
                        &namespace,
                        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
                    )
                    .unwrap();
                    assert!(
                        progress.accepted_fingerprints.contains(fp)
                            || saved.accepted_snapshot_fingerprint_recorded(fp),
                        "the saved covering replay proof must survive into a durable carrier"
                    );
                }
            } else if ack_save_fault && cycle == 3 {
                assert!(
                    result.is_ok(),
                    "recovery selected-save convergence: {result:?}"
                );
                let offered = server.offered.lock().unwrap();
                assert_eq!(offered.len(), 2, "{}", recovery_offer_difference(&offered));
                assert!(saved
                    .files
                    .values()
                    .all(|e| e.effective_upload_body_witness_revision == 3));
                assert!(!money::money_due(
                    &support,
                    &transcript.to_string_lossy(),
                    u64::MAX
                ));
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
            } else if ledger_fault
                && result.as_ref().err().is_some_and(|error| {
                    error
                        .to_string()
                        .contains("request money admission refused")
                })
            {
                assert!(
                    recovering,
                    "only custody recovery may refuse admission once the fault is cleared"
                );
                assert!(
                    cycle + 1 < cycles,
                    "custody recovery must converge to an accepted offer"
                );
                assert!(
                    server.offered.lock().unwrap().is_empty(),
                    "recovery refusal forbids POST"
                );
                assert!(saved
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3));
            } else if ledger_fault
                && cycle > 0
                && saved
                    .files
                    .values()
                    .any(|entry| entry.effective_upload_body_witness_revision != 3)
            {
                assert!(
                    result.is_ok(),
                    "held recovery completes local work: {result:?}"
                );
                assert!(
                    recovering || paused,
                    "only a real custody/history hold may defer recovery"
                );
                assert!(
                    cycle + 1 < cycles,
                    "custody recovery must converge to an accepted offer"
                );
                assert!(
                    server.offered.lock().unwrap().is_empty(),
                    "held recovery forbids POST"
                );
                assert!(
                    money::money_due(&support, &transcript.to_string_lossy(), u64::MAX),
                    "held recovery keeps exact selection debt"
                );
            } else if matches!(
                outcome,
                FinishOutcome::Accept | FinishOutcome::Dominated { .. }
            ) {
                assert!(result.is_ok(), "{outcome:?}: {result:?}");
                recovered = ledger_fault;
                assert!(!saved.files.is_empty());
                assert!(
                    saved
                        .files
                        .contains_key(transcript.to_string_lossy().as_ref()),
                    "debt assertions must address the scanner's actual index key"
                );
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
            money_resume::forget_for_test(&support);
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

// Test-only owner for the real prepare/finish boundary. Only the cadence is
// advanced artificially; source selection, parsing, POST, ACK, CAS and receipts
// are the production callers, and restart drops all process-owned evidence.
struct P2aControl {
    fixture: IdentityPipelineHome,
    support: PathBuf,
    server: FinishServer,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    cadence: IdentityPipelineCadence,
    index_path: PathBuf,
    _env: Vec<EnvVarGuard>,
    previous_deadline: Option<Instant>,
    // The real owner-B guard is a documented composition dependency. This
    // fixture explicitly supplies its Permit contract, never production logic.
    _literal_guard: unknown_recovery::TestGuard,
    resource_receipt: bool,
    settlement_receipt: bool,
    accepted_history: usize,
}
impl P2aControl {
    fn new(outcome: FinishOutcome) -> Self {
        let fixture = IdentityPipelineHome::new();
        let support = fixture.base.join("control-support");
        let secrets = fixture.base.join("control-secrets");
        std::fs::create_dir_all(support.join("snapshots")).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        std::fs::write(
            support.join("snapshots/claude_code-reemission-exclusions.txt"),
            b"",
        )
        .unwrap();
        let server = FinishServer::new(outcome);
        let env = vec![
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url),
        ];
        let device = LocalDeviceBinding {
            device_id: "p2a-control-device".into(),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .unwrap();
        let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
        let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&support, SnapshotSource::ClaudeCode),
            &namespace,
        ));
        ScanIndex::default().save(&index_path).unwrap();
        p2a_initialize_custody(&support);
        Self {
            fixture,
            support,
            client: SnapshotApiClient::new(server.url.clone()),
            server,
            device,
            daemon: test_daemon("otm_test"),
            cadence: IdentityPipelineCadence::new(),
            index_path,
            _env: env,
            _literal_guard: unknown_recovery::guard_for_test(
                unknown_recovery::LiteralPermit::Permit,
            ),
            resource_receipt: false,
            settlement_receipt: false,
            accepted_history: 0,
            previous_deadline: source_upload_deadlines()
                .lock()
                .unwrap()
                .remove("claude_code"),
        }
    }
    fn recovery_startup(&self, now: u64) {
        let binding = unknown_recovery::binding(
            &snapshot_upload_destination_namespace(&self.device, "device-secret"),
            self.client.recovery_origin(),
            "otm_test",
            "",
        );
        for _ in 0..32 {
            if unknown_recovery::startup(&self.support, &binding, now).unwrap() {
                return;
            }
            crate::snapshots::claude_request_money::store::flush();
        }
        panic!(
            "fixture requires initialized durable batch custody before direct preparation/replay"
        );
    }
    fn transcript(&self) -> PathBuf {
        self.fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
    }
    fn restart(&mut self) {
        money_resume::forget_for_test(&self.support);
        unknown_recovery::forget(&self.support);
        crate::snapshots::claude_request_money::store::reload_for_test(&self.support).unwrap();
        self.daemon = test_daemon("otm_test");
    }
    fn resource_call<T>(&self, phase: &str, call: impl FnOnce() -> T) -> T {
        if self.settlement_receipt {
            let (result, receipts) = crate::retry_allocation_probe::measure_money_settlements(call);
            for receipt in receipts.iter() {
                eprintln!("MONEY_SETTLEMENT history={} skipped={} required={} admitted={} funds={} offered={} pairs={} requested_peak={} usable_peak={} allocations={} shared_admission_exact_peak={} within_prepaid={} not_RSS=true",
                    self.accepted_history, receipt.skipped, receipt.required, receipt.admitted,
                    receipt.funds, receipt.offered, receipt.pairs,
                    receipt.allocation.requested_peak_with_overlap, receipt.allocation.usable_peak_with_overlap,
                    receipt.allocation.allocations, receipt.shared_admission_peak,
                    receipt.allocation.requested_peak_with_overlap <= receipt.funds);
                assert!(receipt.pairs <= receipt.offered);
                assert!(
                    receipt.shared_admission_peak
                        <= crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES
                );
                if receipt.admitted {
                    assert_eq!(receipt.funds, receipt.required);
                    assert!(
                        receipt.allocation.requested_peak_with_overlap <= receipt.funds,
                        "settlement scratch exceeded its prepaid funds: {receipt:?}"
                    );
                    assert!(
                        receipt.allocation.usable_peak_with_overlap <= receipt.funds,
                        "native settlement scratch exceeded its prepaid funds: {receipt:?}"
                    );
                } else {
                    assert_eq!(receipt.funds, 0);
                    assert_eq!(receipt.pairs, 0);
                    // Refusal can allocate the existing error object; it must
                    // not construct any settled pairs or retain save funds.
                }
            }
            return result;
        }
        if !self.resource_receipt {
            return call();
        }
        let (result, allocation, admitted) =
            crate::retry_allocation_probe::measure_money_caller_thread(call);
        eprintln!("MONEY_LIVE_CALLER phase={phase} history={} caller_requested_peak={} caller_usable_peak={} caller_allocations={} shared_admission_sampled_peak={} ceiling={} settlement_scratch_isolated=false not_RSS=true",
            self.accepted_history, allocation.requested_peak_with_overlap,
            allocation.usable_peak_with_overlap, allocation.allocations, admitted,
            crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES);
        assert!(admitted <= crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES);
        assert!(
            allocation.requested_peak_with_overlap
                <= crate::snapshots::claude_request_money::SHADOW_MEMORY_CEILING_BYTES,
            "whole caller phase exceeded the 64 MiB resource control: {allocation:?}"
        );
        result
    }
    fn cycle(&self) -> (usize, Vec<SnapshotItem>) {
        self.cycle_result().unwrap()
    }
    // Negative transport fixtures require the production's exact deferred
    // outcome; ordinary positive controls keep cycle().unwrap() unchanged.
    fn cycle_deferred(&self) {
        Self::assert_deferred(self.cycle_result());
    }
    fn assert_deferred(result: Result<(usize, Vec<SnapshotItem>)>) {
        let error = result.expect_err("this boundary must report unsettled delivery");
        let deferred = error
            .downcast_ref::<SnapshotEntityDeferred>()
            .expect("only the typed unsettled-entity result is expected");
        assert!(deferred.count > 0);
    }
    fn with_recovery_evidence(outcome: FinishOutcome) -> Self {
        let control = Self::new(outcome);
        write_native_bootstrap_sidecars(&control.fixture, &control.support);
        control
    }
    fn cycle_result(&self) -> Result<(usize, Vec<SnapshotItem>)> {
        self.cycle_changing(|_| {})
    }
    fn cycle_changing(&self, mut change: impl FnMut(usize)) -> Result<(usize, Vec<SnapshotItem>)> {
        use crate::snapshots::claude_request_money as money;
        let mut retained = None;
        for attempt in 0..32 {
            change(attempt);
            self.cadence.next_due_cycle();
            // Isolate the durable money pause from HTTP backoff, whose own
            // behavior is covered elsewhere. This represents a due retry.
            source_upload_deadlines()
                .lock()
                .unwrap()
                .remove("claude_code");
            let mut transport = crate::net_resilience::TransportCycleOutcome::default();
            let mut retry = live_snapshot_retry::LiveRetryOwner::closed();
            let collection = || AgentStatusCollection {
                snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
                source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
                codex_scan_homes: Vec::new(),
                codex_home_bindings: Vec::new(),
            };
            let frame = self.resource_call("prepare_or_resume", || {
                crate::agent_status_refresh::with_test_collection(collection(), || {
                    prepare_sync_source(
                        &self.client,
                        &self.device,
                        "device-secret",
                        SnapshotSource::ClaudeCode,
                        "otm_test",
                        &self.fixture.home,
                        &self.support,
                        &self.daemon,
                        &mut transport,
                        self.daemon.snapshot_scan_account_witness().unwrap(),
                        false,
                    )
                })
            });
            let mut frame = match frame {
                Ok(Some(frame)) => frame,
                Ok(None) => return Ok(retained.expect("resumed exact scan completed")),
                Err(error)
                    if error
                        .to_string()
                        .contains("request money scheduling checkpoint pending") =>
                {
                    money::store::flush();
                    continue;
                }
                Err(error) => return Err(error),
            };
            // Fixture construction stays outside the production allocation window.
            for n in 0..self.accepted_history {
                let fp = format!("{n:064x}");
                frame
                    .upload_progress
                    .accepted_fingerprints
                    .insert(fp.clone());
                frame
                    .upload_progress
                    .accepted_body_witnesses
                    .insert(fp, "historical-body".into());
            }
            if self.accepted_history > 0 {
                frame
                    .upload_progress
                    .save(&frame.upload_progress_path)
                    .unwrap();
            }
            let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
            let parsed = scan.scanned_file_count;
            let items = scan.snapshots.clone();
            retained = Some((parsed, items.clone()));
            let result = self.resource_call("finish", || {
                crate::agent_status_refresh::with_test_collection(collection(), || {
                    finish_sync_source(
                        preparation,
                        index,
                        scan,
                        &self.client,
                        &self.device,
                        "device-secret",
                        SnapshotSource::ClaudeCode,
                        "otm_test",
                        &self.fixture.home,
                        &self.support,
                        &self.daemon,
                        &mut transport,
                        &mut retry,
                    )
                })
            });
            money::store::flush();
            if result.as_ref().err().is_some_and(|error| {
                error
                    .to_string()
                    .contains("request money scheduling checkpoint pending")
            }) {
                continue;
            }
            result?;
            return Ok((parsed, items));
        }
        Err(
            crate::source_rotation::LocalRefusal("request money scheduling checkpoint pending")
                .into(),
        )
    }
    fn saved(&self) -> ScanIndex {
        ScanIndex::load(&self.index_path).unwrap()
    }
    fn offers(&self) -> Vec<serde_json::Value> {
        self.server.offered.lock().unwrap().clone()
    }
}

impl Drop for P2aControl {
    fn drop(&mut self) {
        money_resume::forget_for_test(&self.support);
        unknown_recovery::forget(&self.support);
        crate::snapshots::claude_request_money::store::forget_for_test(&self.support);
        let mut deadlines = source_upload_deadlines().lock().unwrap();
        deadlines.remove("claude_code");
        if let Some(previous) = self.previous_deadline {
            deadlines.insert("claude_code", previous);
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_protected_change_alias_rebuild_real_upload_never_mints_money() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("protected recorder: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for live in [false, true] {
        for cause in ["real_change", "alias", "rebuild"] {
            let mut control = P2aControl::new(FinishOutcome::Accept);
            control.cycle();
            assert!(!control.offers().is_empty());
            std::fs::write(
                control
                    .support
                    .join("snapshots/claude_code-reemission-exclusions.txt"),
                format!("{:x}\n", Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())),
            )
            .unwrap();
            let _live = live.then(|| money::LiveForTest::new(&control.support));
            let before = control.offers().len();
            match cause {
                "real_change" => {
                    let mut row: serde_json::Value = serde_json::from_str(
                        std::fs::read_to_string(control.transcript())
                            .unwrap()
                            .lines()
                            .last()
                            .unwrap(),
                    )
                    .unwrap();
                    row["requestId"] = "req_changed".into();
                    row["message"]["id"] = "m-changed".into();
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(control.transcript())
                        .unwrap()
                        .write_all((row.to_string() + "\n").as_bytes())
                        .unwrap();
                }
                "alias" => {
                    std::fs::copy(
                        control.transcript(),
                        control
                            .transcript()
                            .with_file_name("00000000-0000-4000-8000-000000000000.jsonl"),
                    )
                    .unwrap();
                }
                "rebuild" => {
                    // An empty rebuilt index replaces the saved one through the
                    // same generation compare-and-swap every writer uses.
                    let mut rebuilt = ScanIndex::default();
                    rebuilt.generation = control.saved().generation;
                    rebuilt.save(&control.index_path).unwrap();
                }
                _ => unreachable!(),
            }
            // Fully paired API/trace evidence makes minting v1 possible on the
            // ordinary fold, so its absence below is a discriminating protection.
            write_native_bootstrap_sidecars(&control.fixture, &control.support);
            control.restart();
            let mut cause_count = 0_u64;
            for _ in 0..3 {
                let (_, diagnostics) =
                    crate::local_resource_diagnostics::capture(|| control.cycle());
                for event in diagnostics
                    .iter()
                    .filter(|event| event["stage"] == "claude_money_protected_offers")
                {
                    cause_count += event["counts"][cause].as_u64().unwrap();
                    assert_eq!(event["counts"]["cause_unavailable"], 0, "{event}");
                }
            }
            let history_vetoed = cause == "rebuild" || live && cause == "real_change";
            if history_vetoed {
                assert_eq!(
                    cause_count, 0,
                    "held history never reaches the POST counter"
                );
                assert_eq!(
                    control.offers().len(),
                    before,
                    "protected {cause} cannot bypass the history gate (live={live})"
                );
                assert!(control
                    .saved()
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3));
                continue;
            }
            // Revision 2 permits genuine changes; a newly discovered alias is
            // fresh under both rows. The alias still resolves to the protected
            // logical family at the money boundary: retain the actual-POST,
            // positive cause-counter and no-new-money controls for that case.
            if live {
                assert!(
                    cause_count > 0,
                    "protected fresh alias is counted at its actual POST boundary"
                );
            } else {
                assert_eq!(
                    cause_count, 0,
                    "live-only diagnostics stay inert under revision 2"
                );
            }
            let offers = control.offers();
            assert!(
                offers.len() > before,
                "{cause} must actually reach the upload recorder"
            );
            for item in &offers[before..] {
                if live {
                    assert!(
                        item["usage_accounting_contract"].is_null(),
                        "protected {cause} must mint neither literal nor v1: {item}"
                    );
                } else {
                    assert_eq!(
                        item["usage_accounting_contract"], "session_exclusive_reported_usage:v1",
                        "revision 2 preserves main's ordinary sidecar-proven contract"
                    );
                }
                assert!(item["removed_request_count"].is_null());
            }
            assert!(
                control
                    .saved()
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision != 3),
                "protected {cause} must never stamp 3"
            );
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_protected_quiet_authority_receipts_equal_v1_and_keep_debt() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("protected quiet receipt: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for terminal in [false, true] {
        let mut receipts = Vec::new();
        for live in [false, true] {
            let mut control = P2aControl::new(FinishOutcome::Accept);
            for _ in 0..3 {
                control.cycle();
            }
            std::fs::write(
                control
                    .support
                    .join("snapshots/claude_code-reemission-exclusions.txt"),
                format!("{:x}\n", Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())),
            )
            .unwrap();
            let mut saved = control.saved();
            let revision = saved
                .files
                .values()
                .next()
                .unwrap()
                .source_file_fingerprint
                .clone();
            // This control starts at a settled, matching policy boundary. A
            // mismatching context/revision is an ordinary reparse control.
            let mut persisted = serde_json::to_value(&saved).unwrap();
            persisted["upload_context_fingerprint"] = serde_json::json!(
                snapshot_upload_context_fingerprint(SnapshotUploadPolicy::default(), None,)
            );
            saved = serde_json::from_value(persisted).unwrap();
            if terminal {
                saved.insert_unproven_terminal_claude_authority_for_test(
                    IDENTITY_PIPELINE_ROOT,
                    &revision,
                );
            } else {
                saved.insert_bound_retry_pending_claude_authority_for_test(
                    IDENTITY_PIPELINE_ROOT,
                    &revision,
                );
            }
            // A distinct persisted upload-v1 record must survive alongside
            // the family authority record, even when the page is quiet.
            let protected_fp = saved
                .current_snapshot_fingerprints()
                .into_iter()
                .next()
                .unwrap();
            let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
            let progress_path = snapshot_upload_progress_path(&control.index_path);
            let mut progress = SnapshotUploadProgress::load(
                &progress_path,
                &namespace,
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap();
            let offers = control.offers();
            let offered = offers
                .iter()
                .rev()
                .find(|item| item["snapshot_fingerprint"] == protected_fp)
                .unwrap();
            // The file checkpoint has a SET witness, whereas upload custody
            // binds the exact entity body. Hash only the wire evidence leaves.
            assert!(offered.get("context_curve").is_none());
            assert!(offered.get("cache_observations").is_none());
            let payload = [
                "session_account_evidence",
                "tool_usage",
                "tool_usage_truncated",
            ]
            .into_iter()
            .filter_map(|key| {
                offered
                    .get(key)
                    .map(|value| (key.to_owned(), value.clone()))
            })
            .collect::<serde_json::Map<_, _>>();
            let witness = format!(
                "{:x}",
                Sha256::digest(
                    crate::canonical_json::canonicalize(&serde_json::Value::Object(payload))
                        .unwrap()
                )
            );
            progress.quarantine_retryable_body(&protected_fp, &witness);
            let record = progress
                .quarantined_fingerprints
                .get_mut(&protected_fp)
                .unwrap();
            record.retry_after_unix_seconds = current_unix_seconds() + 6 * 3600;
            if terminal {
                record.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
                record.failed_reconstruction_count = MAX_SNAPSHOT_RECONSTRUCTION_FAILURES;
                record.retry_after_unix_seconds = 0;
            }
            assert!(
                snapshot_quarantine_deadline_is_bounded(record),
                "quiet-page fixture must survive production bounded decoding"
            );
            assert!(
                record.hold.is_none(),
                "this is v1 custody, not a money server hold"
            );
            let protected_quarantine = serde_json::to_value(&*record).unwrap();
            progress.save(&progress_path).unwrap();
            saved.retain_quarantined_fingerprints(&progress.quarantined_fingerprints);
            saved.save(&control.index_path).unwrap();
            let _live = live.then(|| money::LiveForTest::new(&control.support));
            control.restart();
            let offered = control.offers().len();
            let (parsed, _) = control.cycle();
            assert_eq!(
                parsed, 0,
                "receipt must exercise quiet page with no protected candidate"
            );
            assert_eq!(control.offers().len(), offered);
            let saved = control.saved();
            assert!(
                saved
                    .claude_authority_record_for_test(IDENTITY_PIPELINE_ROOT)
                    .is_some(),
                "v1 quarantine stays retained"
            );
            // Finish transfers cycle custody into the durable index before
            // retiring transient progress. Compare the whole v1 record.
            assert_eq!(
                serde_json::to_value(
                    saved
                        .quarantined_snapshot_fingerprints
                        .get(&protected_fp)
                        .expect("protected upload-v1 custody")
                )
                .unwrap(),
                protected_quarantine
            );
            assert!(saved
                .quarantined_snapshot_fingerprints
                .contains_key(&protected_fp));
            let statuses = control.server.terminal.lock().unwrap();
            let status = statuses.last().unwrap();
            if terminal {
                assert!(
                    status["last_snapshot_unproven_terminal_count"]
                        .as_u64()
                        .unwrap()
                        > 0,
                    "{status}"
                );
            } else {
                assert_eq!(
                    status["last_census_complete"], false,
                    "RetryPending veto: {status}"
                );
            }
            receipts.push(serde_json::json!({"census":status["last_census_complete"],
                "terminal":status["last_snapshot_unproven_terminal_count"],
                "ownership":status["last_ownership_incomplete_file_count"],
                "terminal_ownership":status["last_terminal_ownership_incomplete_file_count"],
                "settled":status["last_census_residue_settled"]}));
            drop(statuses);
            if live {
                let sibling = "8e64da31-2912-4136-b77a-209b87f7ed25";
                let text = std::fs::read_to_string(control.transcript())
                    .unwrap()
                    .replace(IDENTITY_PIPELINE_ROOT, sibling)
                    .replace("req_1", "req_sibling_1")
                    .replace("req_2", "req_sibling_2");
                std::fs::write(
                    control
                        .transcript()
                        .with_file_name(format!("{sibling}.jsonl")),
                    text,
                )
                .unwrap();
                let before = control.offers().len();
                let (parsed, _) = control.cycle();
                assert!(parsed > 0, "unprotected sibling must actually parse");
                let offers = control.offers();
                let new = &offers[before..];
                assert!(
                    new.iter().any(|item| item["source_session_id"] == sibling
                        && item["usage_accounting_contract"] == money::REQUEST_OWNED_CONTRACT),
                    "unprotected sibling must POST its literal: {new:?}"
                );
                assert!(new
                    .iter()
                    .all(|item| item["source_session_id"] != IDENTITY_PIPELINE_ROOT));
                let saved = control.saved();
                assert!(saved
                    .claude_authority_record_for_test(IDENTITY_PIPELINE_ROOT)
                    .is_some());
                assert!(saved
                    .quarantined_snapshot_fingerprints
                    .contains_key(&protected_fp));
                assert_eq!(
                    serde_json::to_value(
                        saved
                            .quarantined_snapshot_fingerprints
                            .get(&protected_fp)
                            .expect("sibling must preserve protected upload-v1 custody")
                    )
                    .unwrap(),
                    protected_quarantine
                );
                let statuses = control.server.terminal.lock().unwrap();
                let status = statuses.last().unwrap();
                if terminal {
                    assert!(
                        status["last_snapshot_unproven_terminal_count"]
                            .as_u64()
                            .unwrap()
                            > 0
                    );
                } else {
                    assert_eq!(
                        status["last_census_complete"], false,
                        "sibling cannot erase protected veto"
                    );
                }
            }
        }
        assert_eq!(
            receipts[0], receipts[1],
            "protected-v1 health with live={terminal}"
        );
    }
}

fn p2a_control_api_rows(
    control: &P2aControl,
    change: impl FnOnce(&mut Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>),
) {
    let path = control
        .support
        .join("local-otel/claude-code-effort")
        .join(format!(
            "{:x}.jsonl",
            Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
        ));
    let mut rows = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect::<Vec<_>>();
    change(&mut rows);
    for row in &mut rows {
        row.fingerprint.clear();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(row).unwrap())
        );
    }
    std::fs::write(
        path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}
fn p2a_control_jsonl(control: &P2aControl) -> Vec<serde_json::Value> {
    crate::snapshots::claude_request_money::store::flush();
    std::fs::read_dir(control.support.join("diagnostics"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("claude-request-money-shadow-")
                && path
                    .extension()
                    .is_some_and(|extension| extension == "jsonl")
        })
        .flat_map(|path| {
            std::fs::read_to_string(path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect::<Vec<_>>()
        })
        .collect()
}
fn p2a_latest_family(rows: &[serde_json::Value]) -> &serde_json::Value {
    rows.iter()
        .filter(|row| row["row"] == "family")
        .max_by_key(|row| row["snapshot"].as_u64().unwrap())
        .expect("published family JSONL")
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_cost_published_jsonl_matches_wire_and_withholds_unpriced_unattributed() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("COST published: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for held in [false, true] {
        let control = P2aControl::new(FinishOutcome::Accept);
        let _live = money::LiveForTest::new(&control.support);
        write_native_bootstrap_sidecars(&control.fixture, &control.support);
        p2a_control_api_rows(&control, |rows| {
            if held {
                let mut side = rows[0].clone();
                side.request_id = "req_unpriced_side".into();
                side.client_request_id = "client-unpriced-side".into();
                side.event_sequence = Some(3);
                side.cost_usd_micros = None;
                side.cache_creation_tokens = 12;
                side.cache_creation_5m_tokens = 0;
                side.cache_creation_1h_tokens = 0;
                rows.push(side);
            } else {
                rows[0].input_tokens = 999;
            }
        });
        control.cycle();
        let rows = p2a_control_jsonl(&control);
        let family = p2a_latest_family(&rows);
        if held {
            assert_eq!(
                family["coverage_complete"], false,
                "final COST hold must reach published JSONL: {family}"
            );
            assert!(family["held"]["requests"].as_u64().unwrap() > 0, "{family}");
            assert!(rows
                .iter()
                .filter(|row| row["row"] == "coverage")
                .all(|row| row["coverage_complete"] == false));
            assert!(
                control.offers().is_empty(),
                "held entity never reaches POST"
            );
        } else {
            let offers = control.offers();
            let item = offers.last().expect("mismatched-token literal POST");
            assert_eq!(
                item["usage_accounting_contract"],
                money::REQUEST_OWNED_CONTRACT
            );
            assert_eq!(
                item["input_tokens"], 30,
                "transcript tokens stay authoritative"
            );
            assert_eq!(item["request_count"], 2);
            assert_eq!(item["cost"]["total_cost_usd"], "0.0002");
            assert_eq!(family["new"]["requests"], item["request_count"]);
            let grains = rows
                .iter()
                .filter(|row| row["row"] == "grain" && row["snapshot"] == family["snapshot"])
                .collect::<Vec<_>>();
            assert!(
                !grains.is_empty(),
                "published mismatch must discriminate own-cost grains"
            );
            let micros = grains
                .iter()
                .map(|row| {
                    row["new"]["cost_usd"]
                        .as_str()
                        .map(|cost| (cost.parse::<f64>().unwrap() * 1_000_000.0).round() as u64)
                        .unwrap_or(0)
                })
                .sum::<u64>();
            assert_eq!(
                micros, 200,
                "published shadow cost must equal actual emitter"
            );
            assert_eq!(family["new"]["tokens"], 33);
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_priced_side_call_then_zero_token_transcript_retains_accepted_cost_and_holds() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("zero token lifecycle: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    write_native_bootstrap_sidecars(&control.fixture, &control.support);
    p2a_control_api_rows(&control, |rows| {
        let mut side = rows[0].clone();
        side.request_id = "req_zero_later".into();
        side.client_request_id = "client-zero-later".into();
        side.event_sequence = Some(3);
        rows.push(side);
    });
    control.cycle();
    let before = control.offers();
    let accepted = before.last().expect("priced side call must be POSTed");
    assert_eq!(accepted["request_count"], 3);
    assert_eq!(accepted["cost"]["total_cost_usd"], "0.0003");
    let mut row: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(control.transcript())
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    row["requestId"] = "req_zero_later".into();
    row["message"]["id"] = "zero-later".into();
    row["message"]["usage"] = serde_json::json!({"input_tokens":0,"output_tokens":0});
    std::fs::OpenOptions::new()
        .append(true)
        .open(control.transcript())
        .unwrap()
        .write_all((row.to_string() + "\n").as_bytes())
        .unwrap();
    control.restart();
    control.cycle();
    assert_eq!(
        control.offers().len(),
        before.len(),
        "zero-token takeover must hold rather than POST reduced money"
    );
    let rows = p2a_control_jsonl(&control);
    let family = p2a_latest_family(&rows);
    assert_eq!(family["coverage_complete"], false);
    assert_eq!(family["removed"]["requests"], 0, "hold is never a removal");
    assert!(control.saved().accepted_snapshot_fingerprint_recorded(
        accepted["snapshot_fingerprint"].as_str().unwrap()
    ));
    let key = control.transcript().to_string_lossy().into_owned();
    assert!(
        control.saved().files.contains_key(&key),
        "debt assertion must address the scanner's actual index key"
    );
    assert!(money::money_due(&control.support, &key, u64::MAX));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_sidecars_only_real_maturity_restart_and_first_transcript_keep_entity() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("sidecars lifecycle: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    write_native_bootstrap_sidecars(&control.fixture, &control.support);
    let transcript = std::fs::read(control.transcript()).unwrap();
    std::fs::remove_file(control.transcript()).unwrap();
    let observed: serde_json::Value =
        serde_json::from_slice(transcript.split(|byte| *byte == b'\n').nth(1).unwrap()).unwrap();
    let at = OffsetDateTime::parse(observed["timestamp"].as_str().unwrap(), &Rfc3339)
        .unwrap()
        .unix_timestamp() as u64;
    {
        let _clock = money::PageClockForTest::new(&control.support, at + 1);
        for _ in 0..4 {
            control.cycle();
        }
        assert!(
            control
                .offers()
                .iter()
                .all(|item| item["request_count"] == 0),
            "immature telemetry cannot count yet"
        );
        assert!(
            control.saved().files.is_empty(),
            "synthetic carrier must not fabricate a transcript index entry"
        );
    }
    control.restart();
    {
        let _clock = money::PageClockForTest::new(&control.support, at + 7200);
        for _ in 0..4 {
            control.cycle();
        }
    }
    let offers = control.offers();
    let synthetic = offers
        .iter()
        .rev()
        .find(|item| item["request_count"] == 2)
        .expect("mature sidecars-only literal must be uploaded");
    assert_eq!(synthetic["source_session_id"], IDENTITY_PIPELINE_ROOT);
    assert_eq!(synthetic["cost"]["total_cost_usd"], "0.0002");
    assert!(control.saved().files.is_empty());
    std::fs::write(control.transcript(), transcript).unwrap();
    control.restart();
    let before = control.offers().len();
    for _ in 0..4 {
        control.cycle();
    }
    let offers = control.offers();
    assert!(
        offers.len() > before,
        "first transcript must replace synthetic carrier through real finish"
    );
    let physical = offers.last().unwrap();
    assert_eq!(
        physical["source_session_id"],
        synthetic["source_session_id"]
    );
    assert_eq!(physical["request_count"], 2);
    assert_eq!(physical["cost"]["total_cost_usd"], "0.0002");
    assert_eq!(control.saved().files.len(), 1);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_bad_first_adoption_slice_over_good_history_restarts_and_recovers() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("stale slice: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::MoneyHeld);
    let _live = money::LiveForTest::new(&control.support);
    let now = OffsetDateTime::now_utc().unix_timestamp() as u64;
    let clock = money::PageClockForTest::new(&control.support, now);
    control.recovery_startup(now);
    // Saved historical acceptances deliberately dwarf the first real bad slice.
    // Use the real preparation's context key, rather than guessing its hash.
    control.cadence.next_due_cycle();
    let mut transport = crate::net_resilience::TransportCycleOutcome::default();
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
        prepare_sync_source(
            &control.client,
            &control.device,
            "device-secret",
            SnapshotSource::ClaudeCode,
            "otm_test",
            &control.fixture.home,
            &control.support,
            &control.daemon,
            &mut transport,
            control.daemon.snapshot_scan_account_witness().unwrap(),
            false,
        )
    })
    .unwrap()
    .unwrap();
    let prefix = money::adoption_prefix(&frame.committed_index);
    drop(frame);
    money::store::with_ledger_for_test(&control.support, |ledger| {
        for n in 0..1000 {
            ledger.insert(
                format!("{prefix}history-{n:04}"),
                crate::snapshots::claude_request_census::ClaudeRequestCensusRecord::money_debt(
                    [1; 32], 4,
                ),
            );
        }
        let mut writer = money::store::WriterState::default();
        while ledger.dirty_shards() > 0 {
            money::store::save_page_for_test(&control.support, ledger, &mut writer).unwrap();
        }
    })
    .unwrap();
    control.cycle();
    let saved = control.saved();
    assert!(
        money::adoption_paused(&control.support, &saved),
        "one bad first slice cannot be diluted by good history"
    );
    assert!(!money::adoption_probe_due(&control.support, &saved));
    control.restart();
    assert!(money::adoption_paused(&control.support, &control.saved()));
    let offers = control.offers().len();
    let (parsed, _) = control.cycle();
    assert_eq!(
        parsed, 0,
        "fresh pause survives real preparation after restart"
    );
    assert_eq!(control.offers().len(), offers);
    drop(clock);
    let _later = money::PageClockForTest::new(&control.support, now + 1801);
    assert!(money::adoption_probe_due(
        &control.support,
        &control.saved()
    ));
    // Advance the existing upload-quarantine deadline too: PageClock only
    // owns money maturity/rates, and cannot advance the transport wall clock.
    let mut saved = control.saved();
    for record in saved.quarantined_snapshot_fingerprints.values_mut() {
        record.retry_after_unix_seconds = 0;
    }
    saved.save(&control.index_path).unwrap();
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let path = snapshot_upload_progress_path(&control.index_path);
    let mut progress = SnapshotUploadProgress::load(
        &path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    for record in progress.quarantined_fingerprints.values_mut() {
        record.retry_after_unix_seconds = 0;
    }
    progress.save(&path).unwrap();
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    let (parsed, _) = control.cycle();
    assert_eq!(parsed, 1, "aged bad slice admits one actual recovery probe");
    assert!(control.offers().len() > offers);
    assert!(control
        .saved()
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 3));
    // Production reads the pause only after the next preparation's
    // reclaim_metadata consumes the post-save settle_money_acks receipt.
    money::store::with_ledger_for_test(&control.support, |ledger| {
        assert!(money::store::checkpoint_for_test(&control.support, ledger));
    })
    .unwrap();
    assert!(!money::adoption_paused(&control.support, &control.saved()));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_cap_exhausted_after_post_preserves_real_server_hold_across_restart() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("outcome cap: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::MoneyHeld);
    let _live = money::LiveForTest::new(&control.support);
    let support = control.support.clone();
    *control.server.before_post.lock().unwrap() = Some(Box::new(move || {
        money::store::with_ledger_for_test(&support, |ledger| {
            let mut exhausted = false;
            for n in 0..=money::store::LEDGER_MAX_RECORDS {
                if ledger.insert(
                    format!("dirty:{n:064x}"),
                    crate::snapshots::claude_request_census::ClaudeRequestCensusRecord::money_debt(
                        [1; 32], 0,
                    ),
                ) == crate::snapshots::claude_request_census::ClaudeRequestCensusInsert::Refused
                {
                    exhausted = true;
                    break;
                }
            }
            assert!(
                exhausted,
                "inject a real record/byte admission exhaustion after offer"
            );
        })
        .unwrap();
    }));
    let _result = control.cycle_result();
    assert!(
        !control.offers().is_empty(),
        "fault happens after actual POST"
    );
    control.restart();
    assert!(
        money::adoption_paused(&control.support, &control.saved()),
        "unknown or held outcome cannot reopen adoption after reload"
    );
    assert!(control
        .saved()
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision != 3));
    let saved = control.saved();
    assert!(
        saved
            .quarantined_snapshot_fingerprints
            .values()
            .any(|record| record.hold.is_some()),
        "server-returned held outcome remains durable"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_failed_route_pause_checkpoint_then_reload_stays_closed() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("route fault: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::MoneyRouteUnavailable);
    let _live = money::LiveForTest::new(&control.support);
    let support = control.support.clone();
    let route_shard = Arc::new(Mutex::new(None::<PathBuf>));
    let blocked = route_shard.clone();
    *control.server.before_post.lock().unwrap() = Some(Box::new(move || {
        money::store::with_ledger_for_test(&support, |ledger| {
            let route = ledger
                .census()
                .records_with_prefix("adopt:entity:v2:")
                .find_map(|(key, _)| {
                    key.strip_suffix("rates")
                        .map(|prefix| format!("{prefix}route"))
                })
                .expect("preflight outcome scope");
            let path =
                money::store::shard_path_for_test(&support, &route).with_extension("json.tmp");
            std::fs::create_dir_all(&path).unwrap();
            *blocked.lock().unwrap() = Some(path);
        })
        .unwrap();
    }));
    let _result = control.cycle_result();
    assert!(!control.offers().is_empty());
    assert!(
        route_shard.lock().unwrap().is_some(),
        "actual upload fault hook ran"
    );
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let progress = SnapshotUploadProgress::load(
        &snapshot_upload_progress_path(&control.index_path),
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert!(
        !progress.quarantined_fingerprints.is_empty(),
        "route retry is durable outside failed money shard"
    );
    let literal_offers = control
        .offers()
        .into_iter()
        .filter(|item| item["usage_accounting_contract"] == money::REQUEST_OWNED_CONTRACT)
        .collect::<Vec<_>>();
    assert!(
        !literal_offers.is_empty(),
        "route control must exercise a literal POST"
    );
    for item in literal_offers {
        let fp = item["snapshot_fingerprint"].as_str().unwrap();
        let record = progress
            .quarantined_fingerprints
            .get(fp)
            .expect("exact offered retry");
        assert_eq!(
            record.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert!(record.hold.is_none());
        assert_eq!(record.version_skew_attempts, 0);
        assert!(record.retry_after_unix_seconds > current_unix_seconds());
    }
    control.restart();
    assert!(
        money::adoption_paused(&control.support, &control.saved()),
        "failed route-pause persistence cannot reopen after reload"
    );
    assert!(
        !money::adoption_probe_due(&control.support, &control.saved()),
        "unknown route state forbids recovery probe"
    );
    let offers = control.offers().len();
    let _result = control.cycle_result();
    assert_eq!(
        control.offers().len(),
        offers,
        "no literal POST while route checkpoint is unproven"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_accepted_a_restored_older_b_message_only_real_reoffers_settle_loser() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestBirth, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    };
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("message-only restore: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for restart in [false, true] {
        let mut control = P2aControl::new(FinishOutcome::Accept);
        let _live = money::LiveForTest::new(&control.support);
        let lines = std::fs::read_to_string(control.transcript())
            .unwrap()
            .lines()
            .map(|line| {
                let mut value: serde_json::Value = serde_json::from_str(line).unwrap();
                value.as_object_mut().unwrap().remove("requestId");
                value
            })
            .collect::<Vec<_>>();
        std::fs::write(
            control.transcript(),
            lines
                .iter()
                .map(|line| line.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        control.cycle();
        let accepted = control.offers();
        assert_eq!(
            accepted.last().unwrap()["request_count"],
            2,
            "A accepted before B exists"
        );
        const B: &str = "00000000-0000-4000-8000-000000000001";
        let path = control.transcript().with_file_name(format!("{B}.jsonl"));
        let mut shared = lines[1].clone();
        shared["sessionId"] = B.into();
        let text = shared.to_string() + "\n";
        std::fs::write(&path, &text).unwrap();
        // Model a restored physical file's older retained birth explicitly;
        // ownership, message watches and all reoffers still come from the
        // actual parser/census/finish caller, never from fabricated wire items.
        // The scanner's (non-canonical) index key; see the ACK/CAS control.
        let key = path.to_string_lossy().into_owned();
        let revision = format!("{:x}", Sha256::digest(text.as_bytes()));
        // A retained birth carries only onto the same physical object (its
        // device and inode); any other identity is a replacement whose birth
        // is this read's. Bind the restored birth to B's actual object.
        let (device, inode) = {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&path).unwrap();
            (metadata.dev(), metadata.ino())
        };
        let mut saved = control.saved();
        saved.claude_request_census_mut_for_test().insert_for_test(
            &key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &revision,
                7,
                ClaudeRequestCensusShape::IdentityIncomplete,
                vec![],
            )
            .with_birth_for_test(Some(ClaudeRequestBirth {
                unix_seconds: 1_700_000_000,
                device,
                inode,
            })),
        );
        saved.save(&control.index_path).unwrap();
        if restart {
            control.restart();
        }
        for _ in 0..6 {
            control.cycle();
        }
        let offers = control.offers();
        let a = offers
            .iter()
            .rev()
            .find(|item| item["source_session_id"] == IDENTITY_PIPELINE_ROOT)
            .unwrap();
        let b = offers
            .iter()
            .rev()
            .find(|item| item["source_session_id"] == B)
            .expect("restored B reaches actual POST");
        assert!(
            offers.len() > accepted.len() + 1,
            "unchanged A must really reoffer after message evidence changes"
        );
        let trail = offers
            .iter()
            .map(|item| {
                format!(
                    "{}:{}/{}:{}",
                    item["source_session_id"],
                    item["request_count"],
                    item["removed_request_count"],
                    item["snapshot_fingerprint"]
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            a["request_count"], 1,
            "accepted A loses shared message exactly once (restart={restart}, before B {}, offers {trail:?})",
            accepted.len()
        );
        assert_eq!(a["removed_request_count"], 1);
        assert_eq!(a["removed_usage"]["input_tokens"], 10);
        assert_eq!(a["removed_usage"]["output_tokens"], 1);
        assert_eq!(b["request_count"], 1);
        assert_eq!(b["removed_request_count"], 0);
        let saved = control.saved();
        for item in [a, b] {
            assert!(saved.accepted_snapshot_fingerprint_recorded(
                item["snapshot_fingerprint"].as_str().unwrap()
            ));
        }
        let before = offers.len();
        control.restart();
        for _ in 0..2 {
            control.cycle();
        }
        assert_eq!(
            control.offers().len(),
            before,
            "covering saved ACKs settle both winner and loser after restart"
        );
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_continuously_changing_evidence_finishes_frozen_epoch_then_next_epoch() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("continuous custody: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::new(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    control.recovery_startup(current_unix_seconds());
    let mut sequence = 0;
    let mut counts = Vec::new();
    for epoch in 0..2 {
        let before = control.offers().len();
        let mut attempts = 0;
        control
            .cycle_changing(|attempt| {
                attempts += 1;
                assert!(
                    attempt < 12,
                    "writer ACKs must bound progress despite ongoing input"
                );
                sequence += 1;
                let clock = (OffsetDateTime::now_utc() - TimeDuration::hours(2))
                    .format(&Rfc3339)
                    .unwrap();
                let row = serde_json::json!({"timestamp":clock, "type":"assistant",
                "sessionId":IDENTITY_PIPELINE_ROOT, "requestId":format!("active-{sequence}"),
                "message":{"id":format!("active-message-{sequence}"), "model":"claude-haiku-4-5",
                    "usage":{"input_tokens":sequence + 30,"output_tokens":1}}});
                std::fs::OpenOptions::new()
                    .append(true)
                    .open(control.transcript())
                    .unwrap()
                    .write_all(format!("{row}\n").as_bytes())
                    .unwrap();
                // All three actual evidence sources change on EVERY turn, including
                // the turn that consumes each writer receipt. No quiet retry exists.
                write_native_bootstrap_sidecars(&control.fixture, &control.support);
            })
            .unwrap();
        assert!(attempts > 1, "exercise actual asynchronous custody yields");
        let offers = control.offers();
        assert!(offers.len() > before, "epoch {epoch} must actually POST");
        let offered = &offers[before];
        assert_eq!(
            offered["usage_accounting_contract"],
            money::REQUEST_OWNED_CONTRACT
        );
        counts.push(offered["request_count"].as_u64().unwrap());
        let saved = control.saved();
        assert!(saved
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 3));
        let fp = offered["snapshot_fingerprint"].as_str().unwrap();
        assert!(
            saved.accepted_snapshot_fingerprint_recorded(fp),
            "exact body's durable ACK and selected save complete under activity"
        );
    }
    assert_eq!(
        counts[0], 3,
        "first checkpoint owns its frozen two original requests plus first append"
    );
    assert!(
        counts[1] > counts[0],
        "later evidence belongs to the next checkpoint epoch"
    );
    assert!(
        sequence + 2 > counts[1],
        "input continues changing even on the last resumed turn"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_checkpoint_resume_revalidates_selected_state_protection_and_live_gate() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("resume revalidation: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for reason in ["selected index", "protection list", "live custody"] {
        let control = P2aControl::new(FinishOutcome::Accept);
        let _live = money::LiveForTest::new(&control.support);
        let mut changed = false;
        let result = control.cycle_changing(|_| {
            if !changed && money_resume::pending_for_test(&control.support) {
                changed = true;
                match reason {
                    "selected index" => {
                        control.saved().save(&control.index_path).unwrap();
                    }
                    "protection list" => std::fs::write(
                        control
                            .support
                            .join("snapshots/claude_code-reemission-exclusions.txt"),
                        format!("{IDENTITY_PIPELINE_ROOT}\n"),
                    )
                    .unwrap(),
                    "live custody" => {
                        std::fs::write(control.support.join("claude-request-owned-live.off"), b"")
                            .unwrap()
                    }
                    _ => unreachable!(),
                }
            }
        });
        assert!(
            result.unwrap_err().to_string().contains(reason),
            "must revalidate {reason}"
        );
        assert!(
            control.offers().is_empty(),
            "stale continuation must never POST"
        );
        assert!(control
            .saved()
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision != 3));
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_enabling_live_between_finish_entry_and_evidence_yields_without_panicking_or_posting() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::new(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    let kill = control.support.join("claude-request-owned-live.off");
    std::fs::write(&kill, b"").unwrap();
    let toggled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let observed = toggled.clone();
    money_resume::set_before_immediate_for_test(move || {
        std::fs::remove_file(kill).unwrap();
        observed.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    let mut refused_turn = false;
    control
        .cycle_changing(|attempt| {
            if attempt == 1 {
                refused_turn = true;
                assert!(
                    control.offers().is_empty(),
                    "a newly pending immediate finish cannot POST"
                );
            }
        })
        .unwrap();
    assert!(toggled.load(std::sync::atomic::Ordering::SeqCst));
    assert!(
        refused_turn,
        "toggle must exercise the Pending -> LocalRefusal boundary"
    );
    assert!(
        !control.offers().is_empty(),
        "fresh admitted live finish must later make progress"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_synchronous_audit_mode_never_yields_or_mutates_live_money_custody() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let control = P2aControl::new(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    let mut index = ScanIndex::default();
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[control
            .fixture
            .home
            .join(".claude/projects/-synthetic-repo")],
        &mut index,
        &current_rfc3339(),
        183,
        16,
        true,
    )
    .unwrap();
    assert!(!scan.snapshots.is_empty());
    let before = money::store::with_ledger_for_test(&control.support, |ledger| {
        serde_json::to_value(ledger.census()).unwrap()
    })
    .unwrap();
    let result = money_resume::immediate(try_apply_claude_local_evidence_to_scan_resume(
        &control.support,
        &mut scan,
        &mut index,
        None,
        None,
        None,
        None,
        None,
        false,
    ))
    .expect("audit mode must stay synchronous even while live money is enabled");
    assert!(result.is_ok());
    assert!(scan.snapshots.iter().all(
        |item| item.usage_accounting_contract.as_deref() != Some(money::REQUEST_OWNED_CONTRACT)
    ));
    let after = money::store::with_ledger_for_test(&control.support, |ledger| {
        serde_json::to_value(ledger.census()).unwrap()
    })
    .unwrap();
    assert_eq!(
        after, before,
        "audit must not mint synthetic/dirty/watch/offer/adoption custody"
    );
    assert!(control.offers().is_empty());
    money::capture::purge_before(&control.support, Instant::now());
}

// Real-cap controls use the production record limit, actual preparation/finish,
// POST, durable ACK, selected save and restart. No test cap or timeout stands
// in for the admission decision.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_full_ledger_releases_live_finish_and_continues_ordinary_collection() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusInsert, ClaudeRequestCensusRecord,
    };
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::Accept);
    control.resource_receipt = true;
    // Production always runs the shadow, so the pre-live transcript already
    // owns its carrier; only the new physical file below needs admission.
    money::enable_shadow_for_test(&control.support);
    control.cycle();
    let _live = money::LiveForTest::new(&control.support);
    money::store::reload_for_test(&control.support).unwrap();
    money::store::with_ledger_for_test(&control.support, |ledger| {
        let vacant = money::store::LEDGER_MAX_RECORDS - ledger.census().record_count();
        for n in 0..vacant {
            assert_eq!(
                ledger.insert(
                    format!("dirty:{n:064x}"),
                    ClaudeRequestCensusRecord::money_debt([7; 32], 0)
                ),
                ClaudeRequestCensusInsert::Stored
            );
        }
        assert_eq!(
            ledger.insert(
                "dirty:over-cap".into(),
                ClaudeRequestCensusRecord::money_debt([8; 32], 0)
            ),
            ClaudeRequestCensusInsert::Refused
        );
        assert!(money::store::checkpoint_for_test(&control.support, ledger));
    })
    .unwrap();
    // Existing carriers can accept more fields at the record ceiling. Force
    // admission of a new physical carrier to exercise actual aggregate refusal.
    let denied_root = "00000000-1111-4000-8000-000000000001";
    let denied = std::fs::read_to_string(control.transcript())
        .unwrap()
        .replace(IDENTITY_PIPELINE_ROOT, denied_root);
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{denied_root}.jsonl")),
        denied,
    )
    .unwrap();
    let _refused = control.cycle_changing(|attempt| {
        assert!(
            attempt < 12,
            "terminal capacity refusal cannot remain parked"
        )
    });
    assert!(!money_resume::pending_for_test(&control.support));
    assert!(
        !money::request_owned_live(&control.support),
        "next collection uses ordinary path"
    );
    let sibling = "7c1bccdd-3ac4-4c78-a15d-1ed09f351405";
    let text = std::fs::read_to_string(control.transcript())
        .unwrap()
        .replace(IDENTITY_PIPELINE_ROOT, sibling)
        .replace("req_1", "capacity-new-1")
        .replace("req_2", "capacity-new-2");
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{sibling}.jsonl")),
        text,
    )
    .unwrap();
    let before = control.offers().len();
    control.cycle();
    let offers = control.offers();
    let ordinary = offers[before..]
        .iter()
        .find(|item| item["source_session_id"] == sibling)
        .expect("ordinary sibling actually POSTs through saturated money custody");
    assert_ne!(
        ordinary["usage_accounting_contract"],
        money::REQUEST_OWNED_CONTRACT
    );
    assert!(control.saved().accepted_snapshot_fingerprint_recorded(
        ordinary["snapshot_fingerprint"].as_str().unwrap()
    ));
    assert!(!money_resume::pending_for_test(&control.support));
    money::store::with_ledger_for_test(&control.support, |ledger| {
        assert_eq!(
            ledger.census().record_count(),
            money::store::LEDGER_MAX_RECORDS
        );
        assert_eq!(
            ledger
                .get(&format!("dirty:{:064x}", 0))
                .unwrap()
                .money_revision(),
            [7; 32],
            "ordinary progress never deletes existing debt"
        );
    })
    .unwrap();
    money::disable_shadow_for_test(&control.support);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_actual_cap_metadata_recovery_finishes_literal_and_survives_restart() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusInsert, ClaudeRequestCensusRecord,
    };
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::Accept);
    control.cycle();
    let _live = money::LiveForTest::new(&control.support);
    money::store::reload_for_test(&control.support).unwrap();
    money::store::with_ledger_for_test(&control.support, |ledger| {
        assert_eq!(
            ledger.insert(
                "due:sentinel".into(),
                ClaudeRequestCensusRecord::money_debt([9; 32], 0)
            ),
            ClaudeRequestCensusInsert::Stored
        );
        let vacant = money::store::LEDGER_MAX_RECORDS - ledger.census().record_count();
        for n in 1..=vacant {
            assert_eq!(
                ledger.insert(
                    format!(
                        "watch:trace:{:x}:{n:016x}",
                        Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
                    ),
                    ClaudeRequestCensusRecord::money_debt([7; 32], 0)
                ),
                ClaudeRequestCensusInsert::Stored
            );
        }
        assert_eq!(
            ledger.insert(
                "dirty:over-cap".into(),
                ClaudeRequestCensusRecord::money_debt([8; 32], 0)
            ),
            ClaudeRequestCensusInsert::Refused
        );
        assert!(money::store::checkpoint_for_test(&control.support, ledger));
    })
    .unwrap();
    money::store::refuse_live(&control.support);
    let before = control.offers().len();
    // A refusal always earns an ordinary collection first. Reclaimed slots
    // then admit the following live attempt without dropping old custody.
    control.cycle();
    assert!(!money_resume::pending_for_test(&control.support));
    control
        .cycle_changing(|attempt| {
            assert!(
                attempt < 16,
                "real reclaimed slots must admit and settle a literal"
            )
        })
        .unwrap();
    let offers = control.offers();
    let literal = offers[before..]
        .iter()
        .find(|item| item["usage_accounting_contract"] == money::REQUEST_OWNED_CONTRACT)
        .expect("actual literal POST after cap reclamation");
    let fp = literal["snapshot_fingerprint"].as_str().unwrap();
    assert!(control.saved().accepted_snapshot_fingerprint_recorded(fp));
    assert!(control
        .saved()
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 3));
    money::store::with_ledger_for_test(&control.support, |ledger| {
        assert!(ledger.census().record_count() < money::store::LEDGER_MAX_RECORDS);
        assert_eq!(
            ledger.get("due:sentinel").unwrap().money_revision(),
            [9; 32]
        );
        assert!(money::store::checkpoint_for_test(&control.support, ledger));
    })
    .unwrap();
    control.restart();
    control.cycle();
    assert!(control.saved().accepted_snapshot_fingerprint_recorded(fp));
    money::store::with_ledger_for_test(&control.support, |ledger| {
        assert_eq!(
            ledger.get("due:sentinel").unwrap().money_revision(),
            [9; 32]
        )
    })
    .unwrap();
    assert!(!money_resume::pending_for_test(&control.support));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_preboxing_memory_refusal_releases_finish_then_collects_ordinary() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::new(FinishOutcome::Accept);
    control.cycle();
    let _live = money::LiveForTest::new(&control.support);
    let held = Arc::new(Mutex::new(None));
    let injected = held.clone();
    money_resume::set_before_start_for_test(move || {
        *injected.lock().unwrap() = Some(
            money::ShadowReservation::admit(
                money::SHADOW_MEMORY_CEILING_BYTES - money::reserved_for_test(),
            )
            .unwrap(),
        );
    });
    let before = control.offers().len();
    let error = control.cycle_result().unwrap_err();
    assert!(error.to_string().contains("admission refused"));
    assert!(!money_resume::pending_for_test(&control.support));
    assert!(!money::request_owned_live(&control.support));
    assert_eq!(
        control.offers().len(),
        before,
        "unadmitted graph cannot POST"
    );
    drop(held.lock().unwrap().take());
    let sibling = "d515a780-afae-4857-8325-b5e900af638c";
    let text = std::fs::read_to_string(control.transcript())
        .unwrap()
        .replace(IDENTITY_PIPELINE_ROOT, sibling)
        .replace("req_1", "memory-new-1")
        .replace("req_2", "memory-new-2");
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{sibling}.jsonl")),
        text,
    )
    .unwrap();
    control.cycle();
    let offers = control.offers();
    let ordinary = offers[before..]
        .iter()
        .find(|item| item["source_session_id"] == sibling)
        .expect("ordinary POST after pre-boxing admission refusal");
    assert_ne!(
        ordinary["usage_accounting_contract"],
        money::REQUEST_OWNED_CONTRACT
    );
    assert!(control.saved().accepted_snapshot_fingerprint_recorded(
        ordinary["snapshot_fingerprint"].as_str().unwrap()
    ));
}
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_parked_finish_releases_on_disabled_source_credential_exit_and_account_reset() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for reason in ["disabled source", "credential exit", "account reset"] {
        let control = P2aControl::new(FinishOutcome::Accept);
        let _live = money::LiveForTest::new(&control.support);
        let mut cancelled = false;
        let result = control.cycle_changing(|_| {
            if cancelled || !money_resume::pending_for_test(&control.support) {
                return;
            }
            assert!(money_resume::pending_for_test(&control.support));
            let reserved = money::reserved_for_test();
            money_resume::cancel_owner(&test_daemon("unrelated-owner"));
            assert!(
                money_resume::pending_for_test(&control.support),
                "another daemon cannot cancel this owner"
            );
            match reason {
                "account reset" => {
                    control
                        .daemon
                        .reset_account_for_authorized_client()
                        .unwrap();
                }
                "disabled source" => {
                    let mut cycle = money_resume::CycleScope::new(&control.daemon);
                    cycle.keep_claude(false);
                }
                "credential exit" => {
                    drop(money_resume::CycleScope::new(&control.daemon));
                }
                _ => unreachable!(),
            }
            cancelled = true;
            assert!(!money_resume::pending_for_test(&control.support));
            assert!(
                money::reserved_for_test() < reserved,
                "{reason} releases the actual retained graph"
            );
            money::store::with_ledger_for_test(&control.support, |ledger| {
                assert!(
                    ledger
                        .census()
                        .records_with_prefix("dirty:")
                        .next()
                        .is_some(),
                    "cancellation preserves scheduling custody"
                );
            })
            .unwrap();
            // Let the fixture driver finish a new ordinary scan after proving
            // cancellation, rather than preparing another live continuation.
            std::fs::write(control.support.join("claude-request-owned-live.off"), b"").unwrap();
        });
        assert!(cancelled, "exercise a real parked finish");
        result.unwrap();
        assert!(!money_resume::pending_for_test(&control.support));
        assert!(
            control
                .offers()
                .iter()
                .all(|item| item["usage_accounting_contract"] != money::REQUEST_OWNED_CONTRACT),
            "cancelled literal cannot POST"
        );
    }
}

// Run whole-caller and settlement-only allocation audits separately against
// the same real small page and large ACK history. The settlement receipt
// includes canonical body witnesses and retains funds through selected save.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_live_page_large_ack_history_resource_receipt() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for (history, settlement_only) in [(0, false), (20_000, false), (0, true), (20_000, true)] {
        let mut control = P2aControl::new(FinishOutcome::Accept);
        control.accepted_history = history;
        control.resource_receipt = !settlement_only;
        control.settlement_receipt = settlement_only;
        let _live = money::LiveForTest::new(&control.support);
        control.cycle();
        assert!(!money_resume::pending_for_test(&control.support));
        let offers = control.offers();
        let literals = offers
            .iter()
            .filter(|item| item["usage_accounting_contract"] == money::REQUEST_OWNED_CONTRACT)
            .collect::<Vec<_>>();
        assert!(
            !literals.is_empty(),
            "gate ON must exercise literal POST and settlement"
        );
        for literal in literals {
            assert!(control.saved().accepted_snapshot_fingerprint_recorded(
                literal["snapshot_fingerprint"].as_str().unwrap()
            ));
        }
        assert!(control
            .saved()
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 3));
    }
}

// Head-only observation complements the unchanged independently built main/head
// comparison. The copied parity test source must keep compiling against main.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_gate_off_m4_money_operation_receipt() {
    use crate::snapshots::claude_request_money as money;
    let _flush = money::store::flush_timeout_for_test(Duration::from_secs(60));
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for history in [0, 20_000] {
        let mut control = P2aControl::new(FinishOutcome::Accept);
        control.accepted_history = history;
        let index = money_m4_saved_inputs(&control.fixture.base, &control.support);
        let mut index: ScanIndex = serde_json::from_value(index).unwrap();
        index.save(&control.index_path).unwrap();
        money::store::reload_for_test(&control.support).unwrap();
        money::store::flush();
        let before = money_saved_ledger_files(&control.support);
        // The pre-existing once-per-scope shadow kill-switch stat is outside
        // the incremental money page observation, just as fixture loading is.
        money::seed_shadow_off(&control.support);
        assert!(!money::request_owned_live(&control.support));
        let ((_, settlements), io) = crate::retry_allocation_probe::measure_money_io(|| {
            crate::retry_allocation_probe::measure_money_settlements(|| control.cycle())
        });
        assert_eq!(io, crate::retry_allocation_probe::MoneyIoReceipt::default());
        let mut skipped = 0;
        for receipt in settlements.iter() {
            assert!(receipt.skipped);
            assert_eq!(receipt.required, 0);
            assert_eq!(receipt.funds, 0);
            assert_eq!(receipt.allocation.allocations, 0);
            assert_eq!(receipt.shared_admission_peak, 0);
            skipped += 1;
        }
        assert!(skipped > 0, "actual finish must observe the OFF branch");
        assert_eq!(before, money_saved_ledger_files(&control.support));
        assert!(control
            .offers()
            .iter()
            .all(|item| item["usage_accounting_contract"] != money::REQUEST_OWNED_CONTRACT));
        eprintln!("MONEY_OFF_OPERATIONS history={history} saved_files={} scratch_allocations=0 scratch_admission=0 money_boundary_attempts={io:?} off_finishes={skipped} preexisting_seed_stat_excluded=true not_syscalls=true", before.len());
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_settlement_admission_refusal_keeps_exact_debt_after_ack_and_restart() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::new(FinishOutcome::Accept);
    control.cycle();
    let _live = money::LiveForTest::new(&control.support);
    let (result, receipts) = crate::retry_allocation_probe::measure_money_settlements(|| {
        crate::retry_allocation_probe::refuse_money_settlement_for_test(|| control.cycle_result())
    });
    assert!(
        result.is_err(),
        "settlement refusal must not certify a selected save"
    );
    assert!(receipts.iter().any(|receipt| receipt.required > 0
        && !receipt.admitted
        && receipt.funds == 0
        && receipt.pairs == 0));
    assert!(!money_resume::pending_for_test(&control.support));
    assert!(
        control
            .offers()
            .iter()
            .any(|item| item["usage_accounting_contract"] == money::REQUEST_OWNED_CONTRACT),
        "exercise a real POST before settlement refusal"
    );
    let key = control.transcript().to_string_lossy().into_owned();
    let debt = money::store::with_ledger_for_test(&control.support, |ledger| {
        let due = ledger
            .get(&money::store::money_key("due:", &key))
            .map(|record| record.to_owned_record());
        let dirty = ledger
            .get(&money::store::money_key("dirty:", &key))
            .map(|record| record.to_owned_record());
        assert!(due.is_some() && dirty.is_some());
        assert!(money::store::checkpoint_for_test(&control.support, ledger));
        (due, dirty)
    })
    .unwrap();
    money::store::reload_for_test(&control.support).unwrap();
    let restarted = money::store::with_ledger_for_test(&control.support, |ledger| {
        (
            ledger
                .get(&money::store::money_key("due:", &key))
                .map(|record| record.to_owned_record()),
            ledger
                .get(&money::store::money_key("dirty:", &key))
                .map(|record| record.to_owned_record()),
        )
    })
    .unwrap();
    assert_eq!(
        restarted, debt,
        "exact revisions/deadlines survive post-ACK admission refusal"
    );
    eprintln!("MONEY_SETTLEMENT_REFUSAL actual_post=true selected_save_certified=false exact_due_dirty_restart=true injected_admission_refusal=true");
}

#[test]
fn p2a_transient_retry_keeps_server_hold_custody_across_restart() {
    let scratch = crate::test_scratch::ScratchDir::new("held-transient-restart");
    let now = current_unix_seconds();
    let fingerprint = "01".repeat(32);
    let body = "02".repeat(32);
    let changed_body = "03".repeat(32);
    for kind in [SnapshotHoldKind::Held, SnapshotHoldKind::Refused] {
        let path = scratch.join(format!("progress-{kind:?}.json"));
        let witness = snapshot_quarantine_witness(SnapshotSource::ClaudeCode);
        let mut progress = SnapshotUploadProgress::new("04".repeat(32), witness.clone());
        progress.quarantine_held_body(fingerprint.as_str(), body.as_str(), kind);
        let record = progress
            .quarantined_fingerprints
            .get_mut(fingerprint.as_str())
            .unwrap();
        let hold = record.hold.as_mut().unwrap();
        hold.stage = 2;
        hold.first_held_unix = now.saturating_sub(31 * 86400);
        hold.retries_in_day = 6;
        let expected = hold.clone();
        let deadline = now + expected.base_seconds(now);
        record.retry_after_unix_seconds = deadline;
        for delay in [1800, 21600] {
            progress.quarantine_transient_body(fingerprint.as_str(), body.as_str(), now + delay);
            let record = &progress.quarantined_fingerprints[fingerprint.as_str()];
            assert_eq!(record.hold.as_ref(), Some(&expected));
            assert_eq!(record.retry_after_unix_seconds, deadline);
            assert!(!record.hold.as_ref().unwrap().allowance(now));
        }
        progress.save(&path).unwrap();
        let mut restored = SnapshotUploadProgress::load(&path, &"04".repeat(32), witness).unwrap();
        let record = &restored.quarantined_fingerprints[fingerprint.as_str()];
        assert_eq!(record.hold.as_ref(), Some(&expected));
        assert_eq!(record.retry_after_unix_seconds, deadline);
        restored.quarantine_transient_body(fingerprint.as_str(), body.as_str(), deadline + 1);
        assert_eq!(
            restored.quarantined_fingerprints[fingerprint.as_str()].retry_after_unix_seconds,
            deadline + 1
        );
        restored.quarantine_transient_body(fingerprint.as_str(), changed_body.as_str(), now + 1800);
        assert!(restored.quarantined_fingerprints[fingerprint.as_str()]
            .hold
            .is_none());
        assert_eq!(
            restored.quarantined_fingerprints[fingerprint.as_str()].retry_after_unix_seconds,
            now + 1800,
            "ordinary quarantine jitter must not delay transient recovery"
        );
    }
}

// UNKNOWN recovery's transport is exercised through the real batch HTTP route.
// The explicit test permit supplies owner B's pending LiteralGuard contract;
// it is not evidence that the dependency has landed or that P2 can activate.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_lost_commit_and_no_commit_exact_replay_restart() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    for lost in [FinishOutcome::LostCommitted, FinishOutcome::LostUncommitted] {
        let mut control = P2aControl::with_recovery_evidence(lost);
        let _live = money::LiveForTest::new(&control.support);
        let now = current_unix_seconds();
        let clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
        assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
        let original = control.server.raw_batches.lock().unwrap()[0].clone();
        let committed_before = control.server.committed.lock().unwrap().len();
        assert_eq!(
            committed_before,
            usize::from(matches!(lost, FinishOutcome::LostCommitted))
        );
        assert!(
            !money::adoption_paused(&control.support, &control.saved()),
            "unrelated work is not paused"
        );
        assert!(money::money_due(
            &control.support,
            &control.transcript().to_string_lossy(),
            u64::MAX
        ));
        let captured = unknown_recovery::active_for_test(&control.support)
            .pop()
            .unwrap();
        let original_offer = captured
            .entities
            .iter()
            .flat_map(|e| e.file_selections.iter())
            .find_map(|s| s.offer);
        assert!(
            original_offer.is_some(),
            "the transcript-backed original send must record its offer binding"
        );
        control.restart();
        *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
        drop(clock);
        let _early = money::PageClockForTest::new(&control.support, now + 299);
        control.cycle();
        assert_eq!(
            control.server.raw_batches.lock().unwrap().len(),
            1,
            "no early replay after restart"
        );
        drop(_early);
        let _due = money::PageClockForTest::new(&control.support, now + 300);
        control.cycle();
        let posts = control.server.raw_batches.lock().unwrap().clone();
        assert_eq!(posts.len(), 2);
        assert_eq!(
            posts[1], original,
            "no timestamp/CAS/token-contract/client-report reshaping"
        );
        assert_eq!(
            control.server.committed.lock().unwrap().len(),
            1,
            "same-head convergence has one entity contribution"
        );
        control.cycle(); // consume durable selected-save release and ordinary debt settlement
        assert!(control
            .saved()
            .files
            .values()
            .all(|e| e.effective_upload_body_witness_revision == 3));
        assert!(!money::money_due(
            &control.support,
            &control.transcript().to_string_lossy(),
            u64::MAX
        ));
        let offers = control.offers();
        assert_eq!(
            control.server.raw_batches.lock().unwrap().len(),
            2,
            "{}",
            recovery_offer_difference(&offers)
        );
    }
}

// Synthetic HTTP fixture diagnostics only. Keep the exact physical-POST bound
// while exposing which entity fields an unexpected successor changed.
fn recovery_offer_difference(offers: &[serde_json::Value]) -> String {
    let Some(first) = offers.first().and_then(serde_json::Value::as_object) else {
        return "no fixture offers".into();
    };
    let Some(last) = offers.last().and_then(serde_json::Value::as_object) else {
        return "no final fixture offer".into();
    };
    first
        .keys()
        .chain(last.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|key| first.get(*key) != last.get(*key))
        .map(|key| format!("{key}: {:?} -> {:?}", first.get(key), last.get(key)))
        .collect::<Vec<_>>()
        .join("; ")
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_late_revision_deny_contract_releases_without_post_charge() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let clock = money::PageClockForTest::new(&control.support, now);
    control.cycle_deferred();
    control.recovery_startup(now);
    let original = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert!(original.entities.iter().any(|entity| entity.literal));
    let mut index = control.saved();
    index.activate_upload_context(original.context.clone());
    index.activate_effective_upload_body_witness_revision(3);
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let progress_path = snapshot_upload_progress_path(&control.index_path);
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    drop(clock);
    let _due = money::PageClockForTest::new(&control.support, now + 300);
    let checks = std::cell::Cell::new(0);
    let denied = std::cell::RefCell::new(None);
    money_resume::drive_for_test(unknown_recovery::replay_due(
        &control.support,
        &mut index,
        &mut progress,
        &progress_path,
        &control.client,
        &control.device,
        "device-secret",
        "otm_test",
        &namespace,
        original.policy,
        || {
            checks.set(checks.get() + 1);
            if checks.get() == 2 {
                let charged = unknown_recovery::active_for_test(&control.support)
                    .pop()
                    .unwrap();
                assert_eq!(
                    (charged.posts, charged.slot),
                    (2, 1),
                    "real durable counter cut point"
                );
                // Required owner-B guard contract: the active row downgrades
                // while the counter writer is pending. No guard is reimplemented.
                *denied.borrow_mut() = Some(unknown_recovery::guard_for_test(
                    unknown_recovery::LiteralPermit::DenyAll,
                ));
            }
            Ok(())
        },
    ))
    .unwrap();
    assert_eq!(checks.get(), 2);
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
    let after = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(
        (after.posts, after.slot),
        (1, 1),
        "a gate veto does not charge a physical POST"
    );
    assert_eq!(
        after.terminal,
        Some(unknown_recovery::Reason::RevisionDowngrade)
    );
    assert!(!progress
        .accepted_fingerprints
        .contains(&original.entities[0].fingerprint));
    control.recovery_startup(now + 300);
    assert!(unknown_recovery::active_for_test(&control.support).is_empty());
    let status: serde_json::Value = serde_json::from_slice(
        &std::fs::read(control.support.join("claude-money-recovery/status")).unwrap(),
    )
    .unwrap();
    assert_eq!(status["unknown_outcome_unresolved"], 1);
    assert!(money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_pause_installed_after_counter_commit_is_current_before_post() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    {
        let _clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
    }
    let original = control.server.raw_batches.lock().unwrap()[0].clone();
    control.recovery_startup(now);
    let attempt = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    let mut index = control.saved();
    index.activate_upload_context(attempt.context.clone());
    index.activate_effective_upload_body_witness_revision(3);
    assert!(!index.request_money_adoption_paused());
    let pause_index = index.clone();
    let calls = std::cell::Cell::new(0);
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let progress_path = snapshot_upload_progress_path(&control.index_path);
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    {
        let _due = money::PageClockForTest::new(&control.support, now + 300);
        money_resume::drive_for_test(unknown_recovery::replay_due(
            &control.support,
            &mut index,
            &mut progress,
            &progress_path,
            &control.client,
            &control.device,
            "device-secret",
            "otm_test",
            &namespace,
            attempt.policy,
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    assert_eq!(
                        unknown_recovery::active_for_test(&control.support)[0].posts,
                        2
                    );
                    money::note_route_pause(&control.support, &pause_index, true);
                    money::store::flush();
                    money::store::with_ledger_for_test(&control.support, |ledger| {
                        assert!(money::store::checkpoint_for_test(&control.support, ledger));
                    })
                    .unwrap();
                    assert!(money::adoption_paused(&control.support, &pause_index));
                }
                Ok(())
            },
        ))
        .unwrap();
    }
    assert_eq!(calls.get(), 2);
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        1,
        "the newly installed independent pause must veto the physical POST"
    );
    let denied = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(
        denied.posts, 1,
        "a gate denial rolls back the unsent physical charge"
    );
    assert_eq!(denied.slot, 1);
    assert!(denied.terminal.is_none());
    assert!(progress.accepted_fingerprints.is_empty());
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    {
        let _next = money::PageClockForTest::new(&control.support, now + 3600);
        money_resume::drive_for_test(unknown_recovery::replay_due(
            &control.support,
            &mut index,
            &mut progress,
            &progress_path,
            &control.client,
            &control.device,
            "device-secret",
            "otm_test",
            &namespace,
            attempt.policy,
            || Ok(()),
        ))
        .unwrap();
    }
    let posts = control.server.raw_batches.lock().unwrap();
    assert_eq!(posts.len(), 2);
    assert_eq!(
        posts[1], original,
        "the later permitted slot retains the original bytes"
    );
    assert!(progress
        .accepted_fingerprints
        .contains(&attempt.entities[0].fingerprint));
    eprintln!("MONEY_UNKNOWN_CURRENT_PAUSE late_pause_post=false unsent_charge_rolled_back=true next_slot_exact=true");
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_saved_replay_ack_cannot_cover_newer_same_body_debt() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for newer_revision in [false, true] {
        let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
        let _live = money::LiveForTest::new(&control.support);
        let now = current_unix_seconds();
        {
            let _clock = money::PageClockForTest::new(&control.support, now);
            control.cycle_deferred();
        }
        let original = unknown_recovery::active_for_test(&control.support)
            .pop()
            .unwrap();
        let (entity, key, offer) = original
            .entities
            .iter()
            .find_map(|entity| {
                entity
                    .files
                    .iter()
                    .zip(&entity.file_selections)
                    .find_map(|(key, selection)| {
                        selection.offer.map(|offer| (entity, key.clone(), offer))
                    })
            })
            .expect("the original transcript-backed literal must retain its durable offer binding");
        assert_eq!(key, control.transcript().to_string_lossy().into_owned());
        assert!(entity.literal);
        *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
        {
            let _clock = money::PageClockForTest::new(&control.support, now + 300);
            control.cycle();
        }
        assert_eq!(control.server.raw_batches.lock().unwrap().len(), 2);
        let mut revision = offer.0;
        if newer_revision {
            revision[0] ^= 1;
        }
        money::store::with_ledger_for_test(&control.support, |ledger| {
            for prefix in ["dirty:", "due:"] {
                let debt = format!("{prefix}{:x}", Sha256::digest(key.as_bytes()));
                assert_eq!(ledger.insert(debt,
                    crate::snapshots::claude_request_census::ClaudeRequestCensusRecord::money_debt(revision, now + 301)),
                    crate::snapshots::claude_request_census::ClaudeRequestCensusInsert::Stored);
            }
            assert!(money::store::checkpoint_for_test(&control.support, ledger));
        }).unwrap();
        let support = control.support.clone();
        let pending_key = key.clone();
        *control.server.before_post.lock().unwrap() = Some(Box::new(move || {
            assert!(
                money::money_due(&support, &pending_key, u64::MAX),
                "the older ACK cannot retire the later obligation before its actual POST"
            );
        }));
        {
            let _clock = money::PageClockForTest::new(&control.support, now + 301);
            control.cycle();
        }
        let offers = control.offers();
        assert_eq!(
            offers.len(),
            3,
            "a later revision or scheduling window requires its own offer"
        );
        assert!(
            offers
                .iter()
                .all(|item| item["snapshot_fingerprint"].as_str()
                    == Some(entity.fingerprint.as_str()))
        );
        assert!(!money::money_due(&control.support, &key, u64::MAX));
    }
    eprintln!("MONEY_UNKNOWN_REOFFER_BOUND newer_revision_requires_post=true later_window_requires_post=true");
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_expiry_releases_only_unknown_and_does_not_rearm_lineage() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let clock = money::PageClockForTest::new(&control.support, now);
    control.cycle_deferred();
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
    let unavailable =
        unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Unavailable);
    assert_eq!(
        unknown_recovery::current_literal_guard(
            &control.saved(),
            &unknown_recovery::active_for_test(&control.support)[0]
        ),
        unknown_recovery::LiteralPermit::Unavailable,
        "missing dependency is closed"
    );
    drop(unavailable);
    control.restart();
    drop(clock);
    let _expired = money::PageClockForTest::new(&control.support, now + 86400);
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    control.cycle();
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        2,
        "ordinary successor admission resumes after terminal receipt"
    );
    assert!(unknown_recovery::active_for_test(&control.support).is_empty());
    assert!(control
        .saved()
        .files
        .values()
        .all(|e| e.effective_upload_body_witness_revision == 3));
    control.restart();
    control.cycle();
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        2,
        "restart cannot rearm the unresolved lineage"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_live_off_retires_existing_payload_before_ordinary_networking() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let _clock = money::PageClockForTest::new(&control.support, now);
    control.cycle_deferred();
    let m = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    let body = control
        .support
        .join("claude-money-recovery")
        .join(format!("{}.body", m.id));
    assert!(body.exists());
    let keys = ["dirty:", "due:"].map(|prefix| {
        format!(
            "{prefix}{:x}",
            Sha256::digest(control.transcript().to_string_lossy().as_bytes())
        )
    });
    let debt = money::store::with_ledger_for_test(&control.support, |ledger| {
        keys.iter()
            .map(|key| ledger.get(key).map(|r| (r.money_revision(), r.window())))
            .collect::<Vec<_>>()
    })
    .unwrap();
    assert!(debt.iter().all(Option::is_some));
    let status = control.support.join("claude-money-recovery/status");
    let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let posted = observed.clone();
    let payload = body.clone();
    *control.server.before_post.lock().unwrap() = Some(Box::new(move || {
        assert!(
            !payload.exists(),
            "disabled custody must retire before the next ordinary batch"
        );
        let status: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&status).unwrap()).unwrap();
        assert_eq!(status["unknown_outcome_unresolved"], 1);
        posted.store(true, std::sync::atomic::Ordering::SeqCst);
    }));
    std::fs::write(control.support.join("claude-money-live.off"), b"stop").unwrap();
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    control.cycle();
    assert!(observed.load(std::sync::atomic::Ordering::SeqCst));
    assert!(!body.exists());
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 2);
    assert!(unknown_recovery::active_for_test(&control.support).is_empty());
    let after = money::store::with_ledger_for_test(&control.support, |ledger| {
        keys.iter()
            .map(|key| ledger.get(key).map(|r| (r.money_revision(), r.window())))
            .collect::<Vec<_>>()
    })
    .unwrap();
    assert_eq!(
        after, debt,
        "only UNKNOWN is released; ordinary OFF delivery cannot retire the literal debt"
    );
    eprintln!("MONEY_UNKNOWN_OFF_CLEANUP prior_payload_deleted=true receipt_before_normal_post=true exact_debt_preserved=true");
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_new_list_and_revision_downgrade_guard_contract_send_none() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for downgrade in [false, true] {
        let control = P2aControl::with_recovery_evidence(FinishOutcome::LostCommitted);
        let _live = money::LiveForTest::new(&control.support);
        let now = current_unix_seconds();
        let clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
        control.recovery_startup(now);
        let m = unknown_recovery::active_for_test(&control.support)
            .pop()
            .unwrap();
        assert!(
            m.entities.iter().any(|e| e.literal),
            "revision contract control requires an actual rev-3 literal"
        );
        let mut index = control.saved();
        index.activate_upload_context(m.context.clone());
        index.activate_effective_upload_body_witness_revision(if downgrade { 2 } else { 3 });
        if !downgrade {
            std::fs::write(
                control
                    .support
                    .join("snapshots/claude_code-reemission-exclusions.txt"),
                format!("{:x}\n", Sha256::digest(m.entities[0].root.as_bytes())),
            )
            .unwrap();
        }
        let _guard = unknown_recovery::guard_for_test(if downgrade {
            unknown_recovery::LiteralPermit::DenyAll
        } else {
            unknown_recovery::LiteralPermit::Permit
        });
        drop(clock);
        let _due = money::PageClockForTest::new(&control.support, now + 300);
        let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
        let progress_path = snapshot_upload_progress_path(&control.index_path);
        let mut progress = SnapshotUploadProgress::load(
            &progress_path,
            &namespace,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        money_resume::drive_for_test(unknown_recovery::replay_due(
            &control.support,
            &mut index,
            &mut progress,
            &progress_path,
            &control.client,
            &control.device,
            "device-secret",
            "otm_test",
            &namespace,
            unknown_recovery::active_for_test(&control.support)[0].policy,
            || Ok(()),
        ))
        .unwrap();
        assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
        let after = unknown_recovery::active_for_test(&control.support)
            .pop()
            .unwrap();
        assert_eq!(after.posts, 1, "denied gates do not spend POST slots");
        assert_eq!(
            after.terminal,
            downgrade.then_some(unknown_recovery::Reason::RevisionDowngrade)
        );
        if !downgrade {
            assert_eq!(
                after.slot, 1,
                "a denied gate skips this due slot without a POST"
            );
            std::fs::write(
                control
                    .support
                    .join("snapshots/claude_code-reemission-exclusions.txt"),
                b"",
            )
            .unwrap();
            let _not_yet = money::PageClockForTest::new(&control.support, now + 301);
            money_resume::drive_for_test(unknown_recovery::replay_due(
                &control.support,
                &mut index,
                &mut progress,
                &progress_path,
                &control.client,
                &control.device,
                "device-secret",
                "otm_test",
                &namespace,
                m.policy,
                || Ok(()),
            ))
            .unwrap();
            assert_eq!(
                control.server.raw_batches.lock().unwrap().len(),
                1,
                "wait for the +1h slot after a gate denial"
            );
        }

        assert!(money::money_due(
            &control.support,
            &control.transcript().to_string_lossy(),
            u64::MAX
        ));
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_mixed_batch_new_list_sends_none_unrelated_work_continues() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let clock = money::PageClockForTest::new(&control.support, now);
    let sibling = "22222222-2222-4222-8222-222222222222";
    let fresh = "33333333-3333-4333-8333-333333333333";
    let original = std::fs::read_to_string(control.transcript()).unwrap();
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{sibling}.jsonl")),
        original
            .replace(IDENTITY_PIPELINE_ROOT, sibling)
            .replace("req_1", "unknown-sibling-1")
            .replace("req_2", "unknown-sibling-2"),
    )
    .unwrap();
    control.cycle_deferred();
    let pending = unknown_recovery::active_for_test(&control.support);
    assert_eq!(pending.len(), 1);
    assert_eq!(
        pending[0].entities.len(),
        2,
        "one complete mixed batch is retained"
    );
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
    std::fs::write(
        control
            .support
            .join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("{:x}\n", Sha256::digest(sibling.as_bytes())),
    )
    .unwrap();
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{fresh}.jsonl")),
        original
            .replace(IDENTITY_PIPELINE_ROOT, fresh)
            .replace("req_1", "unknown-fresh-1")
            .replace("req_2", "unknown-fresh-2"),
    )
    .unwrap();
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    drop(clock);
    let _due = money::PageClockForTest::new(&control.support, now + 300);
    control.cycle();
    let bodies = control.server.raw_batches.lock().unwrap().clone();
    assert_eq!(
        bodies.len(),
        2,
        "the only extra POST is unrelated fresh work"
    );
    let last: serde_json::Value = serde_json::from_str(&bodies[1]).unwrap();
    let items = last["snapshots"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["source_session_id"], fresh);
    assert!(unknown_recovery::active_for_test(&control.support).iter().any(|m|
        m.id == pending[0].id && m.posts == 1 && m.sha256 == pending[0].sha256),
        "new listing sends none of the retained batch, without spending its counter or mutating bytes");
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_new_filename_alias_cannot_escape_family_custody() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let clock = money::PageClockForTest::new(&control.support, now);
    control.cycle_deferred();
    let original = std::fs::read_to_string(control.transcript()).unwrap();
    let alias = control
        .transcript()
        .with_file_name("00000000-0000-4000-8000-000000000000.jsonl");
    std::fs::write(&alias, &original).unwrap();
    let unrelated = "33333333-3333-4333-8333-333333333333";
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{unrelated}.jsonl")),
        original
            .replace(IDENTITY_PIPELINE_ROOT, unrelated)
            .replace("req_1", "alias-control-fresh-1")
            .replace("req_2", "alias-control-fresh-2"),
    )
    .unwrap();
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    drop(clock);
    let _early = money::PageClockForTest::new(&control.support, now + 299);
    control.cycle();
    let posts = control.server.raw_batches.lock().unwrap();
    assert_eq!(
        posts.len(),
        2,
        "only unrelated fresh work may POST before the replay slot"
    );
    let last: serde_json::Value = serde_json::from_str(&posts[1]).unwrap();
    let items = last["snapshots"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["source_session_id"], unrelated);
    let saved = control.saved();
    assert!(
        saved
            .files
            .get(alias.to_string_lossy().as_ref())
            .is_some_and(|entry| entry.effective_upload_body_witness_revision != 3),
        "a newly parsed alias must not acquire an uncertain family's history stamp"
    );
    assert!(money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
    assert!(unknown_recovery::active_for_test(&control.support)
        .iter()
        .any(|m| !m.ack_saved && m.posts == 1));
    eprintln!("MONEY_UNKNOWN_ALIAS parsed_family_hold=true alias_post=false unrelated_post=true stamp_withheld=true");
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_physical_three_replays_exhaustion_and_normal_return() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    let mut control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    {
        let _clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
    }
    for (slot, elapsed) in [300, 3600, 21600].into_iter().enumerate() {
        control.restart();
        let _clock = money::PageClockForTest::new(&control.support, now + elapsed);
        control.cycle();
        let posts = control.server.raw_batches.lock().unwrap();
        assert_eq!(
            posts.len(),
            slot + 2,
            "one physical replay per original slot"
        );
        assert!(posts.iter().all(|body| body == &posts[0]));
        assert!(control
            .saved()
            .files
            .values()
            .all(|e| e.effective_upload_body_witness_revision != 3));
    }
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    let _clock = money::PageClockForTest::new(&control.support, now + 21601);
    control.cycle();
    assert!(unknown_recovery::active_for_test(&control.support).is_empty());
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        5,
        "terminal release permits a normal successor offer"
    );
    assert!(control
        .saved()
        .files
        .values()
        .all(|e| e.effective_upload_body_witness_revision == 3));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_current_stop_and_live_off_latches_deny_each_replay() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    for stop in [true, false] {
        crate::snapshots::restart_claude_reemission_stop_for_test();
        let control = P2aControl::with_recovery_evidence(FinishOutcome::LostCommitted);
        let _live = money::LiveForTest::new(&control.support);
        let now = current_unix_seconds();
        let clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
        control.recovery_startup(now);
        if stop {
            crate::snapshots::latch_claude_reemission_stop_for_test();
        } else {
            std::fs::write(control.support.join("claude-request-owned-live.off"), b"").unwrap();
        }
        let mut index = control.saved();
        index.activate_upload_context(
            unknown_recovery::active_for_test(&control.support)[0]
                .context
                .clone(),
        );
        index.activate_effective_upload_body_witness_revision(3);
        drop(clock);
        let _due = money::PageClockForTest::new(&control.support, now + 300);
        let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
        let progress_path = snapshot_upload_progress_path(&control.index_path);
        let mut progress = SnapshotUploadProgress::load(
            &progress_path,
            &namespace,
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        money_resume::drive_for_test(unknown_recovery::replay_due(
            &control.support,
            &mut index,
            &mut progress,
            &progress_path,
            &control.client,
            &control.device,
            "device-secret",
            "otm_test",
            &namespace,
            unknown_recovery::active_for_test(&control.support)[0].policy,
            || Ok(()),
        ))
        .unwrap();
        assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
        assert_eq!(
            unknown_recovery::active_for_test(&control.support)[0].posts,
            1
        );
    }
    crate::snapshots::restart_claude_reemission_stop_for_test();
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_http_outcome_table_never_splits_and_honors_retry_after() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    for status in [429, 503, 409, 412, 413, 422] {
        let mut control = P2aControl::with_recovery_evidence(FinishOutcome::HttpFailure {
            status,
            retry_after: 7200,
        });
        let _live = money::LiveForTest::new(&control.support);
        let now = current_unix_seconds();
        let clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
        let m = unknown_recovery::active_for_test(&control.support)
            .pop()
            .unwrap();
        assert_eq!(m.posts, 1);
        assert_eq!(
            control.server.raw_batches.lock().unwrap().len(),
            1,
            "no in-place resend or singleton isolation"
        );
        assert!(control
            .saved()
            .files
            .values()
            .all(|e| e.effective_upload_body_witness_revision != 3));
        if matches!(status, 429 | 503) {
            assert!(m.terminal.is_none());
            assert_eq!(m.not_before, now + 7200);
            drop(clock);
            control.restart();
            {
                let _early = money::PageClockForTest::new(&control.support, now + 7199);
                control.cycle();
            }
            assert_eq!(
                control.server.raw_batches.lock().unwrap().len(),
                1,
                "server backoff overrides the +5m slot"
            );
            {
                let _due = money::PageClockForTest::new(&control.support, now + 7200);
                control.cycle();
            }
            assert_eq!(control.server.raw_batches.lock().unwrap().len(), 2);
            assert_eq!(
                unknown_recovery::active_for_test(&control.support)[0].posts,
                2
            );
        } else {
            let expected = match status {
                409 | 412 => unknown_recovery::Reason::HttpConflict,
                413 => unknown_recovery::Reason::Oversize,
                _ => unknown_recovery::Reason::Validation,
            };
            assert_eq!(m.terminal, Some(expected));
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_cancel_after_counter_commit_consumes_slot_for_next_owner() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let _guard = unknown_recovery::guard_for_test(unknown_recovery::LiteralPermit::Permit);
    let control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    {
        let _clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
    }
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
    let mut cancelled = false;
    {
        let _clock = money::PageClockForTest::new(&control.support, now + 300);
        control
            .cycle_changing(|_| {
                if cancelled || !money_resume::pending_for_test(&control.support) {
                    return;
                }
                let active = unknown_recovery::active_for_test(&control.support);
                if active.first().is_some_and(|m| m.posts == 2) {
                    money_resume::cancel_owner(&control.daemon);
                    cancelled = true;
                }
            })
            .unwrap();
    }
    assert!(
        cancelled,
        "cancel the real parked replay after its counter receipt, before POST"
    );
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        1,
        "a consumed slot cannot be rearmed from the old catalog"
    );
    let consumed = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!((consumed.posts, consumed.slot), (2, 1));
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    {
        let _clock = money::PageClockForTest::new(&control.support, now + 3600);
        control.cycle();
    }
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 2);
    let recovered = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(
        (recovered.posts, recovered.slot),
        (3, 2),
        "one durable counter survives cancellation and transport ownership change"
    );
    {
        let _clock = money::PageClockForTest::new(&control.support, now + 3601);
        control.cycle();
    }
    assert!(control
        .saved()
        .files
        .values()
        .all(|e| e.effective_upload_body_witness_revision == 3));
    assert!(!money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_parked_capture_cannot_post_after_original_deadline() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::with_recovery_evidence(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let mut clock = Some(money::PageClockForTest::new(&control.support, now));
    let mut expired = false;
    let result = control.cycle_changing(|_| {
        if expired
            || !money_resume::pending_for_test(&control.support)
            || !control.server.raw_batches.lock().unwrap().is_empty()
        {
            return;
        }
        if !unknown_recovery::active_for_test(&control.support).is_empty() {
            clock.take();
            clock = Some(money::PageClockForTest::new(&control.support, now + 86400));
            expired = true;
        }
    });
    P2aControl::assert_deferred(result);
    assert!(
        expired,
        "advance the clock after durable custody, before the first POST"
    );
    assert!(
        control.server.raw_batches.lock().unwrap().is_empty(),
        "an old prepared body cannot use a new deadline"
    );
    let m = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(m.terminal, Some(unknown_recovery::Reason::Expired));
    assert_eq!(m.deadline, now + 86400);
    assert!(money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
    assert!(control
        .saved()
        .files
        .values()
        .all(|e| e.effective_upload_body_witness_revision != 3));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_known_ack_pending_selected_save_does_not_collide_with_fresh_offer() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::with_recovery_evidence(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    let _reset = P2aConflictReset;
    P2A_INDEX_CONFLICT.with(|state| *state.borrow_mut() = Some(control.index_path.clone()));
    assert!(
        control.cycle_result().is_err(),
        "fail the selected CAS after the real ACK save"
    );
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 1);
    let first = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert!(first.ack_saved);
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let progress_path = snapshot_upload_progress_path(&control.index_path);
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    // A normal delivery re-offer still needs its own custody while the old
    // selection is pending. Remove its transport suppression through the real
    // progress save, without changing the file, body or money debt.
    progress.accepted_fingerprints.clear();
    progress.accepted_body_witnesses.clear();
    progress.save(&progress_path).unwrap();
    control.cycle();
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 2);
    let attempts = unknown_recovery::active_for_test(&control.support);
    assert_eq!(attempts.len(), 2);
    assert!(attempts.iter().all(|m| m.lineage == first.lineage));
    assert_ne!(
        attempts[0].id, attempts[1].id,
        "custody/counters belong to separate authorized attempts"
    );
    assert_eq!(control.server.committed.lock().unwrap().len(), 1);
    assert!(control
        .saved()
        .files
        .values()
        .all(|e| e.effective_upload_body_witness_revision == 3));
    control.cycle();
    assert!(unknown_recovery::active_for_test(&control.support).is_empty());
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 2);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_validated_nonstored_ack_exits_into_ordinary_disposition() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    for outcome in [
        FinishOutcome::MoneyHeld,
        FinishOutcome::MoneyRefused,
        FinishOutcome::Permanent,
        FinishOutcome::Dominated {
            reason: "original_pair_candidate_unproved",
            admit_residue: false,
        },
        FinishOutcome::Retryable,
        FinishOutcome::Basis("dominated_by_head"),
        FinishOutcome::Basis("usage_identical"),
        FinishOutcome::Basis("future_basis_is_not_proof"),
    ] {
        for lost_first in [false, true] {
            let mut control = P2aControl::with_recovery_evidence(if lost_first {
                FinishOutcome::LostUncommitted
            } else {
                outcome
            });
            let _live = money::LiveForTest::new(&control.support);
            let now = current_unix_seconds();
            {
                let _clock = money::PageClockForTest::new(&control.support, now);
                if lost_first || matches!(outcome, FinishOutcome::Retryable) {
                    control.cycle_deferred();
                } else {
                    control.cycle();
                }
            }
            let original = control.server.raw_batches.lock().unwrap()[0].clone();
            if lost_first {
                control.restart();
                *control.server.outcome.lock().unwrap() = outcome;
                let _clock = money::PageClockForTest::new(&control.support, now + 300);
                control.cycle();
                assert_eq!(control.server.raw_batches.lock().unwrap()[1], original);
            }
            let elapsed = if lost_first { 300 } else { 0 };
            let _clock = money::PageClockForTest::new(&control.support, now + elapsed);
            let attempts = unknown_recovery::active_for_test(&control.support);
            assert!(attempts.iter().all(|m| m.ack_saved), "{outcome:?}");
            assert_eq!(
                control.server.raw_batches.lock().unwrap().len(),
                if lost_first { 2 } else { 1 }
            );
            let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
            let progress = SnapshotUploadProgress::load(
                &snapshot_upload_progress_path(&control.index_path),
                &namespace,
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap();
            let original: serde_json::Value = serde_json::from_str(&original).unwrap();
            let fp = original["snapshots"][0]["snapshot_fingerprint"]
                .as_str()
                .unwrap();
            assert!(
                !progress.accepted_fingerprints.contains(fp)
                    && !progress.accepted_body_witnesses.contains_key(fp),
                "nonstored ACK is never body acceptance: {outcome:?}"
            );
            assert!(
                progress.quarantined_fingerprints.contains_key(fp)
                    || control
                        .saved()
                        .quarantined_snapshot_fingerprints
                        .contains_key(fp),
                "the exact nonstored body retains its durable disposition: {outcome:?}"
            );
            assert!(!control.saved().accepted_snapshot_fingerprint_recorded(fp));
            control.restart();
            control.recovery_startup(now + elapsed);
            assert!(
                unknown_recovery::due(&control.support, now + 3600)
                    .unwrap()
                    .0
                    .is_empty(),
                "a validated disposition must never run another UNKNOWN replay: {outcome:?}"
            );
            assert!(
                money::money_due(
                    &control.support,
                    &control.transcript().to_string_lossy(),
                    u64::MAX
                ),
                "nonstored ACK preserves delivery debt: {outcome:?}"
            );
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_literal_version_skew_preserves_its_independent_backoff() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    {
        let _clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
    }
    let attempt = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    let entity = &attempt.entities[0];
    assert!(entity.literal);
    let progress_path = snapshot_upload_progress_path(&control.index_path);
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let mut progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    // This same body already carries a version-skew hold from an earlier
    // ordinary attempt. Its own saved retry policy survives UNKNOWN recovery.
    progress.quarantine_transient_body(&entity.fingerprint, &entity.witness, now);
    progress
        .quarantined_fingerprints
        .get_mut(&entity.fingerprint)
        .unwrap()
        .version_skew_attempts = 2;
    progress.save(&progress_path).unwrap();
    control.restart();
    *control.server.outcome.lock().unwrap() = FinishOutcome::LiteralSkew;
    let _clock = money::PageClockForTest::new(&control.support, now + 300);
    control.cycle();
    let posts = control.server.raw_batches.lock().unwrap();
    assert_eq!(
        posts.len(),
        2,
        "no adaptive split or fallback on the retained 422"
    );
    assert_eq!(posts[0], posts[1]);
    drop(posts);
    let updated = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(
        updated.terminal,
        Some(unknown_recovery::Reason::VersionSkew)
    );
    assert_eq!(updated.posts, 2);
    let progress = SnapshotUploadProgress::load(
        &progress_path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    let saved = control.saved();
    let hold = progress
        .quarantined_fingerprints
        .get(&entity.fingerprint)
        .or_else(|| {
            saved
                .quarantined_snapshot_fingerprints
                .get(&entity.fingerprint)
        })
        .expect("the independent skew hold survives in progress or selected custody");
    assert_eq!(hold.version_skew_attempts, 3);
    assert_eq!(hold.retry_after_unix_seconds, now + 300 + 7200);
    assert!(!progress.accepted_fingerprints.contains(&entity.fingerprint));
    assert!(money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_partial_200_records_only_covering_siblings() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    let sibling = "22222222-2222-4222-8222-222222222222";
    let original = std::fs::read_to_string(control.transcript()).unwrap();
    std::fs::write(
        control
            .transcript()
            .with_file_name(format!("{sibling}.jsonl")),
        original
            .replace(IDENTITY_PIPELINE_ROOT, sibling)
            .replace("req_1", "partial-sibling-1")
            .replace("req_2", "partial-sibling-2"),
    )
    .unwrap();
    {
        let _clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
    }
    let attempt = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(attempt.entities.len(), 2);
    control.restart();
    *control.server.outcome.lock().unwrap() = FinishOutcome::PartialConflict;
    let _clock = money::PageClockForTest::new(&control.support, now + 300);
    let _reset = P2aConflictReset;
    P2A_INDEX_CONFLICT.with(|state| *state.borrow_mut() = Some(control.index_path.clone()));
    assert!(
        control.cycle_result().is_err(),
        "partial proof is durable before the failed selected save"
    );
    let posts = control.server.raw_batches.lock().unwrap();
    assert_eq!(posts.len(), 2);
    assert_eq!(
        posts[0], posts[1],
        "partial outcomes never reshape the retained POST"
    );
    drop(posts);
    let namespace = snapshot_upload_destination_namespace(&control.device, "device-secret");
    let progress = SnapshotUploadProgress::load(
        &snapshot_upload_progress_path(&control.index_path),
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert!(progress
        .accepted_body_witnesses
        .get(&attempt.entities[0].fingerprint)
        .is_some_and(|w| w == &attempt.entities[0].witness));
    assert!(!progress
        .accepted_fingerprints
        .contains(&attempt.entities[1].fingerprint));
    assert!(progress
        .quarantined_fingerprints
        .contains_key(&attempt.entities[1].fingerprint));
    assert!(unknown_recovery::active_for_test(&control.support)
        .iter()
        .all(|m| m.ack_saved));
    for file in &attempt.entities[1].files {
        assert!(
            money::money_due(&control.support, file, u64::MAX),
            "conflict debt remains owed"
        );
        assert_ne!(
            control.saved().files[file].effective_upload_body_witness_revision,
            3
        );
    }
    control.restart();
    control.recovery_startup(now + 300);
    assert!(
        unknown_recovery::due(&control.support, now + 3600)
            .unwrap()
            .0
            .is_empty(),
        "complete partial ACK hands conflicting siblings to ordinary retry custody"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_last_replay_saved_ack_failed_selection_stays_known_at_expiry() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::with_recovery_evidence(FinishOutcome::LostUncommitted);
    let _live = money::LiveForTest::new(&control.support);
    let _reset = P2aConflictReset;
    let now = current_unix_seconds();
    for elapsed in [0, 300, 3600] {
        let _clock = money::PageClockForTest::new(&control.support, now + elapsed);
        if elapsed == 0 {
            control.cycle_deferred();
        } else {
            control.cycle();
        }
        control.restart();
    }
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    P2A_INDEX_CONFLICT.with(|state| *state.borrow_mut() = Some(control.index_path.clone()));
    {
        let _clock = money::PageClockForTest::new(&control.support, now + 21600);
        assert!(
            control.cycle_result().is_err(),
            "fail selected save after the last replay ACK"
        );
    }
    let attempts = unknown_recovery::active_for_test(&control.support);
    assert_eq!(attempts.len(), 1);
    assert!(attempts[0].ack_saved);
    assert_eq!(attempts[0].posts, 4);
    assert!(attempts[0].terminal.is_none());
    let posts = control.server.raw_batches.lock().unwrap();
    assert_eq!(posts.len(), 4);
    assert!(posts.iter().all(|body| body == &posts[0]));
    drop(posts);
    control.restart();
    control.recovery_startup(now + 21601);
    assert!(
        unknown_recovery::active_for_test(&control.support)[0]
            .terminal
            .is_none(),
        "the physical cap cannot turn a durably known ACK back into UNKNOWN"
    );
    assert!(unknown_recovery::due(&control.support, now + 21601)
        .unwrap()
        .0
        .is_empty());
    assert!(money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
    control.recovery_startup(now + 86400);
    assert!(
        unknown_recovery::active_for_test(&control.support).is_empty(),
        "hard expiry still deletes bytes"
    );
    let root = control.support.join("claude-money-recovery");
    let status: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("status")).unwrap()).unwrap();
    assert_eq!(status["unknown_outcome_unresolved"], 0);
    assert_eq!(
        std::fs::read_dir(root)
            .unwrap()
            .filter(|entry| entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .and_then(|s| s.to_str())
                == Some("receipt"))
            .count(),
        0,
        "known ACKs never exhaust the 35-day unresolved receipt quota"
    );
    assert!(
        money::money_due(
            &control.support,
            &control.transcript().to_string_lossy(),
            u64::MAX
        ),
        "privacy retirement never certifies the failed selected save"
    );
    assert_eq!(control.server.raw_batches.lock().unwrap().len(), 4);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_unknown_retry_after_crossing_deadline_expires_without_replay() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::with_recovery_evidence(FinishOutcome::HttpFailure {
        status: 429,
        retry_after: 172800,
    });
    let _live = money::LiveForTest::new(&control.support);
    let now = current_unix_seconds();
    {
        let _clock = money::PageClockForTest::new(&control.support, now);
        control.cycle_deferred();
    }
    let attempt = unknown_recovery::active_for_test(&control.support)
        .pop()
        .unwrap();
    assert_eq!(attempt.deadline, now + 86400);
    assert!(attempt.not_before >= attempt.deadline);
    control.restart();
    {
        let _clock = money::PageClockForTest::new(&control.support, now + 86399);
        control.cycle();
    }
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        1,
        "neither the 30-minute ordinary cap nor a recovery slot shortens Retry-After"
    );
    assert!(money::money_due(
        &control.support,
        &control.transcript().to_string_lossy(),
        u64::MAX
    ));
    *control.server.outcome.lock().unwrap() = FinishOutcome::Accept;
    {
        let _clock = money::PageClockForTest::new(&control.support, now + 86400);
        control.cycle();
    }
    assert!(unknown_recovery::active_for_test(&control.support).is_empty());
    assert_eq!(
        control.server.raw_batches.lock().unwrap().len(),
        2,
        "expiry releases only UNKNOWN; the next POST is an ordinary gated offer"
    );
    let status: serde_json::Value = serde_json::from_slice(
        &std::fs::read(control.support.join("claude-money-recovery/status")).unwrap(),
    )
    .unwrap();
    assert_eq!(status["unknown_outcome_unresolved"], 1);
}
