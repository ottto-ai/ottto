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
        crate::snapshots::claude_request_money::store::reload_for_test(&support).unwrap();
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
            previous_deadline: source_upload_deadlines()
                .lock()
                .unwrap()
                .remove("claude_code"),
        }
    }
    fn transcript(&self) -> PathBuf {
        self.fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
    }
    fn restart(&mut self) {
        crate::snapshots::claude_request_money::store::reload_for_test(&self.support).unwrap();
        self.daemon = test_daemon("otm_test");
    }
    fn cycle(&self) -> (usize, Vec<SnapshotItem>) {
        self.cycle_result().unwrap()
    }
    fn cycle_result(&self) -> Result<(usize, Vec<SnapshotItem>)> {
        use crate::snapshots::claude_request_money as money;
        for _ in 0..32 {
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
            let frame = crate::agent_status_refresh::with_test_collection(collection(), || {
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
            .unwrap()
            .expect("real due preparation");
            let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
            let parsed = scan.scanned_file_count;
            let items = scan.snapshots.clone();
            let result = crate::agent_status_refresh::with_test_collection(collection(), || {
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
        panic!("real prepare/finish writer receipts did not converge")
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
        let _live = money::LiveForTest::new(&control.support);
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
                ScanIndex::default().save(&control.index_path).unwrap();
            }
            _ => unreachable!(),
        }
        // Fully paired API/trace evidence makes minting v1 possible on the
        // ordinary fold, so its absence below is a discriminating protection.
        write_native_bootstrap_sidecars(&control.fixture, &control.support);
        control.restart();
        for _ in 0..3 {
            control.cycle();
        }
        let offers = control.offers();
        assert!(
            offers.len() > before,
            "{cause} must actually reach the upload recorder"
        );
        for item in &offers[before..] {
            assert!(
                item["usage_accounting_contract"].is_null(),
                "protected {cause} must mint neither literal nor v1: {item}"
            );
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
            if terminal {
                let revision = saved
                    .files
                    .values()
                    .next()
                    .unwrap()
                    .source_file_fingerprint
                    .clone();
                saved.insert_unproven_terminal_claude_authority_for_test(
                    IDENTITY_PIPELINE_ROOT,
                    &revision,
                );
            } else {
                saved.insert_retry_pending_claude_authority_for_test(IDENTITY_PIPELINE_ROOT);
            }
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
            assert_eq!(item["cost"]["total_cost_usd"], "0.000200");
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
    assert_eq!(accepted["cost"]["total_cost_usd"], "0.000300");
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
    assert!(money::money_due(
        &control.support,
        &control
            .transcript()
            .canonicalize()
            .unwrap()
            .to_string_lossy(),
        u64::MAX
    ));
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
    assert_eq!(synthetic["cost"]["total_cost_usd"], "0.000200");
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
    assert_eq!(physical["cost"]["total_cost_usd"], "0.000200");
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
        let key = path.canonicalize().unwrap().to_string_lossy().into_owned();
        let revision = format!("{:x}", Sha256::digest(text.as_bytes()));
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
                device: 1,
                inode: 1,
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
        assert_eq!(
            a["request_count"], 1,
            "accepted A loses shared message exactly once"
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
fn p2a_protected_terminal_quiet_root_keeps_real_literal_sibling_and_loss_receipt() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("protected sibling: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let control = P2aControl::new(FinishOutcome::Accept);
    let _live = money::LiveForTest::new(&control.support);
    const PROTECTED: &str = "2448a80a-f36e-4cbc-a5bb-50fc66430ba5";
    std::fs::write(
        control
            .support
            .join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("{:x}\n", Sha256::digest(PROTECTED.as_bytes())),
    )
    .unwrap();
    let mut saved = control.saved();
    saved.insert_unproven_terminal_claude_authority_for_test(PROTECTED, &"a".repeat(64));
    saved.save(&control.index_path).unwrap();
    control.cycle();
    let offers = control.offers();
    assert!(
        offers
            .iter()
            .all(|item| item["source_session_id"] != PROTECTED),
        "protected root has no physical candidate on this page"
    );
    let literal = offers
        .iter()
        .find(|item| item["source_session_id"] == IDENTITY_PIPELINE_ROOT)
        .expect("healthy unprotected sibling reaches real POST");
    assert_eq!(
        literal["usage_accounting_contract"],
        money::REQUEST_OWNED_CONTRACT
    );
    let saved = control.saved();
    assert!(saved.claude_authority_record_for_test(PROTECTED).is_some());
    let statuses = control.server.terminal.lock().unwrap();
    let status = statuses.last().unwrap();
    assert_eq!(status["last_census_complete"], true);
    assert_eq!(status["last_ownership_incomplete_file_count"], 1);
    assert_eq!(status["last_terminal_ownership_incomplete_file_count"], 1);
    assert_eq!(status["last_snapshot_unproven_terminal_count"], 1);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
#[serial(claude_request_money_shadow)]
fn p2a_existing_protected_v1_upload_hold_is_retained_after_restart() {
    use crate::snapshots::claude_request_money as money;
    if !crate::heap_layout_bound::layout_supported() {
        eprintln!("protected v1 upload hold: UNEXECUTED unsupported layout");
        return;
    }
    let _native = crate::snapshots::claude_native_comparison::enable_for_test();
    let mut control = P2aControl::new(FinishOutcome::Accept);
    write_native_bootstrap_sidecars(&control.fixture, &control.support);
    control.cycle();
    let first = control.offers();
    assert_eq!(
        first.last().unwrap()["usage_accounting_contract"],
        "session_exclusive_reported_usage:v1",
        "seed an actual v1 predecessor"
    );
    let mut changed: serde_json::Value = serde_json::from_str(
        std::fs::read_to_string(control.transcript())
            .unwrap()
            .lines()
            .last()
            .unwrap(),
    )
    .unwrap();
    changed["requestId"] = "req_held_v1".into();
    changed["message"]["id"] = "m-held-v1".into();
    std::fs::OpenOptions::new()
        .append(true)
        .open(control.transcript())
        .unwrap()
        .write_all((changed.to_string() + "\n").as_bytes())
        .unwrap();
    write_native_bootstrap_sidecars(&control.fixture, &control.support);
    *control.server.outcome.lock().unwrap() = FinishOutcome::MoneyHeld;
    control.cycle();
    let before = control.saved();
    let (fingerprint, held) = before
        .quarantined_snapshot_fingerprints
        .iter()
        .find(|(_, record)| record.hold.is_some())
        .expect("real server v1 hold persisted");
    let offered = control.offers().len();
    std::fs::write(
        control
            .support
            .join("snapshots/claude_code-reemission-exclusions.txt"),
        format!("{:x}\n", Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())),
    )
    .unwrap();
    let _live = money::LiveForTest::new(&control.support);
    control.restart();
    control.cycle();
    let after = control.saved();
    assert_eq!(
        after.quarantined_snapshot_fingerprints.get(fingerprint),
        Some(held),
        "protected existing v1 hold stays byte-for-byte retained"
    );
    assert_eq!(
        control.offers().len(),
        offered,
        "protection cannot turn retained v1 hold into a new literal or v1 offer"
    );
    assert!(after
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision != 3));
}
