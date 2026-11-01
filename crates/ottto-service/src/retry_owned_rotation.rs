// Included in snapshot_sync::tests. Native ownership/rotation integration;
// transport and clock are deterministic offline adapters, never live providers.
struct RotationRoot(PathBuf);
impl Drop for RotationRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
struct OwnedRotationProof {
    pi: RotationRoot,
    a: SameSourceAckFixture,
    b: SameSourceAckFixture,
    slots: [Option<IntegratedSlot>; 2],
    trace: IntegratedTrace,
    authority: RetryAuthority,
    now: u64,
    line_count: usize,
    owner: std::thread::ThreadId,
    offered: Vec<(SnapshotSource, u64)>,
    complete: Vec<SnapshotSource>,
    errors: Vec<SnapshotSource>,
    retries: Vec<(usize, u64)>,
    controls: BTreeMap<&'static str, (String, serde_json::Value)>,
    cancel: Option<&'static str>,
    force_refusal: bool,
    budget: usize,
    max_parked_bound: usize,
    max_shared_bound_and_send: usize,
}
impl OwnedRotationProof {
    fn new(hours: usize, cancel: Option<&'static str>, force_refusal: bool, budget: usize) -> Self {
        let a = SameSourceAckFixture::new();
        let b = integrated_claude(hours);
        let pi = RotationRoot(test_dir("owned-rotation-pi"));
        std::fs::create_dir_all(&pi.0).unwrap();
        let row="{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1784707201000,\"usage\":{\"input\":100,\"output\":1}}}\n";
        std::fs::write(pi.0.join("long.jsonl"), row.repeat(120)).unwrap();
        let mut trace = IntegratedTrace::default();
        let slots = [
            Some(integrated_capture(&a, &[0], &mut trace)),
            Some(integrated_capture(
                &b,
                &(0..b.items.len()).collect::<Vec<_>>(),
                &mut trace,
            )),
        ];
        let mut controls = BTreeMap::new();
        for (source, root, index) in [
            (SnapshotSource::Pi, &pi.0, ScanIndex::default()),
            (SnapshotSource::Codex, &a.root, ScanIndex::default()),
            (SnapshotSource::ClaudeCode, &b.root, ScanIndex::default()),
        ] {
            let mut index = index;
            let scan = crate::snapshots::scan_source_roots_with_test_limit(
                source,
                std::slice::from_ref(root),
                &mut index,
                "2026-10-05T00:00:00Z",
                crate::snapshots::BACKFILL_WINDOW_DAYS,
                MAX_BACKFILL_FILES_PER_SOURCE,
                true,
            )
            .unwrap();
            controls.insert(
                source.api_slug(),
                (format!("{scan:?}"), serde_json::to_value(index).unwrap()),
            );
        }
        Self {
            pi,
            a,
            b,
            slots,
            trace,
            authority: RetryAuthority::default(),
            now: 0,
            line_count: 0,
            owner: std::thread::current().id(),
            offered: vec![],
            complete: vec![],
            errors: vec![],
            retries: vec![],
            controls,
            cancel,
            force_refusal,
            budget,
            max_parked_bound: 0,
            max_shared_bound_and_send: 0,
        }
    }
    fn offer_retained(&mut self) {
        assert!(SNAPSHOT_SYNC_LOCK.get().unwrap().try_lock().is_err());
        assert_eq!(self.owner, std::thread::current().id());
        assert_eq!(self.trace.tokens_live.get(), 0);
        for n in 0..2 {
            let Some(slot) = self.slots[n].as_mut() else {
                continue;
            };
            if self.now >= slot.budget.expires {
                self.slots[n] = None;
                continue;
            }
            if self.now < slot.budget.due {
                continue;
            }
            let script = if n == 1 {
                IntegratedScript::AuthReplay
            } else if slot.budget.posts_left == 3 {
                IntegratedScript::FallbackShed
            } else {
                IntegratedScript::Ack
            };
            self.retries.push((n, self.now));
            let result = integrated_send(
                slot,
                if n == 0 { &mut self.a } else { &mut self.b },
                if n == 0 {
                    SnapshotSource::Codex
                } else {
                    SnapshotSource::ClaudeCode
                },
                self.now,
                &self.authority,
                script,
                &mut self.trace,
            );
            self.now += 4_000;
            let slots_bound = self.slots.iter().flatten().map(|s| s.bound).sum::<usize>();
            let combined =
                self.max_parked_bound + slots_bound + *self.trace.send_peaks.last().unwrap();
            assert!(combined <= crate::source_rotation::OVERLAP_BUDGET);
            self.max_shared_bound_and_send = self.max_shared_bound_and_send.max(combined);
            if let Err(error) = result {
                let shed = error.downcast_ref::<UploadShed>().expect("typed shed");
                self.slots[n].as_mut().unwrap().budget.due =
                    self.now + shed.retry_after.unwrap().as_millis() as u64 + 6_000;
            } else {
                self.slots[n] = None;
            }
            crate::client_report::record(crate::client_report::ClientReportReason::NetworkError, 1);
            break;
        }
    }
}
impl crate::source_rotation::Owner for OwnedRotationProof {
    type Source = SnapshotSource;
    type Frame = SourcePreparation;
    type Completed = (SourcePreparation, ScanIndex, SourceScanResult);
    fn prepare(
        &mut self,
        source: SnapshotSource,
        _remaining: Option<usize>,
    ) -> Result<Option<SourcePreparation>> {
        assert_eq!(self.owner, std::thread::current().id());
        self.offered.push((source, self.now));
        let root = match source {
            SnapshotSource::Pi => &self.pi.0,
            SnapshotSource::Codex => &self.a.root,
            SnapshotSource::ClaudeCode => &self.b.root,
        };
        let status = test_agent_status(source_kind(source));
        let scan = crate::snapshots::OwnedSourceScan::new(
            source,
            std::slice::from_ref(root),
            ScanIndex::default(),
            "2026-10-05T00:00:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            MAX_BACKFILL_FILES_PER_SOURCE,
            true,
            None,
            &[],
            false,
        );
        let hint: crate::snapshot_client::ActivityHintResponse =
            serde_json::from_value(serde_json::json!({
                "source":source.api_slug(),"server_time":"2026-10-05T00:00:00Z","last_data_at":null,
                "record_count_15m":0,"record_count_24h":0,"local_usage_reconciliation_enabled":true,
                "backfill_window_days":30,"recommended_scan_after":"2026-10-05T00:05:00Z"
            }))
            .unwrap();
        let mut progress = test_upload_progress();
        if self.force_refusal {
            progress
                .accepted_cache_states
                .insert("opaque".into(), serde_json::json!({"opaque":true}));
        }
        Ok(Some(SourcePreparation {
            native_comparison_reservation: None,
            native_comparison_lease: None,
            prepared_claude_evidence: None,
            terminal_native_traversal: None,
            native_comparison_controller: None,
            retry_authority: None,
            source,
            claude_scan_roots: None,
            account_witness: [0; 32],
            scan_started_at: "2026-10-05T00:00:00Z".into(),
            activity_hint: hint,
            receipt_window_days: 30,
            cache_observations_enabled: false,
            scan_agent_status_collection: Some(std::sync::Arc::new(AgentStatusCollection {
                snapshots: vec![status.clone()],
                source_health_snapshot: status,
                codex_scan_homes: vec![],
                codex_home_bindings: vec![],
            })),
            attribution_context: None,
            upload_policy: SnapshotUploadPolicy::default(),
            upload_destination_namespace: "offline-native".into(),
            receipt_client: SnapshotApiClient::new("http://offline.invalid"),
            index_path: root.join("owned-index.json"),
            upload_progress_path: root.join("owned-progress.json"),
            upload_progress: progress,
            committed_index: ScanIndex::default(),
            backfill_state: Default::default(),
            backfill_pending: false,
            replay_generation: "owned".into(),
            legacy_reconciliation_pending: BTreeSet::new(),
            active_legacy_reconciliation: BTreeSet::new(),
            scan: Some(scan),
        }))
    }
    fn validate(&mut self, frame: &SourcePreparation) -> Result<()> {
        if let (SnapshotSource::Pi, true, Some(cancel)) =
            (frame.source, self.line_count >= 20, self.cancel)
        {
            match cancel {
                "account" => self.authority.account += 1,
                "destination" => self.authority.destination += 1,
                _ => self
                    .slots
                    .iter_mut()
                    .flatten()
                    .for_each(|s| s.budget.stopped = true),
            }
            for slot in self.slots.iter_mut().flatten() {
                assert!(!slot.budget.enter(self.now, Some(&self.authority)));
            }
            self.slots = [None, None];
            return Err(anyhow!("injected authority cancellation"));
        }
        self.offer_retained();
        Ok(())
    }
    fn step(
        &mut self,
        mut frame: SourcePreparation,
        remaining: Option<usize>,
    ) -> crate::source_rotation::Step<Self::Frame, Self::Completed> {
        frame.accept_native_rotation_turn(remaining);
        let pi = frame.source == SnapshotSource::Pi;
        let before = frame.scan.as_ref().unwrap().test_active_physical_lines();
        match frame.step() {
            SourcePreparationStep::Pending(frame) => {
                let after = frame.scan.as_ref().unwrap().test_active_physical_lines();
                if pi && after > before {
                    self.now += (after - before) as u64 * 6_000;
                    self.line_count += after - before;
                }
                crate::source_rotation::Step::Pending(frame)
            }
            SourcePreparationStep::Refused(frame, reason) => {
                drop(frame);
                crate::source_rotation::Step::Refused(reason)
            }
            SourcePreparationStep::Complete {
                preparation,
                index,
                scan,
            } => crate::source_rotation::Step::Complete((preparation, index, scan)),
        }
    }
    fn bound(&self, frame: &SourcePreparation, limit: usize) -> Option<usize> {
        let bound = crate::heap_layout_bound::bound(frame, limit);
        if self.force_refusal {
            assert!(bound.is_none());
        }
        bound
    }
    fn finish(&mut self, completed: Self::Completed, _remaining: Option<usize>) -> Result<()> {
        let (preparation, index, scan) = completed;
        let expected = &self.controls[preparation.source.api_slug()];
        assert_eq!(
            format!("{scan:?}"),
            expected.0,
            "complete native scan parity"
        );
        assert_eq!(
            serde_json::to_value(index).unwrap(),
            expected.1,
            "whole native index parity"
        );
        self.complete.push(preparation.source);
        if preparation.source != SnapshotSource::Pi {
            self.now += 5_000;
        }
        Ok(())
    }
    fn outcome(&mut self, source: SnapshotSource, result: Result<()>) {
        if result.is_err() {
            self.errors.push(source);
        }
    }
    fn monotonic(&self) -> Duration {
        Duration::from_millis(self.now)
    }
    fn parked(&mut self, bytes: usize) {
        assert!(bytes <= self.budget);
        self.max_parked_bound = self.max_parked_bound.max(bytes);
    }
}

#[test]
fn owned_rotation_native_authority_fences() {
    let device = LocalDeviceBinding {
        device_id: "synthetic".into(),
        machine_id: Some("machine".into()),
        sources: vec!["codex".into()],
    };
    assert!(validate_snapshot_scan_authority(
        &device,
        &device,
        SnapshotSource::Codex,
        true,
        &[1; 32],
        &[1; 32]
    )
    .is_ok());
    for variant in 0..5 {
        let mut current = device.clone();
        let mut endpoint = true;
        let mut account = [1; 32];
        match variant {
            0 => current.device_id = "other".into(),
            1 => current.machine_id = None,
            2 => current.sources.clear(),
            3 => endpoint = false,
            _ => account = [2; 32],
        }
        let error = validate_snapshot_scan_authority(
            &device,
            &current,
            SnapshotSource::Codex,
            endpoint,
            &[1; 32],
            &account,
        )
        .unwrap_err();
        assert_eq!(
            snapshot_upload_error_class(&error),
            Some(SnapshotUploadErrorClass::LocalState)
        );
    }
    let daemon = test_daemon("machine");
    let initial = daemon.snapshot_scan_account_witness().unwrap();
    let mut account = ottto_protocol::LocalAccountBinding::not_connected();
    account.state = ottto_protocol::LocalAccountState::Connected;
    account.user = Some(ottto_protocol::LocalAccountUser {
        id: "synthetic-u".into(),
        email: "local.invalid".into(),
        display_name: None,
    });
    account.organization = Some(ottto_protocol::LocalAccountOrganization {
        id: "synthetic-o".into(),
        name: "local".into(),
    });
    let daemon = daemon.with_account(account.clone());
    let connected = daemon.snapshot_scan_account_witness().unwrap();
    assert_ne!(initial, connected);
    account.last_refreshed_at = Some("2026-10-05T00:00:00Z".into());
    let daemon = daemon.with_account(account.clone());
    assert_eq!(connected, daemon.snapshot_scan_account_witness().unwrap());
    account.user.as_mut().unwrap().id = "changed".into();
    let daemon = daemon.with_account(account);
    assert_ne!(connected, daemon.snapshot_scan_account_witness().unwrap());
}
