// Shared offline canonical page/ACK adapters for owned collection tests.
struct IntegratedProof {
    fingerprint: [u8; 64],
    body: [u8; 64],
}
struct IntegratedSlot {
    items: Box<[SnapshotItem]>,
    proof: Box<[IntegratedProof]>,
    budget: RetryBudget,
    index_generation: u64,
    progress_generation: u64,
    bound: usize,
    owner: std::thread::ThreadId,
}
impl IntegratedSlot {
    fn capture(f: &SameSourceAckFixture, selected: &[usize]) -> Option<Self> {
        use crate::retry_retention_bound::{HEAP_CAP, PROOF_RESERVE};
        // Admission and copy are inseparable. No progress/index/token/report clone.
        if selected.is_empty() || selected.len() > 50 {
            return None;
        }
        let proof_bytes = selected
            .len()
            .checked_mul(std::mem::size_of::<IntegratedProof>())?
            .checked_add(std::mem::size_of::<Self>())?;
        if proof_bytes > PROOF_RESERVE {
            return None;
        }
        let mut bound = PROOF_RESERVE;
        for n in selected {
            let item = f.items.get(*n)?;
            let one =
                crate::retry_retention_bound::page_bound(std::slice::from_ref(item), HEAP_CAP)?;
            bound = bound.checked_add(one.checked_sub(PROOF_RESERVE)?)?;
            if bound > HEAP_CAP {
                return None;
            }
        }
        let mut items = Vec::with_capacity(selected.len());
        let mut proof = Vec::with_capacity(selected.len());
        for n in selected {
            let item = &f.items[*n];
            let fingerprint = item.snapshot_fingerprint.as_bytes().try_into().ok()?;
            let body = snapshot_upload_body_witness(item)
                .as_bytes()
                .try_into()
                .ok()?;
            items.push(retry_ordinary_owned(item)?);
            proof.push(IntegratedProof { fingerprint, body });
        }
        Some(Self {
            items: items.into_boxed_slice(),
            proof: proof.into_boxed_slice(),
            budget: RetryBudget::after_shed(0, 60_000, 6_000),
            index_generation: f.baseline.generation,
            progress_generation: f.progress.generation,
            bound,
            owner: std::thread::current().id(),
        })
    }
    fn current(&self, f: &SameSourceAckFixture) -> bool {
        self.index_generation == f.baseline.generation
            && self.progress_generation == f.progress.generation
            && self.proof.iter().all(|proof| {
                f.items.iter().any(|item| {
                    item.snapshot_fingerprint.as_bytes() == proof.fingerprint.as_slice()
                        && snapshot_upload_body_witness(item).as_bytes() == proof.body.as_slice()
                })
            })
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(dead_code)] // Historical fault adapters retained for the canonical transport fixture.
enum IntegratedScript {
    Ack,
    FallbackShed,
    AuthReplay,
    LostAck,
    Exhaust,
    Deadline,
    BeforePostAccount,
    AfterAckAccount,
    LedgerCrash,
    IndexRace,
    ProgressRace,
}
#[derive(Default)]
struct IntegratedTrace {
    token_calls: usize,
    tokens_live: std::rc::Rc<std::cell::Cell<usize>>,
    posts: Vec<(u64, &'static str)>,
    reports: Vec<u64>,
    send_peaks: Vec<usize>,
    captures: Vec<(usize, usize, usize)>, // bound, retained layouts, capture peak
}
struct IntegratedToken(std::rc::Rc<std::cell::Cell<usize>>);
impl Drop for IntegratedToken {
    fn drop(&mut self) {
        self.0.set(self.0.get() - 1);
    }
}
fn integrated_token(trace: &mut IntegratedTrace) -> IntegratedToken {
    trace.token_calls += 1;
    trace.tokens_live.set(trace.tokens_live.get() + 1);
    IntegratedToken(trace.tokens_live.clone())
}
fn integrated_post(
    slot: &mut IntegratedSlot,
    now: u64,
    current: &RetryAuthority,
    phase: &'static str,
    trace: &mut IntegratedTrace,
) -> Result<()> {
    if !slot.budget.post(now, Some(current)) {
        return Err(anyhow!("shared POST/deadline rejected"));
    }
    trace.posts.push((now, phase));
    Ok(())
}
fn integrated_ack(
    request: &SnapshotBatchRequest,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    // Synthetic bounded fixture response, not a proposed production response limit.
    let entities = request
        .snapshots
        .iter()
        .map(|item| {
            serde_json::json!({
                "source_session_id":item.source_session_id,
                "snapshot_fingerprint":item.snapshot_fingerprint,
                "occurrence_count":1,"body_witness_version":match crate::snapshots::snapshot_upload_body_witness_version(item) {
                Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_CONTEXT_CURVE_VERSION) =>
                    Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_CONTEXT_CURVE_VERSION),
                Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_CONTEXT_CURVE_VERSION) =>
                    Some(crate::snapshot_client::SNAPSHOT_BODY_WITNESS_PUBLIC_EXCLUSIVE_CONTEXT_CURVE_VERSION),
                None | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_TOOL_VERSION)
                    | Some(crate::snapshots::SNAPSHOT_BODY_WITNESS_ENVELOPE_EXCLUSIVE_TOOL_VERSION) => None,
                other => panic!("unexpected retained ordinary fixture witness: {other:?}"),
            },
                "body_witness_digest":snapshot_upload_body_witness(item)
            })
        })
        .collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&serde_json::json!({
        "accepted":entities.len(),"sessions_reconciled":entities.len(),"session_ids":[],
        "disabled":false,"disabled_reason":null,
        "entity_ack_contract":crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT,
        "accepted_entities":entities
    }))?;
    assert!(bytes.len() < crate::retry_retention_bound::PROOF_RESERVE);
    let response: crate::snapshot_client::SnapshotBatchResponse = serde_json::from_slice(&bytes)?;
    response.validate_entity_ack_with_head_cas(request, false)?;
    Ok(response)
}
fn integrated_send(
    slot: &mut IntegratedSlot,
    f: &mut SameSourceAckFixture,
    source: SnapshotSource,
    now: u64,
    current: &RetryAuthority,
    script: IntegratedScript,
    trace: &mut IntegratedTrace,
) -> Result<()> {
    assert_eq!(std::thread::current().id(), slot.owner);
    assert!(SNAPSHOT_SYNC_LOCK.get().unwrap().try_lock().is_err());
    crate::retry_allocation_probe::phase_begin();
    let result = (|| {
        if !slot.current(f) || !slot.budget.enter(now, Some(current)) {
            return Err(anyhow!("ineligible retained page"));
        }
        let deadline = slot.budget.turn_deadline;
        let pending = slot
            .items
            .iter()
            .enumerate()
            .filter(|(_, item)| {
                !f.progress.contains_body(
                    &item.snapshot_fingerprint,
                    &snapshot_upload_body_witness(item),
                )
            })
            .map(|(n, _)| n)
            .collect::<Vec<_>>();
        let items = std::mem::take(&mut slot.items);
        let result = if pending.is_empty() {
            Ok(SnapshotPageOutcome::Settled { conflicted: 0 })
        } else {
            attempt_snapshot_page(
                &items,
                &pending,
                &unique_poison_scope(),
                &mut f.progress,
                &mut 0,
                &|i: &SnapshotItem| i.snapshot_fingerprint.as_str(),
                &snapshot_upload_body_witness,
                &mut |items| {
                    if !slot.budget.phase(now + 1_000, Some(current)) {
                        return Err(anyhow!("authority before token"));
                    }
                    let _token = integrated_token(trace); // fake fresh acquisition; no credentials
                    let lease = crate::client_report::lease();
                    trace.reports.push(
                        lease
                            .report()
                            .quantity(crate::client_report::ClientReportReason::NetworkError),
                    );
                    let request = SnapshotBatchRequest {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        source: source.api_slug().into(),
                        machine_id: "a".repeat(64),
                        collector_version: Some(collector_version()),
                        snapshots: items,
                        upload_policy: SnapshotUploadPolicy::default(),
                        client_report: lease.report().clone(),
                    };
                    validate_snapshot_batch_request(&request)
                        .map_err(|e| anyhow!("preflight: {e}"))?;
                    let body = serde_json::to_vec(&request)?;
                    assert!(body.len() <= SNAPSHOT_BATCH_MAX_BYTES);
                    let encoded = crate::snapshot_client::retention_gzip_probe(&body);
                    if script == IntegratedScript::BeforePostAccount {
                        let mut changed = current.clone();
                        changed.account += 1;
                        assert!(
                            integrated_post(slot, now + 2_000, &changed, "main", trace).is_err()
                        );
                        return Err(anyhow!("authority changed after token"));
                    }
                    integrated_post(slot, now + 2_000, current, "main", trace)?;
                    match script {
                        IntegratedScript::FallbackShed => {
                            assert!(encoded.is_some());
                            integrated_post(
                                slot,
                                now + 3_000,
                                current,
                                "encoding-fallback",
                                trace,
                            )?;
                            return Err(anyhow::Error::new(crate::snapshot_client::UploadShed {
                                status: 503,
                                retry_after: Some(Duration::from_secs(60)),
                            }));
                        }
                        IntegratedScript::AuthReplay => {
                            // A fresh fake token after typed auth refusal uses the SAME budget.
                            let _refusal =
                                crate::snapshot_client::BatchAuthorizationRejected { status: 401 };
                            let _fresh = integrated_token(trace);
                            integrated_post(slot, now + 3_000, current, "auth-replay", trace)?;
                        }
                        IntegratedScript::LostAck => return Err(anyhow!("synthetic lost ACK")),
                        IntegratedScript::Exhaust => {
                            integrated_post(
                                slot,
                                now + 3_000,
                                current,
                                "encoding-fallback",
                                trace,
                            )?;
                            let _fresh = integrated_token(trace);
                            integrated_post(slot, now + 4_000, current, "auth-replay", trace)?;
                            assert!(integrated_post(
                                slot,
                                now + 5_000,
                                current,
                                "adaptive-fourth",
                                trace
                            )
                            .is_err());
                            return Err(anyhow!("three physical POSTs exhausted"));
                        }
                        IntegratedScript::Deadline => {
                            assert!(integrated_post(
                                slot,
                                deadline,
                                current,
                                "late-fallback",
                                trace
                            )
                            .is_err());
                            assert_eq!(slot.budget.turn_deadline, deadline);
                            return Err(anyhow!("absolute turn deadline expired"));
                        }
                        _ => {}
                    }
                    let response = integrated_ack(&request)?;
                    lease.commit();
                    Ok(response)
                },
                &mut |p: &mut SnapshotUploadProgress| {
                    if script == IntegratedScript::LedgerCrash {
                        return Err(anyhow!("crash before ledger"));
                    }
                    p.save(&f.progress_path)
                },
            )
        };
        slot.items = items;
        let result = result?;
        assert!(matches!(result, SnapshotPageOutcome::Settled { .. }));
        assert_eq!(slot.budget.turn_deadline, deadline);
        if script == IntegratedScript::AfterAckAccount {
            let before = std::fs::read(&f.index_path)?;
            let mut changed = current.clone();
            changed.account += 1;
            assert!(f
                .checkpoint_boundary(|| {
                    if !slot.budget.phase(now + 4_000, Some(&changed)) {
                        Err(anyhow!("post-ACK authority"))
                    } else {
                        Ok(())
                    }
                })
                .is_err());
            assert_eq!(std::fs::read(&f.index_path)?, before);
            return Err(anyhow!("ACK durable; publication authority revoked"));
        }
        if script == IntegratedScript::ProgressRace {
            let mut competing = f.progress.clone();
            competing.save(&f.progress_path)?;
            let bytes = std::fs::read(&f.progress_path)?;
            assert!(f.checkpoint_boundary(|| Ok(())).is_err());
            assert_eq!(std::fs::read(&f.progress_path)?, bytes);
            return Err(anyhow!("manual progress generation wins"));
        }
        if script == IntegratedScript::IndexRace {
            let mut newer = ScanIndex::load(&f.index_path)?;
            newer.mark_bounded_sweep_unsettled();
            newer.save(&f.index_path)?;
            let bytes = std::fs::read(&f.index_path)?;
            assert!(f.checkpoint_boundary(|| Ok(())).is_err());
            assert_eq!(std::fs::read(&f.index_path)?, bytes);
            return Err(anyhow!("manual generation wins"));
        }
        f.checkpoint_boundary(|| {
            if slot.budget.phase(now + 4_000, Some(current)) {
                Ok(())
            } else {
                Err(anyhow!("publication deadline"))
            }
        })?;
        slot.budget.posts_left = 0;
        Ok(())
    })();
    trace
        .send_peaks
        .push(crate::retry_allocation_probe::phase_peak());
    assert_eq!(trace.tokens_live.get(), 0);
    result
}
fn integrated_claude(hours: usize) -> SameSourceAckFixture {
    let root = test_dir("integrated-claude");
    std::fs::create_dir_all(&root).unwrap();
    let start = OffsetDateTime::parse("2026-07-01T00:00:00Z", &Rfc3339).unwrap();
    let sessions = if hours == 50 { 50 } else { 1 };
    let hours_per_session = if sessions == 50 { 1 } else { hours };
    for session in 0..sessions {
        let mut rows = String::new();
        for n in 0..hours_per_session {
            let timestamp = (start + TimeDuration::hours(n as i64))
                .format(&Rfc3339)
                .unwrap();
            rows.push_str(&serde_json::json!({"timestamp":timestamp,"type":"assistant","sessionId":format!("integrated-{session}"),
                "requestId":format!("request-{session}-{n}"),"message":{"id":format!("message-{session}-{n}"),"role":"assistant",
                "model":"claude-sonnet-4","content":[],"usage":{"input_tokens":100,"output_tokens":10,
                    "cache_read_input_tokens":50,"cache_creation_input_tokens":20}}}).to_string());
            rows.push('\n');
        }
        std::fs::write(root.join(format!("synthetic-{session}.jsonl")), rows).unwrap();
    }
    let index_path = root.join("index.json");
    let progress_path = root.join("progress.json");
    let mut baseline = ScanIndex::default();
    baseline.prepare_historical_replay("boundary-pending-replay".into());
    baseline.save(&index_path).unwrap();
    let mut working = baseline.clone();
    working.activate_upload_context("integration-policy".into());
    working.activate_effective_upload_body_witness_revision(1);
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[root.clone()],
        &mut working,
        "2026-10-05T00:00:00Z",
        crate::snapshots::BACKFILL_WINDOW_DAYS,
        100,
        true,
    )
    .unwrap();
    for item in &mut scan.snapshots {
        item.cache_observations = None;
        item.cache_observations_state = None;
        item.session_account_evidence = None;
    }
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut scan, &mut working);
    assert_eq!(scan.snapshots.len(), sessions);
    assert!(scan
        .snapshots
        .iter()
        .all(|item| item.usage_buckets.len() == hours_per_session));
    let mut progress = test_upload_progress();
    progress.destination_namespace_hash =
        format!("{:x}", Sha256::digest(root.to_string_lossy().as_bytes()));
    progress.prepare_historical_replay("boundary-pending-replay");
    let keys = working.files.keys().cloned().collect();
    SameSourceAckFixture {
        root,
        index_path,
        progress_path,
        baseline,
        working,
        items: scan.snapshots,
        progress,
        keys,
    }
}
fn integrated_capture(
    f: &SameSourceAckFixture,
    selected: &[usize],
    trace: &mut IntegratedTrace,
) -> IntegratedSlot {
    let entry = crate::retry_allocation_probe::stats().requested_live;
    crate::retry_allocation_probe::phase_begin();
    let slot = IntegratedSlot::capture(f, selected).unwrap();
    let retained = (crate::retry_allocation_probe::stats().requested_live - entry) as usize;
    let peak = crate::retry_allocation_probe::phase_peak();
    assert!(retained <= slot.bound);
    trace.captures.push((slot.bound, retained, peak));
    slot
}
