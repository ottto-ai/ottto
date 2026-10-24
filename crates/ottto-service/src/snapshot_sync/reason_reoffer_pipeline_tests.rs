// Reason-scoped daily re-offer through the real prepare/finish pipeline.
// One synthetic Claude session, a synthetic backend whose answer changes per
// cycle, and a test-thread wall clock for the local re-offer schedule only.
// Nothing waits 24 hours; no provider, credential or runtime state is read.
use super::*;
use std::cell::Cell;

const DAY: u64 = 86_400;
const ORIGINAL_PAIR: &str = "original_pair_candidate_unproved";

thread_local! {
    static CLOCK: Cell<Option<u64>> = const { Cell::new(None) };
}

/// The synthetic local scheduling clock of this test thread, if set.
pub(crate) fn clock() -> Option<u64> {
    CLOCK.with(Cell::get)
}

struct ClockGuard;

impl ClockGuard {
    fn start(now: u64) -> Self {
        CLOCK.with(|clock| clock.set(Some(now)));
        Self
    }

    fn set(&self, now: u64) {
        CLOCK.with(|clock| clock.set(Some(now)));
    }
}

impl Drop for ClockGuard {
    fn drop(&mut self) {
        CLOCK.with(|clock| clock.set(None));
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Answer {
    /// Permanent refusal with this wire reason.
    Refuse(&'static str),
    Accept,
    /// `unchanged` with an `unchanged_basis`: the server did not store it.
    Unstored,
    Conflict,
}

struct ReofferServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    answer: Arc<Mutex<Answer>>,
    offered: Arc<Mutex<Vec<serde_json::Value>>>,
    terminal: Arc<Mutex<Vec<serde_json::Value>>>,
    cache_enabled: Arc<std::sync::atomic::AtomicBool>,
}

fn entity_ack(item: &serde_json::Value) -> serde_json::Value {
    let mut payload = serde_json::Map::new();
    for key in [
        "session_account_evidence",
        "tool_usage",
        "tool_usage_truncated",
    ] {
        if let Some(value) = item.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    let exclusive = item
        .get("usage_accounting_contract")
        .and_then(|value| value.as_str())
        == Some("session_exclusive_reported_usage:v1");
    let version = item
        .get("session_account_evidence")
        .is_some()
        .then_some(if exclusive { 8u64 } else { 7u64 });
    let digest = format!(
        "{:x}",
        Sha256::digest(
            crate::canonical_json::canonicalize(&serde_json::Value::Object(payload)).unwrap()
        )
    );
    serde_json::json!({"source_session_id":item["source_session_id"],
        "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
        "body_witness_version":version,"body_witness_digest":version.map(|_| digest)})
}

impl ReofferServer {
    /// `capture`: the activity hint carries the exact contract-5 token, so
    /// each cycle captures and emits request identity.
    fn new(first: Answer, capture: bool) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let answer = Arc::new(Mutex::new(first));
        let current = answer.clone();
        let offered = Arc::new(Mutex::new(Vec::new()));
        let bodies = offered.clone();
        let terminal = Arc::new(Mutex::new(Vec::new()));
        let statuses = terminal.clone();
        let cache_enabled = Arc::new(AtomicBool::new(false));
        let cache = cache_enabled.clone();
        let worker = std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic re-offer accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                let raw = request.split_once("\r\n\r\n").unwrap().1;
                let value: serde_json::Value = if raw.is_empty() {
                    serde_json::Value::Null
                } else {
                    serde_json::from_str(raw).unwrap()
                };
                let response = if request.contains("/relay-token") {
                    serde_json::json!({"token":"synthetic-reoffer-token","expires_at":"2099-01-01T00:00:00Z"})
                } else if request.contains("/activity-hints") {
                    let mut hint = serde_json::json!({"source":"claude_code","server_time":current_rfc3339(),
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"});
                    if cache.load(Ordering::Relaxed) {
                        hint["session_cache_observations_contract"] =
                            "session_cache_observations:v1".into();
                        hint["snapshot_head_cas_required"] = false.into();
                    }
                    if capture {
                        hint["session_request_identity_contract"] =
                            "own_request_identity_rows:v1".into();
                    }
                    hint
                } else if request.contains("/agent-status/snapshots") {
                    serde_json::json!({"accepted":1,"machine_id":"otm_test","sources":["claude_code"]})
                } else if let Some(items) = value.get("snapshots").and_then(|v| v.as_array()) {
                    assert!(!items.is_empty());
                    bodies.lock().unwrap().extend(items.iter().cloned());
                    let references = items
                        .iter()
                        .map(|item| {
                            serde_json::json!({
                                "source_session_id":item["source_session_id"],
                                "snapshot_fingerprint":item["snapshot_fingerprint"],
                                "occurrence_count":1
                            })
                        })
                        .collect::<Vec<_>>();
                    let mut outcome = serde_json::json!({"accepted":0,"sessions_reconciled":0,
                        "session_ids":[],"disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[],
                        "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]});
                    match *current.lock().unwrap() {
                        Answer::Refuse(reason) => {
                            outcome["rejected_entities"] = items
                                .iter()
                                .map(|item| {
                                    serde_json::json!({
                                        "source_session_id":item["source_session_id"],
                                        "snapshot_fingerprint":item["snapshot_fingerprint"],
                                        "reason":reason,"detail":"synthetic re-offer refusal",
                                        "permanent":true,"occurrence_count":1
                                    })
                                })
                                .collect();
                        }
                        Answer::Accept => {
                            outcome["accepted"] = items.len().into();
                            outcome["sessions_reconciled"] = items.len().into();
                            outcome["accepted_entities"] = items.iter().map(entity_ack).collect();
                        }
                        Answer::Unstored => {
                            outcome["accepted"] = items.len().into();
                            outcome["unchanged_entities"] = items
                                .iter()
                                .map(|item| {
                                    let mut reference = entity_ack(item);
                                    reference["unchanged_basis"] = "usage_identical".into();
                                    reference
                                })
                                .collect();
                        }
                        Answer::Conflict => {
                            outcome["conflict_entities"] = references.into();
                        }
                    }
                    outcome
                } else {
                    if value["report_kind"] == "scan_status" {
                        statuses.lock().unwrap().push(value.clone());
                    }
                    serde_json::json!({"accepted":true,"source":"claude_code","machine_id":"otm_test","disabled":false})
                };
                bounded_native_response(&mut stream, "200 OK", &response.to_string());
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            answer,
            offered,
            terminal,
            cache_enabled,
        }
    }

    fn answer(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }

    fn offered(&self) -> Vec<serde_json::Value> {
        self.offered.lock().unwrap().clone()
    }

    fn last_terminal(&self) -> serde_json::Value {
        self.terminal.lock().unwrap().last().cloned().unwrap()
    }
}

impl Drop for ReofferServer {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let result = self.worker.take().unwrap().join();
        if !std::thread::panicking() {
            result.unwrap();
        }
    }
}

struct CycleResult {
    result: Result<()>,
    leased_offers: usize,
    cache_enabled: bool,
    index: ScanIndex,
    progress: SnapshotUploadProgress,
    /// The saved upload ledger as JSON, to read the exact disk form.
    progress_json: serde_json::Value,
    progress_path: PathBuf,
    index_path: PathBuf,
}

struct ReofferPipeline {
    server: ReofferServer,
    clock: ClockGuard,
    fixture: IdentityPipelineHome,
    support: PathBuf,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    cadence: IdentityPipelineCadence,
    transport: crate::net_resilience::TransportCycleOutcome,
    retry: live_snapshot_retry::LiveRetryOwner,
    _guards: Vec<EnvVarGuard>,
    _native: crate::snapshots::claude_native_comparison::TestScope,
}

impl ReofferPipeline {
    fn new(name: &str, first: Answer, start: u64) -> Self {
        Self::build(name, first, start, false)
    }

    /// The same pipeline with request-identity capture on (R12).
    fn with_capture(name: &str, first: Answer, start: u64) -> Self {
        Self::build(name, first, start, true)
    }

    fn build(name: &str, first: Answer, start: u64, capture: bool) -> Self {
        let fixture = IdentityPipelineHome::new();
        let native = crate::snapshots::claude_native_comparison::enable_for_test();
        let cadence = IdentityPipelineCadence::new();
        let support = fixture.base.join(format!("{name}-support"));
        let secrets = fixture.base.join(format!("{name}-secrets"));
        std::fs::create_dir_all(&support).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        let server = ReofferServer::new(first, capture);
        let guards = vec![
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url),
        ];
        let device = LocalDeviceBinding {
            device_id: format!("{name}-device"),
            machine_id: Some("otm_test".into()),
            sources: vec!["claude_code".into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .unwrap();
        write_native_bootstrap_sidecars(&fixture, &support);
        let client = SnapshotApiClient::new(server.url.clone());
        Self {
            server,
            clock: ClockGuard::start(start),
            fixture,
            support,
            device,
            client,
            daemon: test_daemon("otm_test"),
            cadence,
            transport: crate::net_resilience::TransportCycleOutcome::default(),
            retry: live_snapshot_retry::LiveRetryOwner::closed(),
            _guards: guards,
            _native: native,
        }
    }

    /// One real due cycle at local time `now`.
    fn cycle(&mut self, now: u64) -> CycleResult {
        self.clock.set(now);
        assert_eq!(clock(), Some(now));
        self.cadence.next_due_cycle();
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
                &mut self.transport,
                self.daemon.snapshot_scan_account_witness().unwrap(),
                false,
            )
        })
        .unwrap()
        .expect("real due preparation");
        let (preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(scan.census_complete, "synthetic census is complete");
        let cache_enabled = preparation.cache_observations_enabled;
        let leased_offers = preparation.upload_progress.reason_reoffer_counts.selected;
        let index_path = preparation.index_path.clone();
        let progress_path = preparation.upload_progress_path.clone();
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
                &mut self.transport,
                &mut self.retry,
            )
        });
        let progress_json = std::fs::read(&progress_path)
            .ok()
            .map(|bytes| serde_json::from_slice(&bytes).unwrap())
            .unwrap_or(serde_json::Value::Null);
        CycleResult {
            result,
            leased_offers,
            cache_enabled,
            index: ScanIndex::load(&index_path).unwrap(),
            progress: SnapshotUploadProgress::load(
                &progress_path,
                &snapshot_upload_destination_namespace(&self.device, "device-secret"),
                snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
            )
            .unwrap(),
            progress_json,
            progress_path,
            index_path,
        }
    }
}

fn supported(name: &str) -> bool {
    let supported = crate::heap_layout_bound::layout_supported();
    if !supported {
        writeln!(
            std::io::stderr().lock(),
            "{name}: supported_positive=UNEXECUTED layout_supported=false"
        )
        .unwrap();
    }
    supported
}

fn fingerprint_of(offer: &serde_json::Value) -> String {
    offer["snapshot_fingerprint"].as_str().unwrap().to_string()
}

fn usage_of(offer: &serde_json::Value) -> (u64, u64, u64) {
    (
        offer["request_count"].as_u64().unwrap_or_default(),
        offer["input_tokens"].as_u64().unwrap_or_default(),
        offer["output_tokens"].as_u64().unwrap_or_default(),
    )
}

fn reoffer_json<'a>(cycle: &'a CycleResult, fingerprint: &str) -> &'a serde_json::Value {
    &cycle.progress_json["permanent_rejections"][fingerprint]["reoffer"]
}

/// Old daemon rewrite: the record keeps `reason: other` and loses the
/// extension it does not know.
fn strip_reoffer_extension(path: &Path, fingerprint: &str) {
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    json["permanent_rejections"][fingerprint]
        .as_object_mut()
        .unwrap()
        .remove("reoffer");
    std::fs::write(path, serde_json::to_vec_pretty(&json).unwrap()).unwrap();
}

/// R1/R2/R7: an unchanged finished session refused for
/// `original_pair_candidate_unproved` is offered once a day, exactly, until
/// the server accepts it. Repeat refusals settle the census while health
/// stays red, and the clock restarts on each refusal.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn original_pair_refusal_is_reoffered_once_a_day_until_accepted() {
    if !supported("original_pair_refusal_is_reoffered_once_a_day_until_accepted") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("reoffer-daily", Answer::Refuse(ORIGINAL_PAIR), t0);

    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 1);
    let fingerprint = fingerprint_of(&offered[0]);
    let refused_body = first.progress.permanent_rejections[&fingerprint]
        .body_witness
        .clone();
    assert_eq!(
        first.progress_json["permanent_rejections"][&fingerprint]["reason"], "other",
        "the new reason keeps the old enum disk form"
    );
    assert_eq!(
        pipeline.server.last_terminal()["last_error_code"],
        "backend_validation_error"
    );

    // Hours later, and just before the day ends: no offer.
    for now in [t0 + 3_600, t0 + 13 * 3_600, t0 + DAY - 1] {
        let quiet = pipeline.cycle(now);
        assert!(quiet.result.is_ok(), "{:?}", quiet.result);
        assert_eq!(
            pipeline.server.offered().len(),
            1,
            "no offer before t0 + 24 h (at +{}s)",
            now - t0
        );
    }

    // Day 1: exactly one offer of the exact refused body; refused again.
    let t1 = t0 + DAY + 60;
    let day1 = pipeline.cycle(t1);
    assert!(day1.result.is_ok(), "{:?}", day1.result);
    let offered = pipeline.server.offered();
    assert_eq!(
        offered.len(),
        2,
        "a due original-pair refusal is re-offered once, through the real scan"
    );
    assert_eq!(fingerprint_of(&offered[1]), fingerprint);
    assert_eq!(usage_of(&offered[1]), usage_of(&offered[0]));
    let refusal = &day1.progress.permanent_rejections[&fingerprint];
    assert_eq!(refusal.body_witness, refused_body, "same exact body");
    assert_eq!(
        reoffer_json(&day1, &fingerprint)["retry_after_unix_seconds"],
        t1 + DAY,
        "the repeat refusal restarts the 24 h clock"
    );
    assert_eq!(reoffer_json(&day1, &fingerprint)["reason"], ORIGINAL_PAIR);
    assert_eq!(
        day1.progress_json["permanent_rejections"][&fingerprint]["reason"],
        "other"
    );
    // R7: the repeat refusal settles the traversal; health stays red.
    assert!(!day1.index.bounded_sweep_had_unsettled_upload());
    assert!(!day1
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint));
    assert_eq!(
        day1.index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
        SnapshotQuarantineDisposition::UnprovenTerminal
    );
    let terminal = pipeline.server.last_terminal();
    assert_eq!(terminal["last_error_code"], "backend_validation_error");
    assert_eq!(terminal["last_census_complete"], true);

    // No 6-12 h ordinary retry and no second offer the same day.
    for now in [t1 + 300, t1 + 13 * 3_600] {
        let quiet = pipeline.cycle(now);
        assert!(quiet.result.is_ok(), "{:?}", quiet.result);
        assert_eq!(pipeline.server.offered().len(), 2);
        assert!(!quiet.index.bounded_sweep_had_unsettled_upload());
        assert_eq!(
            pipeline.server.last_terminal()["last_error_code"],
            "backend_validation_error"
        );
    }

    // Day 2: SOURCE is ready; the normal ACK clears the refusal.
    pipeline.server.answer(Answer::Accept);
    let t2 = t1 + DAY + 60;
    let day2 = pipeline.cycle(t2);
    assert!(day2.result.is_ok(), "{:?}", day2.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 3);
    assert_eq!(fingerprint_of(&offered[2]), fingerprint);
    assert!(!day2
        .progress
        .permanent_rejections
        .contains_key(&fingerprint));
    assert!(day2
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint));
    assert!(!day2
        .index
        .quarantined_snapshot_fingerprints
        .contains_key(&fingerprint));

    // Accepted: nothing left to re-offer, and the next receipt is clean.
    let after = pipeline.cycle(t2 + 2 * DAY);
    assert!(after.result.is_ok(), "{:?}", after.result);
    assert_eq!(pipeline.server.offered().len(), 3);
    let terminal = pipeline.server.last_terminal();
    assert_ne!(
        terminal["last_error_code"], "backend_validation_error",
        "{terminal}"
    );
    assert_eq!(terminal["last_census_complete"], true);
    assert!(!after.index.bounded_sweep_had_unsettled_upload());
}

/// SOURCE ruling 6: a legacy `other` refusal, as every older daemon wrote
/// this reason, is re-offered once. The server's answer re-classifies it:
/// `other` again is final; the exact reason joins the daily cycle.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn legacy_other_refusal_is_reclassified_by_one_offer() {
    if !supported("legacy_other_refusal_is_reclassified_by_one_offer") {
        return;
    }
    for (name, second_answer) in [
        ("legacy-final", Answer::Refuse("future_unknown_reason")),
        ("legacy-daily", Answer::Refuse(ORIGINAL_PAIR)),
    ] {
        let t0 = current_unix_seconds();
        let mut pipeline = ReofferPipeline::new(name, Answer::Refuse("future_unknown_reason"), t0);
        let first = pipeline.cycle(t0);
        assert!(first.result.is_ok(), "{name}: {:?}", first.result);
        let fingerprint = fingerprint_of(&pipeline.server.offered()[0]);
        assert_eq!(
            first.progress_json["permanent_rejections"][&fingerprint]["reason"],
            "other"
        );
        strip_reoffer_extension(&first.progress_path, &fingerprint);

        pipeline.server.answer(second_answer);
        let reclassified = pipeline.cycle(t0 + 600);
        assert!(
            reclassified.result.is_ok(),
            "{name}: {:?}",
            reclassified.result
        );
        assert_eq!(
            pipeline.server.offered().len(),
            2,
            "{name}: a legacy `other` refusal is re-offered once"
        );
        assert_eq!(fingerprint_of(&pipeline.server.offered()[1]), fingerprint);
        assert!(!reclassified.index.bounded_sweep_had_unsettled_upload());

        // Never repeated within the day, whatever the answer.
        let quiet = pipeline.cycle(t0 + 1_200);
        assert!(quiet.result.is_ok(), "{name}: {:?}", quiet.result);
        assert_eq!(pipeline.server.offered().len(), 2, "{name}");

        let later = pipeline.cycle(t0 + 600 + DAY + 60);
        assert!(later.result.is_ok(), "{name}: {:?}", later.result);
        match second_answer {
            Answer::Refuse(ORIGINAL_PAIR) => {
                assert_eq!(
                    pipeline.server.offered().len(),
                    3,
                    "{name}: the exact reason joins the 24 h cycle"
                );
            }
            _ => {
                assert_eq!(
                    pipeline.server.offered().len(),
                    2,
                    "{name}: a server `other` is final; the done marker is per record"
                );
                assert_eq!(reoffer_json(&later, &fingerprint)["reason"], "classified");
            }
        }
        assert!(later
            .progress
            .permanent_rejections
            .contains_key(&fingerprint));
    }
}

/// COST (b): a validated `unchanged` answer that did not store the body
/// retires the old refusal and its schedule, keeps the unstored-body hold,
/// and records no stored body.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn unstored_unchanged_reoffer_retires_the_refusal_and_keeps_the_hold() {
    if !supported("unstored_unchanged_reoffer_retires_the_refusal_and_keeps_the_hold") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("reoffer-unstored", Answer::Refuse(ORIGINAL_PAIR), t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let fingerprint = fingerprint_of(&pipeline.server.offered()[0]);
    let refused_body = first.progress.permanent_rejections[&fingerprint]
        .body_witness
        .clone();

    pipeline.server.answer(Answer::Unstored);
    let t1 = t0 + DAY + 60;
    let day1 = pipeline.cycle(t1);
    assert!(day1.result.is_ok(), "{:?}", day1.result);
    assert_eq!(
        pipeline.server.offered().len(),
        2,
        "due offer reached the server"
    );
    assert!(
        !day1
            .progress
            .permanent_rejections
            .contains_key(&fingerprint),
        "the unstored verdict replaced the refusal"
    );
    assert!(!day1.progress.accepted_fingerprints.contains(&fingerprint));
    assert!(!day1
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint));
    let hold = &day1.index.quarantined_snapshot_fingerprints[&fingerprint];
    assert_eq!(
        hold.disposition,
        SnapshotQuarantineDisposition::UnprovenTerminal
    );
    assert_eq!(
        hold.upload_body_witness.as_deref(),
        Some(refused_body.as_str())
    );

    // The retired reason schedules nothing more.
    let later = pipeline.cycle(t1 + DAY + 60);
    assert!(later.result.is_ok(), "{:?}", later.result);
    assert_eq!(pipeline.server.offered().len(), 2);
}

/// R8: a conflict on the daily offer keeps today's unsettled/follow-up
/// behavior, keeps the refusal and its cooldown, and the conflict's
/// RetryPending state cannot let the refused body escape the 24 h gate.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn conflicting_reoffer_keeps_refusal_cooldown_and_follow_up() {
    if !supported("conflicting_reoffer_keeps_refusal_cooldown_and_follow_up") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("reoffer-conflict", Answer::Refuse(ORIGINAL_PAIR), t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let fingerprint = fingerprint_of(&pipeline.server.offered()[0]);

    pipeline.server.answer(Answer::Conflict);
    let t1 = t0 + DAY + 60;
    let day1 = pipeline.cycle(t1);
    assert_eq!(
        pipeline.server.offered().len(),
        2,
        "due offer reached the server"
    );
    assert!(day1.result.is_err(), "a conflict still owes a follow-up");
    assert_eq!(
        pipeline.server.last_terminal()["last_error_code"],
        "server_error"
    );
    assert!(day1.index.bounded_sweep_had_unsettled_upload());
    assert!(day1
        .progress
        .permanent_rejections
        .contains_key(&fingerprint));
    assert!(
        reoffer_json(&day1, &fingerprint)["retry_after_unix_seconds"]
            .as_u64()
            .is_some_and(|retry_after| retry_after >= t1 + DAY),
        "{}",
        day1.progress_json
    );

    // Even with the conflict's ordinary retry due, the refused body waits.
    pipeline.server.answer(Answer::Accept);
    let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
        &snapshot_index_path(&pipeline.support, SnapshotSource::ClaudeCode),
        &snapshot_upload_destination_namespace(&pipeline.device, "device-secret"),
    ));
    let mut index = ScanIndex::load(&index_path).unwrap();
    if let Some(record) = index
        .quarantined_snapshot_fingerprints
        .get_mut(&fingerprint)
    {
        record.retry_after_unix_seconds = 0;
    }
    index.save(&index_path).unwrap();
    let quiet = pipeline.cycle(t1 + 3_600);
    assert!(
        quiet.result.is_err(),
        "a suppressed body still owes its newer conflict follow-up"
    );
    assert_eq!(
        quiet.index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert_eq!(
        quiet.progress.quarantined_fingerprints[&fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert!(quiet.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        pipeline.server.last_terminal()["last_error_code"],
        "server_error"
    );
    assert_eq!(
        reoffer_json(&quiet, &fingerprint)["retry_after_unix_seconds"],
        reoffer_json(&day1, &fingerprint)["retry_after_unix_seconds"]
    );
    assert_eq!(
        pipeline.server.offered().len(),
        2,
        "no ordinary 6-12 h retry of the refused body"
    );
}

/// COST (a): once the session's head moved past the refused body, the old
/// body is never re-offered and no re-admission raises the session's usage.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn superseded_refused_body_is_never_reoffered_after_the_head_moved() {
    if !supported("superseded_refused_body_is_never_reoffered_after_the_head_moved") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline =
        ReofferPipeline::new("reoffer-head-moved", Answer::Refuse(ORIGINAL_PAIR), t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let refused = pipeline.server.offered()[0].clone();
    let refused_fingerprint = fingerprint_of(&refused);

    // The session grows: one more request moves its head to body B.
    let transcript = pipeline
        .fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(5))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let grown = serde_json::json!({"timestamp": at, "type": "assistant",
        "sessionId": IDENTITY_PIPELINE_ROOT, "requestId": "req_3",
        "message": {"id": "m3", "model": "claude-haiku-4-5",
        "usage": {"input_tokens": 30, "output_tokens": 3}}});
    std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap()
        .write_all(format!("{grown}\n").as_bytes())
        .unwrap();
    write_native_bootstrap_sidecars(&pipeline.fixture, &pipeline.support);
    pipeline.server.answer(Answer::Accept);
    let moved = pipeline.cycle(t0 + 3_600);
    assert!(moved.result.is_ok(), "{:?}", moved.result);
    let offered = pipeline.server.offered();
    assert_eq!(
        offered.len(),
        2,
        "body B is offered through the normal path"
    );
    let head = offered[1].clone();
    assert_ne!(fingerprint_of(&head), refused_fingerprint);

    // Days later: the superseded refused body is not current; nothing is
    // re-offered and the accepted head is not rewritten.
    for day in 1..=2 {
        let later = pipeline.cycle(t0 + day * DAY + 120);
        assert!(later.result.is_ok(), "{:?}", later.result);
        let offered = pipeline.server.offered();
        assert_eq!(offered.len(), 2, "day {day}: no re-admission of body A");
        assert!(later
            .index
            .accepted_snapshot_fingerprint_recorded(&fingerprint_of(&head)));
        assert!(!later
            .progress
            .permanent_rejections
            .contains_key(&refused_fingerprint));
    }
    let uploaded_after_refusal = pipeline.server.offered()[1..]
        .iter()
        .map(usage_of)
        .fold((0, 0, 0), |sum, usage| {
            (sum.0 + usage.0, sum.1 + usage.1, sum.2 + usage.2)
        });
    assert_eq!(
        uploaded_after_refusal,
        usage_of(&head),
        "only the current head's usage is ever offered after the refusal"
    );
}

/// A JSON array's elements; none when the field is absent.
fn json_array(value: &serde_json::Value) -> &[serde_json::Value] {
    value.as_array().map(Vec::as_slice).unwrap_or(&[])
}

/// Every usage row of an offered body: the item's rows and its buckets' rows.
fn usage_rows(offer: &serde_json::Value) -> Vec<&serde_json::Value> {
    json_array(&offer["model_usage"])
        .iter()
        .chain(
            json_array(&offer["usage_buckets"])
                .iter()
                .flat_map(|bucket| json_array(&bucket["model_usage"])),
        )
        .collect()
}

/// The late API capture: the session's API rows are recorded again, now
/// carrying its login and organization (request identity), as a capture that
/// lands after the refusal would. The trace rows are unchanged.
fn capture_late_identity_rows(pipeline: &ReofferPipeline, login: &str, org: &str) {
    let path = pipeline
        .support
        .join("local-otel")
        .join("claude-code-effort")
        .join(format!(
            "{:x}.jsonl",
            Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
        ));
    let rows = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| {
            let mut row: crate::claude_local_otel::ClaudeLocalOtelEvidence =
                serde_json::from_str(line).unwrap();
            row.account_identity_checked = true;
            row.account_identifier_hash = Some(login.to_string());
            row.request_identity = Some(
                serde_json::from_value(serde_json::json!({
                    "identity_hash_scheme":"provider-sha256:v1", "disposition":"complete",
                    "account":{"disposition":"complete", "origin":"log_record", "log_record_hash":login},
                    "organization":{"disposition":"complete", "origin":"log_record", "log_record_hash":org},
                }))
                .unwrap(),
            );
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            serde_json::to_string(&row).unwrap() + "\n"
        })
        .collect::<String>();
    std::fs::write(&path, rows).unwrap();
}

/// SI I-R1 (R12, capture on): between the refusal and the daily re-offer,
/// SOURCE proves the original pair and a late API capture adds the session's
/// identity. The session's next offer is rebuilt from the current evidence,
/// never from the refused body: the server accepts a body with the refused
/// body's usage and the late rows' login and org tags, and the refused body
/// is never sent again.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn late_api_row_tags_the_reoffered_body_once_the_pair_is_proven() {
    if !supported("late_api_row_tags_the_reoffered_body_once_the_pair_is_proven") {
        return;
    }
    use crate::snapshots::claude_request_identity as identity;
    let login = "a".repeat(64);
    let org = "d".repeat(64);
    let t0 = current_unix_seconds();
    let mut pipeline =
        ReofferPipeline::with_capture("reoffer-late-row", Answer::Refuse(ORIGINAL_PAIR), t0);

    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 1);
    let refused = offered[0].clone();
    let refused_fingerprint = fingerprint_of(&refused);
    assert!(first
        .progress
        .permanent_rejections
        .contains_key(&refused_fingerprint));
    assert!(
        usage_rows(&refused)
            .iter()
            .all(|row| row["account_identifier_hash"] != login.as_str()),
        "the refused body predates the late rows: {refused}"
    );
    assert!(
        json_array(&refused["request_evidence"])
            .iter()
            .all(|entry| entry["identity_basis"] != identity::TELEMETRY),
        "{refused}"
    );

    // Between the refusal and the daily re-offer.
    capture_late_identity_rows(&pipeline, &login, &org);
    pipeline.server.answer(Answer::Accept);

    let t1 = t0 + DAY + 60;
    let day1 = pipeline.cycle(t1);
    assert_eq!(
        day1.leased_offers, 1,
        "the daily lease selected the refused record; disabling re-offers must fail this test"
    );
    assert!(day1.result.is_ok(), "{:?}", day1.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 2, "one offer for the session on the due day");
    let accepted = &offered[1];
    assert_eq!(accepted["source_session_id"], IDENTITY_PIPELINE_ROOT);
    let accepted_fingerprint = fingerprint_of(accepted);
    assert_ne!(
        accepted_fingerprint, refused_fingerprint,
        "rebuilt from the current evidence, not the refused body"
    );
    assert_eq!(
        usage_of(accepted),
        usage_of(&refused),
        "same usage; only the identity tags are new"
    );
    // The late rows' tags: every usage row carries the login and links to a
    // telemetry entry naming the org.
    let evidence = accepted["request_evidence"]
        .as_array()
        .unwrap_or_else(|| panic!("the tagged body declares its evidence: {accepted}"));
    let rows = usage_rows(accepted);
    assert!(!rows.is_empty(), "{accepted}");
    for row in rows {
        assert_eq!(
            row["account_identifier_hash"],
            login.as_str(),
            "login tag: {accepted}"
        );
        let reference = row["evidence_ref"]
            .as_u64()
            .unwrap_or_else(|| panic!("every usage row has an identity tag: {accepted}"));
        let entry = &evidence[usize::try_from(reference).unwrap()];
        assert_eq!(entry["identity_basis"], identity::TELEMETRY, "{accepted}");
        assert_eq!(
            entry["provider_workspace_hash"],
            org.as_str(),
            "org tag: {accepted}"
        );
    }
    assert!(
        accepted.get("request_identity_refusals").is_none(),
        "{accepted}"
    );
    // The server-accepted body is the tagged one.
    assert!(day1
        .index
        .accepted_snapshot_fingerprint_recorded(&accepted_fingerprint));

    // Later days: the refused body is superseded, never re-offered, and its
    // refusal is retired; the tagged body stays accepted.
    let later = pipeline.cycle(t1 + DAY + 60);
    assert!(later.result.is_ok(), "{:?}", later.result);
    assert_eq!(pipeline.server.offered().len(), 2);
    assert!(!later
        .progress
        .permanent_rejections
        .contains_key(&refused_fingerprint));
    assert!(later
        .index
        .accepted_snapshot_fingerprint_recorded(&accepted_fingerprint));
}

/// F1: cache capability on, no accepted head and CAS optional. The recorded
/// refusal belongs to the stripped probe, not the cache-enriched scan item.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn cache_head_probe_refusal_reoffers_its_own_exact_body() {
    if !supported("cache_head_probe_refusal_reoffers_its_own_exact_body") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline =
        ReofferPipeline::new("reoffer-cache-probe", Answer::Refuse(ORIGINAL_PAIR), t0);
    pipeline
        .server
        .cache_enabled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    assert!(
        first.cache_enabled,
        "the real preparation negotiated the cache contract"
    );
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 1);
    let refused = offered[0].clone();
    let fingerprint = fingerprint_of(&refused);
    assert!(refused.get("cache_observations").is_none());
    assert!(first.progress.accepted_cache_heads.is_empty());
    let quiet = pipeline.cycle(t0 + DAY - 1);
    assert!(quiet.result.is_ok(), "{:?}", quiet.result);
    assert_eq!(pipeline.server.offered().len(), 1);
    let due = pipeline.cycle(t0 + DAY + 60);
    assert!(due.result.is_ok(), "{:?}", due.result);
    assert_eq!(due.leased_offers, 1);
    assert!(due.cache_enabled);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 2, "the rebuilt probe must reach SOURCE");
    assert_eq!(fingerprint_of(&offered[1]), fingerprint);
    assert!(offered[1].get("cache_observations").is_none());
    assert_eq!(
        due.progress.permanent_rejections[&fingerprint].body_witness,
        first.progress.permanent_rejections[&fingerprint].body_witness
    );
    assert_eq!(
        reoffer_json(&due, &fingerprint)["retry_after_unix_seconds"],
        t0 + DAY + 60 + DAY
    );
}

/// #692: two physical POSTs remain one logical leased offer, including bytes.
/// Advancing the injected clock after 503 proves the saved claim is not bumped
/// by the resend; the legacy done marker appears only with the final answer.
#[test]
#[serial(client_report)]
fn reoffer_fast_503_resend_keeps_one_claim_until_validated_final_answer() {
    let start = 2_000_000_000;
    let clock = ClockGuard::start(start);
    let fingerprint = "b".repeat(64);
    let body = "c".repeat(64);
    let mut progress = test_upload_progress();
    progress.quarantine_permanent_body(&fingerprint, &body, "future_unknown_reason");
    progress
        .permanent_rejections
        .get_mut(&fingerprint)
        .unwrap()
        .reoffer = None;
    progress.reserve_reason_reoffer(&fingerprint, body.clone(), start);
    let leased = progress.active_reason_reoffers.clone();
    // The exact pre-send durable claim is observable by each fake POST.
    let saved = std::cell::RefCell::new(serde_json::to_value(&progress).unwrap());
    let mut posts = 0;
    let mut accepted = 0;
    let mut budget = InplaceRetryBudget::default();
    let (result, waits) = with_inplace_retry_test_clock(Some(Duration::ZERO), || {
        upload_resumable_batches_with_body_witness_partitioned(
            std::slice::from_ref(&fingerprint),
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            String::as_str,
            |_| body.clone(),
            |_| Some("synthetic-session"),
            |_| false,
            &mut budget,
            |items| {
                assert_eq!(items, vec![fingerprint.clone()]);
                let disk = saved.borrow();
                let state = &disk["permanent_rejections"][&fingerprint]["reoffer"];
                assert_eq!(state["reason"], "legacy_other_reclassification");
                assert_eq!(state["retry_after_unix_seconds"], start + DAY);
                posts += 1;
                if posts == 1 {
                    clock.set(start + 600);
                    return Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: Some(Duration::from_secs(1)),
                        code: None,
                    }));
                }
                let mut response = accepted_batch(0);
                response.entity_ack_contract =
                    Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into());
                response
                    .rejected_entities
                    .push(crate::snapshot_client::SnapshotEntityRejection {
                        source_session_id: "synthetic-session".into(),
                        snapshot_fingerprint: fingerprint.clone(),
                        reason: "future_unknown_reason".into(),
                        detail: "synthetic final answer".into(),
                        permanent: true,
                        occurrence_count: 1,
                    });
                Ok(response)
            },
            |checkpoint| {
                *saved.borrow_mut() = serde_json::to_value(checkpoint).unwrap();
                Ok(())
            },
        )
    });
    assert!(matches!(
        result.unwrap(),
        ResumableUploadResult::Rejected { .. }
    ));
    assert_eq!(posts, 2);
    assert_eq!(budget.resends, 1);
    assert_eq!(waits.len(), 1);
    assert!(budget.waited <= SNAPSHOT_INPLACE_RETRY_WAIT_BUDGET);
    assert_eq!(
        saved.borrow()["permanent_rejections"][&fingerprint]["reoffer"]["reason"],
        "classified"
    );
    progress.finish_reason_reoffers(&leased, false, SnapshotSource::ClaudeCode.api_slug());
    let counts = progress.reason_reoffer_counts;
    assert_eq!(
        (
            counts.selected,
            counts.attempted,
            counts.refused_other,
            counts.failed
        ),
        (1, 1, 1, 0)
    );
    assert_eq!(
        counts.attempted_bytes,
        snapshot_packing_json_length(&fingerprint).unwrap()
    );
    assert!(
        progress.contains_body(&fingerprint, &body),
        "lease consumed only by final answer"
    );
}

/// SOURCE condition 5 (Round 13): a protected root, named by the local
/// re-emission list, whose family a census retired as absent (tombstoned,
/// witness kept) and whose member then returns, through the real
/// prepare/finish pipeline and the recording server. The return re-enters
/// the authority path, and nothing emitted for the root is a request-owned
/// literal (`claude_request_counting:v1`, the "new v1"), nor is any file of
/// it stamped with body-witness revision 3. The root either settles its proof
/// (tombstone cleared, no record) or stays held with nothing offered.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn protected_returning_root_emits_no_literal_v1_or_revision_3() {
    if !supported("protected_returning_root_emits_no_literal_v1_or_revision_3") {
        return;
    }
    let root = IDENTITY_PIPELINE_ROOT;
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("patha-protected-return", Answer::Accept, t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let key = first
        .index
        .files
        .keys()
        .find(|key| key.ends_with(&format!("{root}.jsonl")))
        .cloned()
        .expect("the root is indexed");

    crate::snapshots::write_claude_reemission_list_for_test(&pipeline.support, &[root]);
    let mut index = ScanIndex::load(&first.index_path).unwrap();
    index.tombstone_claude_family_for_test(root);
    index.save(&first.index_path).unwrap();
    let transcript = pipeline
        .fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{root}.jsonl"));
    let bytes = std::fs::read(&transcript).unwrap();
    std::fs::remove_file(&transcript).unwrap();
    let absent = pipeline.cycle(t0 + 600);
    assert!(absent.result.is_ok(), "{:?}", absent.result);
    assert!(!absent.index.files.contains_key(&key));
    assert!(absent.index.claude_family_tombstoned_for_test(root));

    let offered_before = pipeline.server.offered().len();
    std::fs::write(&transcript, &bytes).unwrap();
    let returned = pipeline.cycle(t0 + 1_200);
    assert!(returned.result.is_ok(), "{:?}", returned.result);
    let offered = pipeline.server.offered();
    let root_offers = offered[offered_before..]
        .iter()
        .filter(|offer| offer["source_session_id"] == root)
        .collect::<Vec<_>>();
    for offer in &root_offers {
        assert_ne!(
            offer["usage_accounting_contract"], "claude_request_counting:v1",
            "no request-owned literal for a protected root"
        );
        assert!(
            !offer.to_string().contains("claude_request_counting"),
            "no literal body for a protected root"
        );
    }
    if let Some(entry) = returned.index.files.get(&key) {
        assert_ne!(entry.effective_upload_body_witness_revision, 3);
        assert!(
            entry.effective_upload_body_witness_revision
                <= effective_upload_body_witness_revision(SnapshotSource::ClaudeCode)
        );
    }
    let settled = !returned.index.claude_family_tombstoned_for_test(root)
        && returned
            .index
            .claude_authority_record_for_test(root)
            .is_none();
    let held = returned.index.claude_family_tombstoned_for_test(root)
        && returned
            .index
            .claude_authority_record_for_test(root)
            .is_some()
        && root_offers.is_empty();
    assert!(
        settled || held,
        "the return re-enters the authority path: settled={settled} held={held}"
    );
}

/// The Claude scan index this pipeline's destination uses.
fn claude_index_path(support: &Path) -> PathBuf {
    std::fs::read_dir(support.join("snapshots/destinations"))
        .unwrap()
        .flatten()
        .map(|destination| destination.path().join("claude_code-scan-index-v3.json"))
        .find(|path| path.exists())
        .expect("the Claude scan index")
}

/// The local Claude re-emission list.
fn reemission_list_path(support: &Path) -> PathBuf {
    support.join("snapshots/claude_code-reemission-exclusions.txt")
}

/// #712 held-body control for #706: a history-held file (stored revision
/// below the active one, no list, a saved history cutoff after its birth; the
/// refusal in the ledger is prior history) with a due original-pair re-offer
/// lease is not re-offered. Where no list is intended, only an unverified
/// Mac or a move under a non-`full` claim still holds history (StateMissing
/// N1); the index's durable move marker stands for that hold here. The lease is granted but
/// never delivered: no body reaches the server, the refusal and its
/// original-pair extension stay, nothing is accepted and the hold stays
/// terminal. Once an installed list lets the upgrade through, the same lease
/// delivers the exact refused body, so the hold is what blocked it.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn history_held_file_is_not_reoffered_and_its_lease_is_not_delivered() {
    if !supported("history_held_file_is_not_reoffered_and_its_lease_is_not_delivered") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline =
        ReofferPipeline::new("reoffer-history-held", Answer::Refuse(ORIGINAL_PAIR), t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    assert_eq!(pipeline.server.offered().len(), 1);
    let fingerprint = fingerprint_of(&pipeline.server.offered()[0]);
    let refused_body = first.progress.permanent_rejections[&fingerprint]
        .body_witness
        .clone();

    // History-held: every Claude entry stored below the active revision, and
    // a saved history cutoff at or after every fixture birth.
    let index_path = claude_index_path(&pipeline.support);
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).unwrap()).unwrap();
    let files = saved["files"].as_object_mut().expect("indexed files");
    assert!(!files.is_empty());
    for entry in files.values_mut() {
        entry["effective_upload_body_witness_revision"] = 1.into();
    }
    saved["claude_history_cutoff_unix_seconds"] = current_unix_seconds().into();
    saved["claude_history_move_not_full"] = true.into();
    std::fs::write(&index_path, serde_json::to_vec(&saved).unwrap()).unwrap();
    assert!(!reemission_list_path(&pipeline.support).exists(), "no list");

    pipeline.server.answer(Answer::Accept);
    for day in 1..=2 {
        let due = pipeline.cycle(t0 + day * (DAY + 60));
        assert!(due.result.is_ok(), "day {day}: {:?}", due.result);
        assert_eq!(due.leased_offers, 1, "day {day}: the lease is granted");
        assert_eq!(
            pipeline.server.offered().len(),
            1,
            "day {day}: a history-held body is never re-offered"
        );
        let refusal = &due.progress.permanent_rejections[&fingerprint];
        assert_eq!(refusal.body_witness, refused_body, "day {day}");
        assert_eq!(
            reoffer_json(&due, &fingerprint)["reason"],
            ORIGINAL_PAIR,
            "day {day}: the lease is not settled"
        );
        assert!(!due.progress.accepted_fingerprints.contains(&fingerprint));
        assert!(!due
            .index
            .accepted_snapshot_fingerprint_recorded(&fingerprint));
        assert_eq!(
            due.index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::UnprovenTerminal,
            "day {day}"
        );
        assert!(due
            .index
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 1));
    }

    // Positive control: an installed (empty) list paces the upgrade, and the
    // next due lease delivers the exact refused body.
    std::fs::write(reemission_list_path(&pipeline.support), "# synthetic\n").unwrap();
    let permitted = pipeline.cycle(t0 + 3 * (DAY + 60));
    assert!(permitted.result.is_ok(), "{:?}", permitted.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 2, "the permitted upgrade delivers the lease");
    assert_eq!(fingerprint_of(&offered[1]), fingerprint);
    assert!(permitted
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint));
}

/// StateMissing H1 through the real replay decision, and N2: after a
/// completed bootstrap, an unreadable backfill state arms no Claude replay
/// in `prepare_sync_source` (the replay claim, the entries and the server
/// all stay as they were), and the Claude census that cycle completes under
/// the history gate clears the marker.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn unreadable_backfill_state_arms_no_replay_and_clears_after_a_gated_census() {
    if !supported("unreadable_backfill_state_arms_no_replay_and_clears_after_a_gated_census") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("history-unverified", Answer::Accept, t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let offered = pipeline.server.offered().len();
    assert!(offered > 0);
    let state_path = crate::backfill::backfill_state_path(&pipeline.support);
    assert!(
        !crate::backfill::load_backfill_state(&pipeline.support).prior_history_unverified,
        "the bootstrap completed with a readable state"
    );
    std::fs::write(&state_path, b"{\"completed_destination_namespaces\":")
        .expect("corrupt the backfill state");
    assert!(crate::backfill::load_backfill_state(&pipeline.support).prior_history_unverified);

    let second = pipeline.cycle(t0 + 60);
    assert!(second.result.is_ok(), "{:?}", second.result);
    assert_eq!(
        pipeline.server.offered().len(),
        offered,
        "no replay re-sent anything"
    );
    assert_eq!(
        second.progress_json["historical_replay_generation"],
        first.progress_json["historical_replay_generation"],
        "no replay claimed a generation"
    );
    assert_eq!(
        second.index.files.keys().collect::<Vec<_>>(),
        first.index.files.keys().collect::<Vec<_>>(),
        "no replay dropped the entries"
    );
    assert!(second
        .index
        .files
        .iter()
        .all(|(key, entry)| entry.source_file_fingerprint
            == first.index.files[key].source_file_fingerprint));
    assert!(
        !crate::backfill::load_backfill_state(&pipeline.support).prior_history_unverified,
        "N2: the gated census cleared the marker"
    );
}

/// StateMissing N1 (b) through the real pipeline: a fresh install whose
/// upload ledger claimed a replay generation before the scan, but was killed
/// before its first index save and before any server answer was recorded,
/// is still a fresh install. The next cycle uploads its history as new: it
/// is not held, and no history cutoff is recorded.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn ledger_claim_alone_after_a_killed_first_cycle_uploads_history() {
    if !supported("ledger_claim_alone_after_a_killed_first_cycle_uploads_history") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("history-killed-install", Answer::Accept, t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let offered = pipeline.server.offered();
    assert!(!offered.is_empty());
    // Back to what a killed first cycle leaves: the ledger's own claim of a
    // replay generation, saved before the scan, but no server answer, no
    // index and no completed bootstrap.
    // A settled bootstrap leaves no ledger file, so write the claim itself.
    let mut claim = SnapshotUploadProgress::load(
        &first.progress_path,
        &snapshot_upload_destination_namespace(&pipeline.device, "device-secret"),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .expect("load the ledger");
    claim.historical_replay_generation = Some("claude_code:killed-first-cycle".into());
    claim.accepted_fingerprints.clear();
    claim.accepted_body_witnesses.clear();
    claim.accepted_cache_states.clear();
    claim.accepted_cache_heads.clear();
    claim.pending_cache_heads.clear();
    claim.quarantined_fingerprints.clear();
    claim.permanent_rejections.clear();
    claim
        .save(&first.progress_path)
        .expect("write the claim-only ledger");
    assert!(!claim.records_server_attested_upload());
    std::fs::remove_file(claude_index_path(&pipeline.support)).expect("lose the index");
    let _ = std::fs::remove_file(crate::backfill::backfill_state_path(&pipeline.support));

    let second = pipeline.cycle(t0 + 60);
    assert!(second.result.is_ok(), "{:?}", second.result);
    let resent = pipeline.server.offered();
    assert_eq!(resent.len(), 2 * offered.len(), "the history is uploaded");
    assert_eq!(
        resent[offered.len()..]
            .iter()
            .map(fingerprint_of)
            .collect::<BTreeSet<_>>(),
        offered.iter().map(fingerprint_of).collect::<BTreeSet<_>>()
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(claude_index_path(&pipeline.support)).unwrap())
            .unwrap();
    assert!(
        saved.get("claude_history_cutoff_unix_seconds").is_none(),
        "a fresh install records no history cutoff"
    );
}

/// H727-1: the M4 incident shape, through real prepare/finish (including
/// bootstrap completion and N2 clearing), after BOTH list and .seen are lost.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn durable_list_intent_holds_quarantined_history_without_list_or_seen() {
    if !supported("durable_list_intent_holds_quarantined_history_without_list_or_seen") {
        return;
    }
    lost_list_intent_pipeline("history-intent-set", true, false);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn absent_list_intent_paces_quarantined_history() {
    if !supported("absent_list_intent_paces_quarantined_history") {
        return;
    }
    lost_list_intent_pipeline("history-intent-absent", false, false);
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn malformed_list_intent_holds_quarantined_history_without_list_or_seen() {
    if !supported("malformed_list_intent_holds_quarantined_history_without_list_or_seen") {
        return;
    }
    lost_list_intent_pipeline("history-intent-malformed", false, true);
}

fn lost_list_intent_pipeline(name: &str, set: bool, malformed: bool) {
    use crate::backfill::{backfill_state_path, load_backfill_state, ClaudeHistoryListIntent};
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new(name, Answer::Accept, t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let initial = pipeline.server.offered().len();
    assert!(initial > 0, "prior uploads");
    assert_eq!(
        load_backfill_state(&pipeline.support).claude_history_list_intent,
        ClaudeHistoryListIntent::Absent
    );
    let seen = crate::snapshots::claude_reemission_seen_marker_path(&pipeline.support);
    if set {
        // Even an empty well-formed list sets independent intent (M1).
        std::fs::write(
            reemission_list_path(&pipeline.support),
            "# installed empty list\n",
        )
        .unwrap();
        let installed = pipeline.cycle(t0 + 60);
        assert!(installed.result.is_ok(), "{:?}", installed.result);
        assert_eq!(
            load_backfill_state(&pipeline.support).claude_history_list_intent,
            ClaudeHistoryListIntent::Set
        );
        assert!(seen.exists());
        std::fs::remove_file(reemission_list_path(&pipeline.support)).unwrap();
        std::fs::remove_file(&seen).unwrap();
    }
    if malformed {
        let state_path = backfill_state_path(&pipeline.support);
        let mut saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        saved["claude_history_list_intent"] = serde_json::json!({"damaged": true});
        std::fs::write(state_path, serde_json::to_vec(&saved).unwrap()).unwrap();
        assert_eq!(
            load_backfill_state(&pipeline.support).claude_history_list_intent,
            ClaudeHistoryListIntent::Unreadable
        );
    }
    let index_path = claude_index_path(&pipeline.support);
    std::fs::write(&index_path, b"{not json").unwrap();
    assert!(!reemission_list_path(&pipeline.support).exists());
    assert!(!seen.exists());
    let (second, lines) = crate::local_resource_diagnostics::capture(|| {
        crate::snapshots::with_body_witness_adoption_page_budget(1, || pipeline.cycle(t0 + 120))
    });
    assert!(second.result.is_ok(), "{:?}", second.result);
    if set || malformed {
        assert_eq!(
            pipeline.server.offered().len(),
            initial,
            "no history body leaves after quarantine"
        );
        assert!(
            lines
                .iter()
                .any(|line| line["stage"] == "claude_reemission_list_missing_after_install"),
            "missing-list alarm: {lines:?}"
        );
        let third = pipeline.cycle(t0 + 180);
        assert!(third.result.is_ok(), "{:?}", third.result);
        assert_eq!(
            pipeline.server.offered().len(),
            initial,
            "hold survives real completion/marker clearing and reload"
        );
        assert_eq!(
            load_backfill_state(&pipeline.support).claude_history_list_intent,
            if set {
                ClaudeHistoryListIntent::Set
            } else {
                ClaudeHistoryListIntent::Unreadable
            }
        );
    } else {
        assert_eq!(
            pipeline.server.offered().len(),
            initial + 1,
            "positive Absent policy paces one history body"
        );
    }
    assert!(
        std::fs::read_dir(index_path.parent().unwrap())
            .unwrap()
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
        "index was quarantined"
    );
}

#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn first_nonempty_list_read_records_durable_intent_through_prepare_finish() {
    if !supported("first_nonempty_list_read_records_durable_intent_through_prepare_finish") {
        return;
    }
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("history-intent-first-list", Answer::Accept, t0);
    let snapshots = pipeline.support.join("snapshots");
    std::fs::create_dir_all(&snapshots).unwrap();
    std::fs::write(
        reemission_list_path(&pipeline.support),
        format!("{}\n", "a".repeat(64)),
    )
    .unwrap();
    assert_eq!(
        crate::backfill::load_backfill_state(&pipeline.support).claude_history_list_intent,
        crate::backfill::ClaudeHistoryListIntent::Absent
    );
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    assert_eq!(
        crate::backfill::load_backfill_state(&pipeline.support).claude_history_list_intent,
        crate::backfill::ClaudeHistoryListIntent::Set
    );
    assert!(crate::snapshots::claude_reemission_seen_marker_path(&pipeline.support).exists());
}

/// #705's returning tombstoned member remains held by #712 when its
/// pre-cutoff history belongs to a move without an explicit full claim.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn tombstoned_returning_history_obeys_the_move_hold() {
    if !supported("tombstoned_returning_history_obeys_the_move_hold") {
        return;
    }
    let root = IDENTITY_PIPELINE_ROOT;
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("patha-return-history-held", Answer::Accept, t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let key = first
        .index
        .files
        .keys()
        .find(|key| key.ends_with(&format!("{root}.jsonl")))
        .cloned()
        .expect("the root is indexed");
    let mut index = ScanIndex::load(&first.index_path).unwrap();
    index.tombstone_claude_family_for_test(root);
    index.save(&first.index_path).unwrap();
    let transcript = pipeline
        .fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{root}.jsonl"));
    let bytes = std::fs::read(&transcript).unwrap();
    std::fs::remove_file(&transcript).unwrap();
    let absent = pipeline.cycle(t0 + 600);
    assert!(absent.result.is_ok(), "{:?}", absent.result);
    assert!(!absent.index.files.contains_key(&key));
    assert!(absent.index.claude_family_tombstoned_for_test(root));
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&absent.index_path).unwrap()).unwrap();
    std::fs::write(&transcript, &bytes).unwrap();
    saved["claude_history_cutoff_unix_seconds"] = current_unix_seconds().into();
    saved["claude_history_move_not_full"] = true.into();
    std::fs::write(&absent.index_path, serde_json::to_vec(&saved).unwrap()).unwrap();
    assert!(!reemission_list_path(&pipeline.support).exists());
    let offered_before = pipeline.server.offered().len();

    // Healthy local proof may clear #705's tombstone, but cannot waive
    // #712's history hold or stamp the body as uploaded.
    let proved_return = pipeline.cycle(t0 + 1_200);
    assert!(proved_return.result.is_ok(), "{:?}", proved_return.result);
    assert_eq!(pipeline.server.offered().len(), offered_before);
    assert!(!proved_return.index.claude_family_tombstoned_for_test(root));
    assert_eq!(
        proved_return.index.files[&key].effective_upload_body_witness_revision,
        0
    );

    // Retire it again, then return without healthy proof. This is the
    // retained-tombstone case: the history hold and the authority debt both
    // stay owed. Keep all the original retention and wire assertions below.
    let mut index = ScanIndex::load(&proved_return.index_path).unwrap();
    index.tombstone_claude_family_for_test(root);
    index.save(&proved_return.index_path).unwrap();
    std::fs::remove_file(&transcript).unwrap();
    let absent_again = pipeline.cycle(t0 + 1_800);
    assert!(absent_again.result.is_ok(), "{:?}", absent_again.result);
    assert!(!absent_again.index.files.contains_key(&key));
    assert!(absent_again.index.claude_family_tombstoned_for_test(root));
    let api = pipeline
        .support
        .join("local-otel/claude-code-effort")
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    std::fs::write(api, b"{ malformed synthetic proof\n").unwrap();
    std::fs::write(&transcript, bytes).unwrap();
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&absent_again.index_path).unwrap()).unwrap();
    saved["claude_history_cutoff_unix_seconds"] = current_unix_seconds().into();
    std::fs::write(
        &absent_again.index_path,
        serde_json::to_vec(&saved).unwrap(),
    )
    .unwrap();
    let returned = pipeline.cycle(t0 + 2_400);
    assert!(returned.result.is_ok(), "{:?}", returned.result);
    assert_eq!(
        pipeline.server.offered().len(),
        offered_before,
        "history stays held"
    );
    assert!(returned.index.claude_family_tombstoned_for_test(root));
    assert_eq!(
        returned.index.files[&key].effective_upload_body_witness_revision,
        0
    );
}

/// COST (Round 16): a family whose tombstone was used and that then returns
/// goes back through the normal authority/proof path, through the real
/// prepare/finish pipeline and the server's offer recorder. The root is
/// accepted, retired with its tombstone and returns with the same bytes
/// while its local proof is unhealthy: it is read against the retained
/// witness (a bounded RetryPending record re-forms), never as a new file,
/// and nothing is offered. Once the evidence is healthy, its next changed
/// revision re-proves and its current body is offered exactly once: the old
/// body is never re-sent as new history, nothing is offered twice across
/// later cycles, and the root is never dropped (indexed, accepted, tombstone
/// cleared). #712's history hold over a returning member is
/// `tombstoned_returning_history_obeys_the_move_hold` above.
#[test]
#[serial]
#[serial(source_cadences)]
#[serial(client_report)]
fn returning_tombstoned_family_is_held_until_proof_then_reoffered_once() {
    if !supported("returning_tombstoned_family_is_held_until_proof_then_reoffered_once") {
        return;
    }
    let root = IDENTITY_PIPELINE_ROOT;
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("patha-return-reoffered-once", Answer::Accept, t0);
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let root_offers = |offered: &[serde_json::Value]| {
        offered
            .iter()
            .filter(|offer| offer["source_session_id"] == root)
            .map(fingerprint_of)
            .collect::<Vec<_>>()
    };
    let accepted = root_offers(&pipeline.server.offered());
    assert_eq!(accepted.len(), 1, "the root is offered once at first");
    let key = first
        .index
        .files
        .keys()
        .find(|key| key.ends_with(&format!("{root}.jsonl")))
        .cloned()
        .expect("the root is indexed");
    let witness = first
        .index
        .claude_usage_family_witness_digest_for_test(root)
        .expect("the proven root keeps a witness");

    // Retire the family: its tombstone stands while it is absent.
    let mut index = ScanIndex::load(&first.index_path).unwrap();
    index.tombstone_claude_family_for_test(root);
    index.save(&first.index_path).unwrap();
    let transcript = pipeline
        .fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{root}.jsonl"));
    let bytes = std::fs::read(&transcript).unwrap();
    std::fs::remove_file(&transcript).unwrap();
    let absent = pipeline.cycle(t0 + 600);
    assert!(absent.result.is_ok(), "{:?}", absent.result);
    assert!(!absent.index.files.contains_key(&key));
    assert!(absent.index.claude_family_tombstoned_for_test(root));
    assert!(!reemission_list_path(&pipeline.support).exists());
    let offered_before = pipeline.server.offered().len();

    // It returns with the same bytes while its proof is unhealthy: the
    // tombstone routes it to the authority path, held, nothing offered.
    let api = pipeline
        .support
        .join("local-otel/claude-code-effort")
        .join(format!("{:x}.jsonl", Sha256::digest(root.as_bytes())));
    std::fs::write(&api, b"{ malformed synthetic proof\n").unwrap();
    std::fs::write(&transcript, &bytes).unwrap();
    let returned = pipeline.cycle(t0 + 1_200);
    assert!(returned.result.is_ok(), "{:?}", returned.result);
    assert!(
        root_offers(&pipeline.server.offered()[offered_before..]).is_empty(),
        "nothing is offered before the proof"
    );
    let record = returned
        .index
        .claude_authority_record_for_test(root)
        .expect("the returning root re-forms its record, never a new file");
    assert!(record.bound_to_retained_witness && !record.terminal);
    assert_eq!(record.proven_witness_fingerprint, witness);
    assert_eq!(record.failed_reconstruction_count, 1);
    assert!(returned.index.claude_family_tombstoned_for_test(root));

    // Healthy evidence and a changed revision: it re-proves, and its current
    // body is offered once.
    let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(5))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let grown = serde_json::json!({"timestamp": at, "type": "assistant",
        "sessionId": root, "requestId": "req_3",
        "message": {"id": "m3", "model": "claude-haiku-4-5",
        "usage": {"input_tokens": 30, "output_tokens": 3}}});
    std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap()
        .write_all(format!("{grown}\n").as_bytes())
        .unwrap();
    write_native_bootstrap_sidecars(&pipeline.fixture, &pipeline.support);
    let proved = pipeline.cycle(t0 + 1_800);
    assert!(proved.result.is_ok(), "{:?}", proved.result);
    let later = pipeline.cycle(t0 + 2_400);
    assert!(later.result.is_ok(), "{:?}", later.result);
    let reoffered = root_offers(&pipeline.server.offered()[offered_before..]);
    assert_eq!(reoffered.len(), 1, "re-offered exactly once: {reoffered:?}");
    assert_ne!(
        reoffered[0], accepted[0],
        "the old body is never re-sent as new history"
    );
    assert!(later.index.files.contains_key(&key), "never dropped");
    assert!(later
        .index
        .accepted_snapshot_fingerprint_recorded(&reoffered[0]));
    assert!(later.index.claude_authority_record_for_test(root).is_none());
    assert!(!later.index.claude_family_tombstoned_for_test(root));
}
