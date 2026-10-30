// Reason-scoped daily re-offer through the real prepare/finish pipeline.
// One synthetic Claude session, a synthetic backend whose answer changes per
// cycle, and a test-thread wall clock for the local re-offer schedule only.
// Nothing waits 24 hours; no provider, credential or runtime state is read.
use super::*;
use std::cell::{Cell, RefCell};

const DAY: u64 = 86_400;
const ORIGINAL_PAIR: &str = "original_pair_candidate_unproved";

thread_local! {
    static CLOCK: Cell<Option<u64>> = const { Cell::new(None) };
    static EVIDENCE_STATS: RefCell<Option<ClaudeLocalEvidenceStats>> = const { RefCell::new(None) };
}

/// The synthetic local scheduling clock of this test thread, if set.
pub(crate) fn clock() -> Option<u64> {
    CLOCK.with(Cell::get)
}

/// Observe the same counts serialized on the Claude local-evidence line.
pub(crate) fn record_evidence_stats(stats: &ClaudeLocalEvidenceStats) {
    if clock().is_some() {
        EVIDENCE_STATS.with(|slot| slot.replace(Some(stats.clone())));
    }
}

/// The scanner uses a wall-clock second, independently of the scheduling
/// clock. Wait at most one second for a different census window before
/// re-reading a member whose request set changed.
fn wait_for_fresh_census_window(previous: &str) {
    let deadline = Instant::now() + Duration::from_secs(1);
    while current_rfc3339() == previous {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            !remaining.is_zero(),
            "the wall-clock census second must advance"
        );
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
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
    census_window_end: String,
    evidence_stats: Option<ClaudeLocalEvidenceStats>,
    leased_offers: usize,
    cache_enabled: bool,
    index: ScanIndex,
    progress: SnapshotUploadProgress,
    /// The saved upload ledger as JSON, to read the exact disk form.
    progress_json: serde_json::Value,
    progress_path: PathBuf,
    index_path: PathBuf,
    /// Distinct exact-body conflicts the scan's cooldown view deferred.
    cooldown_deferred: usize,
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
        self.cycle_with_census(now, true)
    }

    /// One real due cycle that starts with RetryPending authority debt: its
    /// scanner terminal withholds the ordinary census (path-(a) bridge), and
    /// the debt settles in finish.
    fn cycle_with_authority_debt(&mut self, now: u64) -> CycleResult {
        self.cycle_with_census(now, false)
    }

    fn cycle_with_census(&mut self, now: u64, complete: bool) -> CycleResult {
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
        assert_eq!(
            scan.census_complete, complete,
            "synthetic census is complete unless authority debt withholds it"
        );
        let census_window_end = preparation.scan_started_at.clone();
        EVIDENCE_STATS.with(|slot| slot.replace(None));
        let cooldown_deferred = index.reason_reoffer_cooldown_deferred_count();
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
            census_window_end,
            evidence_stats: EVIDENCE_STATS.with(|slot| slot.take()),
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
            cooldown_deferred,
        }
    }

    /// One real cycle and its physical transcript reads, from the existing
    /// per-page resource record: (parser/acquisition entries, native plus
    /// guard bytes read). `restart` first drops the daemon, as a restart
    /// does, so no retained reduction can hide a re-read.
    fn measured_cycle(&mut self, now: u64, restart: bool) -> (CycleResult, u64, u64) {
        if restart {
            self.daemon = test_daemon("otm_test");
        }
        let (cycle, records) = crate::local_resource_diagnostics::capture(|| self.cycle(now));
        let pages = records
            .iter()
            .filter(|record| {
                record["stage"] == "native_collection_page" && record["source"] == "claude_code"
            })
            .collect::<Vec<_>>();
        assert!(!pages.is_empty(), "the cycle completed a collection page");
        let parsed = pages
            .iter()
            .map(|page| page["counts"]["scanned_files"].as_u64().unwrap_or_default())
            .sum::<u64>();
        let bytes = pages
            .iter()
            .map(|page| {
                let read = &page["counts"]["sampled_acquisition"];
                read["completed_native_bytes"].as_u64().unwrap_or_default()
                    + read["completed_guard_bytes"].as_u64().unwrap_or_default()
            })
            .sum::<u64>();
        eprintln!(
            "O1_MEASURED_CYCLE now={now} restart={restart} parsed={parsed} bytes={bytes} \
             cooldown_deferred={}",
            cycle.cooldown_deferred
        );
        (cycle, parsed, bytes)
    }

    /// M1: deletes every durable warm-cache store under the support
    /// directory, so the next restart also loses the store and reads cold.
    fn drop_durable_stores(&self) {
        fn walk(dir: &std::path::Path) {
            for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if path.extension().is_some_and(|ext| ext == "durable-tail") {
                    std::fs::remove_dir_all(&path).unwrap();
                } else {
                    walk(&path);
                }
            }
        }
        walk(&self.support);
    }

    /// M1: this pipeline stands in for the daemon on its support directory,
    /// holding #801's single-writer lock there, so the post-save durable
    /// write runs.
    #[cfg(unix)]
    fn hold_state_dir_lock(&self) {
        crate::locked_state_dir::test_locks::hold(&self.support);
    }

    /// M1: durable warm-cache records on disk under the support directory.
    #[cfg(unix)]
    fn durable_records(&self) -> usize {
        fn walk(dir: &std::path::Path, inside: bool) -> usize {
            std::fs::read_dir(dir)
                .into_iter()
                .flatten()
                .flatten()
                .map(|entry| {
                    let path = entry.path();
                    if path.is_dir() {
                        let store = path.extension().is_some_and(|ext| ext == "durable-tail");
                        walk(&path, inside || store)
                    } else {
                        usize::from(inside && path.extension().is_some_and(|ext| ext == "rec"))
                    }
                })
                .sum()
        }
        walk(&self.support, false)
    }

    fn transcript(&self) -> PathBuf {
        self.fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
    }

    /// The conflict's ordinary retry is due now on the durable index.
    fn make_conflict_retry_due(&self, fingerprint: &str) {
        let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&self.support, SnapshotSource::ClaudeCode),
            &snapshot_upload_destination_namespace(&self.device, "device-secret"),
        ));
        let mut index = ScanIndex::load(&index_path).unwrap();
        let record = index
            .quarantined_snapshot_fingerprints
            .get_mut(fingerprint)
            .unwrap();
        assert_eq!(
            record.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        record.retry_after_unix_seconds = 0;
        index.save(&index_path).unwrap();
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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
        quiet.result.is_ok(),
        "a quiet traversal may settle exactly bound cooldown debt"
    );
    assert_eq!(
        quiet.index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert_eq!(
        quiet.progress.quarantined_fingerprints[&fingerprint].disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    assert!(!quiet.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(quiet.cooldown_deferred, 1);
    assert_eq!(
        pipeline.server.last_terminal()["last_error_code"],
        "backend_validation_error"
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn late_api_row_tags_the_reoffered_body_once_the_pair_is_proven() {
    // R2-N2: gate on, conflicting org markers go to the starting account; the login is dropped.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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

/// The refusal, a conflict on its due daily offer, and the conflict's
/// ordinary retry made due: the state whose quiet cycles re-read the file.
fn refused_then_conflicted(name: &str) -> (ReofferPipeline, String, u64, serde_json::Value) {
    refused_then_conflicted_holding(name, false)
}

/// `refused_then_conflicted`, optionally holding the state-directory lock
/// from the first cycle on (M1).
fn refused_then_conflicted_holding(
    name: &str,
    locked: bool,
) -> (ReofferPipeline, String, u64, serde_json::Value) {
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new(name, Answer::Refuse(ORIGINAL_PAIR), t0);
    #[cfg(unix)]
    if locked {
        pipeline.hold_state_dir_lock();
    }
    #[cfg(not(unix))]
    let _ = locked;
    let first = pipeline.cycle(t0);
    assert!(first.result.is_ok(), "{:?}", first.result);
    let fingerprint = fingerprint_of(&pipeline.server.offered()[0]);
    pipeline.server.answer(Answer::Conflict);
    let t1 = t0 + DAY + 60;
    let day1 = pipeline.cycle(t1);
    assert!(day1.result.is_err(), "a conflict still owes a follow-up");
    assert_eq!(pipeline.server.offered().len(), 2);
    let deadline = reoffer_json(&day1, &fingerprint)["retry_after_unix_seconds"].clone();
    assert!(
        deadline.as_u64().is_some_and(|due| due >= t1 + DAY),
        "{}",
        day1.progress_json
    );
    pipeline.make_conflict_retry_due(&fingerprint);
    pipeline.server.answer(Answer::Accept);
    (pipeline, fingerprint, t1, deadline)
}

/// M1 through the real sync caller, both ways. Without the daemon's
/// single-writer lock (#801) on the support directory the post-save write
/// writes nothing, and the due-day restart reads the file cold. Holding it,
/// the earlier cycles write the retained copy after their saves, and the
/// same restart restores it instead of re-reading the transcript. Either way
/// the due day offers the same exact body once.
#[cfg(unix)]
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn durable_store_is_written_only_under_the_state_dir_lock() {
    if !supported("durable_store_is_written_only_under_the_state_dir_lock") {
        return;
    }
    for locked in [false, true] {
        let name = if locked {
            "durable-locked"
        } else {
            "durable-unlocked"
        };
        let (mut pipeline, fingerprint, _, deadline) =
            refused_then_conflicted_holding(name, locked);
        let size = std::fs::metadata(pipeline.transcript()).unwrap().len();
        let records = pipeline.durable_records();
        let due = deadline.as_u64().unwrap() + 60;
        let (day2, _, bytes) = pipeline.measured_cycle(due, true);
        assert!(day2.result.is_ok(), "{name}: {:?}", day2.result);
        assert_eq!(day2.leased_offers, 1, "{name}");
        let offered = pipeline.server.offered();
        assert_eq!(offered.len(), 3, "{name}: one offer at the due time");
        assert_eq!(fingerprint_of(&offered[2]), fingerprint, "{name}");
        if locked {
            assert!(records > 0, "{name}: written after the save");
            assert!(bytes < size, "{name}: restored, {bytes} >= {size}");
        } else {
            assert_eq!(records, 0, "{name}: nothing written without the lock");
            assert!(bytes >= size, "{name}: a cold re-read: {bytes} < {size}");
        }
    }
}

/// E1 margin receipt for the scan workers' stack. The real prepare,
/// rotation and finish cycle (a full scan, then a restart that restores the
/// durable copy) completes in the optimized build on a thread with the
/// 2 MiB spawn default, so the workers' larger explicit stack is headroom.
/// An overflow aborts the test process. Release only: the debug build's
/// frames are far larger. Run by the dispatch-only `scan-stack-margin` job
/// in `.github/workflows/ci.yml`.
#[cfg(unix)]
#[test]
#[ignore = "release-mode receipt; run by the ci.yml scan-stack-margin dispatch"]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn scan_worker_stack_margin_receipt() {
    const STACK_BYTES: usize = 2 * 1024 * 1024;
    if cfg!(debug_assertions) {
        panic!("the margin receipt measures the release build: run with --release");
    }
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "the durable restore needs a supported layout"
    );
    let (transcript, restored) = std::thread::Builder::new()
        .name("ottto-snapshot-sync".to_string())
        .stack_size(STACK_BYTES)
        .spawn(|| {
            let (mut pipeline, _, _, deadline) =
                refused_then_conflicted_holding("stack-margin", true);
            let size = std::fs::metadata(pipeline.transcript()).unwrap().len();
            assert!(pipeline.durable_records() > 0, "written after the save");
            let due = deadline.as_u64().unwrap() + 60;
            let (day2, _, bytes) = pipeline.measured_cycle(due, true);
            assert!(day2.result.is_ok(), "{:?}", day2.result);
            assert_eq!(day2.leased_offers, 1);
            assert!(bytes < size, "restored, {bytes} >= {size}");
            (size, bytes)
        })
        .unwrap()
        .join()
        .unwrap();
    eprintln!(
        "SCAN_STACK_MARGIN_RECEIPT stack_bytes={STACK_BYTES} profile=release cycles=3 \
         restart_restored=true transcript_bytes={transcript} restored_cycle_bytes={restored}"
    );
}

/// O1: quiet cycles before the reserved daily re-offer re-read
/// nothing for an unchanged file whose only selection is its already
/// refused exact body, across a restart that rebuilds the runtime view.
/// The refusal, conflict and deadline stay disclosed while the quiet traversal
/// settles. At the due time: one re-read and one offer.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn cooldown_conflict_quiet_cycles_skip_the_reparse_until_the_daily_offer() {
    if !supported("cooldown_conflict_quiet_cycles_skip_the_reparse_until_the_daily_offer") {
        return;
    }
    let (mut pipeline, fingerprint, t1, deadline) = refused_then_conflicted("reoffer-cooldown-io");
    let size = std::fs::metadata(pipeline.transcript()).unwrap().len();
    assert!(size > 0);
    for (now, restart) in [
        (t1 + 3_600, false),
        (t1 + 7_200, true),
        (t1 + 13 * 3_600, true),
        (t1 + DAY - 1, true),
    ] {
        // Each traversal finds the conflict's ordinary timer due again, as
        // every eligible traversal did for ~12-18 h of the cooldown.
        pipeline.make_conflict_retry_due(&fingerprint);
        let (quiet, parsed, bytes) = pipeline.measured_cycle(now, restart);
        assert_eq!(parsed, 0, "no reason-driven re-read at +{}s", now - t1);
        assert_eq!(bytes, 0, "no transcript bytes at +{}s", now - t1);
        assert_eq!(pipeline.server.offered().len(), 2, "no POST before the day");
        assert_eq!(quiet.leased_offers, 0);
        assert_eq!(quiet.cooldown_deferred, 1, "counted once per entity");
        // Only the normal clean-traversal boundary settles the cooldown debt.
        assert!(quiet.result.is_ok(), "{:?}", quiet.result);
        assert!(!quiet.index.bounded_sweep_had_unsettled_upload());
        assert_eq!(
            pipeline.server.last_terminal()["last_error_code"],
            "backend_validation_error"
        );
        assert_eq!(
            pipeline.server.last_terminal()["last_census_complete"],
            true
        );
        assert!(
            pipeline.server.last_terminal()["last_success_at"].is_null(),
            "transport settlement cannot advertise money completeness"
        );
        assert!(!quiet
            .index
            .accepted_snapshot_fingerprint_recorded(&fingerprint));
        assert!(!quiet.progress.accepted_fingerprints.contains(&fingerprint));
        assert!(quiet.progress.contains_body(
            &fingerprint,
            &quiet.progress.permanent_rejections[&fingerprint].body_witness
        ));
        assert_eq!(
            quiet.index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert_eq!(
            quiet.progress.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert_eq!(
            reoffer_json(&quiet, &fingerprint)["retry_after_unix_seconds"],
            deadline
        );
    }

    // The reserved day arrives: exactly one re-read and one offer. With the
    // M1 durable warm cache a restart would restore this file and read no
    // bytes; this cycle measures the cold reconstruction, so the restart
    // also loses the store.
    let due = deadline.as_u64().unwrap() + 60;
    pipeline.drop_durable_stores();
    let (day2, parsed, bytes) = pipeline.measured_cycle(due, true);
    assert_eq!(day2.leased_offers, 1);
    assert_eq!(parsed, 1, "one reconstruction at the due time");
    assert!(bytes >= size, "a real full re-read: {bytes} < {size}");
    assert!(day2.result.is_ok(), "{:?}", day2.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 3, "one offer at the due time");
    assert_eq!(fingerprint_of(&offered[2]), fingerprint);
    assert_eq!(day2.cooldown_deferred, 0);
    assert!(!day2
        .progress
        .permanent_rejections
        .contains_key(&fingerprint));
    assert!(day2
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint));
}

/// SOURCE B1: the cooldown test's twin with the durable store present.
/// Both arms hold the state-directory lock, so their earlier cycles write
/// the retained copy; the cold arm then drops the store, the warm arm keeps
/// it. Across restarts that could restore the file, the quiet cycles still
/// skip it; the daily re-offer still fires at the due time; and the warm
/// arm's re-offer outcome equals the cold arm's. A restore never suppresses
/// or postpones a due re-offer.
#[cfg(unix)]
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn cooldown_reoffer_is_neither_suppressed_nor_postponed_by_a_durable_restore() {
    if !supported("cooldown_reoffer_is_neither_suppressed_nor_postponed_by_a_durable_restore") {
        return;
    }
    let mut outcomes = Vec::new();
    for warm in [false, true] {
        let name = if warm {
            "reoffer-cooldown-warm"
        } else {
            "reoffer-cooldown-cold"
        };
        let (mut pipeline, fingerprint, t1, deadline) = refused_then_conflicted_holding(name, true);
        let size = std::fs::metadata(pipeline.transcript()).unwrap().len();
        assert!(
            pipeline.durable_records() > 0,
            "{name}: written after the save"
        );
        for (now, restart) in [
            (t1 + 3_600, false),
            (t1 + 7_200, true),
            (t1 + 13 * 3_600, true),
            (t1 + DAY - 1, true),
        ] {
            pipeline.make_conflict_retry_due(&fingerprint);
            let (quiet, parsed, bytes) = pipeline.measured_cycle(now, restart);
            let at = now - t1;
            assert_eq!((parsed, bytes), (0, 0), "{name}: no re-read at +{at}s");
            assert_eq!(quiet.leased_offers, 0, "{name}: +{at}s");
            assert_eq!(quiet.cooldown_deferred, 1, "{name}: +{at}s");
            assert!(quiet.result.is_ok(), "{name}: {:?}", quiet.result);
            assert_eq!(
                pipeline.server.offered().len(),
                2,
                "{name}: no POST before the day"
            );
            assert_eq!(
                reoffer_json(&quiet, &fingerprint)["retry_after_unix_seconds"],
                deadline,
                "{name}: +{at}s"
            );
        }
        if !warm {
            pipeline.drop_durable_stores();
        }
        let due = deadline.as_u64().unwrap() + 60;
        let (day2, _, bytes) = pipeline.measured_cycle(due, true);
        if warm {
            assert!(bytes < size, "{name}: restored, {bytes} >= {size}");
        } else {
            assert!(bytes >= size, "{name}: a cold re-read: {bytes} < {size}");
        }
        let offered = pipeline.server.offered();
        outcomes.push((
            day2.result.is_ok(),
            day2.leased_offers,
            offered.len(),
            offered.last().map(fingerprint_of) == Some(fingerprint.clone()),
            day2.cooldown_deferred,
            day2.progress
                .permanent_rejections
                .contains_key(&fingerprint),
            day2.index
                .accepted_snapshot_fingerprint_recorded(&fingerprint),
        ));
    }
    assert_eq!(
        outcomes[1], outcomes[0],
        "warm re-offer equals the cold arm"
    );
    assert_eq!(outcomes[1], (true, 1, 3, true, 0, false, true));
}

/// O1 controls: a file that changes during the cooldown is re-read and its
/// new body offered normally; an injected clock rollback re-clamps the
/// reservation and still re-reads nothing for the unchanged file.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn cooldown_conflict_still_rereads_a_changed_file_and_survives_rollback() {
    if !supported("cooldown_conflict_still_rereads_a_changed_file_and_survives_rollback") {
        return;
    }
    let (mut pipeline, fingerprint, t1, _) = refused_then_conflicted("reoffer-cooldown-change");

    // F2: the local clock rolls back an hour, past the tolerance. The
    // reservation is re-clamped from the prepared ledger (still after the
    // next cycle below), and the unchanged file is still not re-read.
    let rolled_back = t1 - 3_600;
    let (rollback, parsed, bytes) = pipeline.measured_cycle(rolled_back, true);
    assert_eq!((parsed, bytes), (0, 0));
    assert_eq!(pipeline.server.offered().len(), 2);
    assert_eq!(rollback.cooldown_deferred, 1);
    assert!(rollback.result.is_ok(), "{:?}", rollback.result);
    assert!(!rollback.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(
        reoffer_json(&rollback, &fingerprint)["retry_after_unix_seconds"],
        rolled_back + DAY
    );

    // The session grows before the daily offer: the file is re-read and its
    // new body goes through the normal path.
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
        .open(pipeline.transcript())
        .unwrap()
        .write_all(format!("{grown}\n").as_bytes())
        .unwrap();
    write_native_bootstrap_sidecars(&pipeline.fixture, &pipeline.support);
    let (changed, parsed, bytes) = pipeline.measured_cycle(t1 + 3_600, true);
    assert_eq!(parsed, 1, "a changed file re-parses normally");
    assert!(bytes > 0);
    assert!(changed.result.is_ok(), "{:?}", changed.result);
    let offered = pipeline.server.offered();
    assert_eq!(offered.len(), 3, "the new body is offered");
    assert_ne!(fingerprint_of(&offered[2]), fingerprint);
    assert!(changed
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint_of(&offered[2])));
}

/// A previously settled cooldown is no permission once its current witness or
/// durable reservation is lost. The retained conflict blocks immediately.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn cooldown_conflict_broken_bound_blocks_again() {
    if !supported("cooldown_conflict_broken_bound_blocks_again") {
        return;
    }
    for broken in ["witness", "reservation", "file"] {
        let (mut pipeline, fingerprint, t1, _) =
            refused_then_conflicted(&format!("reoffer-broken-{broken}"));
        let quiet = pipeline.cycle(t1 + 3_600);
        assert!(quiet.result.is_ok(), "{broken}: {:?}", quiet.result);
        assert!(!quiet.index.bounded_sweep_had_unsettled_upload());
        assert_eq!(quiet.cooldown_deferred, 1);
        pipeline.make_conflict_retry_due(&fingerprint);
        match broken {
            "witness" => {
                let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
                    &snapshot_index_path(&pipeline.support, SnapshotSource::ClaudeCode),
                    &snapshot_upload_destination_namespace(&pipeline.device, "device-secret"),
                ));
                let mut index = ScanIndex::load(&index_path).unwrap();
                index
                    .quarantined_snapshot_fingerprints
                    .get_mut(&fingerprint)
                    .unwrap()
                    .witness
                    .parser_version
                    .push_str("-older");
                index.save(&index_path).unwrap();
            }
            "reservation" => {
                let mut json = quiet.progress_json.clone();
                json["permanent_rejections"][&fingerprint]["reoffer"] =
                    serde_json::json!({"version": 999, "reason": "corrupt"});
                std::fs::write(&quiet.progress_path, serde_json::to_vec(&json).unwrap()).unwrap();
            }
            "file" => {
                // A byte change without changing semantic usage still invalidates
                // the unchanged-file proof; it cannot erase the retained debt.
                // Keep every line valid JSON for the sidecar fixture reader:
                // trailing whitespace changes bytes, not the decoded event.
                let transcript = std::fs::read_to_string(pipeline.transcript()).unwrap();
                let edited = transcript.replacen('\n', " \n", 1);
                assert_ne!(edited.len(), transcript.len());
                std::fs::write(pipeline.transcript(), edited).unwrap();
                write_native_bootstrap_sidecars(&pipeline.fixture, &pipeline.support);
            }
            _ => unreachable!(),
        }
        let (broken_cycle, parsed, _) = pipeline.measured_cycle(t1 + 7_200, true);
        assert_eq!(parsed, 1, "{broken}: ordinary invalidation reconstructs");
        assert!(
            broken_cycle.result.is_err(),
            "{broken}: retained debt blocks again"
        );
        assert!(
            broken_cycle.index.bounded_sweep_had_unsettled_upload(),
            "{broken}"
        );
        assert_eq!(broken_cycle.cooldown_deferred, 0, "{broken}");
        assert_eq!(
            pipeline.server.last_terminal()["last_error_code"],
            "server_error",
            "{broken}"
        );
        assert_eq!(
            pipeline.server.offered().len(),
            2,
            "{broken}: no early offer"
        );
        assert_eq!(
            broken_cycle.index.quarantined_snapshot_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert_eq!(
            broken_cycle.progress.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert!(broken_cycle
            .progress
            .permanent_rejections
            .contains_key(&fingerprint));
    }
}

/// The quiet-debt disclosure/settlement applies throughout the cooldown, not
/// only after the ordinary conflict timer would have selected the file.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn cooldown_conflict_before_ordinary_retry_is_counted_and_settles() {
    if !supported("cooldown_conflict_before_ordinary_retry_is_counted_and_settles") {
        return;
    }
    let (mut pipeline, fingerprint, t1, deadline) = refused_then_conflicted("reoffer-before-retry");
    let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
        &snapshot_index_path(&pipeline.support, SnapshotSource::ClaudeCode),
        &snapshot_upload_destination_namespace(&pipeline.device, "device-secret"),
    ));
    let mut index = ScanIndex::load(&index_path).unwrap();
    // The ordinary timer uses wall time; keep it inside the loader's 12 h
    // validity bound so normalization cannot silently make this a due test.
    let retry_after = current_unix_seconds() + 3_600;
    index
        .quarantined_snapshot_fingerprints
        .get_mut(&fingerprint)
        .unwrap()
        .retry_after_unix_seconds = retry_after;
    index.save(&index_path).unwrap();
    let loaded = ScanIndex::load(&index_path).unwrap();
    assert_eq!(
        loaded.quarantined_snapshot_fingerprints[&fingerprint].retry_after_unix_seconds,
        retry_after
    );
    assert!(
        retry_after > current_unix_seconds(),
        "ordinary retry is not due"
    );
    let (quiet, parsed, bytes) = pipeline.measured_cycle(t1 + 600, true);
    assert_eq!((parsed, bytes), (0, 0));
    assert!(quiet.result.is_ok(), "{:?}", quiet.result);
    assert!(!quiet.index.bounded_sweep_had_unsettled_upload());
    assert_eq!(quiet.cooldown_deferred, 1);
    assert_eq!(quiet.leased_offers, 0);
    assert_eq!(pipeline.server.offered().len(), 2);
    assert_eq!(
        pipeline.server.last_terminal()["last_error_code"],
        "backend_validation_error"
    );
    assert_eq!(
        pipeline.server.last_terminal()["last_census_complete"],
        true
    );
    assert_eq!(
        reoffer_json(&quiet, &fingerprint)["retry_after_unix_seconds"],
        deadline
    );
    for record in [
        &quiet.index.quarantined_snapshot_fingerprints[&fingerprint],
        &quiet.progress.quarantined_fingerprints[&fingerprint],
    ] {
        assert_eq!(
            record.disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        assert_eq!(
            record.upload_body_witness.as_deref(),
            Some(
                quiet.progress.permanent_rejections[&fingerprint]
                    .body_witness
                    .as_str()
            )
        );
    }
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn durable_list_intent_holds_quarantined_history_without_list_or_seen() {
    if !supported("durable_list_intent_holds_quarantined_history_without_list_or_seen") {
        return;
    }
    lost_list_intent_pipeline("history-intent-set", true, false);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn absent_list_intent_paces_quarantined_history() {
    if !supported("absent_list_intent_paces_quarantined_history") {
        return;
    }
    lost_list_intent_pipeline("history-intent-absent", false, false);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
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
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn tombstoned_returning_history_obeys_the_move_hold() {
    // Tombstone hold until reported proof is gate-off policy; an E2 body replaces its session.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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
/// revision (a note, so the request set still matches the witness)
/// re-proves and its body is offered exactly once with the same usage: never
/// added again as new history, nothing offered twice across later cycles,
/// and the root is never dropped (indexed, accepted, tombstone cleared).
/// #712's history hold over a returning member is
/// `tombstoned_returning_history_obeys_the_move_hold` above.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn returning_tombstoned_family_is_held_until_proof_then_reoffered_once() {
    // Tombstone hold until reported proof is gate-off policy; an E2 body replaces its session.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
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

    // Healthy evidence and a changed revision that adds no request: the
    // retained witness reconstructs, and its body is offered once.
    let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(5))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    let note = serde_json::json!({"timestamp": at, "type": "user", "sessionId": root,
        "message": {"role": "user", "content": "synthetic note"}});
    std::fs::OpenOptions::new()
        .append(true)
        .open(&transcript)
        .unwrap()
        .write_all(format!("{note}\n").as_bytes())
        .unwrap();
    write_native_bootstrap_sidecars(&pipeline.fixture, &pipeline.support);
    // It starts with the RetryPending record, which withholds this scan's
    // census; the next cycle, with the debt settled, completes it again.
    let proved = pipeline.cycle_with_authority_debt(t0 + 1_800);
    assert!(proved.result.is_ok(), "{:?}", proved.result);
    let later = pipeline.cycle(t0 + 2_400);
    assert!(later.result.is_ok(), "{:?}", later.result);
    let offered = pipeline.server.offered();
    let reoffered = root_offers(&offered[offered_before..]);
    assert_eq!(reoffered.len(), 1, "re-offered exactly once: {reoffered:?}");
    let body = |fingerprint: &str| {
        offered
            .iter()
            .find(|offer| fingerprint_of(offer) == fingerprint)
            .unwrap()
    };
    assert_eq!(
        usage_of(body(&reoffered[0])),
        usage_of(body(&accepted[0])),
        "the same usage, never added again as new history"
    );
    assert!(later.index.files.contains_key(&key), "never dropped");
    assert!(later
        .index
        .accepted_snapshot_fingerprint_recorded(&reoffered[0]));
    assert!(later.index.claude_authority_record_for_test(root).is_none());
    assert!(!later.index.claude_family_tombstoned_for_test(root));
}

/// A returning family that grew needs one cumulative replacement body.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn returning_tombstoned_family_that_grew_reproves_in_a_fresh_window() {
    // Tombstone hold until reported proof is gate-off policy; an E2 body replaces its session.
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    if !supported("returning_tombstoned_family_that_grew_reproves_in_a_fresh_window") {
        return;
    }
    let root = IDENTITY_PIPELINE_ROOT;
    let t0 = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new("patha-grown-return-fresh-window", Answer::Accept, t0);
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

    assert_eq!(
        returned
            .evidence_stats
            .as_ref()
            .expect("Claude evidence fold")
            .first_proof_hold
            .census_withheld_retry_pending_family_count,
        1,
        "the existing census counter exposes the held RetryPending family"
    );

    assert_eq!(
        returned
            .evidence_stats
            .as_ref()
            .unwrap()
            .returning_family_grown_held,
        1
    );

    // Growth needs a new witness. Keep exact reconstruction unchanged and
    // let the native terminal re-prove in a new wall-clock census window.
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
    // Still-unhealthy evidence holds the genuinely grown returning family.
    // The dedicated census-line value must expose it while other pending
    // causes remain in the existing aggregate counter.
    wait_for_fresh_census_window(&returned.census_window_end);
    let grown_held = pipeline.cycle_with_authority_debt(t0 + 1_500);
    assert!(grown_held.result.is_ok(), "{:?}", grown_held.result);
    assert_ne!(grown_held.census_window_end, returned.census_window_end);
    let held_stats = grown_held
        .evidence_stats
        .as_ref()
        .expect("Claude evidence fold");
    assert_eq!(held_stats.returning_family_grown_held, 1);
    assert_eq!(
        held_stats
            .duplicate_census
            .page_invalidated_member_changed_count,
        0
    );
    assert_eq!(
        held_stats
            .first_proof_hold
            .census_withheld_retry_pending_family_count,
        1
    );
    assert!(grown_held
        .index
        .claude_authority_record_for_test(root)
        .is_some());
    assert!(grown_held.index.claude_family_tombstoned_for_test(root));
    assert!(root_offers(&pipeline.server.offered()[offered_before..]).is_empty());
    write_native_bootstrap_sidecars(&pipeline.fixture, &pipeline.support);
    // It starts with the RetryPending record, which withholds this scan's
    // census; the next cycle, with the debt settled, completes it again.
    wait_for_fresh_census_window(&grown_held.census_window_end);
    let proved = pipeline.cycle_with_authority_debt(t0 + 1_800);
    assert!(proved.result.is_ok(), "{:?}", proved.result);
    assert_ne!(proved.census_window_end, returned.census_window_end);
    assert_ne!(proved.census_window_end, grown_held.census_window_end);
    assert_eq!(
        proved
            .evidence_stats
            .as_ref()
            .unwrap()
            .returning_family_grown_held,
        0
    );
    assert_eq!(
        proved
            .evidence_stats
            .as_ref()
            .expect("Claude evidence fold")
            .duplicate_census
            .page_invalidated_member_changed_count,
        0
    );
    assert_eq!(
        proved
            .evidence_stats
            .as_ref()
            .expect("Claude evidence fold")
            .first_proof_hold
            .census_withheld_retry_pending_family_count,
        0
    );
    let later = pipeline.cycle(t0 + 2_400);
    assert!(later.result.is_ok(), "{:?}", later.result);
    let offered = pipeline.server.offered();
    let reoffered = root_offers(&offered[offered_before..]);
    assert_eq!(reoffered.len(), 1, "re-offered exactly once: {reoffered:?}");
    let body = |fingerprint: &str| {
        offered
            .iter()
            .find(|offer| fingerprint_of(offer) == fingerprint)
            .unwrap()
    };
    assert_ne!(reoffered[0], accepted[0], "growth creates a new body B1");
    let baseline = usage_of(body(&accepted[0]));
    assert_eq!(
        usage_of(body(&reoffered[0])),
        (baseline.0 + 1, baseline.1 + 30, baseline.2 + 3),
        "B1 is cumulative B0 plus req_3, superseding B0 rather than adding it again"
    );
    assert!(later.index.files.contains_key(&key), "never dropped");
    assert!(later
        .index
        .accepted_snapshot_fingerprint_recorded(&reoffered[0]));
    assert!(later.index.claude_authority_record_for_test(root).is_none());
    assert!(!later.index.claude_family_tombstoned_for_test(root));
    let once_more = pipeline.cycle(t0 + 3_000);
    assert!(once_more.result.is_ok(), "{:?}", once_more.result);
    assert_eq!(
        root_offers(&pipeline.server.offered()[offered_before..]),
        reoffered,
        "the accepted cumulative head is not offered again"
    );
}


/// Real prepare/finish, HTTP validation, upload ledger, selected save and load.
/// No layout/cache gate: the native acquisition may use its ordinary fallback.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn desktop_identity_real_sync_rejected_body_stays_pending_exact_acked_retry_settles() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::off();
    let _manifests = SourceManifestTestGuard::new();
    let start = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new(
        "desktop-identity-exact-ack",
        Answer::Refuse(ORIGINAL_PAIR),
        start,
    );
    let store = pipeline
        .fixture
        .home
        .join("Library/Application Support/Claude/claude-code-sessions")
        .join("123e4567-e89b-12d3-a456-426614174000")
        .join(IDENTITY_PIPELINE_ORG);
    std::fs::create_dir_all(&store).unwrap();
    let created = (OffsetDateTime::now_utc() - TimeDuration::days(1))
        .format(&Rfc3339)
        .unwrap();
    std::fs::write(store.join("child.json"), serde_json::json!({
        "cliSessionId": IDENTITY_PIPELINE_ROOT, "sessionId": "local_child", "createdAt": created,
        "title": "synthetic child", "titleSource": "user"
    }).to_string()).unwrap();
    let key = pipeline.transcript().to_string_lossy().to_string();
    let refused = pipeline.cycle(start);
    refused.result.unwrap(); // Validated permanent refusal settles transport only.
    let offered = pipeline.server.offered.lock().unwrap().clone();
    assert_eq!(offered.len(), 1, "the real upload was attempted");
    assert_eq!(
        offered[0]["session_account_evidence"]["identity_disposition"],
        "complete"
    );
    assert!(offered[0]["session_account_evidence"]["account_identifier_hash"].is_string());
    assert_eq!(
        serde_json::to_value(&refused.index).unwrap()["claude_desktop_identity_latches"][&key],
        "identity_pending",
        "natural completion has no ACK"
    );
    let fingerprint = fingerprint_of(&offered[0]);
    assert!(!refused
        .progress
        .accepted_body_witnesses
        .contains_key(&fingerprint));
    let refused_witness = refused.progress.permanent_rejections[&fingerprint]
        .body_witness
        .clone();
    // Use the EXISTING reason-scoped daily retry, without changing source bytes,
    // receipt state or identity selection history. It precedes identity deferral.
    *pipeline.server.answer.lock().unwrap() = Answer::Accept;
    let acked = pipeline.cycle(start + DAY);
    acked.result.unwrap();
    assert_eq!(
        acked.leased_offers, 1,
        "ordinary reason-scoped retry was earned"
    );
    let offered = pipeline.server.offered.lock().unwrap();
    assert_eq!(
        offered.len(),
        2,
        "retry reached HTTP rather than a synthetic ack helper"
    );
    assert_eq!(fingerprint_of(&offered[1]), fingerprint);
    assert_eq!(
        offered[1]["session_account_evidence"],
        offered[0]["session_account_evidence"]
    );
    assert_eq!(
        entity_ack(&offered[1])["body_witness_digest"],
        refused_witness,
        "the backend ACK independently hashes the exact retried body",
    );
    // Successful save transfers the exact ACK into file custody and retires
    // it from the upload ledger. Verify that transfer, not stale ledger RAM.
    assert!(
        acked
            .index
            .adopted_upload_progress_acks(&BTreeMap::from([(
                fingerprint.clone(),
                refused_witness.clone()
            ),]))
            .contains(&fingerprint),
        "saved file custody adopts these exact ACK bytes"
    );
    assert!(!acked
        .progress
        .permanent_rejections
        .contains_key(&fingerprint));
    assert_eq!(
        serde_json::to_value(&acked.index).unwrap()["claude_desktop_identity_latches"][&key],
        "settled",
        "the real sync settlement hook promoted before the selected save"
    );
}
