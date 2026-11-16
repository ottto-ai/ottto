// Owns synthetic homes, the script and gate observations for the count-once oracle.
// Uses real preparation, owned scan steps, finish, upload, and checkpoint reload.
// Every expected decision is hand-written; server placement replaces, never adds.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{self as transition, with_scan_clock};
use crate::test_effects::{self, Handle, Recording, Scalar};
use serde_json::{json, Value};
use std::cell::RefCell;

const AT: &str = "2026-11-01T10:00:00Z";
const NOW: u64 = 1_793_527_200;

thread_local! {
    static FINALIZED: RefCell<Option<Vec<SnapshotItem>>> = const { RefCell::new(None) };
}

pub(super) fn observe_finalized_items(items: &[SnapshotItem]) {
    FINALIZED.with(|slot| {
        if let Some(captured) = slot.borrow_mut().as_mut() {
            for item in items {
                test_effects::record(
                    "finalized",
                    vec![
                        ("entity", Scalar::Text(item.snapshot_fingerprint.clone())),
                        ("witness", Scalar::Text(snapshot_upload_body_witness(item))),
                    ],
                );
                captured.push(item.clone());
            }
        }
    });
}

struct FinalizedCapture;
impl FinalizedCapture {
    fn start() -> Self {
        FINALIZED.with(|slot| assert!(slot.replace(Some(Vec::new())).is_none()));
        Self
    }
    fn take(&self) -> Vec<SnapshotItem> {
        FINALIZED.with(|slot| std::mem::take(slot.borrow_mut().as_mut().unwrap()))
    }
}
impl Drop for FinalizedCapture {
    fn drop(&mut self) {
        FINALIZED.with(|slot| {
            slot.take();
        });
    }
}

#[derive(Clone, Copy, Debug)]
enum Answer {
    Accept,
    Unstored,
    Refuse(&'static str),
    Conflict,
    LostAck,
    Dropped,
    Shed,
}

fn exact_ack(item: &Value) -> Value {
    let exclusive = item["usage_accounting_contract"] == "session_exclusive_reported_usage:v1";
    let version = item
        .get("session_account_evidence")
        .is_some()
        .then_some(if exclusive { 8u64 } else { 7u64 });
    json!({"source_session_id":item["source_session_id"],
        "snapshot_fingerprint":item["snapshot_fingerprint"],"occurrence_count":1,
        "body_witness_version":version,
        "body_witness_digest":version.map(|_| finish_wire_body_witness(item))})
}

struct OracleServer {
    url: String,
    stop: Arc<std::sync::atomic::AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    script: Arc<Mutex<VecDeque<Vec<Answer>>>>,
    fallback: Arc<Mutex<Answer>>,
    batches: Arc<Mutex<Vec<Vec<u8>>>>,
    placement: Arc<Mutex<BTreeMap<String, Value>>>,
}
impl OracleServer {
    fn new(source: SnapshotSource, handle: Handle) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let script = Arc::new(Mutex::new(VecDeque::<Vec<Answer>>::new()));
        let script_worker = script.clone();
        let fallback = Arc::new(Mutex::new(Answer::Accept));
        let fallback_worker = fallback.clone();
        let batches = Arc::new(Mutex::new(Vec::new()));
        let batches_worker = batches.clone();
        let placement = Arc::new(Mutex::new(BTreeMap::new()));
        let placed = placement.clone();
        let worker = std::thread::spawn(move || {
            let _entered = handle.enter();
            while !done.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("synthetic oracle accept: {error}"),
                };
                stream.set_nonblocking(false).unwrap();
                let request = read_complete_http_request(&mut stream);
                assert!(http_request_complete(request.as_bytes()));
                let raw = request.split_once("\r\n\r\n").unwrap().1;
                let value: Value = if raw.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_str(raw).unwrap()
                };
                let response = if request.contains("/relay-token") {
                    json!({"token":"synthetic-oracle-token","expires_at":"2099-01-01T00:00:00Z"})
                } else if request.contains("/activity-hints") {
                    json!({"source":source.api_slug(),"server_time":AT,
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"})
                } else if request.contains("/agent-status/snapshots") {
                    json!({"accepted":1,"machine_id":"otm_test","sources":[source.api_slug()]})
                } else if let Some(items) = value["snapshots"].as_array() {
                    assert!(!items.is_empty());
                    batches_worker.lock().unwrap().push(raw.as_bytes().to_vec());
                    test_effects::record(
                        "post",
                        vec![("entities", Scalar::U64(items.len() as u64))],
                    );
                    let answers = script_worker
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or_else(|| vec![*fallback_worker.lock().unwrap(); items.len()]);
                    assert_eq!(answers.len(), items.len(), "one answer per offered entity");
                    if answers.iter().any(|a| matches!(a, Answer::Dropped)) {
                        drop(stream);
                        continue;
                    }
                    if answers.iter().any(|a| matches!(a, Answer::Shed)) {
                        bounded_native_response(&mut stream, "503 Service Unavailable", "{}");
                        continue;
                    }
                    let mut reply = json!({"accepted":0,"sessions_reconciled":0,
                        "session_ids":[],"disabled":false,"disabled_reason":null,
                        "entity_ack_contract":"snapshot_entity_ack:v1","accepted_entities":[],
                        "unchanged_entities":[],"rejected_entities":[],"conflict_entities":[]});
                    let mut accepted = 0;
                    for (item, answer) in items.iter().zip(answers) {
                        let mut reference = exact_ack(item);
                        match answer {
                            Answer::Accept | Answer::LostAck => {
                                let mut body = item.clone();
                                body.as_object_mut().unwrap().remove("collected_at");
                                body.as_object_mut().unwrap().remove("semantic_envelope");
                                let key = item["snapshot_fingerprint"].as_str().unwrap().to_owned();
                                let mut stored = placed.lock().unwrap();
                                let unchanged = stored.get(&key) == Some(&body);
                                stored.insert(key, body);
                                if matches!(answer, Answer::Accept) {
                                    let kind = if unchanged {
                                        "unchanged_entities"
                                    } else {
                                        "accepted_entities"
                                    };
                                    reply[kind].as_array_mut().unwrap().push(reference);
                                    accepted += 1;
                                }
                            }
                            Answer::Unstored => {
                                reference["unchanged_basis"] = "usage_identical".into();
                                reply["unchanged_entities"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(reference);
                            }
                            Answer::Refuse(reason) => {
                                reference["reason"] = reason.into();
                                reference["permanent"] = true.into();
                                reply["rejected_entities"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(reference);
                            }
                            Answer::Conflict => {
                                reply["conflict_entities"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(reference);
                            }
                            Answer::Dropped | Answer::Shed => unreachable!("handled per POST"),
                        }
                    }
                    reply["accepted"] = accepted.into();
                    reply["sessions_reconciled"] = accepted.into();
                    reply
                } else {
                    json!({"accepted":true,"source":source.api_slug(),"machine_id":"otm_test","disabled":false})
                };
                bounded_native_response(&mut stream, "200 OK", &response.to_string());
            }
        });
        Self {
            url,
            stop,
            worker: Some(worker),
            script,
            fallback,
            batches,
            placement,
        }
    }
}
impl Drop for OracleServer {
    fn drop(&mut self) {
        stop_server(&self.stop, &mut self.worker);
    }
}

struct Cadence {
    source: SnapshotSource,
    prior: (Option<SourceCadence>, Option<Instant>, Option<u32>),
}
impl Cadence {
    fn new(source: SnapshotSource) -> Self {
        let slug = source.api_slug();
        Self {
            source,
            prior: (
                source_cadences().lock().unwrap().remove(slug),
                source_upload_deadlines().lock().unwrap().remove(slug),
                source_shed_streaks().lock().unwrap().remove(slug),
            ),
        }
    }
    fn due(&self) {
        source_cadences()
            .lock()
            .unwrap()
            .remove(self.source.api_slug());
        source_upload_deadlines()
            .lock()
            .unwrap()
            .remove(self.source.api_slug());
    }
}
impl Drop for Cadence {
    fn drop(&mut self) {
        let slug = self.source.api_slug();
        self.due();
        source_shed_streaks().lock().unwrap().remove(slug);
        if let Some(prior) = self.prior.0.take() {
            source_cadences().lock().unwrap().insert(slug, prior);
        }
        if let Some(prior) = self.prior.1.take() {
            source_upload_deadlines()
                .lock()
                .unwrap()
                .insert(slug, prior);
        }
        if let Some(prior) = self.prior.2.take() {
            source_shed_streaks().lock().unwrap().insert(slug, prior);
        }
    }
}

struct OracleHome {
    fixture: IdentityPipelineHome,
    source: SnapshotSource,
    cadence: Cadence,
    support: PathBuf,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    transport: crate::net_resilience::TransportCycleOutcome,
    retry: live_snapshot_retry::LiveRetryOwner,
    _env: [EnvVarGuard; 4],
}

struct Cycle {
    pre_index_bytes: Vec<u8>,
    before: Vec<SnapshotItem>,
    gate: Value,
    finalized: Vec<SnapshotItem>,
    steps: Vec<Value>,
    consumed: u64,
    io: transition::IoBytes,
    batches: Vec<Vec<u8>>,
    index: ScanIndex,
    progress: SnapshotUploadProgress,
    finish: Result<()>,
}

impl OracleHome {
    fn new(source: SnapshotSource, server: &OracleServer) -> Self {
        crate::client_report::reset_for_test();
        let mut fixture = IdentityPipelineHome::new();
        fixture.base = fixture.base.canonicalize().unwrap();
        fixture.home = fixture.home.canonicalize().unwrap();
        let transcript = fixture
            .home
            .join(".claude/projects/-synthetic-repo")
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
        let rows = [
            json!({"timestamp":"2026-11-01T07:00:00Z","type":"attachment",
                "sessionId":IDENTITY_PIPELINE_ROOT,"attachment":{"type":"credential_org",
                "organizationUuid":IDENTITY_PIPELINE_ORG}}),
            json!({"timestamp":"2026-11-01T07:01:00Z","type":"assistant",
                "sessionId":IDENTITY_PIPELINE_ROOT,"requestId":"req_1",
                "message":{"id":"m1","model":"claude-haiku-4-5","usage":{"input_tokens":10,"output_tokens":1}}}),
            json!({"timestamp":"2026-11-01T07:02:00Z","type":"assistant",
                "sessionId":IDENTITY_PIPELINE_ROOT,"requestId":"req_2",
                "message":{"id":"m2","model":"claude-haiku-4-5","usage":{"input_tokens":20,"output_tokens":2}}}),
        ];
        std::fs::write(
            &transcript,
            rows.iter()
                .map(|r| r.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(transcript)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 3600))
            .unwrap();
        let cadence = Cadence::new(source);
        let support = fixture.base.join("oracle-support");
        let secrets = fixture.base.join("oracle-secrets");
        std::fs::create_dir_all(&support).unwrap();
        std::fs::create_dir_all(&secrets).unwrap();
        let env = [
            EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support),
            EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets),
            EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url),
            EnvVarGuard::set_path("PI_CODING_AGENT_DIR", &fixture.home.join(".pi/agent")),
        ];
        let device = LocalDeviceBinding {
            device_id: "oracle-device".into(),
            machine_id: Some("otm_test".into()),
            sources: vec![source.api_slug().into()],
        };
        FileDeviceStore::default().save(&device).unwrap();
        std::fs::write(
            secrets.join(OTTTO_RELAY_DEVICE_SECRET_ACCOUNT),
            "device-secret",
        )
        .unwrap();
        let destination = snapshot_upload_destination_namespace(&device, "device-secret");
        crate::backfill::record_first_census(&support, source, &destination, AT, true).unwrap();
        Self {
            fixture,
            source,
            cadence,
            support,
            device,
            client: SnapshotApiClient::new(server.url.clone()),
            daemon: test_daemon("otm_test"),
            transport: Default::default(),
            retry: live_snapshot_retry::LiveRetryOwner::closed(),
            _env: env,
        }
    }
    fn collection(&self) -> AgentStatusCollection {
        AgentStatusCollection {
            snapshots: vec![test_agent_status(source_kind(self.source))],
            source_health_snapshot: test_agent_status(source_kind(self.source)),
            codex_scan_homes: Vec::new(),
            codex_home_bindings: Vec::new(),
            setup_snapshot_index: None,
        }
    }
    fn index_path(&self) -> PathBuf {
        snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
            &snapshot_index_path(&self.support, self.source),
            &snapshot_upload_destination_namespace(&self.device, "device-secret"),
        ))
    }
    fn transcript(&self) -> PathBuf {
        if self.source == SnapshotSource::ClaudeCode {
            self.fixture
                .home
                .join(".claude/projects/-synthetic-repo")
                .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
        } else {
            self.source.default_roots(&self.fixture.home)[0].join("oracle.jsonl")
        }
    }
    fn write_rows(&self, rows: &[Value]) {
        let path = self.transcript();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            rows.iter()
                .map(|r| r.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 3600))
            .unwrap();
    }
    fn restart(&mut self) {
        drop(std::mem::replace(&mut self.daemon, test_daemon("otm_test")));
        self.retry = live_snapshot_retry::LiveRetryOwner::closed();
        test_effects::record("restart", Vec::new());
    }
    fn restore_pre_cycle_index(&mut self, cycle: &Cycle) {
        let mut previous: ScanIndex = serde_json::from_slice(&cycle.pre_index_bytes).unwrap();
        let current = ScanIndex::load(&self.index_path()).unwrap();
        // Restore the old logical graph through the real writer, retaining
        // the current CAS/root binding. Progress rows remain authoritative.
        previous.retain_persistence_baseline_from(&current);
        previous.generation = current.generation;
        previous.save(&self.index_path()).unwrap();
        crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
            &self.daemon.transcript_cache,
            &current,
        );
        self.restart();
    }
    fn cycle(&mut self, server: &OracleServer, recording: &Recording) -> Cycle {
        self.cadence.due();
        let start = server.batches.lock().unwrap().len();
        let collection = self.collection();
        let mut frame = with_scan_clock(NOW, || {
            crate::agent_status_refresh::with_test_collection(collection, || {
                prepare_sync_source(
                    &self.client,
                    &self.device,
                    "device-secret",
                    self.source,
                    "otm_test",
                    &self.fixture.home,
                    &self.support,
                    &self.daemon,
                    &mut self.transport,
                    self.daemon.snapshot_scan_account_witness().unwrap(),
                    false,
                )
            })
        })
        .unwrap()
        .expect("due real preparation");
        frame.scan.as_mut().unwrap().set_oracle_collection_time(AT);
        frame.scan_started_at = AT.to_owned();
        let roots = self.source.default_roots(&self.fixture.home);
        let index_path = frame.index_path.clone();
        let progress_path = frame.upload_progress_path.clone();
        let destination = frame.upload_destination_namespace.clone();
        let witness = frame
            .upload_progress
            .active_quarantine_witness
            .clone()
            .unwrap();
        let pre_index_bytes = serde_json::to_vec(&frame.committed_index).unwrap();
        let handle = recording.handle();
        let (preparation, index, scan, steps, io) = run_on_scan_worker_stack(move || {
            let _entered = handle.enter();
            with_scan_clock(NOW, || {
                let ((preparation, index, scan, steps), io) =
                    transition::observe_codex_quiet(|| {
                        let mut steps = Vec::new();
                        for _ in 0..1024 {
                            let before = frame.scan.as_ref().unwrap().trace_projection();
                            match frame.step() {
                                SourcePreparationStep::Pending(next) => {
                                    let row = json!({"outcome":"pending","before":before,
                                    "after":next.scan.as_ref().unwrap().trace_projection()});
                                    test_effects::record(
                                        "step",
                                        vec![("outcome", Scalar::Text("pending".into()))],
                                    );
                                    steps.push(row);
                                    frame = next;
                                }
                                SourcePreparationStep::Refused(_, reason) => {
                                    panic!("unexpected native refusal: {reason:?}")
                                }
                                SourcePreparationStep::Complete {
                                    preparation,
                                    index,
                                    scan,
                                } => {
                                    steps.push(json!({"outcome":"complete","before":before}));
                                    test_effects::record(
                                        "step",
                                        vec![("outcome", Scalar::Text("complete".into()))],
                                    );
                                    return (preparation, index, scan, steps);
                                }
                            }
                        }
                        panic!("scan exceeded 1024 steps");
                    });
                (preparation, index, scan, steps, io)
            })
        });
        let gate = scan.trace_projection(&roots);
        test_effects::record(
            "gate_c",
            vec![("snapshots", Scalar::U64(scan.snapshots.len() as u64))],
        );
        let before = scan.snapshots.clone();
        let capture = FinalizedCapture::start();
        let collection = self.collection();
        let finish = with_scan_clock(NOW, || {
            crate::agent_status_refresh::with_test_collection(collection, || {
                finish_sync_source(
                    preparation,
                    index,
                    scan,
                    &self.client,
                    &self.device,
                    "device-secret",
                    self.source,
                    "otm_test",
                    &self.fixture.home,
                    &self.support,
                    &self.daemon,
                    &mut self.transport,
                    &mut self.retry,
                )
            })
        });
        let finalized = capture.take();
        let (index, _, progress) = load_source_checkpoints(
            &index_path,
            &progress_path,
            self.source,
            &self.support,
            &destination,
            witness,
        )
        .unwrap();
        test_effects::record(
            "reloaded",
            vec![("finish_ok", Scalar::Bool(finish.is_ok()))],
        );
        let batches = server.batches.lock().unwrap()[start..].to_vec();
        Cycle {
            pre_index_bytes,
            before,
            gate,
            finalized,
            steps,
            consumed: io.consumed,
            io,
            batches,
            index,
            progress,
            finish,
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c00_real_runner_collects_finishes_and_reloads() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    let cycle = home.cycle(&server, &recording);
    cycle.finish.unwrap();
    assert_eq!(cycle.before.len(), 1);
    assert_eq!(cycle.gate["snapshots"], 1);
    assert_eq!(cycle.finalized.len(), 1);
    assert_eq!(cycle.finalized[0].input_tokens, 30);
    assert!(cycle.consumed > 0);
    assert!(!cycle.steps.is_empty());
    assert_eq!(cycle.batches.len(), 1);
    assert!(cycle.index.generation > 0);
    let item = &cycle.finalized[0];
    assert!(cycle.progress.contains_body(
        &item.snapshot_fingerprint,
        &snapshot_upload_body_witness(item)
    ));
    assert_eq!(server.placement.lock().unwrap().len(), 1);
    assert!(recording.take().iter().any(|e| e.label == "post"));
}

#[test]
fn script_answers_are_per_post_and_per_entity() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::Pi, recording.handle());
    let answers = [
        Answer::Accept,
        Answer::Unstored,
        Answer::Refuse("synthetic"),
        Answer::Conflict,
        Answer::LostAck,
        Answer::Dropped,
        Answer::Shed,
    ];
    for answer in answers {
        server.script.lock().unwrap().push_back(vec![answer]);
        let body = json!({"snapshots":[{"source_session_id":"synthetic",
            "snapshot_fingerprint":"a".repeat(64)}]})
        .to_string();
        let mut stream =
            std::net::TcpStream::connect(server.url.strip_prefix("http://").unwrap()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(stream, "POST /synthetic HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        if matches!(answer, Answer::Dropped) {
            assert!(response.is_empty());
        } else if matches!(answer, Answer::Shed) {
            assert!(response.contains("503 Service Unavailable"));
        } else {
            assert!(response.contains("200 OK"));
        }
    }
    assert!(server.script.lock().unwrap().is_empty());
    assert_eq!(server.placement.lock().unwrap().len(), 1);
    assert_eq!(server.batches.lock().unwrap().len(), 7);
}

struct SaveFailure(Option<&'static str>);
impl SaveFailure {
    fn at(stage: &'static str) -> Self {
        Self(ACK_POST_SAVE_FAILURE.with(|slot| slot.replace(Some(stage))))
    }
}
impl Drop for SaveFailure {
    fn drop(&mut self) {
        ACK_POST_SAVE_FAILURE.with(|slot| slot.set(self.0));
    }
}

fn assert_durable(cycle: &Cycle) {
    assert!(!cycle.finalized.is_empty(), "positive finalized body");
    for item in &cycle.finalized {
        assert!(cycle.progress.contains_body(
            &item.snapshot_fingerprint,
            &snapshot_upload_body_witness(item)
        ));
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c02_durable_ack_suppresses_replay_of_the_prior_index() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    let first = home.cycle(&server, &recording);
    assert!(first.finish.is_ok());
    assert_durable(&first);
    let placement = server.placement.lock().unwrap().clone();
    home.restore_pre_cycle_index(&first);
    let replay = home.cycle(&server, &recording);
    assert!(replay.finish.is_ok());
    assert_eq!(replay.before.len(), 1, "gate c passed positively");
    assert_eq!(replay.finalized.len(), 1, "gate b passed positively");
    assert!(
        replay.batches.is_empty(),
        "gate a suppressed durable exact ACK"
    );
    assert_durable(&replay);
    assert!(!replay.index.current_snapshot_fingerprints().is_empty());
    assert_eq!(*server.placement.lock().unwrap(), placement);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c03_complete_same_body_reread_drops_at_the_finalizer() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    let first = home.cycle(&server, &recording);
    assert!(first.finish.is_ok());
    assert_durable(&first);
    let placement = server.placement.lock().unwrap().clone();
    let file = std::fs::File::options()
        .write(true)
        .open(home.transcript())
        .unwrap();
    file.set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 1800))
        .unwrap();
    let replay = home.cycle(&server, &recording);
    assert!(replay.finish.is_ok());
    assert_eq!(
        replay.before.len(),
        1,
        "positive complete reread before gate b"
    );
    assert!(replay.gate["pending_finalization"]
        .as_array()
        .unwrap()
        .iter()
        .all(|row| row["parse_complete"] == true));
    assert!(
        replay.finalized.is_empty(),
        "gate b removes the carried no-op"
    );
    assert!(replay.batches.is_empty());
    assert_eq!(*server.placement.lock().unwrap(), placement);
}

fn pi_rows(conflict: bool) -> Vec<Value> {
    let message = |shape: &str, id: &str, tokens: u64, at: &str| {
        json!({
        "type":shape,"timestamp":at,"message":{"role":"assistant","model":"gpt-5",
        "provider":"openai","responseId":id,"timestamp":at,"usage":{"input":tokens,"output":1}}})
    };
    vec![
        json!({"type":"session","id":"oracle-pi","timestamp":"2026-11-01T07:00:00Z"}),
        message("message", "good", 10, "2026-11-01T07:01:00Z"),
        message("message", "paired", 3, "2026-11-01T07:02:00Z"),
        message(
            "message_end",
            "paired",
            if conflict { 7 } else { 3 },
            "2026-11-01T07:02:00Z",
        ),
    ]
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c04_pi_positive_conflicted_result_cannot_publish() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::Pi, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::Pi, &server);
    home.write_rows(&pi_rows(true));
    let held = home.cycle(&server, &recording);
    assert_eq!(held.gate["ownership_incomplete_file_count"], 1);
    let pending = held.gate["pending_finalization"].as_array().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0]["parse_complete"], false);
    assert_eq!(
        pending[0]["parsed_snapshot_count"], 1,
        "positive native vector, not just raw evidence"
    );
    assert!(
        held.before.is_empty(),
        "gate c alone withholds the positive native vector"
    );
    assert!(held.finalized.is_empty());
    assert!(held.batches.is_empty());
    assert!(server.placement.lock().unwrap().is_empty());
    crate::client_report::reset_for_test();
    home.write_rows(&pi_rows(false));
    let complete = home.cycle(&server, &recording);
    assert!(complete.finish.is_ok());
    assert_eq!(complete.finalized.len(), 1);
    assert_eq!(complete.finalized[0].input_tokens, 13);
    assert_eq!(complete.finalized[0].request_count, 2);
    assert_durable(&complete);
    let completed_route = emitted_route(&complete, SnapshotSource::Pi, &server);
    let mut cold_home = OracleHome::new(SnapshotSource::Pi, &server);
    cold_home.write_rows(&pi_rows(false));
    let cold = cold_home.cycle(&server, &recording);
    assert!(cold.finish.is_ok());
    let cold_route = emitted_route(&cold, SnapshotSource::Pi, &server);
    transition::money_oracle::assert_equivalent(&cold_route, &completed_route);
    transition::money_oracle::assert_no_smaller_reemit(
        "oracle-pi",
        &cold_route,
        &completed_route,
        &cold_route,
        false,
    );
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c05_fresh_destination_requires_its_own_exact_ack() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    let first = home.cycle(&server, &recording);
    assert!(first.finish.is_ok());
    assert_durable(&first);
    let fingerprint = first.finalized[0].snapshot_fingerprint.clone();
    home.device.device_id = "other-oracle-device".into();
    FileDeviceStore::default().save(&home.device).unwrap();
    let destination = snapshot_upload_destination_namespace(&home.device, "device-secret");
    crate::backfill::record_first_census(&home.support, home.source, &destination, AT, true)
        .unwrap();
    home.restart();
    *server.fallback.lock().unwrap() = Answer::Unstored;
    let unstored = home.cycle(&server, &recording);
    assert_eq!(unstored.finalized.len(), 1);
    let item = &unstored.finalized[0];
    assert_eq!(item.snapshot_fingerprint, fingerprint);
    assert!(!unstored
        .progress
        .contains_body(&fingerprint, &snapshot_upload_body_witness(item)));
    *server.fallback.lock().unwrap() = Answer::Accept;
    home.restore_pre_cycle_index(&unstored);
    let accepted = home.cycle(&server, &recording);
    assert!(accepted.finish.is_ok());
    assert_eq!(accepted.batches.len(), 1);
    assert_durable(&accepted);
    assert_eq!(
        server.placement.lock().unwrap().len(),
        1,
        "replacement never adds the same entity twice"
    );
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c06_crash_windows_preserve_placement_and_durable_suppression() {
    for answer in [Answer::Dropped, Answer::LostAck, Answer::Accept] {
        let recording = Recording::start();
        let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
        let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
        *server.fallback.lock().unwrap() = answer;
        let failure = matches!(answer, Answer::Accept).then(|| SaveFailure::at("selected_save"));
        let first = home.cycle(&server, &recording);
        drop(failure);
        assert!(first.finish.is_err());
        let durable = matches!(answer, Answer::Accept);
        let item = &first.finalized[0];
        assert_eq!(
            first.progress.contains_body(
                &item.snapshot_fingerprint,
                &snapshot_upload_body_witness(item)
            ),
            durable
        );
        assert_eq!(
            server.placement.lock().unwrap().len(),
            usize::from(!matches!(answer, Answer::Dropped))
        );
        *server.fallback.lock().unwrap() = Answer::Accept;
        home.restore_pre_cycle_index(&first);
        let replay = home.cycle(&server, &recording);
        assert!(replay.finish.is_ok());
        assert_eq!(
            replay.finalized.len(),
            1,
            "replay reaches the ACK gate positively"
        );
        assert_eq!(replay.batches.len(), usize::from(!durable));
        assert_durable(&replay);
        assert_eq!(server.placement.lock().unwrap().len(), 1);
        assert_eq!(
            server.placement.lock().unwrap().values().next().unwrap()["input_tokens"],
            30
        );
    }
}

fn emitted_route(
    cycle: &Cycle,
    source: SnapshotSource,
    server: &OracleServer,
) -> transition::RouteResult {
    let mut route = transition::RouteResult::emitted(
        transition::Mode::ColdFull,
        source,
        cycle.batches.clone(),
        &cycle.finalized,
    );
    let placed = server.placement.lock().unwrap();
    let mut buckets = serde_json::Map::new();
    for body in placed.values() {
        let entity = body["source_session_id"].as_str().unwrap().to_owned();
        route.accepted.insert(
            entity.clone(),
            transition::Accepted {
                body: body.clone(),
                witness: finish_wire_body_witness(body),
            },
        );
        buckets.insert(
            entity,
            json!({"request_evidence":body["request_evidence"],
            "session_account_evidence":body["session_account_evidence"],
            "model_usage":body["model_usage"], "usage_buckets":body["usage_buckets"]}),
        );
    }
    route.accepted_identity_buckets = Some(Value::Object(buckets));
    route.io = cycle.io.clone();
    let last = &cycle.steps.last().unwrap()["before"];
    route.modes = (
        last["full_files"].as_u64().unwrap_or(0) as usize,
        last["tail_files"].as_u64().unwrap_or(0) as usize,
        last["unchanged_files"].as_u64().unwrap_or(0) as usize,
    );
    route
}

fn install_claude_control(home: &OracleHome) {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
        ClaudeLocalOtelEvidence, ClaudeRequestIdentityEvidence, ClaudeTraceOwnershipEvidence,
    };
    let transcript = |id: &str, tokens: u64, at: &str| {
        json!({"type":"assistant",
        "sessionId":IDENTITY_PIPELINE_ROOT,"version":"2.1.309","timestamp":at,"requestId":id,
        "message":{"id":format!("msg-{id}"),"model":"claude-haiku-4-5",
        "usage":{"input_tokens":tokens,"output_tokens":tokens}}})
    };
    home.write_rows(&[
        transcript("account-a", 10, "2026-11-01T07:01:00Z"),
        transcript("account-b", 20, "2026-11-01T07:02:00Z"),
        transcript("gap", 5, "2026-11-01T07:04:00Z"),
    ]);
    let attribute = |hash: String| ClaudeIdentityAttributeEvidence {
        origin: ClaudeIdentityAttributeOrigin::LogRecord,
        disposition: ClaudeIdentityDisposition::Complete,
        resource_hash: None,
        log_record_hash: Some(hash),
    };
    let mut rows = Vec::new();
    let mut traces = Vec::new();
    for (sequence, (request, tokens, account, org, at)) in [
        ("account-a", 10, 'a', '8', "2026-11-01T07:01:00Z"),
        ("account-b", 20, 'b', '9', "2026-11-01T07:02:00Z"),
        ("side", 7, 'b', '9', "2026-11-01T07:03:00Z"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut row = ClaudeLocalOtelEvidence {
            capture_revision: "claude_api_request:v2".into(),
            session_id: IDENTITY_PIPELINE_ROOT.into(),
            request_id: request.into(),
            client_request_id: format!("client-{request}"),
            observed_at: at.into(),
            model: "claude-haiku-4-5".into(),
            effort: "high".into(),
            query_source: "user".into(),
            app_version: "2.1.309".into(),
            event_sequence: Some(sequence as u64 + 1),
            input_tokens: tokens,
            output_tokens: tokens,
            request_count: 1,
            account_identity_checked: true,
            account_identifier_hash: Some(account.to_string().repeat(64).into()),
            request_identity: Some(Arc::new(ClaudeRequestIdentityEvidence {
                identity_hash_scheme: "provider-sha256:v1".into(),
                account: attribute(account.to_string().repeat(64)),
                organization: attribute(org.to_string().repeat(64)),
                disposition: ClaudeIdentityDisposition::Complete,
            })),
            ..Default::default()
        };
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&row).unwrap())
        );
        rows.push(serde_json::to_value(row).unwrap());
        let mut trace = ClaudeTraceOwnershipEvidence {
            capture_revision: "claude_llm_request_ownership:v1".into(),
            session_id: IDENTITY_PIPELINE_ROOT.into(),
            request_id: request.into(),
            client_request_id: format!("client-{request}"),
            agent_id: String::new(),
            observed_at: at.into(),
            ..Default::default()
        };
        trace.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&trace).unwrap())
        );
        traces.push(serde_json::to_value(trace).unwrap());
    }
    for (directory, values) in [
        ("claude-code-effort", rows),
        ("claude-code-trace-ownership", traces),
    ] {
        let path = home
            .support
            .join("local-otel")
            .join(directory)
            .join(format!(
                "{:x}.jsonl",
                Sha256::digest(IDENTITY_PIPELINE_ROOT.as_bytes())
            ));
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            path,
            values
                .iter()
                .map(|v| v.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c01_claude_cold_control_preserves_accounts_side_call_gap_and_tags() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    install_claude_control(&home);
    let cold = home.cycle(&server, &recording);
    assert!(cold.finish.is_ok());
    assert_durable(&cold);
    assert_eq!(
        cold.finalized.iter().map(|s| s.input_tokens).sum::<u64>(),
        42
    );
    assert_eq!(
        cold.finalized.iter().map(|s| s.output_tokens).sum::<u64>(),
        42
    );
    assert_eq!(
        cold.finalized.iter().map(|s| s.request_count).sum::<u64>(),
        4
    );
    let mut accounts = BTreeMap::<String, u64>::new();
    let mut tagged = false;
    for item in &cold.finalized {
        let value = serde_json::to_value(item).unwrap();
        for row in value["model_usage"].as_array().unwrap() {
            tagged |= row["selector_context"]["effort"] == "high";
            let shares = row["identity_parts"]
                .as_array()
                .map(|v| v.iter().collect::<Vec<_>>())
                .unwrap_or_else(|| vec![row]);
            for share in shares {
                *accounts
                    .entry(
                        share["account_identifier_hash"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                    )
                    .or_default() += share["input_tokens"].as_u64().unwrap();
            }
        }
    }
    assert_eq!(
        accounts,
        BTreeMap::from([("a".repeat(64), 10), ("b".repeat(64), 32)])
    );
    assert!(tagged);
    let placement = server.placement.lock().unwrap().clone();
    home.restart();
    let quiet = home.cycle(&server, &recording);
    assert!(quiet.finish.is_ok());
    assert!(quiet.before.is_empty());
    assert!(quiet.finalized.is_empty());
    assert!(quiet.batches.is_empty());
    assert_eq!(*server.placement.lock().unwrap(), placement);
    let mut quiet_route = emitted_route(&quiet, SnapshotSource::ClaudeCode, &server);
    quiet_route.mode = transition::Mode::Restart;
    transition::money_oracle::assert_quiet_restart_zero_bytes(&quiet_route);
}
