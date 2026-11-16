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
                        .unwrap_or_else(|| vec![Answer::Accept; items.len()]);
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
    _env: [EnvVarGuard; 3],
}

struct Cycle {
    before: Vec<SnapshotItem>,
    gate: Value,
    finalized: Vec<SnapshotItem>,
    steps: Vec<Value>,
    consumed: u64,
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
        let roots = self.source.default_roots(&self.fixture.home);
        let index_path = frame.index_path.clone();
        let progress_path = frame.upload_progress_path.clone();
        let destination = frame.upload_destination_namespace.clone();
        let witness = frame
            .upload_progress
            .active_quarantine_witness
            .clone()
            .unwrap();
        let handle = recording.handle();
        let (preparation, index, scan, steps, consumed) = run_on_scan_worker_stack(move || {
            let _entered = handle.enter();
            with_scan_clock(NOW, || {
                let ((preparation, index, scan, steps), consumed) =
                    transition::observe_consumed(|| {
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
                (preparation, index, scan, steps, consumed)
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
            before,
            gate,
            finalized,
            steps,
            consumed,
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
