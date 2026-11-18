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
    static BACKOFF_MIDPOINT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(in crate::snapshot_sync) fn backoff_sample_for_test(span: Duration) -> Option<Duration> {
    BACKOFF_MIDPOINT.with(|slot| slot.get().then_some(span / 2))
}

struct BackoffMidpoint(bool);
impl BackoffMidpoint {
    fn start() -> Self {
        Self(BACKOFF_MIDPOINT.with(|slot| slot.replace(true)))
    }
}
impl Drop for BackoffMidpoint {
    fn drop(&mut self) {
        BACKOFF_MIDPOINT.with(|slot| slot.set(self.0));
    }
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
    acknowledged: Arc<Mutex<Vec<Vec<Value>>>>,
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
        let acknowledged = Arc::new(Mutex::new(Vec::new()));
        let proved = acknowledged.clone();
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
                    let mut hint = json!({"source":source.api_slug(),"server_time":AT,
                        "last_data_at":null,"record_count_15m":0,"record_count_24h":0,
                        "local_usage_reconciliation_enabled":true,"backfill_window_days":183,
                        "recommended_scan_after":"2099-01-01T00:00:00Z"});
                    // Production advertises account carry to Claude Code only.
                    if source == SnapshotSource::ClaudeCode {
                        hint["session_request_account_source_contract"] =
                            crate::snapshots::ACCOUNT_SOURCE_CONTRACT.into();
                    }
                    hint
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
                    let mut accepted_rows = Vec::new();
                    let mut lost_ack = false;
                    for (item, answer) in items.iter().zip(answers) {
                        let mut reference = exact_ack(item);
                        match answer {
                            Answer::Accept | Answer::LostAck => {
                                let mut body = item.clone();
                                body.as_object_mut().unwrap().remove("collected_at");
                                body.as_object_mut().unwrap().remove("semantic_envelope");
                                let key = item["source_session_id"].as_str().unwrap().to_owned();
                                let mut stored = placed.lock().unwrap();
                                let unchanged = stored.get(&key) == Some(&body);
                                stored.insert(key, body);
                                lost_ack |= matches!(answer, Answer::LostAck);
                                if matches!(answer, Answer::Accept) {
                                    let kind = if unchanged {
                                        "unchanged_entities"
                                    } else {
                                        "accepted_entities"
                                    };
                                    reply[kind].as_array_mut().unwrap().push(reference);
                                    accepted += 1;
                                    accepted_rows.push(item.clone());
                                }
                            }
                            Answer::Unstored => {
                                reference["unchanged_basis"] = "usage_identical".into();
                                reply["unchanged_entities"]
                                    .as_array_mut()
                                    .unwrap()
                                    .push(reference);
                                // The wire count includes unchanged refs, even
                                // when their basis grants no stored-body proof.
                                accepted += 1;
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
                    if lost_ack {
                        // The write reached custody, but no response reaches the client.
                        // A malformed 200 instead creates a real validation quarantine.
                        drop(stream);
                        continue;
                    }
                    proved.lock().unwrap().push(accepted_rows);
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
            acknowledged,
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
    now: u64,
    small_page: bool,
    state_budget: Option<usize>,
    row: &'static str,
    cycle_number: usize,
    current_codex_account: &'static str,
    restarted: bool,
    schedule: Option<Schedule>,
    births: BTreeMap<String, u64>,
    support: PathBuf,
    device: LocalDeviceBinding,
    client: SnapshotApiClient,
    daemon: LocalDaemon,
    transport: crate::net_resilience::TransportCycleOutcome,
    _env: [EnvVarGuard; 3],
}

struct Cycle {
    pre_index_bytes: Vec<u8>,
    before: Vec<SnapshotItem>,
    gate: Value,
    finalized: Vec<SnapshotItem>,
    steps: Vec<Value>,
    consumed: u64,
    io: transition::IoBytes,
    quiet_anchor_window: u64,
    batches: Vec<Vec<u8>>,
    acknowledged: Vec<Vec<Value>>,
    index: ScanIndex,
    progress: SnapshotUploadProgress,
    finish: Result<()>,
    effects: Vec<test_effects::Effect>,
    schedule: Option<Value>,
    evidence_chunks: usize,
    debt: Value,
}

impl Cycle {
    fn accepted_body(&self, item: &SnapshotItem) -> bool {
        let bodies = self
            .finalized
            .iter()
            .map(|s| {
                (
                    s.snapshot_fingerprint.clone(),
                    snapshot_upload_body_witness(s),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let witness = snapshot_upload_body_witness(item);
        // contains_body also includes quarantine, which is suppression, NOT ACK proof.
        self.progress
            .accepted_body_witnesses
            .get(&item.snapshot_fingerprint)
            == Some(&witness)
            || self
                .index
                .adopted_upload_progress_acks(&bodies)
                .contains(&item.snapshot_fingerprint)
    }
}

#[derive(Clone, Copy)]
struct Schedule {
    one_chunk: bool,
    limit: usize,
    reverse: bool,
}

struct EvidenceSchedule(bool);
impl Drop for EvidenceSchedule {
    fn drop(&mut self) {
        ONE_EVIDENCE_CHUNK.with(|slot| slot.set(self.0));
    }
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
        #[cfg(unix)]
        crate::locked_state_dir::test_locks::hold(&support);
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
            now: NOW,
            small_page: false,
            state_budget: None,
            row: "c00",
            cycle_number: 0,
            current_codex_account: "a",
            restarted: false,
            schedule: None,
            births: BTreeMap::new(),
            support,
            device,
            client: SnapshotApiClient::new(server.url.clone()),
            daemon: test_daemon("otm_test"),
            transport: Default::default(),
            _env: env,
        }
    }
    fn collection(&self) -> AgentStatusCollection {
        let (codex_scan_homes, codex_home_bindings) = if self.source == SnapshotSource::Codex {
            let home = self.fixture.home.join(".codex");
            std::fs::create_dir_all(&home).unwrap();
            let auth = home.join("auth.json");
            if !auth.exists() {
                std::fs::write(&auth, b"{}").unwrap();
            }
            let at = std::fs::metadata(auth).unwrap().modified().unwrap();
            (
                vec![home.clone()],
                vec![crate::agent_status::CodexHomeBinding {
                    home,
                    account_identifier_hash: self.current_codex_account.repeat(64),
                    workspace_identifier_hash: "f".repeat(64),
                    auth_modified_at: at,
                }],
            )
        } else {
            (Vec::new(), Vec::new())
        };
        AgentStatusCollection {
            snapshots: vec![test_agent_status(source_kind(self.source))],
            source_health_snapshot: test_agent_status(source_kind(self.source)),
            codex_scan_homes,
            codex_home_bindings,
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
        self.restarted = true;
        test_effects::record("restart", Vec::new());
    }
    fn cold_restart(&mut self) {
        self.restart();
        crate::snapshots::state_v2::cold_close_for_test(&self.index_path()).unwrap();
        crate::snapshots::clear_remembered_tripwire_for_test();
    }
    fn restore_pre_cycle_index(&mut self, cycle: &Cycle) {
        let mut previous: ScanIndex = serde_json::from_slice(&cycle.pre_index_bytes).unwrap();
        let current = ScanIndex::load(&self.index_path()).unwrap();
        // Restore the old logical graph through the real writer, retaining
        // the current CAS/root binding. Progress rows remain authoritative.
        previous.retain_persistence_baseline_from(&current);
        previous.generation = current.generation;
        previous.save_fixture(&self.index_path()).unwrap();
        crate::snapshots::e2_pipeline_scan_fixture::forget_continuations_for_test(
            &self.daemon.transcript_cache,
            &current,
        );
        self.restart();
    }
    fn age_listing(&self) {
        let mut index = ScanIndex::load(&self.index_path()).unwrap();
        crate::snapshots::e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        index.save_fixture(&self.index_path()).unwrap();
    }
    fn cycle(&mut self, server: &OracleServer, recording: &Recording) -> Cycle {
        let schedule = self.schedule.map(|s| (s.limit, s.reverse));
        crate::snapshots::OwnedSourceScan::with_oracle_schedule(schedule, || {
            crate::snapshots::OwnedSourceScan::with_oracle_births(self.births.clone(), || {
                self.cycle_inner(server, recording)
            })
        })
    }
    fn cycle_inner(&mut self, server: &OracleServer, recording: &Recording) -> Cycle {
        self.cadence.due();
        let now = self.now;
        let small_page = self.small_page;
        let budget = self.state_budget;

        let at = OffsetDateTime::from_unix_timestamp(now as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let start = server.batches.lock().unwrap().len();
        let ack_start = server.acknowledged.lock().unwrap().len();
        let collection = self.collection();
        let (prepared, prepare_io) = crate::snapshots::OwnedSourceScan::observe_oracle_io(|| {
            with_scan_clock(now, || {
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
                    )
                })
            })
        });
        let mut frame = prepared.unwrap().expect("due real preparation");
        let quiet_anchor_window = frame.scan.as_ref().unwrap().oracle_quiet_anchor_window();
        frame.scan.as_mut().unwrap().set_oracle_collection_time(&at);
        frame.scan_started_at = at;
        let schedule = self.schedule.map(|schedule| {
            let plan = frame.scan.as_ref().unwrap().oracle_schedule_plan();
            test_effects::record(
                "schedule",
                vec![
                    ("one_chunk", Scalar::Bool(schedule.one_chunk)),
                    (
                        "plan",
                        Scalar::Text(
                            String::from_utf8(crate::canonical_json::canonicalize(&plan).unwrap())
                                .unwrap(),
                        ),
                    ),
                ],
            );
            plan
        });
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
        let worker_births = self.births.clone();
        let (preparation, index, scan, steps, mut io) = run_on_scan_worker_stack(move || {
            let _entered = handle.enter();

            let read = move || {
                with_scan_clock(now, || {
                    let ((preparation, index, scan, steps), io) =
                        crate::snapshots::OwnedSourceScan::observe_oracle_io(|| {
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
            };
            let read =
                || crate::snapshots::OwnedSourceScan::with_oracle_births(worker_births, read);
            if small_page {
                crate::snapshots::with_test_limits_for_test(2048, 1024, 64, || {
                    crate::snapshots::OwnedSourceScan::with_oracle_state_budget(budget, read)
                })
            } else {
                read()
            }
        });
        let gate = scan.trace_projection(&roots);
        test_effects::record(
            "gate_c",
            vec![("snapshots", Scalar::U64(scan.snapshots.len() as u64))],
        );
        let before = scan.snapshots.clone();
        let wire_progress = preparation.upload_progress.clone();
        let capture = FinalizedCapture::start();
        let _evidence = self.schedule.map(|schedule| {
            EvidenceSchedule(ONE_EVIDENCE_CHUNK.with(|slot| slot.replace(schedule.one_chunk)))
        });
        let chunks_before = evidence_chunks_for_test();
        let collection = self.collection();
        let (finish, finish_io) = crate::snapshots::OwnedSourceScan::observe_oracle_io(|| {
            with_scan_clock(now, || {
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
                    )
                })
            })
        });
        for part in [prepare_io, finish_io] {
            io.consumed += part.consumed;
            io.rederive_head += part.rederive_head;
            io.rederive_named += part.rederive_named;
            io.cheap_checks = io.cheap_checks.zip(part.cheap_checks).map(|(a, b)| a + b);
            io.anchor_reads = io.anchor_reads.zip(part.anchor_reads).map(|(a, b)| a + b);
            io.other_reads = io.other_reads.zip(part.other_reads).map(|(a, b)| a + b);
            io.parse_activity = io.parse_activity.zip(part.parse_activity).map(|(a, b)| {
                transition::ParseActivity {
                    header_reads: a.header_reads + b.header_reads,
                    jsonl_parses: a.jsonl_parses + b.jsonl_parses,
                    decoders: a.decoders + b.decoders,
                }
            });
        }
        let mut finalized = capture.take();
        // The PF probe precedes the real uploader's cache-contract projection.
        // Our hint leaves cache negotiation disabled; apply that SAME function
        // to the captured types, then require exact typed/wire correspondence.
        for item in &mut finalized {
            prepare_snapshot_cache_for_upload(item, &wire_progress, false, false, &BTreeSet::new());
        }
        drop(wire_progress);
        let evidence_chunks = evidence_chunks_for_test() - chunks_before;
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
        let debt = if schedule.is_some() {
            let mut debt = index.oracle_schedule_debt(&roots);
            debt["progress"] = json!({
                "quarantine":progress.quarantined_fingerprints.len(),
                "refusal":progress.permanent_rejections.len(),
                "pending_heads":progress.pending_cache_heads.len(),
                "challenges":progress.head_conflict_challenges.len(),
                "retry":progress.active_quarantine_retries.len(),
                "reoffer":progress.active_reason_reoffers.len(),
                "pending_save":progress.terminal_contract_retry_pending_save,
                "receipt_candidates":progress.context_receipt_candidates.len(),
            });
            test_effects::record(
                "page_debt",
                vec![(
                    "state",
                    Scalar::Text(
                        String::from_utf8(crate::canonical_json::canonicalize(&debt).unwrap())
                            .unwrap(),
                    ),
                )],
            );
            debt
        } else {
            Value::Null
        };
        let batches = server.batches.lock().unwrap()[start..].to_vec();
        let cycle = Cycle {
            pre_index_bytes,
            before,
            gate,
            finalized,
            steps,
            consumed: io.consumed,
            io,
            quiet_anchor_window,
            batches,
            acknowledged: server.acknowledged.lock().unwrap()[ack_start..].to_vec(),
            index,
            progress,
            finish,
            effects: recording.take(),
            schedule,
            evidence_chunks,
            debt,
        };
        let mut expected = Vec::new();
        if self.restarted {
            expected.push("restart");
        }
        if self.schedule.is_some() {
            expected.push("schedule");
        }
        expected.extend(std::iter::repeat_n("step", cycle.steps.len()));
        expected.push("gate_c");
        expected.extend(std::iter::repeat_n("finalized", cycle.finalized.len()));
        expected.extend(std::iter::repeat_n("post", cycle.batches.len()));
        expected.push("reloaded");
        if self.schedule.is_some() {
            expected.push("page_debt");
        }
        assert_eq!(
            cycle.effects.iter().map(|e| e.label).collect::<Vec<_>>(),
            expected,
            "ordered native steps, gate c, gate b items, gate a POSTs, reload"
        );
        self.restarted = false;
        money_equivalence_tests::emit_cycle(self.row, self.cycle_number, self.source, &cycle);
        self.cycle_number += 1;
        cycle
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c00_real_runner_collects_finishes_and_reloads() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    home.row = "c00";
    let cycle = home.cycle(&server, &recording);
    assert!(cycle.finish.is_ok());
    assert_eq!(cycle.before.len(), 1);
    assert_eq!(cycle.gate["snapshots"], 1);
    assert_eq!(cycle.finalized.len(), 1);
    assert_eq!(cycle.finalized[0].input_tokens, 30);
    assert!(cycle.consumed > 0);
    assert!(!cycle.steps.is_empty());
    assert_eq!(cycle.batches.len(), 1);
    assert!(cycle.index.generation > 0);
    let item = &cycle.finalized[0];
    assert!(cycle.accepted_body(item));
    assert_eq!(server.placement.lock().unwrap().len(), 1);
    assert!(cycle.effects.iter().any(|e| e.label == "post"));
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
        if matches!(answer, Answer::Dropped | Answer::LostAck) {
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
        assert!(
            cycle.accepted_body(item),
            "exact ACK absent from progress and saved file-body adoption for {}",
            item.source_session_id
        );
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c02_durable_ack_suppresses_replay_of_the_prior_index() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    home.row = "c02";
    let failure = SaveFailure::at("selected_save");
    let first = home.cycle(&server, &recording);
    drop(failure);
    assert!(
        first.finish.is_err(),
        "crash before progress retires its adopted ACK"
    );
    assert_durable(&first);
    assert_eq!(first.progress.accepted_body_witnesses.len(), 1);
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
    home.row = "c03";
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
    home.row = "c04";
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
    cold_home.row = "c04_cold";
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
    home.row = "c05";
    let first = home.cycle(&server, &recording);
    assert!(first.finish.is_ok());
    assert_durable(&first);
    let fingerprint = first.finalized[0].snapshot_fingerprint.clone();
    home.device.device_id = "other-oracle-device".into();
    FileDeviceStore::default().save(&home.device).unwrap();
    let destination = snapshot_upload_destination_namespace(&home.device, "device-secret");
    // A different destination with history on this Mac is a move. Authorize
    // that history through the real claim policy before testing its ACK gate.
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &home.support,
        Some("full"),
        None,
        "synthetic-oracle-user",
        Some(&destination),
    )
    .unwrap();
    crate::backfill::record_first_census(&home.support, home.source, &destination, AT, true)
        .unwrap();
    home.restart();
    *server.fallback.lock().unwrap() = Answer::Unstored;
    let unstored = home.cycle(&server, &recording);
    assert!(unstored.finish.is_ok(), "{:?}", unstored.finish);
    assert_eq!(unstored.batches.len(), 1);
    assert!(unstored.acknowledged.iter().all(Vec::is_empty));
    assert_eq!(unstored.finalized.len(), 1);
    let item = &unstored.finalized[0];
    assert_eq!(item.snapshot_fingerprint, fingerprint);
    assert!(!unstored.accepted_body(item));
    let held = &unstored.index.quarantined_snapshot_fingerprints[&fingerprint];
    assert_eq!(
        held.disposition,
        SnapshotQuarantineDisposition::RetryPending
    );
    let retry_at = held.retry_after_unix_seconds;
    assert!(retry_at > home.now);
    assert_eq!(
        held.upload_body_witness.as_deref(),
        Some(snapshot_upload_body_witness(item).as_str())
    );
    *server.fallback.lock().unwrap() = Answer::Accept;
    home.restart();
    let quiet = home.cycle(&server, &recording);
    assert!(quiet.finish.is_ok(), "{:?}", quiet.finish);
    assert!(
        quiet.batches.is_empty(),
        "an unstored context candidate remains held before its retry deadline"
    );
    assert!(!quiet
        .progress
        .accepted_body_witnesses
        .contains_key(&fingerprint));
    assert!(!quiet
        .index
        .accepted_snapshot_fingerprint_recorded(&fingerprint));
    assert_eq!(
        quiet.index.quarantined_snapshot_fingerprints[&fingerprint], *held,
        "restart preserves the exact unACKed body and its retry deadline"
    );
    // Context receipt candidates keep timed retry custody after Unstored.
    // Retry the unchanged body only after its saved deadline, then require
    // this destination's exact ACK before granting any stored-body credit.
    home.now = retry_at + 1;
    let replay = home.cycle(&server, &recording);
    assert!(replay.finish.is_ok(), "{:?}", replay.finish);
    assert_eq!(replay.batches.len(), 1);
    assert_eq!(replay.acknowledged.len(), 1);
    assert_eq!(replay.acknowledged[0].len(), 1);
    assert_eq!(replay.finalized.len(), 1);
    assert_eq!(replay.finalized[0].snapshot_fingerprint, fingerprint);
    assert_eq!(
        snapshot_upload_body_witness(&replay.finalized[0]),
        snapshot_upload_body_witness(item)
    );
    assert_eq!(replay.finalized[0].input_tokens, 30);
    assert_durable(&replay);
    let placement = server.placement.lock().unwrap().clone();
    assert_eq!(placement.len(), 1);
    home.restart();
    let settled = home.cycle(&server, &recording);
    assert!(settled.finish.is_ok(), "{:?}", settled.finish);
    assert!(
        settled.batches.is_empty(),
        "the exact ACK suppresses replay"
    );
    assert!(settled.acknowledged.is_empty());
    assert_eq!(*server.placement.lock().unwrap(), placement);
    let growth = json!({"type":"assistant","sessionId":IDENTITY_PIPELINE_ROOT,
        "requestId":"fresh-destination-growth","timestamp":"2026-11-01T07:03:00Z",
        "message":{"id":"fresh-destination-growth","model":"claude-haiku-4-5",
        "usage":{"input_tokens":13,"output_tokens":1}}});
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(home.transcript())
            .unwrap(),
        "{growth}"
    )
    .unwrap();
    let accepted = home.cycle(&server, &recording);
    assert!(accepted.finish.is_ok());
    assert_eq!(accepted.batches.len(), 1);
    assert_eq!(accepted.finalized[0].input_tokens, 43);
    assert_ne!(accepted.finalized[0].snapshot_fingerprint, fingerprint);
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
        home.row = match answer {
            Answer::Dropped => "c06_dropped",
            Answer::LostAck => "c06_lost_ack",
            Answer::Accept => "c06_selected_save",
            _ => unreachable!("fixed crash table"),
        };
        *server.fallback.lock().unwrap() = answer;
        let failure = matches!(answer, Answer::Accept).then(|| SaveFailure::at("selected_save"));
        // Full jitter may sample less than one second and round down to zero
        // in persisted custody. This row needs a positive timed hold, so fix
        // the random sample within its valid range on this thread only.
        let first = {
            let _backoff = BackoffMidpoint::start();
            home.cycle(&server, &recording)
        };
        drop(failure);
        assert!(first.finish.is_err());
        // Dropped-before-store and stored-with-lost-ACK are both transport
        // failures; only the selected-save crash has durable exact ACK proof.
        let durable = matches!(answer, Answer::Accept);
        let item = &first.finalized[0];
        assert_eq!(first.accepted_body(item), durable);
        let mut replay_at = home.now + 3600;
        if !durable {
            let custody = &first.progress.quarantined_fingerprints[&item.snapshot_fingerprint];
            assert_eq!(
                custody.disposition,
                SnapshotQuarantineDisposition::RetryPending
            );
            assert!(
                custody.retry_after_unix_seconds > home.now,
                "{}: retry deadline {} must follow fixture clock {}",
                home.row,
                custody.retry_after_unix_seconds,
                home.now
            );
            assert_eq!(
                custody.upload_body_witness.as_deref(),
                Some(snapshot_upload_body_witness(item).as_str())
            );
            replay_at = custody.retry_after_unix_seconds + 1;
        }
        assert_eq!(
            server.placement.lock().unwrap().len(),
            usize::from(!matches!(answer, Answer::Dropped))
        );
        *server.fallback.lock().unwrap() = Answer::Accept;
        home.restore_pre_cycle_index(&first);
        // Transport failure keeps the exact unACKed body in retryable custody.
        // A restart alone does not make that custody's deadline due.
        home.now = replay_at;
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
    install_claude_control_for(home, IDENTITY_PIPELINE_ROOT, "", false);
}

fn install_claude_control_for(
    home: &OracleHome,
    session: &str,
    prefix: &str,
    with_parent_growth: bool,
) {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
        ClaudeLocalOtelEvidence, ClaudeRequestIdentityEvidence, ClaudeTraceOwnershipEvidence,
    };
    let time = |at: &'static str| {
        if prefix == "family-1:" {
            match at {
                "2026-11-01T07:01:00Z" => "2026-11-01T07:04:00Z",
                "2026-11-01T07:02:00Z" => "2026-11-01T07:05:00Z",
                "2026-11-01T07:03:00Z" => "2026-11-01T07:06:00Z",
                "2026-11-01T07:04:00Z" => "2026-11-01T07:07:00Z",
                _ => at,
            }
        } else {
            at
        }
    };
    let transcript = |id: &str, tokens: u64, at: &'static str| {
        let at = time(at);
        let id = format!("{prefix}{id}");
        json!({"type":"assistant",
        "sessionId":session,"version":"2.1.309","timestamp":at,"requestId":id,
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
    let mut requests = [
        ("account-a", 10, 'a', '8', "2026-11-01T07:01:00Z"),
        ("account-b", 20, 'b', '9', "2026-11-01T07:02:00Z"),
        ("side", 7, 'b', '9', "2026-11-01T07:03:00Z"),
    ]
    .into_iter()
    .map(|(request, tokens, account, org, at)| {
        (format!("{prefix}{request}"), tokens, account, org, time(at))
    })
    .collect::<Vec<_>>();
    if with_parent_growth {
        // Accepted behaviour: an account only carried from a deduplicated row may follow
        // the keeper (accepted/disclosed); pin direct evidence for convergence.
        requests.push(("parent-growth".into(), 13, 'b', '9', "2026-11-01T07:05:00Z"));
    }
    for (sequence, (request, tokens, account, org, at)) in requests.into_iter().enumerate() {
        let mut row = ClaudeLocalOtelEvidence {
            capture_revision: "claude_api_request:v2".into(),
            session_id: session.into(),
            request_id: request.clone(),
            client_request_id: format!("client-{request}"),
            observed_at: at.into(),
            model: "claude-haiku-4-5".into(),
            effort: "high".into(),
            query_source: "user".into(),
            app_version: "2.1.309".into(),
            event_sequence: Some(sequence as u64 + 1),
            cost_usd_micros: Some(tokens * 10),
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
            session_id: session.into(),
            request_id: request.clone(),
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
            .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())));
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
    home.row = "c01_claude";
    install_claude_control(&home);
    let inputs = money_equivalence_tests::inputs(&home);
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
            tagged |= row["reasoning_effort"] == "high";
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
    // Carry.on (CI run 44113140067): account-b's copied request never seeds
    // a carry, so the 5-token gap is placed with account-a (the start or
    // its carry), not with the latest own account (b). Totals are unchanged.
    assert_eq!(
        accounts,
        BTreeMap::from([("a".repeat(64), 15), ("b".repeat(64), 27)])
    );
    assert!(tagged);
    money_equivalence_tests::emit_money(
        "once_credit_claude",
        money_equivalence_tests::bodies(SnapshotSource::ClaudeCode, &cold),
        inputs,
    );
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
    transition::money_oracle::assert_quiet_restart_with_anchor_window(
        &quiet_route,
        quiet.quiet_anchor_window,
    );
}

fn codex_member(
    owner: &str,
    response: &str,
    input: u64,
    cumulative: u64,
    created: &str,
) -> Vec<Value> {
    let usage = |n| {
        json!({"input_tokens":n,"cached_input_tokens":0,"cache_write_input_tokens":0,
        "output_tokens":0,"reasoning_output_tokens":0,"total_tokens":n})
    };
    crate::snapshots::codex_bound_fixture_rows(&[
        json!({"type":"session_meta","timestamp":created,"payload":{"id":owner}}),
        json!({"type":"token_usage_record","timestamp":"2026-11-01T07:01:00Z","payload":{
            "thread_id":owner,"response_id":response,"usage":usage(input),"thread_token_usage":usage(cumulative)}}),
        json!({"type":"event_msg","timestamp":"2026-11-01T07:01:01Z","payload":{"type":"token_count",
            "info":{"model":"gpt-5.2","last_token_usage":usage(input),"total_token_usage":usage(cumulative)}}}),
    ])
}

fn write_jsonl(path: &Path, rows: &[Value]) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        path,
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

fn install_group(home: &OracleHome, overlap: bool) {
    let root = home.source.default_roots(&home.fixture.home)[0].clone();
    if overlap {
        write_jsonl(
            &root.join("a.jsonl"),
            &codex_member(
                IDENTITY_PIPELINE_ROOT,
                "a",
                100,
                100,
                "2026-11-01T07:00:00Z",
            ),
        );
        write_jsonl(
            &root.join("b.jsonl"),
            &codex_member(
                IDENTITY_PIPELINE_ROOT,
                "b",
                200,
                250,
                "2026-11-01T07:01:00Z",
            ),
        );
    } else {
        for (name, start, created) in [
            ("a", 0, "2026-11-01T07:00:00Z"),
            ("b", 300, "2026-11-01T07:30:00Z"),
        ] {
            let mut rows = Vec::new();
            for n in 0..30 {
                let mut pair = codex_member(
                    IDENTITY_PIPELINE_ROOT,
                    &format!("{name}-{n}"),
                    10,
                    start + 10 * (n + 1),
                    created,
                );
                if n == 0 {
                    rows.push(pair.remove(0));
                } else {
                    pair.remove(0);
                }
                rows.extend(pair);
            }
            write_jsonl(&root.join(format!("{name}.jsonl")), &rows);
        }
    }
}

fn last_counter(cycle: &Cycle, name: &str) -> u64 {
    cycle.steps.last().unwrap()["before"][name]
        .as_u64()
        .unwrap()
}

fn assert_redisclosed(first: &Cycle, quiet: &Cycle) {
    assert_eq!(quiet.consumed, 0, "memo/park never consumes parser bytes");
    assert!(quiet.before.is_empty() && quiet.finalized.is_empty() && quiet.batches.is_empty());
    for field in [
        "pending_finalization",
        "ownership_incomplete_file_count",
        "residue_count",
        "census_complete",
        "scanned_session_count",
    ] {
        assert_eq!(
            quiet.gate[field], first.gate[field],
            "re-disclosure/{field}"
        );
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c07_codex_group_memo_rediscloses_without_session_credit() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::Codex, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::Codex, &server);
    home.row = "c07";
    install_group(&home, true);
    let first = home.cycle(&server, &recording);
    assert!(first.consumed > 0);
    assert_eq!(last_counter(&first, "memo_records"), 1);
    home.now += 86_400;
    let quiet = home.cycle(&server, &recording);
    assert_eq!(
        last_counter(&quiet, "memo_hits"),
        last_counter(&first, "memo_hits") + 1
    );
    assert_eq!(quiet.gate["scanned_session_count"], 0);
    assert_redisclosed(&first, &quiet);
    assert!(server.placement.lock().unwrap().is_empty());
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c08_codex_group_park_rediscloses_without_reading() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::Codex, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::Codex, &server);
    home.row = "c08";
    install_group(&home, false);
    home.small_page = true;
    home.state_budget = Some(1);
    let first = home.cycle(&server, &recording);
    assert!(first.consumed > 0);
    assert_eq!(last_counter(&first, "jobs_state_bound"), 1);
    home.state_budget = None;
    home.now += 86_400;
    let quiet = home.cycle(&server, &recording);
    assert_eq!(
        last_counter(&quiet, "parked_hits"),
        last_counter(&first, "parked_hits") + 1
    );
    assert_eq!(quiet.gate["scanned_session_count"], 0);
    assert_redisclosed(&first, &quiet);
    assert!(server.placement.lock().unwrap().is_empty());
}

fn install_created_thread(home: &OracleHome, fork: bool, session: &str, priority: bool) {
    let root = home.source.default_roots(&home.fixture.home)[0].clone();
    let path = root.join(format!("rollout-{session}.jsonl"));
    let turn = |n| format!("1338a80a-5000-7000-8000-{n:012}");
    let usage = |(input, cached, output, reasoning)| {
        json!({"input_tokens":input,
        "cached_input_tokens":cached,"output_tokens":output,"reasoning_output_tokens":reasoning})
    };
    let tokens = |at, total, last| {
        json!({"timestamp":at,"type":"event_msg","payload":{"type":"token_count",
        "info":{"total_token_usage":usage(total),"last_token_usage":usage(last),"model":"gpt-5.6-sol"}}})
    };
    let mut meta = json!({"id":session,"session_id":session,
        "timestamp":"2026-11-01T07:00:00Z","history_mode":"paginated","thread_source":"agent_created_thread",
        "source":"vscode","originator":"Codex Desktop","creator_user_id":format!("synthetic-user-{session}"),"creator_account_id":format!("synthetic-workspace-{session}")});
    if fork {
        meta["forked_from_id"] = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5".into();
    }
    let mut rows = vec![
        json!({"timestamp":"2026-11-01T07:00:00.500Z","type":"session_meta","payload":meta}),
        json!({"timestamp":"2026-11-01T07:00:00.501Z","type":"event_msg","payload":{"type":"task_started",
            "turn_id":turn(1),"started_at":NOW-10800,"trace_id":"0123456789abcdef0123456789abcdef"}}),
        json!({"timestamp":"2026-11-01T07:00:01Z","type":"turn_context","payload":{"turn_id":turn(1),"model":"gpt-5.6-sol","service_tier":"priority"}}),
        tokens("2026-11-01T07:00:02Z", (120, 100, 6, 2), (120, 100, 6, 2)),
        json!({"timestamp":"2026-11-01T07:00:03Z","type":"compacted","payload":{"replacement_history":[]}}),
        json!({"timestamp":"2026-11-01T07:00:03.500Z","type":"event_msg","payload":{"type":"task_complete","turn_id":turn(1)}}),
        json!({"timestamp":"2026-11-01T07:00:04Z","type":"event_msg","payload":{"type":"task_started","turn_id":turn(2),"started_at":NOW-10796}}),
        json!({"timestamp":"2026-11-01T07:00:04.100Z","type":"turn_context","payload":{"turn_id":turn(2),"model":"gpt-5.6-sol","service_tier":"priority"}}),
        tokens("2026-11-01T07:00:05Z", (50, 40, 3, 1), (50, 40, 3, 1)),
        tokens("2026-11-01T07:00:06Z", (80, 60, 5, 1), (30, 20, 2, 0)),
    ];
    for (ordinal, row) in rows.iter_mut().enumerate() {
        row["ordinal"] = json!(ordinal);
        if !priority && row["type"] == "turn_context" {
            row["payload"]
                .as_object_mut()
                .unwrap()
                .remove("service_tier");
        }
    }
    write_jsonl(&path, &rows);
    let db = rusqlite::Connection::open(root.parent().unwrap().join("state_5.sqlite")).unwrap();
    db.execute_batch("CREATE TABLE IF NOT EXISTS threads (id TEXT NOT NULL,title TEXT,tokens_used INTEGER NOT NULL,thread_source TEXT,first_user_message TEXT,created_at_ms INTEGER,rollout_path TEXT); CREATE TABLE IF NOT EXISTS thread_spawn_edges(parent_thread_id TEXT NOT NULL,child_thread_id TEXT NOT NULL);").unwrap();
    db.execute("DELETE FROM threads WHERE id=?1", [session])
        .unwrap();
    db.execute(
        "INSERT INTO threads VALUES (?1,'Thread',1,'agent_created_thread','Synthetic task',?2,?3)",
        rusqlite::params![
            session,
            ((NOW - 10800) * 1000) as i64,
            path.to_string_lossy().into_owned()
        ],
    )
    .unwrap();
    let history =
        rusqlite::Connection::open(root.parent().unwrap().join("thread_history_1.sqlite")).unwrap();
    history.execute_batch("CREATE TABLE IF NOT EXISTS thread_history_projection_state(thread_id TEXT NOT NULL,next_rollout_byte_offset INTEGER NOT NULL,next_rollout_ordinal INTEGER NOT NULL);").unwrap();
    history
        .execute(
            "DELETE FROM thread_history_projection_state WHERE thread_id=?1",
            [session],
        )
        .unwrap();
    history
        .execute(
            "INSERT INTO thread_history_projection_state VALUES (?1,?2,?3)",
            rusqlite::params![
                session,
                std::fs::metadata(path).unwrap().len() as i64,
                rows.len() as i64
            ],
        )
        .unwrap();
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c09_codex_singleton_memo_keeps_the_previous_body() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::Codex, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::Codex, &server);
    home.row = "c09";
    // A rewritten priority prefix is held by TierReplay before native
    // ownership completion and memo admission. Exercise the ownership memo
    // with default-tier usage; the native money row keeps positive priority.
    install_created_thread(&home, false, IDENTITY_PIPELINE_ROOT, false);
    let cold = home.cycle(&server, &recording);
    assert!(cold.finish.is_ok());
    assert_durable(&cold);
    assert_eq!(
        cold.finalized[0].input_tokens, 120,
        "V2 publishes the closed first turn; the second is pending"
    );
    assert!(cold.index.files.values().all(|entry| {
        entry.codex_applied_tier_receipt.is_none()
            && !entry.codex_applied_tier_receipt_required
            && entry.codex_captured_tier_receipt.is_none()
            && !entry.codex_captured_tier_receipt_required
    }));
    let placement = server.placement.lock().unwrap().clone();
    install_created_thread(&home, true, IDENTITY_PIPELINE_ROOT, false);
    // This is a header rewrite, not an append. Change its listing stamp and
    // make the retained listing due so the real path takes a fresh Full read.
    std::fs::File::options()
        .write(true)
        .open(
            home.source.default_roots(&home.fixture.home)[0]
                .join(format!("rollout-{IDENTITY_PIPELINE_ROOT}.jsonl")),
        )
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 1800))
        .unwrap();
    home.age_listing();
    let held = home.cycle(&server, &recording);
    assert!(
        held.consumed > 0,
        "the rewritten header must actually be parsed"
    );
    assert_eq!(held.gate["ownership_incomplete_file_count"], 1);
    assert_eq!(last_counter(&held, "full_files"), 1);
    assert_eq!(last_counter(&held, "memo_records"), 1);
    assert!(held.gate["pending_finalization"][0]["previous_snapshot"]
        .as_bool()
        .unwrap());
    assert!(held.gate["pending_finalization"][0]["previous_witness"]
        .as_bool()
        .unwrap());
    home.now += 86_400;
    home.age_listing();
    let quiet = home.cycle(&server, &recording);
    assert_eq!(
        last_counter(&quiet, "memo_hits"),
        last_counter(&held, "memo_hits") + 1
    );
    // Ownership-incomplete Codex conversion constructs no native items, so
    // the memo's replayed parsed_snapshot_count is exactly zero on this input.
    assert_eq!(quiet.gate["scanned_session_count"], 0);
    assert_redisclosed(&held, &quiet);
    assert_eq!(*server.placement.lock().unwrap(), placement);
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c10_codex_singleton_park_keeps_the_previous_body() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::Codex, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::Codex, &server);
    home.row = "c10";
    let mut rows = codex_member(
        IDENTITY_PIPELINE_ROOT,
        "first",
        100,
        100,
        "2026-11-01T07:00:00Z",
    );
    home.write_rows(&rows);
    let cold = home.cycle(&server, &recording);
    assert!(cold.finish.is_ok());
    assert_durable(&cold);
    let placement = server.placement.lock().unwrap().clone();
    for n in 0..80 {
        let mut pair = codex_member(
            IDENTITY_PIPELINE_ROOT,
            &format!("append-{n}"),
            10,
            110 + 10 * n,
            "2026-11-01T07:00:00Z",
        );
        pair.remove(0);
        rows.extend(pair);
    }
    home.write_rows(&rows);
    home.small_page = true;
    home.state_budget = Some(1);
    let held = home.cycle(&server, &recording);
    assert_eq!(last_counter(&held, "jobs_state_bound"), 1);
    home.state_budget = None;
    home.now += 86_400;
    let quiet = home.cycle(&server, &recording);
    assert_eq!(
        last_counter(&quiet, "parked_hits"),
        last_counter(&held, "parked_hits") + 1
    );
    assert_eq!(quiet.gate["scanned_session_count"], 0);
    assert_eq!(
        quiet.gate["pending_finalization"][0]["parse_complete"],
        false
    );
    assert_eq!(
        quiet.gate["pending_finalization"][0]["previous_snapshot"],
        true
    );
    assert_eq!(
        quiet.gate["pending_finalization"][0]["previous_witness"],
        true
    );
    assert_redisclosed(&held, &quiet);
    assert_eq!(*server.placement.lock().unwrap(), placement);
}

fn fragment_corpus(home: &OracleHome) {
    let mut rows = Vec::new();
    for n in 0..30 {
        let mut pair = codex_member(
            IDENTITY_PIPELINE_ROOT,
            &format!("fragment-{n}"),
            10,
            10 * (n + 1),
            "2026-11-01T07:00:00Z",
        );
        if n == 0 {
            rows.push(pair.remove(0));
        } else {
            pair.remove(0);
        }
        rows.extend(pair);
    }
    home.write_rows(&rows);
    // A valid trailing JSON record would be applied at genuine EOF. Invalid
    // unterminated bytes stay withheld, producing a real cursor fragment.
    std::fs::OpenOptions::new()
        .append(true)
        .open(home.transcript())
        .unwrap()
        .write_all(b"{\"type\":")
        .unwrap();
    std::fs::File::options()
        .write(true)
        .open(home.transcript())
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 3600))
        .unwrap();
}

fn finish_fragment(
    home: &mut OracleHome,
    server: &OracleServer,
    recording: &Recording,
    outlive: bool,
) -> Cycle {
    for page in 0..64 {
        let cycle = home.cycle(server, recording);
        if !cycle.gate["pending_finalization"]
            .as_array()
            .unwrap()
            .is_empty()
        {
            assert!(cycle.gate["pending_finalization"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["parse_complete"] == true));
            return cycle;
        }
        assert!(cycle.before.is_empty() && cycle.finalized.is_empty() && cycle.batches.is_empty());
        if page == 0 && outlive {
            home.now = NOW + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS + 1;
        }
    }
    panic!("fragment file did not reach native completion");
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c11_fragment_and_obligation_charge_one_slot_and_existing_marker_charges_none() {
    for outlive in [false, true] {
        let recording = Recording::start();
        let server = OracleServer::new(SnapshotSource::Codex, recording.handle());
        let mut home = OracleHome::new(SnapshotSource::Codex, &server);
        home.row = if outlive { "c11_both" } else { "c11_marker" };
        home.small_page = true;
        fragment_corpus(&home);
        let new = finish_fragment(&mut home, &server, &recording, outlive);
        assert_eq!(new.before.len(), 1);
        assert_eq!(new.before[0].input_tokens, 300);
        let slots = crate::transcript_cache::CACHE_ENTRIES as u64;
        assert_eq!(new.steps[0]["before"]["audit_slots"], slots);
        assert_eq!(
            last_counter(&new, "audit_slots"),
            slots - 1,
            "fragment alone, or an outlived Full obligation plus fragment, reserves one slot"
        );
        assert_eq!(last_counter(&new, "audit_cap_delay"), 0);
        if !outlive {
            // The future marker already exists. A same-byte stat edit forces
            // another Full; marker carry survives record() before staging.
            std::fs::File::options()
                .write(true)
                .open(home.transcript())
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + Duration::from_secs(NOW - 1800))
                .unwrap();
            let existing = finish_fragment(&mut home, &server, &recording, false);
            assert_eq!(existing.steps[0]["before"]["audit_slots"], slots - 1);
            assert_eq!(
                last_counter(&existing, "audit_slots"),
                slots - 1,
                "an existing marker reserves no second slot"
            );
        }
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn c11_account_hold_bypasses_the_full_audit_cap_without_staging_a_marker() {
    let recording = Recording::start();
    let server = OracleServer::new(SnapshotSource::ClaudeCode, recording.handle());
    let mut home = OracleHome::new(SnapshotSource::ClaudeCode, &server);
    home.row = "c11_account_hold";
    let cold = home.cycle(&server, &recording);
    assert!(cold.finish.is_ok());
    assert_durable(&cold);
    let deferred = cold
        .finalized
        .iter()
        .map(|item| (item.snapshot_fingerprint.clone(), item.input_tokens))
        .collect::<BTreeMap<_, _>>();
    let mut index = cold.index.clone();
    index.oracle_hold_at_audit_cap(
        &home.transcript(),
        &deferred,
        NOW + crate::transcript_acquisition::AUDIT_INTERVAL_SECONDS,
    );
    crate::snapshots::e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    index.save_fixture(&home.index_path()).unwrap();
    let row = json!({"type":"assistant","sessionId":IDENTITY_PIPELINE_ROOT,
        "version":"2.1.309","timestamp":"2026-11-01T07:03:00Z","requestId":"held-growth",
        "message":{"id":"held-growth-message","model":"claude-haiku-4-5",
            "usage":{"input_tokens":130,"output_tokens":13}}});
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(home.transcript())
            .unwrap(),
        "{row}"
    )
    .unwrap();
    let held = home.cycle(&server, &recording);
    assert_eq!(held.steps[0]["before"]["audit_slots"], 0);
    assert_eq!(last_counter(&held, "full_files"), 0);
    assert_eq!(last_counter(&held, "tail_files"), 1);
    assert_eq!(
        last_counter(&held, "audit_cap_delay"),
        0,
        "account custody bypasses the refusal despite an unfunded new marker"
    );
    assert_eq!(
        last_counter(&held, "audit_marker_count"),
        crate::transcript_cache::CACHE_ENTRIES as u64,
        "the held retry cannot stage another marker"
    );
    assert_eq!(
        held.before.len(),
        1,
        "held retry reaches complete native publication"
    );
    assert_eq!(held.before[0].input_tokens, 160);
}

// Distinct telemetry ids per root; native copied ids retain their original bytes.
// Independent locations stay queued when related-file pulls expand a page.
// Claude also keeps a byte-identical content twin beside its session's main.
fn scheduling_corpus(home: &OracleHome, seed_only: bool) -> Vec<(PathBuf, String)> {
    let root = home.source.default_roots(&home.fixture.home)[0].clone();
    let sessions = [
        IDENTITY_PIPELINE_ROOT,
        "3338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "4338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "5338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "6338a80a-f36e-4cbc-a5bb-50fc66430ba5",
    ];
    let mut paths = Vec::new();
    let mut parent = Vec::<Value>::new();
    for n in 0..5 {
        let session = if n == 3 && home.source != SnapshotSource::Pi {
            sessions[0]
        } else {
            sessions[n]
        };
        let mut rows = match home.source {
            SnapshotSource::ClaudeCode if n == 3 => {
                let mut rows = parent.clone();
                let mut growth = rows[2].clone();
                growth["requestId"] = json!("parent-growth");
                growth["message"]["id"] = json!("msg-parent-growth");
                growth["timestamp"] = json!("2026-11-01T07:05:00Z");
                growth["message"]["usage"] = json!({"input_tokens":13,"output_tokens":13});
                rows.push(growth);
                rows
            }
            SnapshotSource::ClaudeCode => {
                install_claude_control_for(
                    home,
                    session,
                    &format!("family-{n}:"),
                    n == 0 && !seed_only,
                );
                std::fs::read_to_string(home.transcript())
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str::<Value>(line).unwrap())
                    .collect()
            }
            SnapshotSource::Codex => codex_member(
                session,
                &format!("member-{n}"),
                if n == 3 { 200 } else { 100 },
                if n == 3 { 300 } else { 100 },
                if n == 3 {
                    "2026-11-01T07:01:00Z"
                } else {
                    "2026-11-01T07:00:00Z"
                },
            ),
            SnapshotSource::Pi => {
                let mut rows = pi_rows(false);
                rows[0]["id"] = json!(session);
                rows
            }
        };
        if n == 0 {
            parent = rows.clone();
        }
        if home.source == SnapshotSource::ClaudeCode {
            if n == 1 {
                for original in parent.iter().take(2).rev() {
                    let mut copied = original.clone();
                    copied["sessionId"] = json!(session);
                    rows.insert(0, copied);
                }
            }
            for row in &mut rows {
                row["cwd"] = json!("/synthetic/workspace");
            }
        }
        let folder = if n == 1 && home.source == SnapshotSource::ClaudeCode {
            // Claude resumes share their parent's cwd-derived project folder.
            0
        } else {
            [0, 2, 1, 3, 4][n]
        };
        let path = root.join(format!("{folder}-member/{session}.jsonl"));
        write_jsonl(&path, &rows);
        paths.push((path, session.into()));
        if seed_only {
            break;
        }
    }
    if home.source == SnapshotSource::ClaudeCode {
        if !seed_only {
            let twin = paths[1].0.with_file_name(format!("{}.jsonl", sessions[3]));
            std::fs::copy(&paths[1].0, &twin).unwrap();
            paths.push((twin, sessions[1].into()));
        }
        std::fs::remove_file(home.transcript()).unwrap();
    }
    paths
}

fn schedule_debt_is_clear(debt: &Value) -> bool {
    schedule_money_debt_is_clear(debt) && debt["pending"] == 0
}

fn schedule_money_debt_is_clear(debt: &Value) -> bool {
    debt["holds"].as_object().unwrap().is_empty()
        && debt["owed"].as_array().unwrap().is_empty()
        && debt["copy_wait"].as_array().unwrap().is_empty()
        && ["debt", "progress"].into_iter().all(|part| {
            debt[part]
                .as_object()
                .unwrap()
                .values()
                .all(|v| v == &json!(0) || v == &json!(false) || v.is_null())
        })
}

// Update by logical session after EACH exact ACK, retaining earlier-cycle heads.
// Holds explain withheld candidates; they never license a smaller accepted body.
fn schedule_accepts(source: SnapshotSource, cycle: &Cycle, latest: &mut BTreeMap<String, Value>) {
    let normalized = money_equivalence_tests::normalized_posts(source, cycle);
    assert_eq!(
        normalized.len(),
        cycle.acknowledged.len(),
        "every scripted POST has an exact ACK"
    );
    for (posts, proved) in normalized.into_iter().zip(&cycle.acknowledged) {
        let before = latest.clone();
        for batch in posts.as_array().unwrap() {
            assert_eq!(batch["snapshots"].as_array().unwrap().len(), proved.len());
            for row in batch["snapshots"].as_array().unwrap() {
                assert!(proved
                    .iter()
                    .any(|raw| raw["source_session_id"] == row["source_session_id"]
                        && raw["snapshot_fingerprint"] == row["snapshot_fingerprint"]));
                let entity = row["source_session_id"].as_str().unwrap().to_owned();
                let mut body = row.clone();
                body.as_object_mut().unwrap().remove("collected_at");
                latest.insert(
                    entity,
                    json!({"body":body,"placement":{
                    "source":batch["source"],"machine_id":batch["machine_id"]}}),
                );
            }
        }
        let families = |heads: &BTreeMap<String, Value>| {
            let mut counts = BTreeMap::<String, u64>::new();
            for (entity, row) in heads {
                *counts
                    .entry(entity.split("_agent-").next().unwrap().into())
                    .or_default() += row["body"]["request_count"].as_u64().unwrap();
            }
            counts
        };
        for (entity, old) in &before {
            assert!(
                latest[entity]["body"]["request_count"].as_u64().unwrap()
                    >= old["body"]["request_count"].as_u64().unwrap(),
                "accepted entity dip: {entity}"
            );
        }
        let after_families = families(latest);
        for (family, old) in families(&before) {
            assert!(
                after_families[&family] >= old,
                "accepted family dip: {family}"
            );
        }
    }
    for raw in cycle
        .acknowledged
        .iter()
        .flatten()
        .rev()
        .fold(BTreeMap::new(), |mut heads, raw| {
            heads
                .entry(raw["source_session_id"].as_str().unwrap())
                .or_insert(raw);
            heads
        })
        .values()
    {
        let item = cycle
            .finalized
            .iter()
            .find(|s| {
                raw["snapshot_fingerprint"] == s.snapshot_fingerprint
                    && raw["source_file_fingerprint"] == json!(s.source_file_fingerprint)
            })
            .unwrap();
        assert!(cycle.accepted_body(item));
    }
}

fn assert_schedule_root_placement_stable(
    cycle: &Cycle,
    accepted: &BTreeMap<String, Value>,
    root_locations: &[(String, String)],
    first_split: &mut Option<(usize, Value)>,
    cycle_index: usize,
    context: &str,
) {
    if root_locations.len() != 2 {
        return; // Pi has distinct sessions at these locations, not ROOT twins.
    }
    if first_split.is_none() {
        // Reuse the saved index and the existing per-path debt projection:
        // an all-copy twin may be decided empty rather than carry an ACK.
        let both_decided = root_locations.iter().all(|(key, relative)| {
            cycle.index.files.contains_key(key)
                && ["owed", "copy_wait"].into_iter().all(|part| {
                    !cycle.debt[part]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|path| path.as_str() == Some(relative.as_str()))
                })
        }) && cycle.debt["holds"].get(IDENTITY_PIPELINE_ROOT).is_none();
        if !both_decided || !accepted.contains_key(IDENTITY_PIPELINE_ROOT) {
            return;
        }
    }
    let mut split = accepted[IDENTITY_PIPELINE_ROOT]["body"]["model_usage"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            let shares = row["identity_parts"]
                .as_array()
                .map(|parts| parts.iter().collect::<Vec<_>>())
                .unwrap_or_else(|| vec![row]);
            let mut accounts = shares
                .into_iter()
                .map(|share| {
                    (
                        share["account_identifier_hash"].as_str().map(str::to_owned),
                        share["input_tokens"].as_u64().unwrap(),
                        share["output_tokens"].as_u64().unwrap(),
                        share["request_count"].as_u64().unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            accounts.sort();
            (row["model"].as_str().unwrap().to_owned(), accounts)
        })
        .collect::<Vec<_>>();
    split.sort();
    let split = json!(split);
    if let Some((first_cycle, expected)) = first_split.as_ref() {
        assert_eq!(
            &split, expected,
            "BUG: ROOT same-machine placement moved: {context}, cycle {cycle_index}, first cycle {first_cycle}, first split {expected}, current split {split}"
        );
    } else {
        *first_split = Some((cycle_index, split));
    }
}

// Sort the actual full-path keys, then assign growth to each end in turn. Fixed
// relative names alone cannot pin a hash order under a unique temporary root.
fn equal_birth_twins(home: &OracleHome) -> [PathBuf; 2] {
    use crate::snapshots::claude_money_birth_store::location_key;
    let root = home.source.default_roots(&home.fixture.home)[0].clone();
    let mut paths = ["a-copy", "z-original"].map(|dir| {
        root.join(dir)
            .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"))
    });
    paths.sort_by_key(|path| location_key(&path.to_string_lossy()));
    assert!(
        location_key(&paths[0].to_string_lossy()) < location_key(&paths[1].to_string_lossy()),
        "equal-birth twins must have distinct, explicitly ordered full-path keys"
    );
    paths
}

fn assert_twin_request_survives(index: &ScanIndex, request: &str, locations: &[PathBuf]) {
    use crate::snapshots::claude_money_birth_store::location_key;
    use crate::snapshots::claude_request_census::claude_request_hash;
    let hash = claude_request_hash(request);
    let removed = locations
        .iter()
        .filter(|path| {
            index
                .claude_copy_removals
                .get(location_key(&path.to_string_lossy()))
                .iter()
                .any(|(_, hashes)| hashes.binary_search(&hash).is_ok())
        })
        .count();
    assert!(
        removed < locations.len(),
        "request {request} removed at every location of its session: {removed}/{}",
        locations.len()
    );
}

// Seed a positive r1 ACK, then put that same pre-birth request at both homes.
// The twins' first page must still count r1 once. Grow the earlier and later
// location in separate arms, crossing discovery, finish and restart schedules.
fn scheduling_equal_birth_twins(before_cutoff: bool) {
    let source = SnapshotSource::ClaudeCode;
    let (copied_at, born_at, own_at) = if before_cutoff {
        (
            "2026-11-03T07:00:10Z",
            "2026-11-03T07:02:00Z",
            "2026-11-03T07:04:00Z",
        )
    } else {
        (
            "2026-11-06T07:00:10Z",
            "2026-11-06T07:02:00Z",
            "2026-11-06T07:04:00Z",
        )
    };
    let birth = OffsetDateTime::parse(born_at, &Rfc3339)
        .unwrap()
        .unix_timestamp_nanos() as u64;
    let response = |request: &str, at: &str, tokens: u64| {
        json!({"type":"assistant","sessionId":IDENTITY_PIPELINE_ROOT,
            "version":"2.1.309","timestamp":at,"requestId":request,
            "message":{"id":format!("msg-{request}"),"model":"claude-haiku-4-5",
                "usage":{"input_tokens":tokens,"output_tokens":tokens}}})
    };
    // r1 is copied; r2 is the first own response. Both must move with birth
    // to cross COPY_PROOF_FROM without making the growth an all-copy file.
    let r1 = response("r1", copied_at, 10);
    let r2 = response("r2", own_at, 20);
    let mut baseline = None;
    let mut run = 0;
    let mut tie_orders = BTreeSet::new();
    for growing in [0, 1] {
        for one_chunk in [true, false] {
            for limit in [3, 2] {
                for reverse in [false, true] {
                    for restart in [false, true] {
                        let recording = Recording::start();
                        let server = OracleServer::new(source, recording.handle());
                        let mut home = OracleHome::new(source, &server);
                        home.now = OffsetDateTime::parse("2026-11-06T10:00:00Z", &Rfc3339)
                            .unwrap()
                            .unix_timestamp() as u64;
                        home.row = if before_cutoff {
                            "schedule_equal_birth_twins_before_cutoff"
                        } else {
                            "schedule_equal_birth_twins"
                        };
                        home.cycle_number = run * 128;
                        home.schedule = Some(Schedule {
                            one_chunk,
                            limit,
                            reverse,
                        });
                        let paths = equal_birth_twins(&home);
                        let other = 1 - growing;
                        use crate::snapshots::claude_money_birth_store::location_key;
                        let growth_first = location_key(&paths[growing].to_string_lossy())
                            < location_key(&paths[other].to_string_lossy());
                        assert_eq!(growth_first, growing == 0, "pin both birth tie orders");
                        tie_orders.insert(growth_first);
                        home.births = paths
                            .iter()
                            .map(|path| (path.to_string_lossy().into_owned(), birth))
                            .collect();
                        std::fs::remove_file(home.transcript()).unwrap();
                        write_jsonl(&paths[0], std::slice::from_ref(&r1));
                        let mut accepted = BTreeMap::new();
                        let seed = home.cycle(&server, &recording);
                        assert!(seed.finish.is_ok());
                        schedule_accepts(source, &seed, &mut accepted);
                        assert_eq!(accepted.len(), 1);
                        assert_eq!(accepted[IDENTITY_PIPELINE_ROOT]["body"]["request_count"], 1);
                        drop(seed);

                        write_jsonl(&paths[1], std::slice::from_ref(&r1));
                        home.age_listing();
                        home.now += 3600;
                        let first = home.cycle(&server, &recording);
                        assert!(first.finish.is_ok());
                        schedule_accepts(source, &first, &mut accepted);
                        assert_eq!(
                            first.finalized.len(),
                            1,
                            "first twin page emits its removal"
                        );
                        assert_eq!(
                            (
                                first.finalized[0].request_count,
                                first.finalized[0].removed_request_count
                            ),
                            (1, Some(1)),
                            "first twin page counts r1 once"
                        );
                        assert_eq!(first.finalized[0].input_tokens, 10);
                        for path in &paths {
                            let key = path.to_string_lossy();
                            assert!(first.index.files.contains_key(key.as_ref()));
                            assert_eq!(
                                first
                                    .index
                                    .claude_money_birth_store
                                    .observed_birth(IDENTITY_PIPELINE_ROOT, &key),
                                Some(i128::from(birth)),
                                "both physical births remain equal"
                            );
                        }
                        assert_twin_request_survives(&first.index, "r1", &paths);
                        let first_body = accepted.clone();
                        drop(first);
                        if before_cutoff {
                            // Re-read the counting path as the changed file so
                            // it carries the summed body's COPY mark as well
                            // as its positive ACK. Blank JSONL changes no usage.
                            writeln!(std::fs::OpenOptions::new()
                                .append(true)
                                .open(&paths[0])
                                .unwrap())
                            .unwrap();
                            std::fs::File::options()
                                .write(true)
                                .open(&paths[0])
                                .unwrap()
                                .set_modified(
                                    std::time::UNIX_EPOCH + Duration::from_secs(home.now - 1800),
                                )
                                .unwrap();
                            home.age_listing();
                            home.now += 3600;
                            let carrier = home.cycle(&server, &recording);
                            assert!(carrier.finish.is_ok());
                            schedule_accepts(source, &carrier, &mut accepted);
                            assert_eq!(accepted, first_body, "carrier refresh changes no body");
                            assert!(schedule_debt_is_clear(&carrier.debt));
                            assert_twin_request_survives(&carrier.index, "r1", &paths);
                            drop(carrier);
                        }
                        if restart {
                            home.cold_restart();
                        }
                        if before_cutoff {
                            let index = ScanIndex::load(&home.index_path()).unwrap();
                            crate::snapshots::claude_request_money::e2::pipeline_test_observer::assert_counting_twin_grandfather_premise(
                                &index,
                                &paths[0],
                                &paths[1],
                                copied_at,
                                own_at,
                            );
                        }
                        writeln!(
                            std::fs::OpenOptions::new()
                                .append(true)
                                .open(&paths[growing])
                                .unwrap(),
                            "{r2}"
                        )
                        .unwrap();
                        std::fs::File::options()
                            .write(true)
                            .open(&paths[growing])
                            .unwrap()
                            .set_modified(
                                std::time::UNIX_EPOCH + Duration::from_secs(home.now - 1800),
                            )
                            .unwrap();
                        home.age_listing();
                        home.now += 3600;
                        let changed = home.cycle(&server, &recording);
                        assert!(changed.finish.is_ok());
                        assert_eq!(changed.finalized.len(), 1, "growth emits the twin session");
                        let body = &changed.finalized[0];
                        assert_eq!(
                            (body.request_count, body.removed_request_count),
                            (2, Some(1)),
                            "equal-birth twin growth must retain r1: before_cutoff={before_cutoff} growth_first={growth_first} reverse={reverse} restart={restart} limit={limit} one_chunk={one_chunk}"
                        );
                        assert_eq!((body.input_tokens, body.output_tokens), (30, 30));
                        assert_twin_request_survives(&changed.index, "r1", &paths);
                        assert_twin_request_survives(
                            &changed.index,
                            "r2",
                            &paths[growing..=growing],
                        );
                        schedule_accepts(source, &changed, &mut accepted);
                        assert_eq!(accepted.len(), 1);
                        assert!(schedule_debt_is_clear(&changed.debt));
                        let bodies = json!({"first":first_body,"grown":accepted});
                        if let Some(expected) = &baseline {
                            assert_eq!(
                                &bodies, expected,
                                "equal-birth full bodies, totals, removals and placement converge"
                            );
                        } else {
                            baseline = Some(bodies);
                        }
                        run += 1;
                    }
                }
            }
        }
    }
    assert_eq!(tie_orders, BTreeSet::from([false, true]));
    assert_eq!(run, 32);
}

/// [money] Real prepare pages, evidence chunks and cold restarts change scheduling
/// only. Distinct sidecar ids exclude the separately documented context-tripwire
/// counterexample. This base predates the named copy-first correction (#1730);
/// that unseeded correction case alone is unavailable here.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn scheduling_permutations_converge_to_the_same_bodies() {
    scheduling_equal_birth_twins(false);
    scheduling_equal_birth_twins(true);
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut baseline = None;
        let mut baseline_inputs = None;
        let mut forward_orders = BTreeMap::new();
        let mut run = 0;
        for one_chunk in [true, false] {
            for limit in [3, 2] {
                for (restart, late) in [(false, false), (true, false), (false, true), (true, true)]
                {
                    if source != SnapshotSource::ClaudeCode && late {
                        continue;
                    }
                    for reverse in [false, true] {
                        let recording = Recording::start();
                        let server = OracleServer::new(source, recording.handle());
                        let mut home = OracleHome::new(source, &server);
                        home.row = match source {
                            SnapshotSource::ClaudeCode => "schedule_claude",
                            SnapshotSource::Codex => "schedule_codex",
                            SnapshotSource::Pi => "schedule_pi",
                        };
                        home.cycle_number = run * 128;
                        let mut accepted = BTreeMap::new();
                        let seed_paths = scheduling_corpus(&home, true);
                        home.births = seed_paths
                            .iter()
                            .map(|(p, _)| {
                                (
                                    p.to_string_lossy().into_owned(),
                                    (NOW - 14400) * 1_000_000_000,
                                )
                            })
                            .collect();
                        let seed = home.cycle(&server, &recording);
                        assert!(seed.finish.is_ok());
                        schedule_accepts(source, &seed, &mut accepted);
                        assert_eq!(
                            accepted.len(),
                            1,
                            "establish an identical positive ownership seed"
                        );
                        drop(seed);
                        home.now += 3600;
                        let paths = scheduling_corpus(&home, false);
                        assert_eq!(
                            paths.len(),
                            if source == SnapshotSource::ClaudeCode {
                                6
                            } else {
                                5
                            }
                        );
                        home.births = paths
                            .iter()
                            .map(|(p, session)| {
                                let age = if source == SnapshotSource::ClaudeCode
                                    && session == "3338a80a-f36e-4cbc-a5bb-50fc66430ba5"
                                {
                                    if p == &paths[1].0 {
                                        10620 // Main born at 07:03, before its own turns.
                                    } else {
                                        10320 // Copy born at 07:08, after all copied turns.
                                    }
                                } else {
                                    14400
                                };
                                (
                                    p.to_string_lossy().into_owned(),
                                    (NOW - age) * 1_000_000_000,
                                )
                            })
                            .collect();
                        home.schedule = Some(Schedule {
                            one_chunk,
                            limit,
                            reverse,
                        });
                        home.small_page = source == SnapshotSource::Codex;
                        let inputs = money_equivalence_tests::inputs(&home);
                        if let Some(expected) = &baseline_inputs {
                            assert_eq!(&inputs, expected);
                        } else {
                            baseline_inputs = Some(inputs);
                        }
                        let delayed = if late {
                            ["claude-code-effort", "claude-code-trace-ownership"]
                                .map(|dir| {
                                    let path =
                                        home.support.join("local-otel").join(dir).join(format!(
                                            "{:x}.jsonl",
                                            Sha256::digest(paths[1].1.as_bytes())
                                        ));
                                    let bytes = std::fs::read(&path).unwrap();
                                    std::fs::remove_file(&path).unwrap();
                                    (path, bytes)
                                })
                                .to_vec()
                        } else {
                            Vec::new()
                        };
                        let roots = source.default_roots(&home.fixture.home);
                        let relative = |path: &Path| {
                            format!(
                                "root-0/{}",
                                path.strip_prefix(&roots[0]).unwrap().to_string_lossy()
                            )
                        };
                        let root_locations = paths
                            .iter()
                            .filter(|(_, session)| session == IDENTITY_PIPELINE_ROOT)
                            .map(|(path, _)| (path.to_string_lossy().into_owned(), relative(path)))
                            .collect::<Vec<_>>();
                        let placement_context = format!(
                            "{source:?}, arm (one_chunk={one_chunk}, limit={limit}, reverse={reverse}, restart={restart}, late={late})"
                        );
                        let mut first_root_split = None;
                        let mut history = Vec::new();
                        let mut effective = Vec::new();
                        let mut first_page = BTreeMap::new();
                        let mut multi_chunk = false;
                        let mut nonterminal = false;
                        let mut restarted = false;
                        let mut released = !late;
                        let mut grown = source != SnapshotSource::Pi;
                        let mut finished = false;
                        for page in 0..64 {
                            let cycle = home.cycle(&server, &recording);
                            assert!(cycle.finish.is_ok());
                            let plan = cycle.schedule.as_ref().unwrap();
                            let order = plan["discovery"].as_array().unwrap();
                            if !order.is_empty() {
                                // continuation constructors select no files
                                assert_eq!(cycle.gate["backfill_file_limit"], limit);
                            }
                            assert!(order.windows(2).all(|pair| if reverse {
                                pair[0].as_str() >= pair[1].as_str()
                            } else {
                                pair[0].as_str() <= pair[1].as_str()
                            }));
                            for key in plan["selected"].as_array().unwrap() {
                                first_page
                                    .entry(key.as_str().unwrap().to_owned())
                                    .or_insert(page);
                            }
                            effective.extend(
                                cycle.gate["pending_finalization"]
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .map(|p| p["key"].as_str().unwrap().to_owned()),
                            );
                            multi_chunk |= cycle.evidence_chunks >= 2;
                            if one_chunk {
                                assert_eq!(cycle.evidence_chunks, 0);
                            }
                            schedule_accepts(source, &cycle, &mut accepted);
                            assert_schedule_root_placement_stable(
                                &cycle,
                                &accepted,
                                &root_locations,
                                &mut first_root_split,
                                home.cycle_number - 1,
                                &placement_context,
                            );
                            let pending = cycle.debt["pending"].as_u64().unwrap() > 0
                                || cycle.gate["continuation_pending"] == true;
                            nonterminal |= cycle.debt["pending"].as_u64().unwrap() > 0;
                            history.push(json!({"page":page,"plan":plan,"gate":cycle.gate,
                                "debt":cycle.debt,"acknowledged":cycle.acknowledged,
                                "evidence_chunks":cycle.evidence_chunks,"accepted":accepted}));
                            if restart && !restarted && cycle.debt["pending"].as_u64().unwrap() > 0
                            {
                                drop(cycle);
                                home.cold_restart();
                                restarted = true;
                                continue;
                            }
                            let visited = paths
                                .iter()
                                .all(|(p, _)| first_page.contains_key(&relative(p)));
                            // A joined Codex peer can finish without appearing in selected.
                            // Require per-path selection only before changing fixture inputs.
                            if !pending {
                                if !released && visited {
                                    for (path, bytes) in &delayed {
                                        std::fs::write(path, bytes).unwrap();
                                    }
                                    released = true;
                                    home.now += 3600; // one COMPLETE source pass without this pair
                                } else if !grown && visited {
                                    let mut rows = pi_rows(false);
                                    rows[0]["id"] = json!(IDENTITY_PIPELINE_ROOT);
                                    let mut growth = rows[1].clone();
                                    growth["message"]["responseId"] = json!("pi-growth");
                                    growth["message"]["usage"]["input"] = json!(5);
                                    growth["timestamp"] = json!("2026-11-01T07:03:00Z");
                                    growth["message"]["timestamp"] = growth["timestamp"].clone();
                                    rows.push(growth);
                                    write_jsonl(&paths[0].0, &rows);
                                    grown = true;
                                    home.now += 3600;
                                } else if released
                                    && grown
                                    && cycle.gate["census_complete"] == true
                                    && schedule_debt_is_clear(&cycle.debt)
                                {
                                    assert_eq!(cycle.gate["residue_count"], 0);
                                    assert_eq!(cycle.gate["ownership_incomplete_file_count"], 0);
                                    assert!(cycle.gate["pending_finalization"]
                                        .as_array()
                                        .unwrap()
                                        .iter()
                                        .all(|p| p["parse_complete"] == true));
                                    if source == SnapshotSource::ClaudeCode {
                                        assert!(cycle.debt["content_twins"].as_u64().unwrap() > 0);
                                    }
                                    finished = true;
                                    break;
                                } else if visited {
                                    home.now += 3600;
                                }
                            }
                        }
                        assert!(finished, "bounded drain left debt: {history:?}");
                        if source != SnapshotSource::Pi {
                            assert!(
                                first_root_split.is_some(),
                                "ROOT twins must reach the placement stability guard: {placement_context}, cycle {}",
                                home.cycle_number - 1
                            );
                        }
                        assert!(released && grown);
                        assert!(
                            nonterminal,
                            "real finished nonterminal page must be reached"
                        );
                        assert_eq!(restarted, restart);
                        let key = (one_chunk, limit, restart, late);
                        if reverse {
                            assert_ne!(
                                &effective, &forward_orders[&key],
                                "effective native acquisition order must change"
                            );
                        } else {
                            forward_orders.insert(key, effective);
                        }
                        if source == SnapshotSource::ClaudeCode {
                            // Preparation pulls changed path-twin homes into
                            // one read closure after applying the file limit.
                            // This corpus cannot witness a split of that pair;
                            // independent files still prove nonterminal pages.
                            if limit == 2 {
                                // Both CHILD paths share ROOT's folder; n=2 stays independent.
                                assert_ne!(
                                    first_page[&relative(&paths[0].0)],
                                    first_page[&relative(&paths[2].0)],
                                    "main and independent session cross real pages"
                                );
                            }
                            if !one_chunk {
                                assert!(multi_chunk, "at least two real evidence chunks");
                            }
                        }
                        let expected_sessions = if source == SnapshotSource::Pi { 5 } else { 4 };
                        assert_eq!(accepted.len(), expected_sessions);
                        for (entity, value) in &accepted {
                            let parent = entity == IDENTITY_PIPELINE_ROOT;
                            let (input, requests) = match source {
                                SnapshotSource::ClaudeCode => {
                                    if parent {
                                        (55, 5)
                                    } else {
                                        (42, 4)
                                    }
                                }
                                SnapshotSource::Codex => {
                                    if parent {
                                        (300, 2)
                                    } else {
                                        (100, 1)
                                    }
                                }
                                SnapshotSource::Pi => {
                                    if parent {
                                        (18, 3)
                                    } else {
                                        (13, 2)
                                    }
                                }
                            };
                            assert_eq!(
                                value["body"]["input_tokens"], input,
                                "{source:?} entity {entity} input (one_chunk {one_chunk} limit {limit} reverse {reverse} restart {restart} late {late})"
                            );
                            assert_eq!(
                                value["body"]["request_count"], requests,
                                "{source:?} entity {entity} requests (one_chunk {one_chunk} limit {limit} reverse {reverse} restart {restart} late {late})"
                            );
                            assert_eq!(
                                value["placement"],
                                json!({"source":source.api_slug(),"machine_id":"otm_test"})
                            );
                        }
                        let canonical =
                            crate::canonical_json::canonicalize(&json!(accepted)).unwrap();
                        if let Some(expected) = &baseline {
                            let expected =
                                crate::canonical_json::canonicalize(&json!(expected)).unwrap();
                            assert_eq!(canonical, expected, "full rows and placement converge: {source:?} {one_chunk} {limit} {reverse} {restart} {late}");
                        } else {
                            baseline = Some(accepted.clone());
                        }
                        // No old Cycle/index/progress Arc survives into the cold-close seam.
                        home.cold_restart();
                        // A completed census starts a fresh walk of every physical file.
                        // one_chunk only changes evidence packing at finish, not selection.
                        let files = paths.len(); // Claude: 6 physical files; Codex/Pi: 5.
                        let quiet_limit = home.schedule.unwrap().limit;
                        // A new census queues every discovered entry again; the quiet
                        // drain must shrink it every cycle and finish within one cycle
                        // per physical file, reading no bodies (asserted above).
                        let quiet_cycles = files;
                        let mut previous_pending = files;
                        for quiet_page in 0..quiet_cycles {
                            let quiet = home.cycle(&server, &recording);
                            let context = format!(
                                "quiet restart: {source:?} {one_chunk} {limit} {reverse} {restart} {late}, page {quiet_page}, files {files}, file limit {quiet_limit}, debt: {}",
                                quiet.debt
                            );
                            assert!(quiet.finish.is_ok(), "{context}");
                            assert!(quiet.batches.is_empty(), "quiet POST: {context}");
                            assert_eq!(quiet.consumed, 0, "quiet body read: {context}");
                            let prior = accepted.clone();
                            schedule_accepts(source, &quiet, &mut accepted);
                            assert_schedule_root_placement_stable(
                                &quiet,
                                &accepted,
                                &root_locations,
                                &mut first_root_split,
                                home.cycle_number - 1,
                                &placement_context,
                            );
                            assert_eq!(accepted, prior, "quiet accepted changed: {context}");
                            let route = emitted_route(&quiet, source, &server);
                            // A quiet census page reads no transcript body; identity
                            // sampling stays within a fixed bound per file it opens:
                            // head + tail samples (snapshots/wire.rs
                            // FILE_CONTENT_SAMPLE_BYTES) for each file on the page,
                            // plus one path-twin peer each. Exact byte accounting is
                            // not this guard's job.
                            const IDENTITY_SAMPLE_BYTES: u64 = 4 * 1024;
                            let page_files = previous_pending.min(quiet_limit) as u64;
                            let sample_bound = page_files * 2 * 2 * IDENTITY_SAMPLE_BYTES;
                            assert_eq!(route.modes.0, 0, "quiet Full read: {context}");
                            assert_eq!(route.io.consumed, 0, "quiet parser bytes: {context}");
                            assert_eq!(
                                route.io.rederive_head, 0,
                                "quiet head re-derive: {context}"
                            );
                            assert_eq!(
                                route.io.rederive_named, 0,
                                "quiet named re-derive: {context}"
                            );
                            let activity = route.io.parse_activity.unwrap_or_else(|| {
                                panic!("quiet parse activity unmeasured: {context}")
                            });
                            if source == SnapshotSource::Codex {
                                // Inventory covers the whole roster, including peers
                                // outside this page's selection. Uncached identities
                                // decode only the bounded session_meta first record.
                                assert_eq!(activity.decoders, 0, "quiet decoder: {context}");
                                assert_eq!(
                                    activity.jsonl_parses, activity.header_reads,
                                    "quiet non-header parse: {activity:?}: {context}"
                                );
                                assert!(
                                    activity.header_reads <= files as u64,
                                    "quiet repeated header read: {activity:?}: {context}"
                                );
                            }
                            // Header byte totals remain unmeasured. The activity
                            // invariant above bounds that identity work separately.
                            if source != SnapshotSource::Codex || activity.header_reads == 0 {
                                assert_eq!(
                                    route.io.cheap_checks,
                                    Some(0),
                                    "quiet cheap checks: {context}"
                                );
                                assert_eq!(
                                    route.io.other_reads,
                                    Some(0),
                                    "quiet other reads: {context}"
                                );
                            }
                            let sampled = route.io.anchor_reads.unwrap_or_else(|| {
                                panic!("identity sampling unmeasured: {context}")
                            });
                            assert!(
                                sampled <= sample_bound,
                                "quiet identity sampling {sampled} above {sample_bound}: {context}"
                            );
                            assert!(
                                schedule_money_debt_is_clear(&quiet.debt),
                                "quiet restart left money/debt: {context}"
                            );
                            let pending = quiet.debt["pending"].as_u64().unwrap() as usize;
                            assert!(
                                pending <= files,
                                "quiet census pending above the physical file count: {context}"
                            );
                            assert!(
                                pending < previous_pending,
                                "quiet census must strictly drain from {previous_pending}: {context}"
                            );
                            if quiet_page + 1 == quiet_cycles {
                                assert_eq!(
                                    pending, 0,
                                    "quiet census exceeded its bound: {context}"
                                );
                            }
                            if pending == 0 {
                                break;
                            }
                            previous_pending = pending;
                        }
                        if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
                            money_equivalence_tests::emit_trace(
                                &out,
                                &format!("{}-result-{run}", home.row),
                                &json!({"rows":accepted,"pages":history,"one_chunk":one_chunk,"limit":limit,
                                    "reverse":reverse,"restart":restart,"late":late,
                                    "copy_first_correction":"not_available_on_pre_1730_base"}),
                            );
                        }
                        run += 1;
                    }
                }
            }
        }
        assert_eq!(
            run,
            if source == SnapshotSource::ClaudeCode {
                32
            } else {
                16
            }
        );
    }
}

mod money_equivalence_tests {
    use super::*;
    use crate::snapshot_sync::tests::claude_money_e2_pipeline_tests::money_equivalence_tests::{
        receipt_with_output, ReceiptBody,
    };

    pub(super) fn normalized_posts(source: SnapshotSource, cycle: &Cycle) -> Vec<Value> {
        let mut normalized_posts = Vec::new();
        for batch in &cycle.batches {
            let wire: Value = serde_json::from_slice(batch).unwrap();
            let sent = wire["snapshots"]
                .as_array()
                .unwrap()
                .iter()
                .map(|raw| {
                    cycle
                        .finalized
                        .iter()
                        .find(|item| {
                            raw["snapshot_fingerprint"] == item.snapshot_fingerprint
                                && raw["source_file_fingerprint"]
                                    == json!(item.source_file_fingerprint)
                        })
                        .expect("actual offered item, including coalesced twins")
                        .clone()
                })
                .collect::<Vec<_>>();
            let route = transition::RouteResult::emitted(
                transition::Mode::ColdFull,
                source,
                vec![batch.clone()],
                &sent,
            );
            normalized_posts.push(route.normalized);
        }
        normalized_posts
    }

    pub(super) fn emit_cycle(row: &str, number: usize, source: SnapshotSource, cycle: &Cycle) {
        let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") else {
            return;
        };
        let normalized_posts = normalized_posts(source, cycle);
        let finalized = cycle
            .finalized
            .iter()
            .map(|item| {
                let mut value = serde_json::to_value(item).unwrap();
                value["source_file_fingerprint"] = json!("physical-identity:excluded");
                value
            })
            .collect::<Vec<_>>();
        let effects: Value =
            serde_json::from_slice(&test_effects::canonical(&cycle.effects)).unwrap();
        let receipt = json!({"row":row,"cycle":number,"source":source.api_slug(),
            "steps":cycle.steps,"gate_c":cycle.gate,"finalized":finalized,"posts":normalized_posts,
            "effects":effects,"saved":{"generation":cycle.index.generation,
                "fingerprints":cycle.index.current_snapshot_fingerprints(),
                "accepted_body_witnesses":cycle.progress.accepted_body_witnesses},
            "finish_ok":cycle.finish.is_ok(),"parser_bytes":cycle.consumed,
            "io":{"cheap_checks":cycle.io.cheap_checks,"anchor_reads":cycle.io.anchor_reads,
                "other_reads":cycle.io.other_reads,"parse_activity":cycle.io.parse_activity,
                "quiet_anchor_window":cycle.quiet_anchor_window},
            "schedule":cycle.schedule,"evidence_chunks":cycle.evidence_chunks,"debt":cycle.debt});
        emit_trace(&out, &format!("{row}-{number}"), &receipt);
    }

    pub(super) fn emit_trace(out: &std::ffi::OsStr, name: &str, receipt: &Value) {
        let bytes = crate::canonical_json::canonicalize(receipt).unwrap();
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let dir = PathBuf::from(out).join("step-trace");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("{name}.json")), bytes).unwrap();
        println!("STEP_TRACE {name} sha256={digest}");
    }

    pub(super) fn bodies(source: SnapshotSource, cycle: &Cycle) -> Vec<ReceiptBody> {
        assert!(!cycle.batches.is_empty());
        if source == SnapshotSource::ClaudeCode {
            vec![ReceiptBody::new(
                serde_json::to_vec(&cycle.batches).unwrap(),
                source,
                cycle.finalized.clone(),
            )]
        } else {
            cycle
                .batches
                .iter()
                .map(|batch| ReceiptBody::new(batch.clone(), source, cycle.finalized.clone()))
                .collect()
        }
    }

    pub(super) fn inputs(home: &OracleHome) -> BTreeMap<String, Vec<u8>> {
        fn walk(prefix: &str, base: &Path, dir: &Path, rows: &mut BTreeMap<String, Vec<u8>>) {
            if !dir.exists() {
                return;
            }
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(prefix, base, &path, rows);
                } else if path.extension().is_some_and(|ext| ext == "jsonl") {
                    rows.insert(
                        format!(
                            "{prefix}/{}",
                            path.strip_prefix(base).unwrap().to_string_lossy()
                        ),
                        std::fs::read(path).unwrap(),
                    );
                }
            }
        }
        let mut rows = BTreeMap::new();
        for (i, root) in home
            .source
            .default_roots(&home.fixture.home)
            .iter()
            .enumerate()
        {
            walk(
                &format!("{}/root-{i}", home.source.api_slug()),
                root,
                root,
                &mut rows,
            );
        }
        let sidecars = home.support.join("local-otel");
        walk(
            &format!("{}/sidecars", home.source.api_slug()),
            &sidecars,
            &sidecars,
            &mut rows,
        );
        assert!(!rows.is_empty());
        rows
    }

    pub(super) fn emit_money(
        name: &str,
        bodies: Vec<ReceiptBody>,
        inputs: BTreeMap<String, Vec<u8>>,
    ) {
        if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(
                PathBuf::from(out).join(format!("{name}.inputs")),
                crate::canonical_json::canonicalize(&serde_json::to_value(inputs).unwrap())
                    .unwrap(),
            )
            .unwrap();
        }
        receipt_with_output(
            name,
            &bodies,
            "OTTTO_MONEY_EQUIVALENCE_OUTPUT",
            "MONEY_EQUIVALENCE",
        );
    }

    // The wrappers below own their existing serial guards individually.
    // Calling them here makes the filtered money lane execute every gate row.
    #[test]
    fn once_credit_claude() {
        c01_claude_cold_control_preserves_accounts_side_call_gap_and_tags();
        c02_durable_ack_suppresses_replay_of_the_prior_index();
        c03_complete_same_body_reread_drops_at_the_finalizer();
        c04_pi_positive_conflicted_result_cannot_publish();
        c05_fresh_destination_requires_its_own_exact_ack();
        c06_crash_windows_preserve_placement_and_durable_suppression();
        c07_codex_group_memo_rediscloses_without_session_credit();
        c08_codex_group_park_rediscloses_without_reading();
        c09_codex_singleton_memo_keeps_the_previous_body();
        c10_codex_singleton_park_keeps_the_previous_body();
        c11_fragment_and_obligation_charge_one_slot_and_existing_marker_charges_none();
        c11_account_hold_bypasses_the_full_audit_cap_without_staging_a_marker();
        scheduling_permutations_converge_to_the_same_bodies();
    }

    #[test]
    #[serial]
    #[serial(source_cadences, source_manifests, client_report)]
    fn once_credit_native() {
        let recording = Recording::start();
        let mut receipt_bodies = Vec::new();
        let mut fixture_inputs = BTreeMap::new();
        {
            let server = OracleServer::new(SnapshotSource::Codex, recording.handle());
            let mut home = OracleHome::new(SnapshotSource::Codex, &server);
            home.row = "c01_codex";
            install_created_thread(&home, false, IDENTITY_PIPELINE_ROOT, true);
            install_created_thread(&home, false, "3338a80a-f36e-4cbc-a5bb-50fc66430ba5", true);
            fixture_inputs.extend(inputs(&home));
            let cold = home.cycle(&server, &recording);
            assert!(cold.finish.is_ok());
            assert_eq!(cold.finalized.len(), 2);
            assert_eq!(
                cold.finalized.iter().map(|s| s.input_tokens).sum::<u64>(),
                240,
                "V2 publishes each closed 120-token turn; open turns remain pending"
            );
            let accounts = cold
                .finalized
                .iter()
                .map(|s| {
                    s.session_account_evidence
                        .as_ref()
                        .unwrap()
                        .account_identifier_hash
                        .clone()
                        .unwrap()
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(accounts.len(), 2);
            assert!(cold
                .finalized
                .iter()
                .all(|item| item.model_usage.iter().any(|row| row
                    .selector_context
                    .get("service_tier")
                    .map(String::as_str)
                    == Some("priority"))));
            assert_durable(&cold);
            receipt_bodies.extend(bodies(SnapshotSource::Codex, &cold));
            let placement = server.placement.lock().unwrap().clone();
            home.current_codex_account = "b";
            std::fs::write(
                home.fixture.home.join(".codex/auth.json"),
                br#"{"synthetic_account":"b"}"#,
            )
            .unwrap();
            home.restart();
            let quiet = home.cycle(&server, &recording);
            assert!(quiet.finish.is_ok());
            assert!(quiet.batches.is_empty());
            assert_eq!(*server.placement.lock().unwrap(), placement);
            let mut route = emitted_route(&quiet, SnapshotSource::Codex, &server);
            route.mode = transition::Mode::Restart;
            transition::money_oracle::assert_quiet_restart_with_anchor_window(
                &route,
                quiet.quiet_anchor_window,
            );
        }
        {
            let server = OracleServer::new(SnapshotSource::Pi, recording.handle());
            let mut home = OracleHome::new(SnapshotSource::Pi, &server);
            home.row = "c01_pi";
            let mut rows = pi_rows(false);
            rows.insert(
                1,
                json!({"type":"custom","customType":"ottto-selector",
                "timestamp":"2026-11-01T07:00:01Z","data":{"service_tier":"priority"}}),
            );
            rows.push(json!({"type":"usage","timestamp":"2026-11-01T07:03:00Z",
                "model":"gpt-5","usage":{"input":3,"output":1}}));
            home.write_rows(&rows);
            fixture_inputs.extend(inputs(&home));
            let cold = home.cycle(&server, &recording);
            assert!(cold.finish.is_ok());
            assert_eq!(cold.finalized.len(), 1);
            assert_eq!(cold.finalized[0].input_tokens, 16);
            assert_eq!(cold.finalized[0].request_count, 3);
            assert!(cold.finalized[0].model_usage.iter().any(|row| row
                .selector_context
                .get("service_tier")
                .map(String::as_str)
                == Some("priority")));
            // Pi has no provider account-creation witness; absence is explicit.
            assert!(cold.finalized[0].session_account_evidence.is_none());
            assert_durable(&cold);
            receipt_bodies.extend(bodies(SnapshotSource::Pi, &cold));
            let placement = server.placement.lock().unwrap().clone();
            home.restart();
            let quiet = home.cycle(&server, &recording);
            assert!(quiet.finish.is_ok());
            assert!(quiet.batches.is_empty());
            assert_eq!(*server.placement.lock().unwrap(), placement);
            let mut route = emitted_route(&quiet, SnapshotSource::Pi, &server);
            route.mode = transition::Mode::Restart;
            transition::money_oracle::assert_quiet_restart_with_anchor_window(
                &route,
                quiet.quiet_anchor_window,
            );
        }
        emit_money("once_credit_native", receipt_bodies, fixture_inputs);
    }
}
