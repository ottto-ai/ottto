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
    now: u64,
    small_page: bool,
    state_budget: Option<usize>,
    legacy_counting: bool,
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
    effects: Vec<test_effects::Effect>,
    schedule: Option<Value>,
    evidence_chunks: usize,
    debt: Value,
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
            EnvVarGuard::set_path("PI_CODING_AGENT_DIR", &fixture.home.join(".pi/agent")),
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
            legacy_counting: false,
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
            retry: live_snapshot_retry::LiveRetryOwner::closed(),
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
        self.retry = live_snapshot_retry::LiveRetryOwner::closed();
        self.restarted = true;
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
        crate::snapshots::OwnedSourceScan::with_oracle_births(self.births.clone(), || {
            self.cycle_inner(server, recording)
        })
    }
    fn cycle_inner(&mut self, server: &OracleServer, recording: &Recording) -> Cycle {
        self.cadence.due();
        let now = self.now;
        let small_page = self.small_page;
        let budget = self.state_budget;
        let legacy = self.legacy_counting;
        let _cutover = legacy.then(|| crate::snapshots::TestCutover::set(i64::MAX));
        let at = OffsetDateTime::from_unix_timestamp(now as i64)
            .unwrap()
            .format(&Rfc3339)
            .unwrap();
        let start = server.batches.lock().unwrap().len();
        let collection = self.collection();
        let (prepared, prepare_io) = transition::observe_codex_quiet(|| {
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
                        false,
                    )
                })
            })
        });
        let mut frame = prepared.unwrap().expect("due real preparation");
        frame.scan.as_mut().unwrap().set_oracle_collection_time(&at);
        frame.scan_started_at = at;
        let schedule = self.schedule.map(|schedule| {
            let (scan, plan) = with_scan_clock(now, || {
                frame.scan.take().unwrap().with_oracle_schedule(
                    schedule.limit,
                    schedule.reverse,
                    now,
                )
            });
            frame.scan = Some(scan);
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
            let _cutover = legacy.then(|| crate::snapshots::TestCutover::set(i64::MAX));
            let read = move || {
                with_scan_clock(now, || {
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
        io.consumed += prepare_io.consumed;
        io.rederive_head += prepare_io.rederive_head;
        io.rederive_named += prepare_io.rederive_named;
        io.cheap_checks = io
            .cheap_checks
            .zip(prepare_io.cheap_checks)
            .map(|(a, b)| a + b);
        io.anchor_reads = io
            .anchor_reads
            .zip(prepare_io.anchor_reads)
            .map(|(a, b)| a + b);
        io.other_reads = io
            .other_reads
            .zip(prepare_io.other_reads)
            .map(|(a, b)| a + b);
        let gate = scan.trace_projection(&roots);
        test_effects::record(
            "gate_c",
            vec![("snapshots", Scalar::U64(scan.snapshots.len() as u64))],
        );
        let before = scan.snapshots.clone();
        let capture = FinalizedCapture::start();
        let _evidence = self.schedule.map(|schedule| {
            EvidenceSchedule(ONE_EVIDENCE_CHUNK.with(|slot| slot.replace(schedule.one_chunk)))
        });
        let chunks_before = evidence_chunks_for_test();
        let collection = self.collection();
        let finish = with_scan_clock(now, || {
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
            let debt = index.oracle_schedule_debt(&roots);
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
            batches,
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
    home.row = "c02";
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
        home.row = match answer {
            Answer::Dropped => "c06_dropped",
            Answer::LostAck => "c06_lost_ack",
            Answer::Accept => "c06_selected_save",
            _ => unreachable!("fixed crash table"),
        };
        *server.fallback.lock().unwrap() = answer;
        let failure = matches!(answer, Answer::Accept).then(|| SaveFailure::at("selected_save"));
        let first = home.cycle(&server, &recording);
        drop(failure);
        if !matches!(answer, Answer::LostAck) {
            assert!(first.finish.is_err());
        }
        // A proofless successful reply need not be a transport error; the
        // durable body ledger, below, decides whether replay is permitted.
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
    install_claude_control_for(home, IDENTITY_PIPELINE_ROOT, "");
}

fn install_claude_control_for(home: &OracleHome, session: &str, prefix: &str) {
    use crate::claude_local_otel::{
        ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
        ClaudeLocalOtelEvidence, ClaudeRequestIdentityEvidence, ClaudeTraceOwnershipEvidence,
    };
    let transcript = |id: &str, tokens: u64, at: &str| {
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
    for (sequence, (request, tokens, account, org, at)) in [
        ("account-a", 10, 'a', '8', "2026-11-01T07:01:00Z"),
        ("account-b", 20, 'b', '9', "2026-11-01T07:02:00Z"),
        ("side", 7, 'b', '9', "2026-11-01T07:03:00Z"),
    ]
    .into_iter()
    .enumerate()
    {
        let request = format!("{prefix}{request}");
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
    transition::money_oracle::assert_quiet_restart_zero_bytes(&quiet_route);
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
    vec![
        json!({"type":"session_meta","timestamp":created,"payload":{"id":owner}}),
        json!({"type":"token_usage_record","timestamp":"2026-11-01T07:01:00Z","payload":{
            "thread_id":owner,"response_id":response,"usage":usage(input),"thread_token_usage":usage(cumulative)}}),
        json!({"type":"event_msg","timestamp":"2026-11-01T07:01:01Z","payload":{"type":"token_count",
            "info":{"model":"gpt-5.2","last_token_usage":usage(input),"total_token_usage":usage(cumulative)}}}),
    ]
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
    home.legacy_counting = true;
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
    home.legacy_counting = true;
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

fn install_created_thread(home: &OracleHome, fork: bool, session: &str) {
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
    home.legacy_counting = true;
    install_created_thread(&home, false, IDENTITY_PIPELINE_ROOT);
    let cold = home.cycle(&server, &recording);
    assert!(cold.finish.is_ok());
    assert_durable(&cold);
    assert_eq!(cold.finalized[0].input_tokens, 200);
    let placement = server.placement.lock().unwrap().clone();
    install_created_thread(&home, true, IDENTITY_PIPELINE_ROOT);
    let held = home.cycle(&server, &recording);
    assert_eq!(last_counter(&held, "memo_records"), 1);
    assert!(held.gate["pending_finalization"][0]["previous_snapshot"]
        .as_bool()
        .unwrap());
    assert!(held.gate["pending_finalization"][0]["previous_witness"]
        .as_bool()
        .unwrap());
    home.now += 86_400;
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
    home.legacy_counting = true;
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
        home.legacy_counting = true;
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
    index.save(&home.index_path()).unwrap();
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

// One immutable corpus per source. The Claude copy is a content twin:
// its in-file id is ROOT, while its filename names a different session.
// Pi has the same logical session observed at two physical locations.
fn scheduling_corpus(home: &OracleHome) -> Vec<(PathBuf, String)> {
    let root = home.source.default_roots(&home.fixture.home)[0].clone();
    let sessions = [
        IDENTITY_PIPELINE_ROOT,
        "3338a80a-f36e-4cbc-a5bb-50fc66430ba5",
        "4338a80a-f36e-4cbc-a5bb-50fc66430ba5",
    ];
    let mut paths = Vec::new();
    for (n, session) in sessions.into_iter().enumerate() {
        let rows = match home.source {
            SnapshotSource::ClaudeCode => {
                install_claude_control_for(home, session, &format!("family-{n}:"));
                std::fs::read_to_string(home.transcript())
                    .unwrap()
                    .lines()
                    .map(|line| {
                        let mut row: Value = serde_json::from_str(line).unwrap();
                        row["cwd"] = json!("/synthetic/workspace");
                        row
                    })
                    .collect::<Vec<_>>()
            }
            SnapshotSource::Codex => {
                let mut rows = Vec::new();
                for k in 0..30 {
                    let mut pair = codex_member(
                        session,
                        &format!("{session}-{k}"),
                        10,
                        10 * (k + 1),
                        "2026-11-01T07:00:00Z",
                    );
                    if k > 0 {
                        pair.remove(0);
                    }
                    rows.extend(pair);
                }
                rows
            }
            SnapshotSource::Pi => {
                let mut rows = pi_rows(false);
                rows[0]["id"] = json!(session);
                rows
            }
        };
        let path = root.join(format!("{n}-main/{session}.jsonl"));
        write_jsonl(&path, &rows);
        paths.push((path, session.into()));
        if n == 0 && home.source != SnapshotSource::Codex {
            let copy = root.join("z-copy/5338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
            write_jsonl(&copy, &rows);
            paths.push((copy, session.into()));
        }
    }
    if home.source == SnapshotSource::ClaudeCode {
        std::fs::remove_file(home.transcript()).unwrap();
    }
    paths
}

/// [money] Page and evidence-chunk boundaries change scheduling only. Compare
/// every full normalized wire row, not just additive token totals. No expected
/// receipt is learned or blessed: the reference is another schedule of the
/// identical input bytes in this same test invocation.
#[test]
#[serial]
#[serial(source_cadences, source_manifests, client_report)]
fn scheduling_permutations_converge_to_the_same_bodies() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut baseline = None;
        let mut baseline_inputs = None;
        let mut run = 0;
        for one_chunk in [true, false] {
            for limit in [64, 2] {
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
                    home.legacy_counting = source == SnapshotSource::Codex;
                    home.small_page = limit == 2 && source == SnapshotSource::Codex;
                    home.schedule = Some(Schedule {
                        one_chunk,
                        limit,
                        reverse,
                    });
                    let paths = scheduling_corpus(&home);
                    if source == SnapshotSource::ClaudeCode {
                        home.births = paths
                            .iter()
                            .map(|(path, _)| {
                                let age = if path.to_string_lossy().contains("z-copy") {
                                    10620
                                } else {
                                    14400
                                };
                                (
                                    path.to_string_lossy().into_owned(),
                                    (NOW - age) * 1_000_000_000,
                                )
                            })
                            .collect();
                    }
                    let inputs = money_equivalence_tests::inputs(&home);
                    if let Some(expected) = &baseline_inputs {
                        assert_eq!(&inputs, expected);
                    } else {
                        baseline_inputs = Some(inputs);
                    }
                    let roots = source.default_roots(&home.fixture.home);
                    let relative = |path: &Path| {
                        format!(
                            "root-0/{}",
                            path.strip_prefix(&roots[0]).unwrap().to_string_lossy()
                        )
                    };
                    let mut accepted = BTreeMap::<String, Value>::new();
                    let mut previous = BTreeMap::<String, u64>::new();
                    let mut previous_holds = BTreeMap::<String, Value>::new();
                    let mut history = Vec::new();
                    let mut first_page = BTreeMap::new();
                    let mut multi_chunk = false;
                    let mut cursor_spanned_pages = false;
                    let mut finished = false;
                    for page in 0..64 {
                        let cycle = home.cycle(&server, &recording);
                        assert!(cycle.finish.is_ok());
                        let plan = cycle.schedule.as_ref().unwrap();
                        let order = plan["discovery"].as_array().unwrap();
                        assert!(
                            order.windows(2).all(|pair| {
                                if reverse {
                                    pair[0].as_str() >= pair[1].as_str()
                                } else {
                                    pair[0].as_str() <= pair[1].as_str()
                                }
                            }),
                            "the real re-selection queue uses the requested discovery order"
                        );
                        for path in plan["selected"].as_array().unwrap() {
                            first_page
                                .entry(path.as_str().unwrap().to_owned())
                                .or_insert(page);
                        }
                        multi_chunk |= cycle.evidence_chunks > 1;
                        cursor_spanned_pages |= cycle.gate["continuation_pending"] == true
                            || (cycle.consumed > 0 && cycle.before.is_empty());
                        if one_chunk {
                            assert_eq!(
                                cycle.evidence_chunks, 0,
                                "reference chunks are excluded by the existing counter"
                            );
                        }
                        for batches in money_equivalence_tests::normalized_posts(source, &cycle) {
                            for batch in batches.as_array().unwrap() {
                                for row in batch["snapshots"].as_array().unwrap() {
                                    assert!(cycle.finalized.iter().any(|item|
                                        row["snapshot_fingerprint"] == item.snapshot_fingerprint
                                        && cycle.progress.contains_body(&item.snapshot_fingerprint,
                                            &snapshot_upload_body_witness(item))),
                                        "count only an actual offered body with reloaded exact ACK proof");
                                    accepted.insert(
                                        row["source_session_id"].as_str().unwrap().into(),
                                        row.clone(),
                                    );
                                }
                            }
                        }
                        let mut holds = cycle.debt["holds"]
                            .as_object()
                            .unwrap()
                            .iter()
                            .map(|(entity, reason)| (entity.clone(), reason.clone()))
                            .collect::<BTreeMap<_, _>>();
                        for key in cycle.debt["copy_wait"].as_array().unwrap() {
                            let (_, entity) = paths
                                .iter()
                                .find(|(path, _)| relative(path) == key.as_str().unwrap())
                                .unwrap();
                            holds.insert(entity.clone(), json!(["copy_prefix_wait"]));
                        }
                        let counts = accepted
                            .iter()
                            .map(|(entity, row)| {
                                (entity.clone(), row["request_count"].as_u64().unwrap())
                            })
                            .collect::<BTreeMap<_, _>>();
                        for (entity, before) in &previous {
                            let after = counts.get(entity).copied().unwrap_or(0);
                            assert!(after >= *before || holds.contains_key(entity) || previous_holds.contains_key(entity),
                                "unexplained accepted request dip for {entity}: {before} -> {after}");
                        }
                        history.push(json!({"page":page,"request_counts":counts,"holds":holds,
                            "owed":cycle.debt["owed"],"evidence_chunks":cycle.evidence_chunks}));
                        previous = counts;
                        previous_holds = holds;
                        let all_seen = paths.iter().all(|(path, _)| {
                            cycle.index.files.keys().any(|key| Path::new(key) == path)
                        });
                        if cycle.gate["census_complete"] == true
                            && all_seen
                            && accepted.len() == 3
                            && previous_holds.is_empty()
                            && cycle.debt["owed"].as_array().unwrap().is_empty()
                        {
                            assert_eq!(cycle.gate["residue_count"], 0);
                            assert_eq!(cycle.gate["ownership_incomplete_file_count"], 0);
                            assert!(cycle.gate["pending_finalization"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .all(|p| p["parse_complete"] == true));
                            if source == SnapshotSource::ClaudeCode {
                                assert!(
                                    cycle.debt["content_twins"].as_u64().unwrap() > 0,
                                    "a native content-twin census witness"
                                );
                            }
                            finished = true;
                            break;
                        }
                    }
                    assert!(
                        finished,
                        "all holds, copy waits and owed keys must be released within 64 pages"
                    );
                    assert_eq!(
                        accepted.len(),
                        3,
                        "three logical sessions, including duplicate-location sessions only once"
                    );
                    assert!(accepted
                        .values()
                        .all(|row| row["input_tokens"].as_u64().unwrap() > 0
                            && row["request_count"].as_u64().unwrap() > 0));
                    if limit == 2 {
                        assert!(
                            history.len() > 1,
                            "small allowance must cross a page boundary"
                        );
                        if source != SnapshotSource::Codex {
                            assert_ne!(
                                first_page[&relative(&paths[0].0)],
                                first_page[&relative(&paths[1].0)],
                                "main and content/session copy cross pages"
                            );
                        } else {
                            assert!(
                                cursor_spanned_pages,
                                "a native session must pause across acquisition pages"
                            );
                        }
                    }
                    if source == SnapshotSource::ClaudeCode && !one_chunk {
                        assert!(
                            multi_chunk,
                            "positive side-file bytes must actually force several evidence chunks"
                        );
                    }
                    let canonical = crate::canonical_json::canonicalize(
                        &serde_json::to_value(&accepted).unwrap(),
                    )
                    .unwrap();
                    if let Some(expected) = &baseline {
                        assert_eq!(&canonical, expected, "canonical full rows converge for {source:?}, chunks={one_chunk}, limit={limit}, reverse={reverse}");
                    } else {
                        baseline = Some(canonical);
                    }
                    if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
                        money_equivalence_tests::emit_trace(
                            &out,
                            &format!("{}-result-{run}", home.row),
                            &json!({"rows":accepted,"pages":history,"one_chunk":one_chunk,"limit":limit,"reverse":reverse}),
                        );
                    }
                    run += 1;
                }
            }
        }
        assert_eq!(run, 8, "the full 2 × 2 × 2 schedule product");
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
            home.legacy_counting = true;
            install_created_thread(&home, false, IDENTITY_PIPELINE_ROOT);
            install_created_thread(&home, false, "3338a80a-f36e-4cbc-a5bb-50fc66430ba5");
            fixture_inputs.extend(inputs(&home));
            let cold = home.cycle(&server, &recording);
            assert!(cold.finish.is_ok());
            assert_eq!(cold.finalized.len(), 2);
            assert_eq!(
                cold.finalized.iter().map(|s| s.input_tokens).sum::<u64>(),
                400
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
            transition::money_oracle::assert_quiet_restart_zero_bytes(&route);
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
            transition::money_oracle::assert_quiet_restart_zero_bytes(&route);
        }
        emit_money("once_credit_native", receipt_bodies, fixture_inputs);
    }
}
