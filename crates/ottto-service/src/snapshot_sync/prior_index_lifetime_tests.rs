// Test-thread-only observer at the leased retirement boundary. The native
// input is earned once, cloned unchanged for both real finish calls, and never
// used to manufacture an eligible native-comparison lease.
use super::*;
use std::cell::RefCell;

#[derive(Clone, Copy, Debug)]
struct Observation {
    retained: bool,
    before: Option<crate::retry_allocation_probe::Stats>,
    after: Option<crate::retry_allocation_probe::Stats>,
}

#[derive(Default)]
struct Hook {
    enabled: bool,
    keep: bool,
    before: Option<crate::retry_allocation_probe::Stats>,
    observations: Vec<Observation>,
    conflict_path: Option<PathBuf>,
    retry_clock: Option<u64>,
    retry_clock_reads: usize,
}
thread_local! {
    static HOOK: RefCell<Hook> = RefCell::new(Hook::default());
}

pub(crate) fn keep_prior() -> bool {
    HOOK.with(|state| state.borrow().keep)
}
pub(crate) fn retry_clock() -> Option<u64> {
    HOOK.with(|state| {
        let mut state = state.borrow_mut();
        let clock = state.retry_clock;
        if clock.is_some() {
            state.retry_clock_reads += 1;
        }
        clock
    })
}
pub(crate) fn before_retirement() {
    HOOK.with(|state| {
        let mut state = state.borrow_mut();
        if state.enabled {
            state.before = crate::retry_allocation_probe::caller_thread_stats();
        }
    });
}
pub(crate) fn after_retirement(retained: bool) {
    HOOK.with(|state| {
        let mut state = state.borrow_mut();
        if state.enabled {
            let before = state.before;
            // Capacity is paid before the caller audit; the observer itself
            // copies counters only, with no allocation or pointer-table walk.
            assert!(state.observations.len() < state.observations.capacity());
            state.observations.push(Observation {
                retained,
                before,
                after: crate::retry_allocation_probe::caller_thread_stats(),
            });
            if let Some(path) = state.conflict_path.take() {
                // Another synthetic writer wins before the existing CAS. No
                // hook is added to the decoder, lock or save implementation.
                let mut current = ScanIndex::load(&path).unwrap();
                current.save(&path).unwrap();
            }
        }
    });
}
/// The test collector's rotation budget and what the native allowance saw
/// at each initialization: (remaining, needed, granted).
type NativeAllowance = (Option<usize>, Option<usize>, bool);
thread_local! {
    static ROTATION: RefCell<(Option<usize>, Vec<NativeAllowance>)> =
        const { RefCell::new((None, Vec::new())) };
}
pub(crate) fn rotation_budget() -> usize {
    ROTATION.with(|state| {
        state
            .borrow()
            .0
            .unwrap_or(crate::source_rotation::PARKED_BUDGET)
    })
}
pub(crate) fn note_native_allowance(
    remaining: Option<usize>,
    needed: Option<usize>,
    granted: bool,
) {
    ROTATION.with(|state| state.borrow_mut().1.push((remaining, needed, granted)));
}
/// Run `collect` under `budget`; what the native allowance saw.
fn with_rotation_budget<T>(
    budget: usize,
    collect: impl FnOnce() -> T,
) -> (T, Vec<NativeAllowance>) {
    ROTATION.with(|state| *state.borrow_mut() = (Some(budget), Vec::new()));
    let collected = collect();
    let seen = ROTATION.with(|state| std::mem::take(&mut *state.borrow_mut()).1);
    (collected, seen)
}

struct Guard;
impl Guard {
    fn new(keep: bool, conflict_path: Option<PathBuf>, retry_clock: Option<u64>) -> Self {
        HOOK.with(|state| {
            assert!(!state.borrow().enabled);
            *state.borrow_mut() = Hook {
                enabled: true,
                keep,
                observations: Vec::with_capacity(8),
                conflict_path,
                retry_clock,
                ..Default::default()
            };
        });
        Self
    }
    fn observations(&self) -> Vec<Observation> {
        HOOK.with(|state| state.borrow().observations.clone())
    }
    fn retry_clock_reads(&self) -> usize {
        HOOK.with(|state| state.borrow().retry_clock_reads)
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        HOOK.with(|state| *state.borrow_mut() = Hook::default());
    }
}

fn large_prior_index(occurrences: usize) -> ScanIndex {
    let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
    let mut rows = serde_json::Map::new();
    let mut hashes = Vec::new();
    for n in 0..occurrences {
        let hash = format!("{n:064x}");
        hashes.push(hash.clone());
        rows.insert(
            hash,
            serde_json::json!({"sequence":n,"input_tokens":1,"output_tokens":1,
            "cache_read_tokens":0,"cache_creation_5m_tokens":0,"cache_creation_1h_tokens":0,
            "reasoning_output_tokens":0,"model":format!("synthetic-{}", "m".repeat(192)),
            "speed_mode":"fast","reasoning_effort":"high"}),
        );
    }
    // Old native proof work, not an accepted body or a current observation.
    // The real scan replaces this old-window member through its normal fold.
    value["claude_usage_family_pending"] = serde_json::json!({IDENTITY_PIPELINE_ROOT:{
        "census_window_end":"2000-01-01T00:00:00Z",
        "member_request_id_hashes":{IDENTITY_PIPELINE_ROOT:hashes},
        "member_occurrences":{IDENTITY_PIPELINE_ROOT:rows},"invalid":false}});
    serde_json::from_value(value).unwrap()
}

struct Finished {
    index: Vec<u8>,
    progress: Option<Vec<u8>>,
    offered: Vec<serde_json::Value>,
    observation: Observation,
    allocation: crate::retry_allocation_probe::Stats,
    ok: bool,
}

fn same_input_finish_pair(outcome: FinishOutcome, conflict: bool, count: usize) -> [Finished; 2] {
    let fixture = IdentityPipelineHome::new();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("prior-index-support");
    let secrets = fixture.base.join("prior-index-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(outcome);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "prior-index-device".into(),
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
    let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
    let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
        &snapshot_index_path(&support, SnapshotSource::ClaudeCode),
        &namespace,
    ));
    large_prior_index(count).save(&index_path).unwrap();
    // Preserve exactly the initial on-disk inputs, including sidecars. No
    // clock/body normalization is used in any conservation assertion below.
    fn files(dir: &Path, into: &mut Vec<(PathBuf, Vec<u8>, std::fs::Permissions)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files(&path, into);
            } else {
                into.push((
                    path.clone(),
                    std::fs::read(&path).unwrap(),
                    std::fs::metadata(path).unwrap().permissions(),
                ));
            }
        }
    }
    let mut initial = Vec::new();
    files(&support, &mut initial);
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    let mut common = None;
    let mut output = Vec::new();
    // Freeze only the existing retry-deadline clock for these paired finishes.
    // The same real instant is supplied before either outcome is produced;
    // no persisted field is normalized after the fact.
    let pair_retry_clock = current_unix_seconds();
    for keep in [true, false] {
        std::fs::remove_dir_all(&support).unwrap();
        for (path, bytes, permissions) in &initial {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, permissions.clone()).unwrap();
        }
        server.offered.lock().unwrap().clear();
        server.terminal.lock().unwrap().clear();
        cadence.next_due_cycle();
        let daemon = test_daemon("otm_test");
        let client = SnapshotApiClient::new(server.url.clone());
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
        .expect("actual due preparation");
        assert!(!frame.native_comparison_lease.as_ref().unwrap().allowed());
        let (mut preparation, index, scan) = collect_native_preparation_with_rotation(frame, false);
        assert!(crate::snapshots::claude_terminal_off());
        assert!(!scan.census_complete);
        assert_eq!(scan.snapshots.len(), 1);
        if common.is_none() {
            common = Some((
                index.clone(),
                scan.clone(),
                preparation.scan_started_at.clone(),
                serde_json::to_vec(&preparation.committed_index).unwrap(),
            ));
        }
        let (index, scan, started, previous) = common.as_ref().unwrap();
        assert_eq!(
            serde_json::to_vec(&preparation.committed_index).unwrap(),
            *previous
        );
        preparation.scan_started_at = started.clone();
        // Both finish calls consume the SAME actual completed native input.
        // Each still has its own actual unadmitted lease and exact disk CAS.
        let index = index.clone();
        let scan = scan.clone();
        let progress_path = preparation.upload_progress_path.clone();
        let guard = Guard::new(
            keep,
            conflict.then(|| index_path.clone()),
            Some(pair_retry_clock),
        );
        let (result, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
            // Charge P's actual deep clone to this born-pointer scope. Freeing
            // its pre-existing predecessor cannot mask a subsequent peak.
            preparation.committed_index = preparation.committed_index.clone();
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
            })
        });
        let observations = guard.observations();
        assert_eq!(observations.len(), 1, "actual final-save boundary reached");
        assert_eq!(observations[0].retained, keep);
        if matches!(outcome, FinishOutcome::Retryable) {
            assert!(
                guard.retry_clock_reads() > 0,
                "actual retry clock was controlled"
            );
        }
        assert_eq!(
            result.is_ok(),
            !conflict && !matches!(outcome, FinishOutcome::Retryable),
            "actual finish {outcome:?}: {result:?}"
        );
        let saved = ScanIndex::load(&index_path).unwrap();
        let offered = server.offered.lock().unwrap().clone();
        assert_eq!(offered.len(), 1);
        let fingerprint = offered[0]["snapshot_fingerprint"].as_str().unwrap();
        if matches!(outcome, FinishOutcome::Accept) && !conflict {
            assert!(saved.accepted_snapshot_fingerprint_recorded(fingerprint));
        }
        if matches!(outcome, FinishOutcome::Permanent) {
            assert!(!saved.accepted_snapshot_fingerprint_recorded(fingerprint));
            assert!(saved
                .quarantined_snapshot_fingerprints
                .contains_key(fingerprint));
        }
        // Successful cycles may retire this disposable ledger. Preserve that
        // absence as a distinct durable outcome; all other I/O errors fail.
        let progress = match std::fs::read(progress_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read final upload progress: {error}"),
        };
        output.push(Finished {
            index: serde_json::to_vec(&saved).unwrap(),
            progress,
            offered,
            observation: observations[0],
            allocation,
            ok: result.is_ok(),
        });
        drop(guard);
        assert!(
            retry_clock().is_none(),
            "retry clock cannot escape its pair run"
        );
    }
    output.try_into().ok().unwrap()
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn prior_index_lifetime_real_finish_releases_before_cas_with_exact_conservation() {
    let [base, candidate] = same_input_finish_pair(FinishOutcome::Accept, false, 2048);
    assert_eq!(base.index, candidate.index);
    assert_eq!(base.progress, candidate.progress);
    assert_eq!(base.offered, candidate.offered);
    let live = |o: Observation| o.before.unwrap().requested_live - o.after.unwrap().requested_live;
    assert_eq!(live(base.observation), 0);
    assert!(
        live(candidate.observation) > 512 * 1024,
        "actual prior graph freed before CAS"
    );
    assert!(
        candidate.allocation.requested_peak < base.allocation.requested_peak,
        "same-input real finish requested peak: base={:?} candidate={:?}",
        base.allocation,
        candidate.allocation
    );
    writeln!(std::io::stderr().lock(), "prior_index_lifetime: real_finish=true exact_index_progress_body=true base_requested_peak={} candidate_requested_peak={} freed_before_CAS={} RSS_unmeasured=true",
        base.allocation.requested_peak, candidate.allocation.requested_peak, live(candidate.observation)).unwrap();
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn prior_index_lifetime_real_finish_preserves_refusals_retry_and_failed_cas() {
    for (outcome, conflict) in [
        (FinishOutcome::Permanent, false),
        (FinishOutcome::Retryable, false),
        (FinishOutcome::Accept, true),
    ] {
        let [base, candidate] = same_input_finish_pair(outcome, conflict, 16);
        assert_eq!(base.ok, candidate.ok);
        assert_eq!(base.index, candidate.index);
        assert_eq!(base.progress, candidate.progress);
        assert_eq!(base.offered, candidate.offered);
    }
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn prior_index_lifetime_retains_real_earned_receipt_path() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let guard = Guard::new(false, None, None);
    permanent_finish_pipeline(FinishOutcome::Permanent, true);
    let records = guard.observations();
    assert_eq!(records.len(), 3);
    assert!(!records[0].retained);
    assert!(
        records[2].retained,
        "actual predecessor grant keeps P through durable save"
    );
}

/// What one real cycle of the money parity control left: the live outputs
/// and the native allowance its collection saw.
#[derive(Debug, PartialEq)]
struct MoneyCycle {
    ok: bool,
    index: Vec<u8>,
    progress: Option<Vec<u8>>,
    offered: Vec<serde_json::Value>,
    terminal: Vec<serde_json::Value>,
    allowance: Vec<NativeAllowance>,
}

/// Wall-clock stamps the arms cannot share (they run one after another and
/// may straddle a second): nulled before the comparison.
fn money_unclocked(mut value: serde_json::Value) -> serde_json::Value {
    const CLOCKED: [&str; 5] = [
        "retry_after_unix_seconds",
        "last_scan_started_at",
        "last_scan_finished_at",
        "last_success_at",
        "next_retry_at",
    ];
    fn walk(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, field) in map.iter_mut() {
                    if CLOCKED.contains(&key.as_str()) {
                        *field = serde_json::Value::Null;
                    } else {
                        walk(field);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter_mut().for_each(walk),
            _ => {}
        }
    }
    walk(&mut value);
    value
}

#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn e2_real_caller_parity_at_tight_allowances() {
    let _gate = crate::snapshots::claude_request_money::e2::GateForTest::set(true);
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = IdentityPipelineHome::new();
    let _enabled = crate::snapshots::claude_native_comparison::enable_for_test();
    let cadence = IdentityPipelineCadence::new();
    let support = fixture.base.join("money-parity-support");
    let secrets = fixture.base.join("money-parity-secrets");
    std::fs::create_dir_all(&support).unwrap();
    std::fs::create_dir_all(&secrets).unwrap();
    let _support = EnvVarGuard::set_path("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &support);
    let _secrets = EnvVarGuard::set_path(OTTTO_SECRET_FALLBACK_DIR_ENV, &secrets);
    let server = FinishServer::new(FinishOutcome::Accept);
    let _api = EnvVarGuard::set_str("OTTTO_API_BASE_URL", &server.url);
    let device = LocalDeviceBinding {
        device_id: "money-parity-device".into(),
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
    let namespace = snapshot_upload_destination_namespace(&device, "device-secret");
    let index_path = snapshot_v3_index_path(&snapshot_destination_scoped_index_path(
        &snapshot_index_path(&support, SnapshotSource::ClaudeCode),
        &namespace,
    ));
    large_prior_index(16).save(&index_path).unwrap();
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    let retry_clock = current_unix_seconds();
    // The budget's first completed native input, shared by its arms.
    let mut common = BTreeMap::<(usize, bool), (ScanIndex, SourceScanResult, String)>::new();
    let mut cycle = |budget: usize, conflict: bool, shared: bool| -> MoneyCycle {
        server.offered.lock().unwrap().clear();
        server.terminal.lock().unwrap().clear();
        cadence.next_due_cycle();
        let daemon = test_daemon("otm_test");
        let client = SnapshotApiClient::new(server.url.clone());
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
        .expect("actual due preparation");
        let ((mut preparation, index, scan), allowance) = with_rotation_budget(budget, || {
            collect_native_preparation_with_rotation(frame, false)
        });
        let (index, scan) = if shared {
            let (index, scan, started) = common
                .entry((budget, conflict))
                .or_insert_with(|| (index, scan, preparation.scan_started_at.clone()))
                .clone();
            preparation.scan_started_at = started;
            (index, scan)
        } else {
            (index, scan)
        };
        let progress_path = preparation.upload_progress_path.clone();
        let guard = Guard::new(
            false,
            conflict.then(|| index_path.clone()),
            Some(retry_clock),
        );
        let result = crate::agent_status_refresh::with_test_collection(collection(), || {
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
        drop(guard);
        let progress = match std::fs::read(progress_path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => panic!("read final upload progress: {error}"),
        };
        MoneyCycle {
            ok: result.is_ok(),
            index: serde_json::to_vec(&money_unclocked(
                serde_json::to_value(ScanIndex::load(&index_path).unwrap()).unwrap(),
            ))
            .unwrap(),
            progress,
            offered: server.offered.lock().unwrap().clone(),
            terminal: server
                .terminal
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .map(money_unclocked)
                .collect(),
            allowance,
        }
    };

    let transcript = fixture
        .home
        .join(".claude/projects/-synthetic-repo")
        .join(format!("{IDENTITY_PIPELINE_ROOT}.jsonl"));
    let mut lines = std::fs::read_to_string(&transcript).unwrap();
    let at = (OffsetDateTime::now_utc() - TimeDuration::minutes(30))
        .replace_nanosecond(0)
        .unwrap()
        .format(&Rfc3339)
        .unwrap();
    lines.push_str(&format!(
        "{}\n",
        serde_json::json!({"timestamp": at, "type": "assistant", "sessionId": IDENTITY_PIPELINE_ROOT,
            "requestId": "req_3", "message": {"id": "m3", "model": "claude-haiku-4-5",
            "usage": {"input_tokens": 30, "output_tokens": 3}}})
    ));
    std::fs::write(&transcript, lines).unwrap();
    fn files(dir: &Path, into: &mut Vec<(PathBuf, Vec<u8>, std::fs::Permissions)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                files(&path, into);
            } else {
                into.push((
                    path.clone(),
                    std::fs::read(&path).unwrap(),
                    std::fs::metadata(path).unwrap().permissions(),
                ));
            }
        }
    }
    // The support directory (index, progress and sidecars)
    // is put back before every arm; the transcripts are only read.
    let mut saved = Vec::new();
    files(&support, &mut saved);
    let mut run = |budget: usize, conflict: bool| {
        std::fs::remove_dir_all(&support).unwrap();
        for (path, bytes, permissions) in &saved {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, permissions.clone()).unwrap();
        }
        cycle(budget, conflict, true)
    };

    // The native comparison's exact need at the full budget, then a budget
    // that leaves exactly that, and one byte less.
    let full = run(crate::source_rotation::PARKED_BUDGET, false);
    let [(Some(remaining), Some(needed), true)] = full.allowance[..] else {
        panic!("one granted native allowance: {:?}", full.allowance);
    };
    let tight = crate::source_rotation::PARKED_BUDGET - (remaining - needed);
    for (budget, granted) in [(tight, true), (tight - 1, false)] {
        for conflict in [false, true] {
            let baseline = run(budget, conflict);
            let remaining = needed - usize::from(!granted);
            assert_eq!(
                baseline.allowance,
                vec![(Some(remaining), Some(needed), granted)],
                "budget {budget}: the tight allowance"
            );
            assert_eq!(baseline.ok, !conflict, "{baseline:?}");
            assert_eq!(run(budget, conflict), baseline,
                "gate-on replay preserves bytes, ACKs and allowances at budget {budget}, conflict {conflict}");
        }
    }
    writeln!(std::io::stderr().lock(), "e2_money_parity: real_caller=true native_needed={needed} tight_budget={tight} below_refused=true failed_selected_save=true replay_equal=true").unwrap();
}
