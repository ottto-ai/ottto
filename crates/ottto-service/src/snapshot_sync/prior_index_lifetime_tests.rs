// Test-thread-only observer at the leased retirement boundary. The native
// input is earned once, cloned unchanged for both real finish calls, and never
// used to manufacture an eligible native-comparison lease.
use super::*;
use std::cell::RefCell;

#[derive(Default)]
struct Hook {
    enabled: bool,
    keep: bool,
    conflict_path: Option<PathBuf>,
    retry_clock: Option<u64>,
}
thread_local! {
    static HOOK: RefCell<Hook> = RefCell::new(Hook::default());
}

pub(crate) fn keep_prior() -> bool {
    HOOK.with(|state| state.borrow().keep)
}
pub(crate) fn retry_clock() -> Option<u64> {
    HOOK.with(|state| state.borrow().retry_clock)
}
pub(crate) fn after_retirement(_retained: bool) {
    HOOK.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(path) = state.conflict_path.take() {
            // Another synthetic writer wins before the existing CAS. No
            // hook is added to the decoder, lock or save implementation.
            let mut current = ScanIndex::load(&path).unwrap();
            current.save(&path).unwrap();
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
                conflict_path,
                retry_clock,
            };
        });
        Self
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
