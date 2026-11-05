// Test-thread-only observer at the ordinary prior-index retirement boundary.
// The completed input is cloned unchanged for both real finish calls.
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
// The ordinary test collector's rotation budget.
thread_local! {
    static ROTATION: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}
pub(crate) fn rotation_budget() -> usize {
    ROTATION.with(|state| state.get().unwrap_or(crate::source_rotation::PARKED_BUDGET))
}
fn with_rotation_budget<T>(budget: usize, collect: impl FnOnce() -> T) -> T {
    ROTATION.with(|state| state.set(Some(budget)));
    let collected = collect();
    ROTATION.with(|state| state.set(None));
    collected
}

pub(in crate::snapshot_sync) struct Guard;
impl Guard {
    pub(in crate::snapshot_sync) fn new(
        keep: bool,
        conflict_path: Option<PathBuf>,
        retry_clock: Option<u64>,
    ) -> Self {
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

/// What one real cycle of the money parity control left: the live outputs
/// through the ordinary selected save.
#[derive(Debug, PartialEq)]
struct MoneyCycle {
    ok: bool,
    index: Vec<u8>,
    progress: Option<Vec<u8>>,
    offered: Vec<serde_json::Value>,
    terminal: Vec<serde_json::Value>,
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
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let fixture = IdentityPipelineHome::new();
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
    ScanIndex::default().save(&index_path).unwrap();
    let collection = || AgentStatusCollection {
        snapshots: vec![test_agent_status(SourceKind::ClaudeCode)],
        source_health_snapshot: test_agent_status(SourceKind::ClaudeCode),
        codex_scan_homes: Vec::new(),
        codex_home_bindings: Vec::new(),
    };
    let retry_clock = current_unix_seconds();
    // The budget's first completed input, shared by its arms.
    let mut common = BTreeMap::<(usize, bool), (ScanIndex, SourceScanResult, String)>::new();
    let mut cycle = |budget: usize, conflict: bool, keep_prior: bool| -> MoneyCycle {
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
        let (mut preparation, index, scan) =
            with_rotation_budget(budget, || collect_preparation_with_rotation(frame));
        let (index, scan) = {
            let (index, scan, started) = common
                .entry((budget, conflict))
                .or_insert_with(|| (index, scan, preparation.scan_started_at.clone()))
                .clone();
            preparation.scan_started_at = started;
            (index, scan)
        };
        let progress_path = preparation.upload_progress_path.clone();
        let guard = Guard::new(
            keep_prior,
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
    let mut run = |budget: usize, conflict: bool, keep_prior: bool| {
        std::fs::remove_dir_all(&support).unwrap();
        for (path, bytes, permissions) in &saved {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
            std::fs::set_permissions(path, permissions.clone()).unwrap();
        }
        cycle(budget, conflict, keep_prior)
    };

    for budget in [crate::source_rotation::PARKED_BUDGET, 64 * 1024] {
        for conflict in [false, true] {
            let baseline = run(budget, conflict, false);
            assert_eq!(baseline.ok, !conflict, "{baseline:?}");
            assert_eq!(
                run(budget, conflict, true), baseline,
                "retire versus keep preserves bytes and ACKs at budget {budget}, conflict {conflict}"
            );
        }
    }
    writeln!(std::io::stderr().lock(), "e2_money_parity: real_caller=true tight_budget=true failed_selected_save=true replay_equal=true").unwrap();
}
