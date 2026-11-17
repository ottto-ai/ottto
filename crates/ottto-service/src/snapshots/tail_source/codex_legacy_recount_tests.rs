// Frozen historical reductions exercise upgrades without a Legacy producer.
use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::E2ScanFixture;
use crate::snapshots::sampled_scan::transition_fixture as oracle;
use crate::snapshots::sources::codex::counting::version;
use crate::snapshots::tail_source::counters;
use crate::snapshots::tail_source::historical_codex::{self, Frozen};

fn historical() -> (SnapshotAccumulator, Vec<String>) {
    historical_codex::read(Frozen::Legacy)
}

struct LegacyFixture {
    route: Route,
    path: PathBuf,
    key: String,
}
impl LegacyFixture {
    fn new() -> Self {
        Self::under(Frozen::Legacy)
    }
    fn under(kind: Frozen) -> Self {
        let mut route = route_for(Source::Codex);
        let path = route.dir.join(Codex::name());
        let (_, lines) = historical_codex::read(kind);
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        let (mut index, mut scan, _) = E2ScanFixture::default().scan_other(
            SnapshotSource::Codex,
            std::slice::from_ref(&route.dir),
            &route.dir,
            route.index,
            true,
        );
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        scan.finish_codex_capture_boundary(&mut index);
        route.index = index;
        route.save(false);
        historical_codex::seed(&mut route.index, &path, &route.dir, kind);
        route.save(false);
        let key = local_index_key(&path);
        Self { route, path, key }
    }
    fn page(&mut self, scanner: &E2ScanFixture) -> (SourceScanResult, (usize, usize, usize)) {
        let (mut index, mut scan, modes) = scanner.scan_other(
            SnapshotSource::Codex,
            std::slice::from_ref(&self.route.dir),
            &self.route.dir,
            std::mem::take(&mut self.route.index),
            true,
        );
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        scan.finish_codex_capture_boundary(&mut index);
        self.route.index = index;
        (scan, modes)
    }
    fn accept(&mut self, scan: &SourceScanResult) {
        let accepted = scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        self.route
            .index
            .record_accepted_snapshot_fingerprints(&accepted);
        self.route.save(false);
    }
    fn seed_copy(&mut self) -> PathBuf {
        let path = self
            .route
            .dir
            .join(format!("rollout-2026-10-18T10-00-01-{SESSION}.jsonl"));
        fs::copy(&self.path, &path).unwrap();
        let (pending, native) = complete::<Codex>(&self.route, &path, None, |_| {});
        assert!(pending.publish(&native));
        let mut entry = self.route.index.files[&self.key].clone();
        let stat = fs::metadata(&path).unwrap();
        entry.size_bytes = stat.len();
        entry.modified_unix_seconds = unix_seconds(stat.modified().unwrap()).unwrap();
        entry.modified_unix_nanos = unix_nanos(stat.modified().unwrap());
        self.route.index.files.insert(local_index_key(&path), entry);
        self.route.save(false);
        historical_codex::seed(
            &mut self.route.index,
            &path,
            &self.route.dir,
            Frozen::Legacy,
        );
        self.route.save(false);
        path
    }
    fn change(&self, text: &str) {
        use std::io::Write;
        File::options()
            .append(true)
            .open(&self.path)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
    }
    fn cold(&self) -> oracle::RouteResult {
        let (mut index, mut scan, _) = E2ScanFixture::default().scan_other(
            SnapshotSource::Codex,
            std::slice::from_ref(&self.route.dir),
            &self.route.dir,
            ScanIndex::default(),
            true,
        );
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        oracle::scan_money(SnapshotSource::Codex, &index, &scan)
    }
}

/// [money] Audit, witness adoption and set-aside cannot convert unchanged history.
#[test]
fn codex_legacy_unchanged_upgrade_restart() {
    for selection in ["settled", "audit", "witness", "retry"] {
        let mut f = LegacyFixture::new();
        match selection {
            "audit" => {
                f.route
                    .index
                    .files
                    .get_mut(&f.key)
                    .unwrap()
                    .scan_identity_version =
                    Some(format!("{}:0", sampled_audit::UNVERIFIED_IDENTITY))
            }
            "witness" => {
                f.route
                    .index
                    .activate_effective_upload_body_witness_revision(99);
            }
            "retry" => {
                state_v2::set_aside_tail(&f.route.path, &f.key, state_v2::SetAsideCause::Encode)
                    .unwrap()
            }
            _ => {}
        }
        let before = f.route.index.files[&f.key].clone();
        let ((scan, modes), io) = oracle::observe_codex_quiet(|| f.page(&E2ScanFixture::default()));
        let mut observed = oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan);
        observed.modes = modes;
        observed.io = io;
        oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);
        assert!(!f.route.index.files[&f.key].codex_counting_v2);
        assert_eq!(
            f.route.index.files[&f.key].last_snapshot_fingerprint,
            before.last_snapshot_fingerprint
        );
    }
    let mut joined = LegacyFixture::new();
    joined.seed_copy();
    let ((scan, modes), io) =
        oracle::observe_codex_quiet(|| joined.page(&E2ScanFixture::default()));
    let mut observed = oracle::scan_money(SnapshotSource::Codex, &joined.route.index, &scan);
    observed.modes = modes;
    observed.io = io;
    oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);

    for damage in ["missing", "corrupt"] {
        let mut f = LegacyFixture::new();
        if damage == "missing" {
            state_v2::erase_tail(&f.route.path, &mut f.route.index, [f.key.clone()]).unwrap();
        } else {
            let mut old = head::<Codex>(&f.route, &f.key);
            old.body.pop();
            state_v2::stage_tail(
                &f.route.path,
                &f.key,
                state_v2::StagedFile {
                    revision: old.revision,
                    head: old.body,
                    ..Default::default()
                },
            )
            .unwrap();
        }
        f.route.save(false);
        f.change("\n");
        let ((scan, modes), io) = oracle::observe_codex_quiet(|| f.page(&E2ScanFixture::default()));
        let mut observed = oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan);
        observed.modes = modes;
        observed.io = io;
        oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);
        assert!(!f.route.index.files[&f.key].codex_counting_v2);
    }

    // A paused audit job must also stop if its file is again at the accepted
    // physical checkpoint. Restoration changes ctime, not the content stamp.
    let mut paused = LegacyFixture::new();
    let stat = fs::metadata(&paused.path).unwrap();
    paused.change(
        &(codex_lines(40)
            .into_iter()
            .skip(codex_lines(1).len())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
    );
    let scanner = E2ScanFixture::default();
    sampled_scan::codex_cursor::with_test_limits(2048, 1024, 64, || {
        let (scan, _) = paused.page(&scanner);
        assert!(scan.snapshots.is_empty());
        assert!(scanner.cache.cursor_job_key().is_some());
        let file = File::options().write(true).open(&paused.path).unwrap();
        file.set_len(stat.len()).unwrap();
        file.set_times(fs::FileTimes::new().set_modified(stat.modified().unwrap()))
            .unwrap();
        let ((scan, modes), io) = oracle::observe_codex_quiet(|| paused.page(&scanner));
        assert!(scanner.cache.cursor_job_key().is_none());
        let mut observed = oracle::scan_money(SnapshotSource::Codex, &paused.route.index, &scan);
        observed.modes = modes;
        observed.io = io;
        oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);
    });
}

/// [money] One changed Legacy head reconstructs, then durable V2 resumes Tail.
#[test]
fn codex_legacy_growth_recounts_cold_v2() {
    use crate::durable_tail_codec::{Dec, Durable, Enc};
    for bytes in [
        &[0, 0, 0, 0][..],
        &[0, 0, 1, 0, 0][..],
        &[0, 0, 1, 1, 0][..],
    ] {
        let old = codex_usage_occurrence::CodexCounting::take(&mut Dec::new(bytes)).unwrap();
        assert_eq!(Enc::count_write(4096, |out| old.put(out)).unwrap(), bytes);
    }
    for view in ["1793016000000:none", "1793016000000:v2_marked", "legacy"] {
        assert!(version::reusable_under_view(
            &historical_codex::read(Frozen::V2).0,
            view
        ));
        assert!(!version::reusable_under_view(&historical().0, view));
    }
    assert!(version::reusable(None, None));
    for kind in [Frozen::Legacy, Frozen::V2] {
        let mut f = LegacyFixture::under(kind);
        let extra = codex_lines(2)
            .into_iter()
            .skip(codex_lines(1).len())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        f.change(&extra);
        let (scan, modes) = f.page(&E2ScanFixture::default());
        assert_eq!(
            modes,
            if matches!(kind, Frozen::Legacy) {
                (1, 0, 0)
            } else {
                (0, 1, 0)
            }
        );
        oracle::money_oracle::assert_equivalent(
            &f.cold(),
            &oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan),
        );
        assert!(f.route.index.files[&f.key].codex_counting_v2);
        f.accept(&scan);
        let extra = codex_lines(3)
            .into_iter()
            .skip(codex_lines(2).len())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        f.change(&extra);
        let (scan, modes) = f.page(&E2ScanFixture::default());
        assert_eq!(modes, (0, 1, 0));
        oracle::money_oracle::assert_equivalent(
            &f.cold(),
            &oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan),
        );
    }
    let mut group = LegacyFixture::new();
    let changed = group.seed_copy();
    use std::io::Write;
    File::options()
        .append(true)
        .open(changed)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    let (scan, _) = group.page(&E2ScanFixture::default());
    assert!(!scan.snapshots.is_empty());
    oracle::money_oracle::assert_equivalent(
        &group.cold(),
        &oracle::scan_money(SnapshotSource::Codex, &group.route.index, &scan),
    );

    let mut paged = LegacyFixture::new();
    paged.change(
        &(codex_lines(40)
            .into_iter()
            .skip(codex_lines(1).len())
            .collect::<Vec<_>>()
            .join("\n")
            + "\n"),
    );
    let scanner = E2ScanFixture::default();
    let before = counters::total("tail_reconstruct", "incompatible_counting_version");
    sampled_scan::codex_cursor::with_test_limits(2048, 1024, 64, || {
        let (first, _) = paged.page(&scanner);
        assert!(first.snapshots.is_empty());
        assert!(
            scanner.cache.cursor_job_key().is_some(),
            "changed Legacy parse paused"
        );
        for _ in 0..1000 {
            let (scan, _) = paged.page(&scanner);
            if !scan.snapshots.is_empty() {
                oracle::money_oracle::assert_equivalent(
                    &sampled_scan::codex_cursor::with_test_limits(
                        16 * 1024 * 1024,
                        16 * 1024 * 1024,
                        64,
                        || paged.cold(),
                    ),
                    &oracle::scan_money(SnapshotSource::Codex, &paged.route.index, &scan),
                );
                assert_eq!(
                    counters::total("tail_reconstruct", "incompatible_counting_version") - before,
                    1
                );
                return;
            }
        }
        panic!("paged Legacy conversion did not complete");
    });
    placement_control();
}

// Reuse the real home-binding and saved-start-binding paths beside the
// converted file: A remains A after a switch to B; B's side call is tagged;
// a session older than B's login has no invented owner.
fn placement_control() {
    use crate::agent_status::CodexHomeBinding;
    const A: &str = "019a0c2a-8e11-7222-8333-944445555001";
    const SIDE: &str = "019a0c2a-8e11-7222-8333-944445555002";
    const GAP: &str = "019a0c2a-8e11-7222-8333-944445555003";
    let mut f = LegacyFixture::new();
    let sessions = f.route.dir.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let clock = |at: &str| {
        std::time::UNIX_EPOCH
            + std::time::Duration::from_secs(
                OffsetDateTime::parse(at, &Rfc3339)
                    .unwrap()
                    .unix_timestamp() as u64,
            )
    };
    let home = |account: &str, workspace: &str, at: &str| CodexHomeBinding {
        home: f.route.dir.clone(),
        account_identifier_hash: account.repeat(64),
        workspace_identifier_hash: workspace.repeat(64),
        auth_modified_at: clock(at),
    };
    let login_a = home("a", "c", "2026-10-17T00:00:00Z");
    let login_b = home("b", "d", "2026-10-19T00:00:00Z");
    fn rows(id: &str, turn: &str, at: &str, input: u64) -> Vec<Value> {
        let usage = serde_json::json!({"input_tokens":input,"cached_input_tokens":0,"cache_write_input_tokens":0,
            "output_tokens":2,"reasoning_output_tokens":0,"total_tokens":input+2});
        vec![
            serde_json::json!({"timestamp":at,"type":"session_meta","payload":{"id":id,"timestamp":at}}),
            serde_json::json!({"timestamp":at,"type":"event_msg","payload":{"type":"task_started","turn_id":turn}}),
            serde_json::json!({"timestamp":at,"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
            serde_json::json!({"timestamp":at,"type":"token_usage_record","payload":{"thread_id":id,"turn_id":turn,"response_id":turn,
                "auth_mode":"chatgpt","usage":usage,"thread_token_usage":usage}}),
            serde_json::json!({"timestamp":at,"type":"event_msg","payload":{"type":"task_complete","turn_id":turn}}),
        ]
    }
    let text = |rows: Vec<Value>| {
        rows.into_iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>()
    };
    fn page(
        f: &LegacyFixture,
        index: ScanIndex,
        homes: &[CodexHomeBinding],
    ) -> (ScanIndex, SourceScanResult) {
        let (mut index, mut scan, _) = E2ScanFixture::default().scan_other(
            SnapshotSource::Codex,
            std::slice::from_ref(&f.route.dir),
            &f.route.dir,
            index,
            true,
        );
        index.bind_session_accounts(
            SnapshotSource::Codex,
            "historical-placement",
            &mut scan.snapshots,
            homes,
        );
        apply_upload_policy(
            SnapshotSource::Codex,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
        scan.finish_codex_capture_boundary(&mut index);
        (index, scan)
    }
    let path = |id: &str| sessions.join(format!("rollout-{id}.jsonl"));
    fs::write(path(A), text(rows(A, "a1", "2026-10-18T10:00:00Z", 7))).unwrap();
    let prior = std::mem::take(&mut f.route.index);
    let (index, warm) = page(&f, prior, &[login_a]);
    f.route.index = index;
    assert_eq!(warm.snapshots.len(), 1);
    assert_eq!(
        warm.snapshots[0].model_usage[0]
            .account_identifier_hash
            .as_deref(),
        Some("a".repeat(64).as_str())
    );
    f.accept(&warm);
    let saved_start = f.route.index.session_account_bindings.clone();
    use std::io::Write;
    File::options()
        .append(true)
        .open(path(A))
        .unwrap()
        .write_all(
            text(
                rows(A, "a2", "2026-10-20T10:00:00Z", 11)
                    .into_iter()
                    .skip(1)
                    .collect(),
            )
            .as_bytes(),
        )
        .unwrap();
    let mut side = rows(SIDE, "side", "2026-10-20T10:01:00Z", 23);
    side[0]["payload"]["source"] =
        serde_json::json!({"subagent":{"thread_spawn":{"parent_thread_id":A,"depth":1}}});
    side[0]["payload"]["thread_source"] = serde_json::json!("subagent");
    fs::write(path(SIDE), text(side)).unwrap();
    fs::write(
        path(GAP),
        text(rows(GAP, "gap", "2026-10-18T10:02:00Z", 31)),
    )
    .unwrap();
    f.change("\n");
    let prior = std::mem::take(&mut f.route.index);
    let (index, changed) = page(&f, prior, std::slice::from_ref(&login_b));
    let mut cold_index = ScanIndex::default();
    cold_index.session_account_bindings = saved_start;
    let (cold_index, cold) = page(&f, cold_index, &[login_b]);
    oracle::money_oracle::assert_equivalent(
        &oracle::scan_money(SnapshotSource::Codex, &cold_index, &cold),
        &oracle::scan_money(SnapshotSource::Codex, &index, &changed),
    );
    let owners = changed
        .snapshots
        .iter()
        .map(|item| {
            (
                item.source_session_id.as_str(),
                item.model_usage[0].account_identifier_hash.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        owners[A],
        Some("a".repeat(64)),
        "saved A survives the login switch"
    );
    assert_eq!(owners[SIDE], Some("b".repeat(64)), "B owns its side call");
    assert_eq!(owners[GAP], None, "the evidence gap stays untagged");
    assert_eq!(owners[SESSION], None, "the conversion invents no identity");
}

/// [money] A mixed-direction correction equals cold V2 and alarms only on replacement.
#[test]
fn codex_legacy_shrink_once() {
    let mut f = LegacyFixture::new();
    let old = historical().0.accepted_usage_totals;
    f.change("\n");
    let (scan, _) = f.page(&E2ScanFixture::default());
    assert_eq!(scan.snapshots.len(), 1);
    assert!(scan.snapshots[0].input_tokens < old.input_tokens);
    assert!(scan.snapshots[0].output_tokens > old.output_tokens);
    oracle::money_oracle::assert_equivalent(
        &f.cold(),
        &oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan),
    );
    assert_eq!(counters::total("codex_legacy_recount", "shrink"), 1);
    f.accept(&scan);
    let (scan, _) = f.page(&E2ScanFixture::default());
    assert!(scan.snapshots.is_empty());
    assert_eq!(counters::total("codex_legacy_recount", "shrink"), 1);
}

/// [money] An ordinary history_base owns local records without an age selector.
#[test]
fn codex_history_base_first_record_uses_v2() {
    let mut f = LegacyFixture::new();
    let (_, mut lines) = historical();
    let mut header: Value = serde_json::from_str(&lines[0]).unwrap();
    header["payload"]["history_base"] = serde_json::json!({"id":"external-history"});
    lines[0] = header.to_string();
    fs::write(&f.path, lines.join("\n") + "\n").unwrap();
    let (scan, _) = f.page(&E2ScanFixture::default());
    assert!(f.route.index.files[&f.key].codex_counting_v2);
    oracle::money_oracle::assert_equivalent(
        &f.cold(),
        &oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan),
    );
}

/// [money] Missing comparison proof is counted; never-ACKed input is new usage.
/// [behaviour] Retired counting history retains no heap as history grows.
#[test]
fn codex_legacy_baseline_unknown_and_new_usage() {
    for accepted in [true, false] {
        let mut f = LegacyFixture::new();
        if accepted {
            let changed = f.seed_copy();
            use std::io::Write;
            File::options()
                .append(true)
                .open(changed)
                .unwrap()
                .write_all(b"\n")
                .unwrap();
            let (scan, _) = f.page(&E2ScanFixture::default());
            assert!(!scan.snapshots.is_empty());
            oracle::money_oracle::assert_equivalent(
                &f.cold(),
                &oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan),
            );
            assert_eq!(
                counters::total("codex_legacy_recount", "baseline_unknown"),
                1
            );
        } else {
            let entry = f.route.index.files.get_mut(&f.key).unwrap();
            entry.last_snapshot_fingerprint = None;
            entry.last_upload_body_witness = None;
            f.route.index.accepted_snapshot_fingerprints.clear();
            let (scan, _) = f.page(&E2ScanFixture::default());
            assert!(!scan.snapshots.is_empty());
            assert_eq!(counters::total("codex_legacy_recount", "new_usage"), 1);
        }
    }
    let mut retained = None;
    for count in [1, 512] {
        let mut value = serde_json::to_value(ScanIndex::default()).unwrap();
        value["codex_counting_tombstones"] = serde_json::json!((0..count).map(|n|
            (format!("{n:064x}"), serde_json::json!({"evidence":"legacy_acked", "retired_in":"historical", "created_unix_ms":null})))
            .collect::<BTreeMap<_,_>>());
        value["codex_counting_evicted_legacy"] = serde_json::json!((0..count)
            .map(|n| serde_json::json!({"owner":format!("{n:064x}"),"selected_v2":false}))
            .collect::<Vec<_>>());
        let loaded: ScanIndex = serde_json::from_value(value).unwrap();
        let encoded = serde_json::to_value(&loaded).unwrap();
        assert!(encoded.get("codex_counting_tombstones").is_none());
        assert!(encoded.get("codex_counting_evicted_legacy").is_none());
        let bound = crate::heap_layout_bound::bound(&loaded, usize::MAX);
        if let Some(previous) = retained {
            assert_eq!(bound, previous, "retired history must not remain resident");
        }
        retained = Some(bound);
    }
}
