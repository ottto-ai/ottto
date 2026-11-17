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
        let (old, lines) = historical_codex::read(kind);
        let path = route.dir.join(format!(
            "rollout-2026-10-18T10-00-00-{}.jsonl",
            old.source_session_id.as_ref().unwrap()
        ));
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        let prior = std::mem::take(&mut route.index);
        let (mut index, mut scan, _) = E2ScanFixture::default().scan_other(
            SnapshotSource::Codex,
            std::slice::from_ref(&route.dir),
            &route.dir,
            prior,
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
        collapse_aliases(&mut scan);
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
    fn restore(&mut self) {
        self.route.index = self
            .route
            ._session
            .as_ref()
            .unwrap()
            .save_reload(&mut self.route.index);
    }
    fn accepted_group() -> Self {
        let route = route_for(Source::Codex);
        let (old, lines) = historical_codex::read(Frozen::StickyLegacy);
        let owner = old.source_session_id.as_deref().unwrap();
        let path = route
            .dir
            .join(format!("rollout-2026-10-18T10-00-00-{owner}.jsonl"));
        fs::write(&path, lines.join("\n") + "\n").unwrap();
        let key = local_index_key(&path);
        let mut f = Self { route, path, key };
        f.continuation();
        let (scan, modes) = f.page(&E2ScanFixture::default());
        assert!(
            !scan.snapshots.is_empty(),
            "group setup: census={} ownership={} modes={modes:?}",
            scan.census_complete,
            scan.ownership_incomplete_file_count
        );
        f.accept(&scan);
        // Production group commits write accepted index facts, not member
        // reductions. Rebind the genuine historical body to that same shape.
        let members = f
            .route
            .index
            .files
            .keys()
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        assert_eq!(members.len(), 2);
        for member in &members {
            let key = local_index_key(member);
            assert!(
                state_v2::load_head(&f.route.index, &key, Codex::REDUCTION_REVISION)
                    .unwrap()
                    .is_none_or(|head| head.metadata_only),
                "a group member must not have a reduction head"
            );
            let entry = &f.route.index.files[&key];
            let items = historical_codex::read(Frozen::StickyLegacy).0.into_items(
                member,
                "2026-10-27T08:00:00Z",
                entry.source_file_fingerprint.clone(),
                None,
            );
            assert_eq!(items.len(), 1);
            let fingerprints = items
                .iter()
                .map(|item| snapshot_fingerprint(SnapshotSource::Codex, item))
                .collect::<BTreeSet<_>>();
            let entry = f.route.index.files.get_mut(&key).unwrap();
            entry.codex_counting_v2 = false;
            entry.last_snapshot_fingerprint =
                Some(snapshot_file_entity_set_hex(fingerprints.clone()));
            entry.last_upload_body_witness = Some(snapshot_upload_body_witness(&items[0]));
            f.route
                .index
                .file_snapshot_fingerprints
                .insert(key, fingerprints.clone());
            f.route
                .index
                .record_accepted_snapshot_fingerprints(&fingerprints);
            assert!(version::legacy_head_missing(
                &f.route.index,
                &local_index_key(member)
            ));
        }
        f.route.save(false);
        f.restore();
        f
    }
    fn continuation(&self) {
        let (_, lines) = historical_codex::read(Frozen::StickyLegacy);
        let owner: Value = serde_json::from_str(&lines[0]).unwrap();
        let id = owner["payload"]["id"].as_str().unwrap();
        let path = self
            .route
            .dir
            .join(format!("rollout-2026-10-27T07-01-00-{id}.jsonl"));
        let mut rows = lines
            .into_iter()
            .map(|line| {
                serde_json::from_str::<Value>(
                    &line
                        .replace("turn-a", "turn-b")
                        .replace("T07:00:", "T07:01:"),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        rows[0]["timestamp"] = serde_json::json!("2026-10-27T07:01:00Z");
        rows[0]["payload"]["timestamp"] = rows[0]["timestamp"].clone();
        for row in &mut rows {
            if row["type"] == "token_usage_record" {
                row["payload"]["usage"]["input_tokens"] = 30.into();
                row["payload"]["usage"]["total_tokens"] = 32.into();
                row["payload"]["thread_token_usage"]["input_tokens"] = 40.into();
                row["payload"]["thread_token_usage"]["output_tokens"] = 4.into();
                row["payload"]["thread_token_usage"]["total_tokens"] = 44.into();
            }
            if row["payload"]["type"] == "token_count" {
                row["payload"]["info"]["last_token_usage"]["input_tokens"] = 30.into();
                row["payload"]["info"]["last_token_usage"]["total_tokens"] = 32.into();
                row["payload"]["info"]["total_token_usage"]["input_tokens"] = 40.into();
                row["payload"]["info"]["total_token_usage"]["output_tokens"] = 4.into();
                row["payload"]["info"]["total_token_usage"]["total_tokens"] = 44.into();
            }
        }
        fs::write(
            path,
            rows.iter()
                .map(|row| row.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
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
        collapse_aliases(&mut scan);
        oracle::scan_money(SnapshotSource::Codex, &index, &scan)
    }
}

fn collapse_aliases(scan: &mut SourceScanResult) {
    scan.snapshots
        .sort_by(|a, b| a.snapshot_fingerprint.cmp(&b.snapshot_fingerprint));
    scan.snapshots.dedup_by(|a, b| {
        if a.snapshot_fingerprint != b.snapshot_fingerprint {
            return false;
        }
        // The aliases differ only in the physical file fingerprint. Preserve
        // every money, placement and body-evidence field in this assertion.
        let mut a = serde_json::to_value(a).unwrap();
        let mut b = serde_json::to_value(b).unwrap();
        a.as_object_mut().unwrap().remove("source_file_fingerprint");
        b.as_object_mut().unwrap().remove("source_file_fingerprint");
        assert_eq!(a, b, "joined aliases must carry identical logical bodies");
        true
    });
}

/// [money] Audit, witness adoption and set-aside cannot convert unchanged history.
#[test]
fn codex_legacy_unchanged_upgrade_restart() {
    let _decoder = oracle::codex_decoder_test_lock();
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
        f.restore();
        let before = f.route.index.files[&f.key].clone();
        let ((scan, modes), io) = oracle::observe_codex_quiet(|| f.page(&E2ScanFixture::default()));
        let mut observed = oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan);
        observed.mode = oracle::Mode::Restart;
        observed.modes = modes;
        observed.io = io;
        oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);
        assert!(!f.route.index.files[&f.key].codex_counting_v2);
        assert_eq!(
            f.route.index.files[&f.key].last_snapshot_fingerprint,
            before.last_snapshot_fingerprint
        );
    }
    let mut joined = LegacyFixture::accepted_group();
    let ((scan, modes), io) =
        oracle::observe_codex_quiet(|| joined.page(&E2ScanFixture::default()));
    let mut observed = oracle::scan_money(SnapshotSource::Codex, &joined.route.index, &scan);
    observed.mode = oracle::Mode::Restart;
    observed.modes = modes;
    observed.io = io;
    oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);
    assert_eq!(scan.ownership_incomplete_file_count, 0);
    assert!(scan.census_complete);

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
        f.restore();
        f.change("\n");
        let before = f.route.index.files[&f.key].clone();
        let activity = codex_zst_refusal_tests::activity();
        let ((scan, modes), io) = oracle::observe_codex_quiet(|| f.page(&E2ScanFixture::default()));
        let mut observed = oracle::scan_money(SnapshotSource::Codex, &f.route.index, &scan);
        observed.mode = oracle::Mode::Restart;
        observed.modes = modes;
        observed.io = io;
        // The file changed and its reduction proof is damaged. A bounded
        // owning-header lookup may run; no body parse or replacement may.
        assert!(
            scan.snapshots.is_empty(),
            "damaged Legacy proof keeps the body held"
        );
        assert_eq!(observed.modes, (0, 0, 0));
        assert_eq!(observed.io.consumed, 0);
        let after = codex_zst_refusal_tests::activity();
        assert_eq!(after.0, activity.0, "no decoder constructed");
        assert!(
            after.1 - activity.1 <= 1,
            "at most one header lookup per member"
        );
        assert_eq!(
            f.route.index.files[&f.key].last_snapshot_fingerprint,
            before.last_snapshot_fingerprint
        );
        assert_eq!(
            f.route.index.files[&f.key].last_upload_body_witness,
            before.last_upload_body_witness
        );
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
        observed.mode = oracle::Mode::Restart;
        observed.modes = modes;
        observed.io = io;
        oracle::money_oracle::assert_quiet_restart_zero_bytes(&observed);
    });
}

/// [money] A stable Legacy group and a finalized unit share a real checkpoint without Legacy reads.
#[test]
fn codex_legacy_group_mixed_page_checkpoint() {
    use std::cell::Cell;
    use std::io::Write;
    let _decoder = oracle::codex_decoder_test_lock();
    let mut f = LegacyFixture::accepted_group();
    let legacy = f.route.index.files.keys().cloned().collect::<Vec<_>>();
    const OTHER: &str = "019a0c2a-8e11-7222-8333-944445555778";
    let path = f
        .route
        .dir
        .join(format!("rollout-2026-10-18T10-00-02-{OTHER}.jsonl"));
    let rows = |n| codex_lines(n).join("\n").replace(SESSION, OTHER) + "\n";
    let before = rows(20);
    fs::write(&path, &before).unwrap();
    let (seed, _) = f.page(&E2ScanFixture::default());
    assert_eq!(seed.snapshots.len(), 1);
    f.accept(&seed);
    f.restore();
    let after = rows(21);
    let extra = after.strip_prefix(&before).unwrap();
    File::options()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(extra.as_bytes())
        .unwrap();
    let window = 2 * FILE_CONTENT_SAMPLE_BYTES as u64;
    assert!(before.len() as u64 > window);
    assert!(legacy
        .iter()
        .all(|key| fs::metadata(key).unwrap().len() < window));
    let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(Cell::get);
    let scanner = E2ScanFixture::default();
    let (((scan, modes), consumed), headers) =
        codex_file_join::header_cache_tests::observe_read_paths(|| {
            oracle::observe_consumed(|| f.page(&scanner))
        });
    assert_eq!(modes, (0, 1, 0));
    assert_eq!(
        consumed,
        extra.len() as u64,
        "only the changed unit's Tail is consumed"
    );
    assert!(scanner
        .acquisitions
        .lock()
        .unwrap()
        .iter()
        .all(|read| read.path == path));
    assert!(
        !headers.is_empty(),
        "the changed unit exercises header reads"
    );
    assert!(
        headers.iter().all(|read| read == &path),
        "Legacy members must have zero header reads: {headers:?}"
    );
    let sampled = START_IDENTITY_SAMPLE_FOR_TEST.with(Cell::get);
    assert!(sampled.0 > samples.0);
    assert_eq!(
        sampled.1 - samples.1,
        (sampled.0 - samples.0) * window,
        "identity samples belong only to the large changed unit, never the Legacy members"
    );
    assert!(scan.census_complete, "the mixed page completes");
    assert!(
        scan.codex_join_validation.is_some(),
        "a real checkpoint is required"
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].source_session_id, OTHER);
    assert!(
        !scan.pending_finalization.is_empty(),
        "exercise the checkpoint boundary"
    );
    let ((), headers) = codex_file_join::header_cache_tests::observe_read_paths(|| {
        scan.validate_codex_checkpoint()
            .expect("mixed page must not reject JOINED_MEMBER_CHANGED");
    });
    assert!(
        headers.is_empty(),
        "stable checkpoint headers need no reread"
    );
    assert_eq!(
        START_IDENTITY_SAMPLE_FOR_TEST.with(Cell::get),
        sampled,
        "checkpoint validation must not sample the skipped Legacy group"
    );
    f.accept(&scan);
    f.restore();
    for key in legacy {
        assert!(!f.route.index.files[&key].codex_counting_v2);
    }
}

/// [money] One changed Legacy head reconstructs, then durable V2 resumes Tail.
#[test]
fn codex_legacy_growth_recounts_cold_v2() {
    use crate::durable_tail_codec::{Dec, Durable, Enc};
    for bytes in [
        &[0, 0, 0, 0][..],
        &[0, 0, 1, 0, 0][..],
        &[0, 0, 1, 1, 0][..],
        &[1, 0, 1, 1, 0][..],
        &[2, 0, 1, 0, 0][..],
    ] {
        let old = codex_usage_occurrence::CodexCounting::take(&mut Dec::new(bytes)).unwrap();
        assert_eq!(Enc::count_write(4096, |out| old.put(out)).unwrap(), bytes);
    }
    let fresh = SnapshotAccumulator::new(SnapshotSource::Codex);
    assert!(version::reusable(
        &historical_codex::read(Frozen::V2).0,
        &fresh
    ));
    assert!(!version::reusable(&historical().0, &fresh));
    let other = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    assert!(version::reusable(&other, &other));
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
        f.restore();
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
    let mut group = LegacyFixture::under(Frozen::StickyLegacy);
    group.continuation();
    group.change("\n");
    let (scan, _) = group.page(&E2ScanFixture::default());
    assert!(!scan.snapshots.is_empty());
    oracle::money_oracle::assert_equivalent(
        &group.cold(),
        &oracle::scan_money(SnapshotSource::Codex, &group.route.index, &scan),
    );

    for paged in [false, true] {
        let mut group = LegacyFixture::accepted_group();
        let continuation = fs::read_dir(&group.route.dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("rollout-2026-10-27T07-01-00-")
            })
            .unwrap();
        let extra = fs::read_to_string(&continuation)
            .unwrap()
            .lines()
            .skip(1)
            .map(|line| {
                let mut row: Value = serde_json::from_str(
                    &line
                        .replace("turn-b", "turn-c")
                        .replace("T07:01:", "T07:02:"),
                )
                .unwrap();
                if row["type"] == "token_usage_record" {
                    row["payload"]["thread_token_usage"]["input_tokens"] = 70.into();
                    row["payload"]["thread_token_usage"]["output_tokens"] = 6.into();
                    row["payload"]["thread_token_usage"]["total_tokens"] = 76.into();
                }
                if row["payload"]["type"] == "token_count" {
                    row["payload"]["info"]["total_token_usage"]["input_tokens"] = 70.into();
                    row["payload"]["info"]["total_token_usage"]["output_tokens"] = 6.into();
                    row["payload"]["info"]["total_token_usage"]["total_tokens"] = 76.into();
                }
                row.to_string() + "\n"
            })
            .collect::<String>();
        group.key = local_index_key(&continuation);
        group.path = continuation;
        group.change(&extra);
        if paged {
            group.change(&"\n".repeat(5000));
        }
        let scanner = E2ScanFixture::default();
        let before = counters::total("codex_legacy_recount", "baseline_unknown");
        let mut pages = 0;
        let mut paused = false;
        let mut run = || {
            for _ in 0..1000 {
                pages += 1;
                let (scan, _) = group.page(&scanner);
                if !scan.snapshots.is_empty() {
                    let cold = sampled_scan::codex_cursor::with_test_limits(
                        16 * 1024 * 1024,
                        16 * 1024 * 1024,
                        64,
                        || group.cold(),
                    );
                    oracle::money_oracle::assert_equivalent(
                        &cold,
                        &oracle::scan_money(SnapshotSource::Codex, &group.route.index, &scan),
                    );
                    assert_eq!(scan.ownership_incomplete_file_count, 0);
                    assert_eq!(
                        counters::total("codex_legacy_recount", "baseline_unknown") - before,
                        1
                    );
                    return;
                }
                paused |= scanner.cache.cursor_job_key().is_some();
            }
            panic!("accepted Legacy group did not complete");
        };
        if paged {
            sampled_scan::codex_cursor::with_test_limits(2048, 1024, 64, &mut run);
            assert!(pages > 1, "group exercised cursor resume");
            assert!(paused, "changed accepted group retained a cursor job");
        } else {
            run();
        }
    }

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
    let cold_index = ScanIndex {
        session_account_bindings: saved_start,
        ..Default::default()
    };
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
        let mut f = if accepted {
            LegacyFixture::under(Frozen::StickyLegacy)
        } else {
            LegacyFixture::new()
        };
        if accepted {
            f.continuation();
            f.change("\n");
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
