//! Synthetic state-repair fixtures. Native reads use the production scanner;
//! disk selection uses the real store envelope and existing field codec.
use super::super::sampled_jsonl::durable as codec;
use super::*;
use crate::durable_tail_store::{
    self as store, Binding, DurableSource, DurableTailStore, PendingRecord,
};
use crate::locked_state_dir::test_locks;
use crate::transcript_acquisition::{birth_unix_nanos, FullReason, ReadMode, Scope};

const CHILD: &str = "019fa111-2222-7333-8444-555555555555";
const PARENT: &str = "019fa111-2222-7333-8444-666666666666";
const ROOT: &str = "019fa111-2222-7333-8444-777777777777";
const NOW: &str = "2026-10-07T12:00:00Z";
const NAMESPACE: &str = "child-pair-rederive";

struct Fixture {
    scratch: crate::test_scratch::ScratchDir,
    root: PathBuf,
    path: PathBuf,
    index_path: PathBuf,
}
impl Fixture {
    fn new(kind: &str) -> Self {
        let scratch = crate::test_scratch::ScratchDir::new("child-pair-rederive");
        let root = scratch.join(".codex/sessions");
        fs::create_dir_all(&root).unwrap();
        let path = root.join(format!("rollout-2026-10-07T10-00-00-{CHILD}.jsonl"));
        let mut header = json!({"type":"session_meta","ordinal":0,"timestamp":"2026-10-07T10:00:00Z","payload":{
            "id":CHILD,"session_id":PARENT,"timestamp":"2026-10-07T10:00:00Z","thread_source":"subagent",
            "source":{"subagent":{"thread_spawn":{"parent_thread_id":PARENT,"depth":1}}},
            "forked_from_id":PARENT,"history_mode":"paginated","subagent_history_start_ordinal":1,
            "creator_user_id":"synthetic-child-user","creator_account_id":"synthetic-child-account"}});
        if kind == "incomplete" {
            header["payload"]
                .as_object_mut()
                .unwrap()
                .remove("creator_account_id");
        }
        if matches!(kind, "depth2" | "depth1" | "unrelated") {
            for field in [
                "forked_from_id",
                "history_mode",
                "subagent_history_start_ordinal",
            ] {
                header["payload"].as_object_mut().unwrap().remove(field);
            }
        }
        if kind == "depth2" {
            header["payload"]["session_id"] = json!(ROOT);
            header["payload"]["source"]["subagent"]["thread_spawn"]["depth"] = json!(2);
        }
        if kind == "unrelated" {
            header["payload"]["session_id"] = json!(CHILD);
            header["payload"]["source"] = json!("cli");
            header["payload"]["thread_source"] = json!("cli");
        }
        let mut rows = vec![header.clone()];
        if kind == "conflict" {
            let mut conflict = header;
            conflict["ordinal"] = json!(1);
            conflict["payload"]["creator_user_id"] = json!("synthetic-different-user");
            rows.push(conflict);
        }
        let ordinal = rows.len();
        rows.push(json!({"type":"event_msg","ordinal":ordinal,"timestamp":"2026-10-07T11:00:00Z","payload":{"type":"token_count","info":{
            "model":"gpt-5.5","total_token_usage":{"input_tokens":100,"output_tokens":5},"last_token_usage":{"input_tokens":100,"output_tokens":5}}}}));
        fs::write(
            &path,
            rows.iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
        let index_path = scratch.join("index.json");
        Self {
            scratch,
            root,
            path,
            index_path,
        }
    }
    fn cache(&self) -> Arc<sampled_scan::SharedCache> {
        let cache = Arc::new(sampled_scan::SharedCache::default());
        cache.durable_begin_pass(
            SnapshotSource::Codex,
            &self.index_path,
            &Scope(NAMESPACE.into()),
            false,
        );
        cache
    }
    fn run(
        &self,
        index: ScanIndex,
        cache: Option<Arc<sampled_scan::SharedCache>>,
        metadata: &CodexTitleMetadata,
    ) -> (ScanIndex, SourceScanResult, usize) {
        self.run_inner(index, cache, metadata, None)
    }
    fn run_inner(
        &self,
        index: ScanIndex,
        cache: Option<Arc<sampled_scan::SharedCache>>,
        metadata: &CodexTitleMetadata,
        faults: Option<&std::cell::Cell<usize>>,
    ) -> (ScanIndex, SourceScanResult, usize) {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            std::slice::from_ref(&self.root),
            index,
            NOW,
            BACKFILL_WINDOW_DAYS,
            10,
            false,
            None,
            &[],
            false,
            true,
        );
        scan.codex_title_metadata.spawn_parents = metadata.spawn_parents.clone();
        if let Some(cache) = cache {
            scan = scan.with_sampled_acquisition(cache, Scope(NAMESPACE.into()));
        }
        let ((index, result), reads) = terminal_contract_retry::source_acquisitions(|| loop {
            if let Some(active) = scan.active_file.as_deref() {
                let key = local_index_key(&active.candidate.path);
                if matches!(
                    scan.index
                        .files
                        .get(&key)
                        .and_then(|entry| entry.codex_child_pair_rederive),
                    Some(Stamp::Pending { .. })
                ) {
                    assert_eq!(
                        active
                            .sampling
                            .as_ref()
                            .expect("repair uses acquisition plan")
                            .mode,
                        ReadMode::Full(FullReason::AuditDue)
                    );
                }
            }
            let next = if let Some(faults) = faults.filter(|_| scan.active_file.is_some()) {
                faults.set(faults.get() + 1);
                with_transcript_io_denied(|| scan.step(None))
            } else {
                scan.step(None)
            };
            match next {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete {
                    mut index,
                    scan: result,
                    ..
                } => {
                    let mut projected = result.clone();
                    apply_upload_policy(
                        SnapshotSource::Codex,
                        &mut projected.snapshots,
                        SnapshotUploadPolicy::default(),
                    );
                    finalize_scan_after_policy(SnapshotSource::Codex, &mut projected, &mut index);
                    index.record_accepted_snapshot_fingerprints(
                        &projected
                            .snapshots
                            .iter()
                            .map(|item| item.snapshot_fingerprint.clone())
                            .collect(),
                    );
                    break (index, projected);
                }
            }
        });
        (index, result, reads.get(&self.path).copied().unwrap_or(0))
    }
    fn seed(&self, index: &ScanIndex, conflicted: bool, absent_pair: bool) {
        let scope = Scope("synthetic-old-cache".into());
        let mut parser = OwnedJsonlParser::new(
            File::open(&self.path).unwrap(),
            &self.path,
            SnapshotSource::Codex,
            apply_codex_line,
            None,
            None,
            None,
            false,
            true,
        )
        .unwrap();
        parser
            .prepare_acquisition(None, &scope, None, 1_800_000_000)
            .unwrap();
        while !parser.step().unwrap() {}
        parser.accumulator.codex_creator_evidence_conflicted = conflicted;
        if absent_pair {
            parser.accumulator.codex_creator_evidence = None;
        }
        let reduction = parser.durable_test_reduction_copy();
        let checkpoint = match parser
            .certify_without_retention(&scope, 1_800_000_000)
            .unwrap()
        {
            sampled_jsonl::SideCertificate::Certified { completed, .. } => completed.checkpoint,
            _ => panic!("native seed must certify"),
        };
        let key = local_index_key(&self.path);
        let entry = &index.files[&key];
        let lock = test_locks::hold(self.scratch.as_ref());
        let mut disk = DurableTailStore::new(
            store::store_dir_for_index(&self.index_path),
            DurableSource::Codex,
        );
        disk.write_after_save(
            lock,
            index.generation,
            vec![PendingRecord {
                binding: Binding {
                    source: DurableSource::Codex,
                    key: store::key_digest(DurableSource::Codex, &key),
                    context: store::context_digest(
                        NAMESPACE,
                        index.active_upload_context_fingerprint.as_deref(),
                    ),
                    scope: [0; 32],
                    entry: store::replay_entry_digest(
                        &store::entry_digest(
                            &entry.source_file_fingerprint,
                            entry.last_upload_body_witness.as_deref(),
                        ),
                        entry.effective_upload_body_witness_revision,
                        0,
                    ),
                },
                certificate: checkpoint
                    .durable_certificate(birth_unix_nanos(&fs::metadata(&self.path).unwrap()))
                    .unwrap(),
                body: codec::encode(&reduction, store::RECORD_BYTES, jsonl_line_cap() as u64)
                    .unwrap(),
                allowlist: codec::allowlist_digest(SnapshotSource::Codex),
            }],
        )
        .unwrap();
    }
}

#[test]
fn codex_child_pair_named_conflict_incomplete_read_once_then_two_restarts() {
    for (kind, expected) in [
        ("named", Stamp::Named),
        ("conflict", Stamp::Conflict),
        ("incomplete", Stamp::Incomplete),
        ("depth2", Stamp::Named),
    ] {
        let fixture = Fixture::new(kind);
        let mut metadata = CodexTitleMetadata::default();
        if kind == "depth2" {
            metadata.spawn_parents.insert(CHILD.into(), PARENT.into());
            metadata.spawn_parents.insert(PARENT.into(), ROOT.into());
        }
        let (mut index, oracle, _) = fixture.run(ScanIndex::default(), None, &metadata);
        let key = local_index_key(&fixture.path);
        assert!(index.files.contains_key(&key));
        index.save(&fixture.index_path).unwrap();
        fixture.seed(&index, kind != "depth2", kind == "depth2");
        let cache = fixture.cache();
        assert!(cache.durable_child_pair_candidate(&key, &index, &metadata));
        let (mut index, repaired, reads) = fixture.run(index, Some(cache.clone()), &metadata);
        assert_eq!(reads, 1, "{kind}");
        assert_eq!(
            index.files[&key].codex_child_pair_rederive,
            Some(expected),
            "{kind}"
        );
        assert!(
            !index.files[&key].has_unverified_source(),
            "repair debt retired: {kind}"
        );
        let counts = cache.durable_counters(SnapshotSource::Codex).unwrap().0;
        assert_eq!(counts.codex_child_pair_rederive[0], 1);
        assert_eq!(
            counts.codex_child_pair_rederive[1],
            index.files[&key].size_bytes
        );
        assert_eq!(
            counts.codex_child_pair_rederive[outcome_slot(expected).unwrap()],
            1
        );
        assert_eq!(oracle.snapshots.len(), repaired.snapshots.len());
        for (old, new) in oracle.snapshots.iter().zip(&repaired.snapshots) {
            let mut old = serde_json::to_value(old).unwrap();
            let mut new = serde_json::to_value(new).unwrap();
            old.as_object_mut()
                .unwrap()
                .remove("session_account_evidence");
            new.as_object_mut()
                .unwrap()
                .remove("session_account_evidence");
            assert_eq!(old, new, "tokens, money and non-evidence bytes: {kind}");
        }
        if kind == "conflict" {
            assert_eq!(
                repaired.snapshots[0]
                    .session_account_evidence
                    .as_ref()
                    .unwrap()
                    .identity_disposition,
                Some("conflict")
            );
        }
        let (same, _, reads) = fixture.run(index, Some(cache), &metadata);
        index = same;
        assert_eq!(reads, 0, "next pass {kind}");
        for restart in 0..2 {
            index.save(&fixture.index_path).unwrap();
            let child = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "snapshots::codex_child_pair_rederive::tests::codex_child_pair_restart_probe",
                    "--nocapture",
                ])
                .env("OTTTO_CHILD_PAIR_TEST_ROOT", &fixture.root)
                .env("OTTTO_CHILD_PAIR_TEST_INDEX", &fixture.index_path)
                .env(
                    "OTTTO_CHILD_PAIR_TEST_DEPTH2",
                    if kind == "depth2" { "1" } else { "0" },
                )
                .output()
                .unwrap();
            assert!(
                child.status.success(),
                "fresh-process restart {restart} {kind}: {} {}",
                String::from_utf8_lossy(&child.stdout),
                String::from_utf8_lossy(&child.stderr)
            );
            let loaded = ScanIndex::load(&fixture.index_path).unwrap();
            let (next, _, reads) = fixture.run(loaded, Some(fixture.cache()), &metadata);
            assert_eq!(reads, 0, "restart {restart} {kind}");
            index = next;
        }
    }
}

#[test]
fn codex_child_pair_selector_excludes_good_plain_depth_one_and_non_native() {
    for (kind, conflicted) in [("named", false), ("depth1", true), ("unrelated", true)] {
        let fixture = Fixture::new(kind);
        let metadata = CodexTitleMetadata::default();
        let (index, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
        fixture.seed(&index, conflicted, false);
        let cache = fixture.cache();
        let (index, _, reads) = fixture.run(index, Some(cache.clone()), &metadata);
        assert_eq!(reads, 0, "{kind}");
        assert!(index.files[&local_index_key(&fixture.path)]
            .codex_child_pair_rederive
            .is_none());
        assert_eq!(
            cache
                .durable_counters(SnapshotSource::Codex)
                .unwrap()
                .0
                .codex_child_pair_rederive,
            [0; 6]
        );
    }
}

#[test]
fn codex_child_pair_bytes_are_index_sizes_and_over_budget_stages_nothing() {
    let fixture = Fixture::new("named");
    let metadata = CodexTitleMetadata::default();
    let (mut index, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
    let key = local_index_key(&fixture.path);
    index.files.get_mut(&key).unwrap().size_bytes = MAX_BYTES + 1;
    fixture.seed(&index, true, false);
    let cache = fixture.cache();
    with_transcript_io_denied(|| stage(&mut index, &cache, &metadata));
    assert!(index.files[&key].codex_child_pair_rederive.is_none());
    assert!(!index.files[&key].has_unverified_source());
    assert_eq!(
        &cache
            .durable_counters(SnapshotSource::Codex)
            .unwrap()
            .0
            .codex_child_pair_rederive[..2],
        &[1, MAX_BYTES + 1]
    );
}

#[test]
fn codex_child_pair_three_retries_then_unreadable_preserve_independent_debt() {
    for previous_due in [None, Some(7)] {
        let fixture = Fixture::new("named");
        let metadata = CodexTitleMetadata::default();
        let (mut index, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
        let key = local_index_key(&fixture.path);
        let fp = index.files[&key].source_file_fingerprint.clone();
        assert!(index.stage_sampled_audit(
            &key,
            &fp,
            crate::transcript_acquisition::AuditDebt {
                due_unix_seconds: 100
            }
        ));
        index.files.get_mut(&key).unwrap().codex_child_pair_rederive = Some(Stamp::Pending {
            attempts: 0,
            retry_after: 100,
            running: false,
            previous_due,
        });
        let mut now = 100;
        for attempt in 1..=4 {
            assert!(begin(&mut index, &key, now));
            assert_eq!(failed(&mut index, &key, now), attempt == 4);
            index.save(&fixture.index_path).unwrap();
            index = ScanIndex::load(&fixture.index_path).unwrap();
            if attempt < 4 {
                assert!(waiting(&index.files[&key], now));
                assert!(!begin(&mut index, &key, now));
                now += 1 << attempt.min(3);
            }
        }
        assert_eq!(
            index.files[&key].codex_child_pair_rederive,
            Some(Stamp::Unreadable)
        );
        assert_eq!(index.files[&key].unverified_deadline(), previous_due);
        assert!(!begin(&mut index, &key, now + 1_000));
        assert!(!failed(&mut index, &key, now + 1_000));
    }
}

mod old_201 {
    include!("codex_child_pair_decoder_0_1_201.rs");
}
mod old_202 {
    include!("codex_child_pair_decoder_0_1_202.rs");
}

#[test]
fn codex_child_pair_old_decoders_tolerate_marker_and_202_save_costs_one_more_read() {
    let fixture = Fixture::new("named");
    let metadata = CodexTitleMetadata::default();
    let (mut index, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
    let key = local_index_key(&fixture.path);
    index.files.get_mut(&key).unwrap().codex_child_pair_rederive = Some(Stamp::Named);
    index.save(&fixture.index_path).unwrap();
    let mut old_index: Value =
        serde_json::from_slice(&fs::read(&fixture.index_path).unwrap()).unwrap();
    let entry = old_index["files"][&key].clone();
    let old_201: old_201::ScanIndexEntry = serde_json::from_value(entry.clone()).unwrap();
    let old_202: old_202::ScanIndexEntry = serde_json::from_value(entry).unwrap();
    assert_eq!(
        old_201.source_file_fingerprint,
        index.files[&key].source_file_fingerprint
    );
    assert_eq!(
        old_202.last_upload_body_witness,
        index.files[&key].last_upload_body_witness
    );
    old_index["files"][&key] = serde_json::to_value(&old_202).unwrap();
    fs::write(&fixture.index_path, serde_json::to_vec(&old_index).unwrap()).unwrap();
    let dropped = ScanIndex::load(&fixture.index_path).unwrap();
    assert!(dropped.files[&key].codex_child_pair_rederive.is_none());
    // Worst case: the old binary also leaves/recreates the old conflicted
    // cache. The upgraded writer must spend at most one more counted Full.
    fixture.seed(&dropped, true, false);
    let (mut upgraded, _, reads) = fixture.run(dropped, Some(fixture.cache()), &metadata);
    assert_eq!(reads, 1);
    assert_eq!(
        upgraded.files[&key].codex_child_pair_rederive,
        Some(Stamp::Named)
    );
    for _ in 0..2 {
        upgraded.save(&fixture.index_path).unwrap();
        let loaded = ScanIndex::load(&fixture.index_path).unwrap();
        let (next, _, reads) = fixture.run(loaded, Some(fixture.cache()), &metadata);
        assert_eq!(reads, 0);
        upgraded = next;
    }
}

#[test]
fn codex_child_pair_unknown_marker_is_fail_closed_and_partial_save_carries_credit() {
    let fixture = Fixture::new("named");
    let (mut previous, _, _) =
        fixture.run(ScanIndex::default(), None, &CodexTitleMetadata::default());
    let key = local_index_key(&fixture.path);
    previous
        .files
        .get_mut(&key)
        .unwrap()
        .codex_child_pair_rederive = Some(Stamp::Pending {
        attempts: 1,
        retry_after: 100,
        running: true,
        previous_due: None,
    });
    previous
        .files
        .get_mut(&key)
        .unwrap()
        .set_unverified_deadline(100);
    let mut working = previous.clone();
    assert!(retire(&mut working, &key, Stamp::Incomplete));
    let subset = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    let retained = subset.files[&key].clone();
    assert_eq!(retained.codex_child_pair_rederive, Some(Stamp::Incomplete));
    assert!(!retained.has_unverified_source());
    let mut value = serde_json::to_value(&retained).unwrap();
    value["codex_child_pair_rederive"] = json!({"future_marker":"synthetic-canary"});
    let decoded: ScanIndexEntry = serde_json::from_value(value).unwrap();
    assert_eq!(decoded.codex_child_pair_rederive, Some(Stamp::Unreadable));
    assert!(!serde_json::to_string(&decoded)
        .unwrap()
        .contains("synthetic-canary"));
}

#[test]
fn codex_child_pair_injected_read_failures_back_off_and_stop_after_three_retries() {
    struct Clock;
    impl Drop for Clock {
        fn drop(&mut self) {
            sampled_scan::set_test_now(None);
        }
    }
    let _clock = Clock;
    sampled_scan::set_test_now(Some(100));
    let fixture = Fixture::new("named");
    let metadata = CodexTitleMetadata::default();
    let (mut index, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
    fixture.seed(&index, true, false);
    let key = local_index_key(&fixture.path);
    let faults = std::cell::Cell::new(0);
    let cache = fixture.cache();
    for (attempt, now) in [(1, 100), (2, 102), (3, 106), (4, 114)] {
        sampled_scan::set_test_now(Some(now));
        let (next, _, _) = fixture.run_inner(index, Some(cache.clone()), &metadata, Some(&faults));
        index = next;
        assert_eq!(
            faults.get(),
            attempt,
            "one actual injected native read attempt"
        );
        index.save(&fixture.index_path).unwrap();
        index = ScanIndex::load(&fixture.index_path).unwrap();
        let (next, _, reads) =
            fixture.run_inner(index, Some(cache.clone()), &metadata, Some(&faults));
        index = next;
        assert_eq!(reads, 0);
        assert_eq!(
            faults.get(),
            attempt,
            "backoff/stamp forbids another attempt"
        );
    }
    assert_eq!(
        index.files[&key].codex_child_pair_rederive,
        Some(Stamp::Unreadable)
    );
    for _ in 0..2 {
        sampled_scan::set_test_now(Some(1_000));
        index.save(&fixture.index_path).unwrap();
        let loaded = ScanIndex::load(&fixture.index_path).unwrap();
        let (next, _, reads) =
            fixture.run_inner(loaded, Some(fixture.cache()), &metadata, Some(&faults));
        assert_eq!(reads, 0);
        assert_eq!(faults.get(), 4);
        index = next;
    }
}

#[test]
fn codex_child_pair_child_own_account_changes_without_touching_parent() {
    let fixture = Fixture::new("named");
    let parent_path = fixture
        .root
        .join(format!("rollout-2026-10-07T10-00-00-{PARENT}.jsonl"));
    let mut rows = fs::read_to_string(&fixture.path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    rows[0]["payload"]["id"] = json!(PARENT);
    rows[0]["payload"]["session_id"] = json!(PARENT);
    rows[0]["payload"]["source"] = json!("cli");
    rows[0]["payload"]["thread_source"] = json!("cli");
    rows[0]["payload"]["creator_user_id"] = json!("synthetic-parent-user");
    rows[0]["payload"]["creator_account_id"] = json!("synthetic-parent-account");
    for field in [
        "forked_from_id",
        "history_mode",
        "subagent_history_start_ordinal",
    ] {
        rows[0]["payload"].as_object_mut().unwrap().remove(field);
    }
    fs::write(
        &parent_path,
        rows.iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let metadata = CodexTitleMetadata::default();
    let (index, before, _) = fixture.run(ScanIndex::default(), None, &metadata);
    let parent = before
        .snapshots
        .iter()
        .find(|item| item.source_session_id == PARENT)
        .unwrap();
    let evidence = parent.session_account_evidence.clone();
    let key = local_index_key(&parent_path);
    let original_parent_entry = serde_json::to_value(&index.files[&key]).unwrap();
    fixture.seed(&index, true, false);
    let (index, after, reads) = fixture.run(index, Some(fixture.cache()), &metadata);
    assert_eq!(reads, 1);
    assert_eq!(
        serde_json::to_value(&index.files[&key]).unwrap(),
        original_parent_entry
    );
    assert_eq!(parent.session_account_evidence, evidence);
    let child = after
        .snapshots
        .iter()
        .find(|item| item.source_session_id == CHILD)
        .unwrap();
    assert_eq!(
        child
            .session_account_evidence
            .as_ref()
            .unwrap()
            .account_identifier_hash,
        ottto_core::billing_identity_hash("openai", "account", "synthetic-child-user")
    );
    assert_ne!(child.session_account_evidence, evidence);
}

#[test]
fn codex_child_pair_independent_audit_staged_during_repair_survives_terminal_and_subset() {
    let fixture = Fixture::new("named");
    let metadata = CodexTitleMetadata::default();
    let (mut previous, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
    fixture.seed(&previous, true, false);
    let key = local_index_key(&fixture.path);
    stage(&mut previous, &fixture.cache(), &metadata);
    let mut working = previous.clone();
    let fp = working.files[&key].source_file_fingerprint.clone();
    assert!(working.stage_sampled_audit(
        &key,
        &fp,
        crate::transcript_acquisition::AuditDebt {
            due_unix_seconds: 7
        }
    ));
    assert!(retire(&mut working, &key, Stamp::Incomplete));
    let subset = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(working.files[&key].unverified_deadline(), Some(7));
    assert_eq!(subset.files[&key].unverified_deadline(), Some(7));
    assert_eq!(
        subset.files[&key].codex_child_pair_rederive,
        Some(Stamp::Incomplete)
    );
}

#[test]
fn codex_child_pair_metadata_selection_refuses_cross_context_entry_and_generation() {
    let fixture = Fixture::new("named");
    let metadata = CodexTitleMetadata::default();
    let (index, _, _) = fixture.run(ScanIndex::default(), None, &metadata);
    fixture.seed(&index, true, false);
    let key = local_index_key(&fixture.path);
    assert!(fixture
        .cache()
        .durable_child_pair_candidate(&key, &index, &metadata));
    let mut wrong = index.clone();
    wrong.active_upload_context_fingerprint = Some("different-account".into());
    assert!(!fixture
        .cache()
        .durable_child_pair_candidate(&key, &wrong, &metadata));
    wrong = index.clone();
    wrong.files.get_mut(&key).unwrap().source_file_fingerprint = "different-source".into();
    assert!(!fixture
        .cache()
        .durable_child_pair_candidate(&key, &wrong, &metadata));
    let mut ahead = index.clone();
    ahead.generation = index.generation + 1;
    fixture.seed(&ahead, true, false);
    assert!(!fixture
        .cache()
        .durable_child_pair_candidate(&key, &index, &metadata));
}

/// Invoked only by the parent fixture in a fresh test process with saved state.
#[test]
#[ignore = "subprocess target; exercised by read-once restart fixture"]
fn codex_child_pair_restart_probe() {
    let root =
        PathBuf::from(std::env::var_os("OTTTO_CHILD_PAIR_TEST_ROOT").expect("parent fixture root"));
    let index_path = PathBuf::from(
        std::env::var_os("OTTTO_CHILD_PAIR_TEST_INDEX").expect("parent fixture index"),
    );
    let index = ScanIndex::load(&index_path).unwrap();
    assert!(index
        .files
        .values()
        .any(|entry| entry.codex_child_pair_rederive.is_some()));
    let cache = Arc::new(sampled_scan::SharedCache::default());
    cache.durable_begin_pass(
        SnapshotSource::Codex,
        &index_path,
        &Scope(NAMESPACE.into()),
        false,
    );
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root],
        index,
        NOW,
        BACKFILL_WINDOW_DAYS,
        10,
        false,
        None,
        &[],
        false,
        true,
    );
    if std::env::var("OTTTO_CHILD_PAIR_TEST_DEPTH2").as_deref() == Ok("1") {
        scan.codex_title_metadata
            .spawn_parents
            .insert(CHILD.into(), PARENT.into());
        scan.codex_title_metadata
            .spawn_parents
            .insert(PARENT.into(), ROOT.into());
    }
    scan = scan.with_sampled_acquisition(cache, Scope(NAMESPACE.into()));
    let (_, reads) = terminal_contract_retry::source_acquisitions(|| loop {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { scan: result, .. } => {
                assert!(result.snapshots.is_empty());
                break;
            }
        }
    });
    assert!(
        reads.is_empty(),
        "a stamped child never reacquires in a fresh process"
    );
}
