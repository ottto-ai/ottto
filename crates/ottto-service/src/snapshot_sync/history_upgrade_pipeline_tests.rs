// Executed-shape regressions for the Claude history-upgrade gate (SOURCE P1).
// At the 0.1.189 start the Claude index was empty after a quarantine, so every
// file came back as a new file and was re-sent under body-witness revision 2
// without the protected list, the no-list hold, the latch or the pacing.
// Each cycle here runs the production stage order of `prepare_sync_source` and
// `finish_sync_source`: load, replay reset, history cutoff, scan, the local
// evidence fold, the emission seam, account binding, upload policy, cutoff and
// proof-correction capture, finalization, local-hold classification, an
// in-process upload and settlement, then a durable save and reload.
// Fixtures are synthetic; the cutoff seam makes every fixture birth "old".
// Where no list is intended, only an unverified Mac (or a move under a claim
// policy other than `full`) holds history; elsewhere it is paced (SOURCE
// Amendment 16, StateMissing N1), so the held-shape tests corrupt the
// backfill state.

use super::*;

const HISTORY_MACHINE_ID: &str = "machine-history-upgrade";
const HISTORY_DESTINATION: &str = "history-upgrade-destination";
const HISTORY_SESSIONS: [&str; 3] = [
    "d4444444-4444-4444-8444-444444444444",
    "e5555555-5555-4555-8555-555555555555",
    "f6666666-6666-4666-8666-666666666666",
];

fn history_line(session: &str, request: &str, second: u32) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:{second:02}Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"requestId\":\"{request}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

fn history_digest(id: &str) -> String {
    format!("{:x}", sha2::Sha256::digest(id.as_bytes()))
}

#[derive(Clone, Copy)]
struct HistoryCycle<'a> {
    revision: u64,
    upload_context: &'a str,
    replay_generation: Option<&'a str>,
    /// This destination completed its Claude history bootstrap (persisted to
    /// the support directory's backfill state before the cycle).
    bootstrapped: bool,
    upload: PipelineUpload,
    /// Another relay destination (its own index); `None` is the default one.
    destination: Option<&'a str>,
    /// Stand in for MONEY's emitter (#699): after finalization, add one
    /// request-owned literal copy of every item, ignoring #699's own
    /// protected-root skip, so only the gate's hook can remove it.
    mint_literal: bool,
    /// Observe the contract-5 contract before the scan, as a daemon cycle
    /// does. Evidence is always built (contract 5 always on); `false` leaves
    /// the index's recorded contract untouched.
    request_identity: bool,
    shed_upload: bool,
}

const HISTORY_BASELINE: HistoryCycle<'static> = HistoryCycle {
    revision: 1,
    upload_context: "history-context-1",
    replay_generation: None,
    bootstrapped: false,
    upload: PipelineUpload::Accept,
    destination: None,
    mint_literal: false,
    request_identity: false,
    shed_upload: false,
};

struct HistoryOutcome {
    scan: crate::snapshots::SourceScanResult,
    index: ScanIndex,
    /// Sessions whose bodies reached the in-process upload.
    uploaded: BTreeSet<String>,
    /// Sessions whose request-owned literal items reached it.
    uploaded_literal: BTreeSet<String>,
    /// Captured cutoff and proof corrections; no gated body may feed one.
    corrections: usize,
}

struct HistoryFixture {
    pending_hints: std::cell::RefCell<Vec<PathBuf>>,
    base: PathBuf,
    root: PathBuf,
    support: PathBuf,
    index_path: PathBuf,
}

impl HistoryFixture {
    fn new(name: &str) -> Self {
        let base = test_dir(name);
        let root = base.join("projects");
        let support = base.join("support");
        std::fs::create_dir_all(&root).expect("create synthetic Claude root");
        std::fs::create_dir_all(support.join("snapshots")).expect("create support directory");
        for (number, session) in HISTORY_SESSIONS.iter().enumerate() {
            std::fs::write(
                root.join(format!("{session}.jsonl")),
                history_line(session, &format!("req_{number}_1"), 0),
            )
            .expect("write synthetic Claude transcript");
        }
        Self {
            pending_hints: Default::default(),
            index_path: base.join("claude-scan-index.json"),
            base,
            root,
            support,
        }
    }

    fn append(&self, session: &str, request: &str) {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(self.root.join(format!("{session}.jsonl")))
            .expect("open synthetic Claude transcript");
        file.write_all(history_line(session, request, 30).as_bytes())
            .expect("append synthetic Claude response");
        self.pending_hints
            .borrow_mut()
            .push(self.root.join(format!("{session}.jsonl")));
    }

    fn install_list(&self, listed: &[&str]) {
        let lines = listed
            .iter()
            .map(|session| history_digest(session))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            self.support
                .join("snapshots/claude_code-reemission-exclusions.txt"),
            format!("# synthetic\n{lines}\n"),
        )
        .expect("install synthetic list");
    }

    fn key(index: &ScanIndex, session: &str) -> String {
        let suffix = format!("{session}.jsonl");
        index
            .files
            .keys()
            .find(|key| key.ends_with(&suffix))
            .cloned()
            .expect("indexed synthetic transcript")
    }

    /// Corrupt the saved index, as the 0.1.188 daemon's whole-index check
    /// left it; the next load quarantines it and starts empty.
    fn corrupt_index(&self) {
        std::fs::write(&self.index_path, b"{not json").expect("corrupt saved index");
    }

    /// Valid JSON with more damaged records than the lenient hold admission.
    /// This must take the same quarantined-origin history gate as syntax loss.
    fn exceed_decode_hold_budget(&self) {
        let mut value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&self.index_path).expect("read synthetic index"))
                .expect("decode synthetic index");
        for n in 0..4097 {
            value["files"][format!("/synthetic-damage/{n}.jsonl")] =
                serde_json::json!({"size_bytes": []});
        }
        std::fs::write(&self.index_path, serde_json::to_vec(&value).unwrap())
            .expect("write excessive record damage");
    }

    fn index_path_for(&self, destination: Option<&str>) -> PathBuf {
        destination.map_or_else(
            || self.index_path.clone(),
            |destination| {
                self.base
                    .join(format!("claude-scan-index-{destination}.json"))
            },
        )
    }

    fn corrupt_backfill_state(&self) {
        std::fs::write(
            crate::backfill::backfill_state_path(&self.support),
            b"{\"completed_destination_namespaces\":",
        )
        .expect("corrupt backfill state");
    }

    fn cycle(&self, collected_at: &str, cycle: HistoryCycle<'_>) -> HistoryOutcome {
        self.cycle_with_scan(collected_at, cycle, |_| {})
    }

    fn cycle_with_scan(
        &self,
        collected_at: &str,
        cycle: HistoryCycle<'_>,
        before_evidence: impl FnOnce(&mut crate::snapshots::SourceScanResult),
    ) -> HistoryOutcome {
        // A cycle below revision 3 stands in for a daemon from before the
        // switch-on, whose E2 gate was off (the flip raised both together).
        if cycle.revision < 3 {
            return crate::snapshots::claude_request_money::e2::with_disabled(|| {
                self.cycle_at_gate(collected_at, cycle, before_evidence)
            });
        }
        self.cycle_at_gate(collected_at, cycle, before_evidence)
    }

    fn cycle_at_gate(
        &self,
        collected_at: &str,
        cycle: HistoryCycle<'_>,
        before_evidence: impl FnOnce(&mut crate::snapshots::SourceScanResult),
    ) -> HistoryOutcome {
        let destination = cycle.destination.unwrap_or(HISTORY_DESTINATION);
        let index_path = self.index_path_for(cycle.destination);
        let (mut index, origin) = ScanIndex::load_for_snapshot_source_with_origin(
            &index_path,
            SnapshotSource::ClaudeCode,
            &self.support,
        )
        .expect("load scan index");
        let loaded_fresh = origin != crate::snapshots::ScanIndexLoadOrigin::Loaded
            || (index.generation == 0 && index.files.is_empty());
        index.activate_file_upload_context(
            SnapshotSource::ClaudeCode,
            cycle.upload_context.to_string(),
        );
        let mut backfill = crate::backfill::load_backfill_state(&self.support);
        if cycle.bootstrapped {
            crate::backfill::mark_backfill_complete_for_destination(
                &mut backfill,
                SnapshotSource::ClaudeCode,
                destination,
            );
            crate::backfill::save_backfill_state(&self.support, &backfill)
                .expect("persist backfill state");
        }
        let mut progress = test_upload_progress();
        // Read before the replay claims a generation, as in production.
        let prior_history = claude_prior_history(
            &backfill,
            destination,
            &progress,
            &index_path,
            &self.support,
        );
        // Production's replay decision: an unreadable state arms no Claude
        // replay. A due replay generation stands in for a needed curve replay.
        let replay_pending = ReplayArming::decide(
            SnapshotSource::ClaudeCode,
            &backfill,
            destination,
            cycle.replay_generation.is_some(),
        )
        .curve_replay_pending;
        let replay_dropped = replay_pending
            && cycle
                .replay_generation
                .is_some_and(|generation| index.prepare_historical_replay(generation.to_string()));
        note_claude_history_cutoff_for_cycle(
            &mut index,
            SnapshotSource::ClaudeCode,
            prior_history,
            &backfill,
            loaded_fresh || replay_dropped,
        );
        index.activate_effective_upload_body_witness_revision(cycle.revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
        crate::snapshots::claude_request_money::e2::apply_money_rules(&mut index);
        if cycle.request_identity {
            index.observe_claude_request_identity_contract(true);
        }
        activate_source_upload_context(
            SnapshotSource::ClaudeCode,
            cycle.upload_context.to_string(),
            &mut index,
            &mut progress,
        );
        let committed_index = index.clone();
        let hints = self.pending_hints.take();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit_and_hints(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            &mut index,
            collected_at,
            183,
            100,
            true,
            &hints,
        )
        .expect("scan Claude page");
        before_evidence(&mut scan);
        let (mut disposition, _, _) =
            apply_claude_local_evidence_to_scan(&self.support, &mut scan, &mut index);
        index.veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut scan.snapshots);
        let deferred_accounts = index.bind_session_accounts_with_mixed(
            SnapshotSource::ClaudeCode,
            HISTORY_MACHINE_ID,
            &mut scan.snapshots,
            &[],
            &disposition.mixed_uploads,
        );
        disposition.defer_sessions(deferred_accounts);
        apply_upload_policy(
            SnapshotSource::ClaudeCode,
            &mut scan.snapshots,
            SnapshotUploadPolicy::default(),
        );
        let (_, cutoff_corrections) = apply_backfill_cutoff_with_claude_corrections(
            &mut scan,
            &index,
            &disposition,
            &backfill,
        );
        exclude_held_effective_body_witness_revision(&mut index, &scan.snapshots, &disposition);
        let proof_corrections =
            index.capture_claude_proof_corrections(&mut scan, &disposition, |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &progress,
                    false,
                    false,
                    &BTreeSet::new(),
                    &disposition,
                )
            });
        let corrections = cutoff_corrections.len() + proof_corrections.len();
        finalize_scan_after_policy_with_body_witness(
            SnapshotSource::ClaudeCode,
            &mut scan,
            &mut index,
            |snapshot| {
                effective_snapshot_upload_body_witness(
                    snapshot,
                    &progress,
                    false,
                    false,
                    &BTreeSet::new(),
                    &disposition,
                )
            },
        );
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut index,
            &mut scan,
            &disposition,
        );
        if cycle.mint_literal {
            let copies = scan
                .snapshots
                .iter()
                .map(|item| {
                    let mut copy = item.clone();
                    copy.usage_accounting_contract =
                        Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT.into());
                    copy.snapshot_fingerprint =
                        crate::snapshots::snapshot_fingerprint(SnapshotSource::ClaudeCode, &copy);
                    copy
                })
                .collect::<Vec<_>>();
            scan.snapshots.extend(copies);
        }
        index.retain_claude_history_emission_permitted(&mut scan.snapshots);
        progress.prepare_context_receipt_candidates(&index, &committed_index, &scan.snapshots);
        let mut uploaded = BTreeSet::new();
        let mut uploaded_literal = BTreeSet::new();
        let mut accepted = 0;
        let result = upload_resumable_batches_with_body_witness(
            &scan.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |items| {
                if cycle.shed_upload {
                    return Err(anyhow::Error::new(UploadShed {
                        status: 503,
                        retry_after: None,
                        code: None,
                    }));
                }
                uploaded.extend(items.iter().map(|item| item.source_session_id.clone()));
                uploaded_literal.extend(
                    items
                        .iter()
                        .filter(|item| {
                            item.usage_accounting_contract.as_deref()
                                == Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT)
                        })
                        .map(|item| item.source_session_id.clone()),
                );
                let response = super::claude_money_e2_pipeline_tests::ack(&items)?;
                response.validate_entity_ack(&SnapshotBatchRequest {
                    schema_version: SNAPSHOT_SCHEMA_VERSION,
                    source: SnapshotSource::ClaudeCode.api_slug().into(),
                    machine_id: HISTORY_MACHINE_ID.into(),
                    collector_version: None,
                    snapshots: items,
                    upload_policy: SnapshotUploadPolicy::default(),
                    client_report: crate::client_report::ClientReport::empty(),
                })?;
                Ok(response)
            },
            |_| Ok(()),
        )
        .expect("in-process upload");
        if cycle.shed_upload {
            assert!(matches!(result, ResumableUploadResult::Shed { .. }));
            assert_eq!(accepted, 0);
        } else {
            assert_eq!(result, ResumableUploadResult::Completed);
        }
        let index = if cycle.shed_upload {
            index.committable_subset(
                &committed_index,
                &progress.accepted_fingerprints,
                &progress.quarantined_fingerprints,
            )
        } else {
            index
        };
        let settlement = if cycle.shed_upload {
            settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
        } else {
            match cycle.upload {
                PipelineUpload::ServerDeferred => {
                    settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
                }
                _ => settle_completed_upload(index, &committed_index, &progress, &holds),
            }
        };
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
        index.accept_file_upload_context_acks(
            &progress.context_receipt_candidates,
            &progress.fresh_context_body_acks,
        );
        index.save(&index_path).expect("save scan index");
        HistoryOutcome {
            scan,
            index: ScanIndex::load(&index_path).expect("reload scan index"),
            uploaded,
            uploaded_literal,
            corrections,
        }
    }

    /// Every file sent and stamped at revision 1 under a fresh install.
    fn baseline(&self) -> ScanIndex {
        assert!(
            crate::snapshots::claude_terminal_off(),
            "history pipeline requires production policy"
        );
        let outcome = self.cycle("2026-08-02T08:00:00Z", HISTORY_BASELINE);
        assert_eq!(outcome.uploaded.len(), HISTORY_SESSIONS.len());
        assert!(!outcome.scan.census_complete);
        assert!(outcome
            .index
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 1));
        outcome.index
    }

    fn census_keys(index: &ScanIndex) -> usize {
        HISTORY_SESSIONS
            .iter()
            .filter(|session| {
                index
                    .claude_request_census_for_test()
                    .get(&Self::key(index, session))
                    .is_some()
            })
            .count()
    }
}

impl Drop for HistoryFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

const HISTORY_REVISION_2: HistoryCycle<'static> = HistoryCycle {
    revision: 2,
    upload_context: "history-context-1",
    replay_generation: None,
    bootstrapped: true,
    upload: PipelineUpload::Accept,
    destination: None,
    mint_literal: false,
    request_identity: false,
    shed_upload: false,
};

/// Primary incident shape (addendum 2) on an unverified Mac: a bootstrapped
/// destination's index is quarantined, no list and no seen-marker, the
/// backfill state is unreadable, the active revision is bumped. Every file
/// comes back as a new file. On dba838f0 every body is re-sent (`uploaded`
/// holds all three sessions); here none is, every file is recorded locally
/// with its census record, and the next two cycles do not re-read anything.
#[test]
fn quarantined_index_after_bootstrap_holds_all_history_without_a_list() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-quarantine");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let rebuilt = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert_eq!(
            rebuilt.scan.scanned_file_count,
            HISTORY_SESSIONS.len(),
            "new files are parsed locally"
        );
        assert!(rebuilt.uploaded.is_empty(), "{:?}", rebuilt.uploaded);
        assert_eq!(rebuilt.corrections, 0, "no correction carries them");
        assert!(!rebuilt.scan.census_complete);
        assert_eq!(rebuilt.index.files.len(), HISTORY_SESSIONS.len());
        assert_eq!(HistoryFixture::census_keys(&rebuilt.index), 3);
        for entry in rebuilt.index.files.values() {
            assert_eq!(entry.effective_upload_body_witness_revision, 0);
            assert!(entry.last_snapshot_fingerprint.is_some());
            assert!(entry.last_upload_body_witness.is_none());
        }
        // Held local bodies never reached this destination or upload policy,
        // so the source manifest does not advertise them.
        assert!(rebuilt.index.current_snapshot_fingerprints().is_empty());
        let manifest = rebuilt
            .index
            .manifest_for_window(
                SnapshotSource::ClaudeCode,
                "2000-01-01T00:00:00Z",
                "2100-01-01T00:00:00Z",
            )
            .unwrap();
        assert_eq!(manifest.entity_count, 0);
        // A partial checkpoint (nothing accepted) keeps every held entry, so
        // an upload outage does not re-read the history.
        let partial = rebuilt.index.committable_subset(
            &ScanIndex::default(),
            &BTreeSet::new(),
            &BTreeMap::new(),
        );
        assert_eq!(partial.files.len(), rebuilt.index.files.len());
        for (key, entry) in &rebuilt.index.files {
            let kept = &partial.files[key];
            assert_eq!(kept.source_file_fingerprint, entry.source_file_fingerprint);
            assert_eq!(kept.size_bytes, entry.size_bytes);
            assert_eq!(
                kept.last_snapshot_fingerprint,
                entry.last_snapshot_fingerprint
            );
        }
        for hour in [10, 11] {
            let again = fixture.cycle(&format!("2026-08-02T{hour}:00:00Z"), HISTORY_REVISION_2);
            assert_eq!(again.scan.scanned_file_count, 0, "no re-read storm");
            assert!(again.uploaded.is_empty());
        }
    });
}

/// Addendum 3: a historical replay drops the Claude entries without resetting
/// the generation, so every file is new again. On a verified Mac with no
/// list the dropped history is owed (born before the cutoff the drop
/// records) and paced through the budget, one file per page here, never
/// re-sent at once (StateMissing N1).
#[test]
fn historical_replay_after_bootstrap_paces_history_without_a_list() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-replay");
    let baseline = fixture.baseline();
    assert!(baseline.generation > 0);
    let replay = HistoryCycle {
        replay_generation: Some("history-replay-2"),
        ..HISTORY_REVISION_2
    };
    let mut sent = Vec::new();
    crate::snapshots::with_body_witness_adoption_page_budget(1, || {
        let replayed = fixture.cycle("2026-08-02T09:00:00Z", replay);
        assert_eq!(replayed.scan.scanned_file_count, HISTORY_SESSIONS.len());
        assert_eq!(replayed.corrections, 0);
        assert!(replayed.index.generation > baseline.generation, "no reset");
        assert_eq!(replayed.index.files.len(), HISTORY_SESSIONS.len());
        assert_eq!(HistoryFixture::census_keys(&replayed.index), 3);
        sent.push(replayed.uploaded.len());
        for hour in 10..13 {
            sent.push(
                fixture
                    .cycle(&format!("2026-08-02T{hour:02}:00:00Z"), replay)
                    .uploaded
                    .len(),
            );
        }
    });
    assert_eq!(sent, vec![1, 1, 1, 0], "paced, one history file per page");
}

/// StateMissing N1: the incident shape on a verified Mac where no list is
/// intended (durable intent Absent, no list, no seen-marker; this destination's own bootstrap): the
/// rebuilt history is paced through the budget, not held for good.
#[test]
fn quarantined_index_without_an_intended_list_paces_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-quarantine-paced");
    fixture.baseline();
    assert_eq!(
        crate::backfill::load_backfill_state(&fixture.support).claude_history_list_intent,
        crate::backfill::ClaudeHistoryListIntent::Absent
    );
    fixture.corrupt_index();
    let mut sent = Vec::new();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        crate::snapshots::with_body_witness_adoption_page_budget(1, || {
            for hour in 9..13 {
                sent.push(
                    fixture
                        .cycle(&format!("2026-08-02T{hour:02}:00:00Z"), HISTORY_REVISION_2)
                        .uploaded
                        .len(),
                );
            }
        });
    });
    assert_eq!(sent, vec![1, 1, 1, 0]);
    let index = ScanIndex::load(&fixture.index_path).expect("reload");
    assert!(index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 2));
}

/// Addendum 1 item 1 (secondary): existing revision-1 entries, an
/// independent second reason on every file (a changed upload context), no
/// list. Nothing is emitted, the old upload tuple stays, and the reason
/// settles: the next cycle reads nothing.
#[test]
fn upload_context_change_does_not_carry_history_past_the_gate() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-upload-context");
    let baseline = fixture.baseline();
    // Held where no list is intended only on an unverified Mac (N1).
    fixture.corrupt_backfill_state();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let changed = fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                upload_context: "history-context-2",
                ..HISTORY_REVISION_2
            },
        );
        assert_eq!(changed.scan.scanned_file_count, HISTORY_SESSIONS.len());
        assert!(changed.uploaded.is_empty(), "{:?}", changed.uploaded);
        for (key, entry) in &changed.index.files {
            let before = &baseline.files[key];
            assert_eq!(entry.effective_upload_body_witness_revision, 1);
            assert_eq!(
                entry.last_snapshot_fingerprint,
                before.last_snapshot_fingerprint
            );
            assert_eq!(
                entry.last_upload_body_witness,
                before.last_upload_body_witness
            );
        }
        assert_eq!(HistoryFixture::census_keys(&changed.index), 3);
        let again = fixture.cycle(
            "2026-08-02T10:00:00Z",
            HistoryCycle {
                upload_context: "history-context-2",
                ..HISTORY_REVISION_2
            },
        );
        assert_eq!(again.scan.scanned_file_count, 0, "parsed at most once");
        assert!(again.uploaded.is_empty());
    });
}

/// Addendum 1 items 1 and 5: a re-armed entry (fingerprint cleared, size and
/// mtime equal) is unchanged history: held, never emitted, and settled.
#[test]
fn rearmed_unchanged_history_is_held_and_settles() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-rearmed");
    let mut baseline = fixture.baseline();
    for entry in baseline.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    baseline
        .save(&fixture.index_path)
        .expect("save re-armed index");
    fixture.corrupt_backfill_state();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let rearmed = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert_eq!(rearmed.scan.scanned_file_count, HISTORY_SESSIONS.len());
        assert!(rearmed.uploaded.is_empty(), "{:?}", rearmed.uploaded);
        assert!(rearmed.index.files.values().all(|entry| {
            entry.effective_upload_body_witness_revision == 1
                && !entry.source_file_fingerprint.is_empty()
        }));
        let again = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
        assert_eq!(again.scan.scanned_file_count, 0);
    });
}

/// Addendum 2 item 13: with the list installed and budget available, history
/// after a quarantine is paced and a listed family is never emitted.
#[test]
fn installed_list_paces_rebuilt_history_and_denies_listed_families() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-list-budget");
    fixture.baseline();
    fixture.install_list(&[HISTORY_SESSIONS[0]]);
    fixture.corrupt_index();
    let mut sent = Vec::new();
    crate::snapshots::with_body_witness_adoption_page_budget(1, || {
        for hour in 9..13 {
            let outcome =
                fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), HISTORY_REVISION_2);
            sent.push(outcome.uploaded.len());
            assert!(!outcome.uploaded.contains(HISTORY_SESSIONS[0]));
        }
    });
    assert_eq!(sent, vec![1, 1, 0, 0], "one history file per page");
    let index = ScanIndex::load(&fixture.index_path).expect("reload");
    let listed = HistoryFixture::key(&index, HISTORY_SESSIONS[0]);
    for (key, entry) in &index.files {
        let expected = if *key == listed { 0 } else { 2 };
        assert_eq!(entry.effective_upload_body_witness_revision, expected);
    }
}

/// Addendum 2 item 13 and addendum 3 item 19: a genuinely fresh install (a
/// positively empty support state: no backfill state, no quarantined index,
/// no upload ledger, no seen-marker) ingests new files normally, even with
/// old births. A quarantined index is prior history (SOURCE F1a), so this
/// fixture no longer starts from one.
#[test]
fn fresh_install_without_a_prior_bootstrap_ingests_new_files() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-fresh");
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let fresh = fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                bootstrapped: false,
                ..HISTORY_REVISION_2
            },
        );
        assert_eq!(fresh.uploaded.len(), HISTORY_SESSIONS.len());
        assert!(fresh
            .index
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 2));
    });
}

/// Addendum 2 item 13: after a held rebuild, only files that grew emit, by
/// ordinary sync, and they settle at the active revision.
#[test]
fn only_files_that_grew_after_a_rebuild_emit() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-growth");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let held = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert!(held.uploaded.is_empty());
        fixture.append(HISTORY_SESSIONS[1], "req_1_2");
        let grown = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
        assert_eq!(grown.scan.scanned_file_count, 1);
        assert_eq!(
            grown.uploaded,
            BTreeSet::from([HISTORY_SESSIONS[1].to_string()])
        );
        let key = HistoryFixture::key(&grown.index, HISTORY_SESSIONS[1]);
        assert_eq!(
            grown.index.files[&key].effective_upload_body_witness_revision,
            2
        );
    });
}

/// User Repair override (#718): one interactive Repair of a rebuild-loop
/// pause runs the same #712-gated rebuild as the first incident. On an
/// unverified Mac history stays held, so no file comes back as new history,
/// and the override witness re-arms the seven-day guard.
#[test]
fn user_repair_override_rebuild_keeps_history_held() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::ScanIndexRebuildOverride;
    let fixture = HistoryFixture::new("history-upgrade-user-repair-override");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let held = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert!(held.uploaded.is_empty(), "{:?}", held.uploaded);
        // Budget damage keeps the identity fields strictly recoverable, so
        // the press may rebuild (SI-718-O1); syntax damage refuses it.
        fixture.exceed_decode_hold_budget();
        let refused = ScanIndex::load_for_snapshot_source_with_origin(
            &fixture.index_path,
            SnapshotSource::ClaudeCode,
            &fixture.support,
        )
        .unwrap_err();
        assert!(format!("{refused:#}").contains("scan_index_rebuild_loop"));
        assert_eq!(
            crate::snapshots::arm_scan_index_rebuild_manual_override(
                SnapshotSource::ClaudeCode,
                std::time::SystemTime::now()
            ),
            ScanIndexRebuildOverride::Armed
        );
        let overridden = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
        assert_eq!(
            crate::snapshots::scan_index_rebuild_manual_override_count(),
            1
        );
        assert!(
            overridden.uploaded.is_empty(),
            "the override rebuild re-sent history: {:?}",
            overridden.uploaded
        );
        assert_eq!(overridden.corrections, 0);
        assert_eq!(overridden.scan.scanned_file_count, HISTORY_SESSIONS.len());
        assert_eq!(overridden.index.files.len(), HISTORY_SESSIONS.len());
        for entry in overridden.index.files.values() {
            assert_eq!(entry.effective_upload_body_witness_revision, 0);
            assert!(entry.last_upload_body_witness.is_none());
        }
        fixture.corrupt_index();
        let refused = ScanIndex::load_for_snapshot_source_with_origin(
            &fixture.index_path,
            SnapshotSource::ClaudeCode,
            &fixture.support,
        )
        .unwrap_err();
        assert!(format!("{refused:#}").contains("scan_index_rebuild_loop"));
    });
}

/// SI-718-O1: the override rebuild keeps the retained owner through a
/// replacement cycle whose upload is only server-deferred (a partial
/// settlement), and held history still uploads nothing.
#[test]
fn user_repair_override_keeps_prior_owner_through_a_deferred_upload() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::ScanIndexRebuildOverride;
    let fixture = HistoryFixture::new("history-upgrade-override-identity");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    let owner_key = crate::context_footprint::sha256_hex(&[
        "session_owner:v1",
        HISTORY_MACHINE_ID,
        HISTORY_SESSIONS[0],
    ]);
    let owner = "a".repeat(64);
    let saved = |fixture: &HistoryFixture| -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(&fixture.index_path).expect("read saved index"))
            .expect("decode saved index")
    };
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let held = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert!(held.uploaded.is_empty(), "{:?}", held.uploaded);
        // A retained owner and a true contract latch beside budget damage.
        let mut value = saved(&fixture);
        value["session_account_bindings"] =
            serde_json::json!({ owner_key.clone(): {"account_identifier_hash": owner} });
        value["claude_request_identity_contract"] = serde_json::json!("prior-contract");
        value["claude_request_identity_contract_changed"] = serde_json::json!(true);
        std::fs::write(&fixture.index_path, serde_json::to_vec(&value).unwrap())
            .expect("seed prior identity");
        fixture.exceed_decode_hold_budget();
        let refused = ScanIndex::load_for_snapshot_source_with_origin(
            &fixture.index_path,
            SnapshotSource::ClaudeCode,
            &fixture.support,
        )
        .unwrap_err();
        assert!(format!("{refused:#}").contains("scan_index_rebuild_loop"));
        assert_eq!(
            crate::snapshots::arm_scan_index_rebuild_manual_override(
                SnapshotSource::ClaudeCode,
                std::time::SystemTime::now()
            ),
            ScanIndexRebuildOverride::Armed
        );
        let overridden = fixture.cycle(
            "2026-08-02T10:00:00Z",
            HistoryCycle {
                upload: PipelineUpload::ServerDeferred,
                ..HISTORY_REVISION_2
            },
        );
        assert_eq!(
            crate::snapshots::scan_index_rebuild_manual_override_count(),
            1
        );
        assert!(
            overridden.uploaded.is_empty(),
            "the override rebuild re-sent history: {:?}",
            overridden.uploaded
        );
        assert_eq!(overridden.corrections, 0);
        // The retained owner survived the rebuild, the scan, the partial
        // settlement and the save: it is still the authority on disk.
        let value = saved(&fixture);
        assert_eq!(
            value["session_account_bindings"][&owner_key]["account_identifier_hash"],
            serde_json::json!(owner)
        );
        // A later cycle keeps it too, and still uploads no held history.
        let again = fixture.cycle("2026-08-02T11:00:00Z", HISTORY_REVISION_2);
        assert!(again.uploaded.is_empty(), "{:?}", again.uploaded);
        assert_eq!(
            saved(&fixture)["session_account_bindings"][&owner_key]["account_identifier_hash"],
            serde_json::json!(owner)
        );
    });
}

/// MONEY P1: seed genuine accepted incidence immediately before the override,
/// not before a syntax rebuild that would already have erased the ACK ledger.
/// Retain it through complete census and files held without further parses;
/// release must reconstruct those files with zero re-offer of accepted history.
#[test]
fn user_repair_override_carries_accepted_history_through_census_and_release() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::ScanIndexRebuildOverride;
    let fixture = HistoryFixture::new("history-override-carried-ack-release");
    let baseline = fixture.baseline();
    let state = serde_json::to_value(&baseline).unwrap();
    let accepted = state["accepted_snapshot_fingerprints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fp| fp.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(accepted.len(), HISTORY_SESSIONS.len());
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    assert_eq!(
        ScanIndex::load_for_snapshot_source_with_origin(
            &fixture.index_path,
            SnapshotSource::ClaudeCode,
            &fixture.support
        )
        .unwrap()
        .1,
        crate::snapshots::ScanIndexLoadOrigin::Quarantined
    );
    // Seed ACKs RIGHT BEFORE damage/override. No intervening rebuild or settlement.
    std::fs::write(&fixture.index_path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    fixture.exceed_decode_hold_budget();
    let refused = ScanIndex::load_for_snapshot_source_with_origin(
        &fixture.index_path,
        SnapshotSource::ClaudeCode,
        &fixture.support,
    )
    .unwrap_err();
    assert!(format!("{refused:#}").contains("scan_index_rebuild_loop"));
    assert_eq!(
        crate::snapshots::arm_scan_index_rebuild_manual_override(
            SnapshotSource::ClaudeCode,
            std::time::SystemTime::now()
        ),
        ScanIndexRebuildOverride::Armed
    );
    let assert_acks = |index: &ScanIndex| {
        assert!(accepted
            .iter()
            .all(|fp| index.accepted_snapshot_fingerprint_recorded(fp)));
    };
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let held = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert!(!held.scan.census_complete);
        assert!(held.uploaded.is_empty());
        assert_eq!(held.corrections, 0);
        assert!(held.index.current_snapshot_fingerprints().is_empty());
        assert_acks(&held.index);
        let carried =
            serde_json::to_value(&held.index).unwrap()["accepted_rebuild_incidence"].clone();
        assert_eq!(carried, state["file_snapshot_fingerprints"]);
        assert!(
            crate::snapshots::scan_index_containment_lines_for_test()
                .iter()
                .any(|line| line
                    .contains("retained_carried_entries=3 history_held_carried_entries=3"))
        );
        let again = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
        assert!(!again.scan.census_complete);
        assert_eq!(
            again.scan.scanned_file_count, 0,
            "held files never re-parse"
        );
        assert!(again.uploaded.is_empty());
        let lines = crate::snapshots::scan_index_containment_lines_for_test();
        let census = lines
            .iter()
            .rev()
            .find(|line| line.starts_with("local snapshot census: source=claude_code "))
            .unwrap();
        assert!(
            census.contains("retained_carried_entries=3 history_held_carried_entries=3"),
            "{census}"
        );
        assert_acks(&again.index);
        assert_eq!(
            serde_json::to_value(&again.index).unwrap()["accepted_rebuild_incidence"],
            carried
        );
        fixture.install_list(&[]);
        let released = fixture.cycle("2026-08-02T11:00:00Z", HISTORY_REVISION_2);
        assert!(!released.scan.census_complete);
        assert_eq!(
            released.scan.scanned_file_count,
            HISTORY_SESSIONS.len(),
            "release reconstructs each file"
        );
        assert!(
            released.uploaded.is_empty(),
            "accepted history must never re-offer: {:?}",
            released.uploaded
        );
        assert_eq!(released.corrections, 0);
        assert_acks(&released.index);
        assert_eq!(released.index.current_snapshot_fingerprints(), accepted);
        assert!(
            crate::snapshots::scan_index_containment_lines_for_test()
                .iter()
                .any(|line| line
                    .contains("retained_carried_entries=0 history_held_carried_entries=0"))
        );
        assert!(serde_json::to_value(&released.index)
            .unwrap()
            .get("accepted_rebuild_incidence")
            .is_none());
    });
}

/// SOURCE N1 third half: vanished history releases only on a healthy complete terminal.
#[test]
fn user_repair_carried_history_vanished_file_releases_at_healthy_terminal() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::ScanIndexRebuildOverride;
    let fixture = HistoryFixture::new("history-override-carried-ack-gone");
    let baseline = fixture.baseline();
    let state = serde_json::to_value(&baseline).unwrap();
    let accepted = state["accepted_snapshot_fingerprints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fp| fp.as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    assert_eq!(accepted.len(), HISTORY_SESSIONS.len());
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    assert_eq!(
        ScanIndex::load_for_snapshot_source_with_origin(
            &fixture.index_path,
            SnapshotSource::ClaudeCode,
            &fixture.support
        )
        .unwrap()
        .1,
        crate::snapshots::ScanIndexLoadOrigin::Quarantined
    );
    // Seed ACKs RIGHT BEFORE damage/override. No intervening rebuild or settlement.
    std::fs::write(&fixture.index_path, serde_json::to_vec(&baseline).unwrap()).unwrap();
    fixture.exceed_decode_hold_budget();
    let refused = ScanIndex::load_for_snapshot_source_with_origin(
        &fixture.index_path,
        SnapshotSource::ClaudeCode,
        &fixture.support,
    )
    .unwrap_err();
    assert!(format!("{refused:#}").contains("scan_index_rebuild_loop"));
    assert_eq!(
        crate::snapshots::arm_scan_index_rebuild_manual_override(
            SnapshotSource::ClaudeCode,
            std::time::SystemTime::now()
        ),
        ScanIndexRebuildOverride::Armed
    );
    let assert_acks = |index: &ScanIndex| {
        assert!(accepted
            .iter()
            .all(|fp| index.accepted_snapshot_fingerprint_recorded(fp)));
    };
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let held = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert!(!held.scan.census_complete);
        assert!(held.uploaded.is_empty());
        assert_eq!(held.corrections, 0);
        assert!(held.index.current_snapshot_fingerprints().is_empty());
        assert_acks(&held.index);
        let carried =
            serde_json::to_value(&held.index).unwrap()["accepted_rebuild_incidence"].clone();
        assert_eq!(carried, state["file_snapshot_fingerprints"]);
        let again = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
        assert!(!again.scan.census_complete);
        assert_eq!(
            again.scan.scanned_file_count, 0,
            "held files never re-parse"
        );
        assert!(again.uploaded.is_empty());
        assert_acks(&again.index);
        assert_eq!(
            serde_json::to_value(&again.index).unwrap()["accepted_rebuild_incidence"],
            carried
        );
        // A vanished held file releases only at a healthy complete terminal;
        // the other history-held files keep their original carried incidence.
        let vanished_key = HistoryFixture::key(&again.index, HISTORY_SESSIONS[0]);
        let vanished_acks = state["file_snapshot_fingerprints"][&vanished_key]
            .as_array()
            .unwrap()
            .iter()
            .map(|fp| fp.as_str().unwrap().to_owned())
            .collect::<BTreeSet<_>>();
        std::fs::remove_file(fixture.root.join(format!("{}.jsonl", HISTORY_SESSIONS[0]))).unwrap();
        let gone = fixture.cycle("2026-08-02T10:30:00Z", HISTORY_REVISION_2);
        assert!(!gone.scan.census_complete);
        assert!(gone.uploaded.is_empty());
        assert!(
            gone.index.files.contains_key(&vanished_key),
            "terminal-off retains absent history custody"
        );
        let gone_state = serde_json::to_value(&gone.index).unwrap();
        let debt = gone_state["accepted_rebuild_incidence"]
            .as_object()
            .unwrap();
        assert!(debt.contains_key(&vanished_key));
        assert_eq!(debt.len(), HISTORY_SESSIONS.len());
        assert!(gone_state["accepted_incidence_pending_census"]
            .as_bool()
            .unwrap());
        let remaining = accepted
            .difference(&vanished_acks)
            .cloned()
            .collect::<BTreeSet<_>>();
        assert!(remaining
            .iter()
            .all(|fp| gone.index.accepted_snapshot_fingerprint_recorded(fp)));
        assert!(vanished_acks
            .iter()
            .all(|fp| gone.index.accepted_snapshot_fingerprint_recorded(fp)));
    });
}

/// SOURCE Amendment 14 (owner B ruling 1): under revision 3 a LISTED root's
/// genuine transcript change emits its ORDINARY body; no request-owned
/// literal item and no revision-3 stamp reaches that file, and
/// `history_emission_denied{reason=listed_literal}` counts it. Unlisted
/// history upgrades carry the literal. The next cycle the unchanged listed
/// root is owed and held, never settled as revision-3 history.
#[test]
fn revision_three_listed_change_emits_its_ordinary_body_without_the_literal() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    crate::snapshots::with_max_gated_claude_revision(3, || {
        use crate::snapshots::{history_local_count, HistoryLocalCount};
        let fixture = HistoryFixture::new("history-upgrade-revision-three");
        fixture.baseline();
        fixture.install_list(&[HISTORY_SESSIONS[0]]);
        fixture.append(HISTORY_SESSIONS[0], "req_0_2");
        let revision_3 = HistoryCycle {
            revision: 3,
            upload_context: "history-context-2",
            mint_literal: true,
            ..HISTORY_REVISION_2
        };
        let denied = history_local_count(HistoryLocalCount::ListedLiteralDenied);
        let changed = fixture.cycle("2026-08-02T09:00:00Z", revision_3);
        assert_eq!(
            history_local_count(HistoryLocalCount::ListedLiteralDenied),
            denied + 1,
            "listed_literal counts the listed root's change"
        );
        assert!(
            changed.uploaded.contains(HISTORY_SESSIONS[0]),
            "the listed root's ordinary body emits on a genuine change"
        );
        assert_eq!(
            changed.uploaded_literal,
            HISTORY_SESSIONS[1..]
                .iter()
                .map(|session| session.to_string())
                .collect::<BTreeSet<_>>(),
            "no literal item of the listed root; unlisted history carries it"
        );
        let listed = HistoryFixture::key(&changed.index, HISTORY_SESSIONS[0]);
        assert_eq!(
            changed.index.files[&listed].effective_upload_body_witness_revision, 1,
            "no revision-3 stamp on the listed root"
        );
        for session in &HISTORY_SESSIONS[1..] {
            let key = HistoryFixture::key(&changed.index, session);
            assert_eq!(
                changed.index.files[&key].effective_upload_body_witness_revision,
                3
            );
        }
        let quiet = fixture.cycle("2026-08-02T10:00:00Z", revision_3);
        assert!(
            quiet.uploaded.is_empty(),
            "owed and held: {:?}",
            quiet.uploaded
        );
        assert_eq!(
            quiet.index.files[&listed].effective_upload_body_witness_revision,
            1
        );
    });
}

/// Addendum 1 item 5: revision 2 lets a listed family's genuine change sync,
/// and a stored 3 is never downgraded by revision 2.
#[test]
fn revision_two_syncs_listed_changes_and_never_downgrades_three() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-revision-two-listed");
    fixture.baseline();
    fixture.install_list(&[HISTORY_SESSIONS[0]]);
    fixture.append(HISTORY_SESSIONS[0], "req_0_2");
    let allowed = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
    assert!(
        allowed.uploaded.contains(HISTORY_SESSIONS[0]),
        "revision 2 lets a listed family's genuine change sync"
    );

    let fixture = HistoryFixture::new("history-upgrade-no-downgrade");
    let mut index = fixture.baseline();
    for entry in index.files.values_mut() {
        entry.effective_upload_body_witness_revision = 3;
    }
    index.save(&fixture.index_path).expect("save newer stamps");
    let older = fixture.cycle(
        "2026-08-02T09:00:00Z",
        HistoryCycle {
            upload_context: "history-context-2",
            ..HISTORY_REVISION_2
        },
    );
    assert!(older
        .index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 3));
}

/// Owner B ruling 3 through the pipeline: MONEY's census re-owes a stored 3
/// (as #699's selection-loss path will); the file is owed again, a listed
/// one is held and keeps 2, an unlisted one upgrades back to 3.
#[test]
fn a_re_owed_file_goes_back_through_the_gate() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    crate::snapshots::with_max_gated_claude_revision(3, || {
        use crate::snapshots::{history_local_count, HistoryLocalCount};
        let fixture = HistoryFixture::new("history-upgrade-reowe");
        fixture.baseline();
        fixture.install_list(&[]);
        let revision_3 = HistoryCycle {
            revision: 3,
            upload_context: "history-context-1",
            ..HISTORY_REVISION_2
        };
        let upgraded = fixture.cycle("2026-08-02T09:00:00Z", revision_3);
        assert_eq!(upgraded.uploaded.len(), HISTORY_SESSIONS.len());
        let mut index = upgraded.index;
        index.activate_effective_upload_body_witness_revision(3);
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        for session in &HISTORY_SESSIONS[..2] {
            let key = HistoryFixture::key(&index, session);
            assert!(index.re_owe_effective_upload_body_witness_revision(&key, 2));
        }
        assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed + 2);
        index
            .save(&fixture.index_path)
            .expect("save re-owed stamps");
        fixture.install_list(&[HISTORY_SESSIONS[0]]);
        let again = fixture.cycle("2026-08-02T10:00:00Z", revision_3);
        assert_eq!(
            again.uploaded,
            BTreeSet::from([HISTORY_SESSIONS[1].to_string()]),
            "the listed re-owed root is held; the unlisted one upgrades"
        );
        for (session, revision) in HISTORY_SESSIONS.iter().zip([2, 3, 3]) {
            let key = HistoryFixture::key(&again.index, session);
            assert_eq!(
                again.index.files[&key].effective_upload_body_witness_revision, revision,
                "{session}"
            );
        }
    });
}

/// Addendum 2 item 14 (#700): with the seen-marker present, an empty load
/// latches; held history stays held even with an installed list, while a
/// file born after the cutoff still ingests.
#[test]
fn seen_marker_rebuild_latch_and_cutoff_feed_one_decision() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-latch");
    fixture.baseline();
    fixture.install_list(&[]);
    fixture.corrupt_index();
    let rebuilt = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
    assert!(
        fixture
            .support
            .join("snapshots/claude_code-reemission-exclusions.seen")
            .exists(),
        "the installed list wrote its marker"
    );
    assert_eq!(
        rebuilt.uploaded.len(),
        HISTORY_SESSIONS.len(),
        "an installed empty list paces history; the marker was not there at load"
    );
    fixture.corrupt_index();
    let current_bytes = std::fs::read(&fixture.index_path).unwrap();
    let refused = ScanIndex::load_for_snapshot_source_with_origin(
        &fixture.index_path,
        SnapshotSource::ClaudeCode,
        &fixture.support,
    )
    .unwrap_err();
    assert!(format!("{refused:#}").contains("scan_index_rebuild_loop"));
    assert_eq!(std::fs::read(&fixture.index_path).unwrap(), current_bytes);
    // This second incident occurs after the seven-day cooldown. Model elapsed
    // time in the fixture's rename stamp, retaining the exact prior witness.
    let backups = std::fs::read_dir(&fixture.base)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("claude-scan-index.corrupt.")
        })
        .collect::<Vec<_>>();
    assert_eq!(backups.len(), 1);
    let prior_bytes = std::fs::read(&backups[0]).unwrap();
    let prior_stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos()
        - 8 * 24 * 60 * 60 * 1_000_000_000;
    let older_backup = fixture.base.join(format!(
        "claude-scan-index.corrupt.{}.{prior_stamp}.json",
        std::process::id()
    ));
    std::fs::rename(&backups[0], &older_backup).unwrap();
    assert_eq!(std::fs::read(&older_backup).unwrap(), prior_bytes);
    let latched = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
    assert!(latched.uploaded.is_empty(), "{:?}", latched.uploaded);
    let newcomer = "a7777777-7777-4777-8777-777777777777";
    // Births are whole seconds; a file born in the cutoff's second is history.
    std::thread::sleep(std::time::Duration::from_millis(1_100));
    std::fs::write(
        fixture.root.join(format!("{newcomer}.jsonl")),
        history_line(newcomer, "req_new_1", 0),
    )
    .expect("write a session born after the cutoff");
    let fresh = fixture.cycle("2026-08-02T11:00:00Z", HISTORY_REVISION_2);
    assert_eq!(fresh.uploaded, BTreeSet::from([newcomer.to_string()]));
}

/// Addendum 1 item 6 group 6: a held file beside an accepted, changed sibling
/// on a deferred page never enters accepted-body progress or its new
/// revision; the next completed page holds it again.
#[test]
fn held_history_never_settles_as_accepted_on_a_deferred_page() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-deferred");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.append(HISTORY_SESSIONS[2], "req_2_2");
    let changed_context = HistoryCycle {
        upload_context: "history-context-2",
        ..HISTORY_REVISION_2
    };
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let deferred = fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                upload: PipelineUpload::ServerDeferred,
                ..changed_context
            },
        );
        assert_eq!(
            deferred.uploaded,
            BTreeSet::from([HISTORY_SESSIONS[2].to_string()])
        );
        let completed = fixture.cycle("2026-08-02T10:00:00Z", changed_context);
        assert!(!completed.uploaded.contains(HISTORY_SESSIONS[0]));
        assert!(!completed.uploaded.contains(HISTORY_SESSIONS[1]));
        for session in &HISTORY_SESSIONS[..2] {
            let key = HistoryFixture::key(&completed.index, session);
            assert_eq!(
                completed.index.files[&key].effective_upload_body_witness_revision,
                1
            );
        }
        let key = HistoryFixture::key(&completed.index, HISTORY_SESSIONS[2]);
        assert_eq!(
            completed.index.files[&key].effective_upload_body_witness_revision,
            2
        );
    });
}

/// SOURCE F4a: the incident shape on an unverified Mac with no override of
/// the no-list cutoff. The fixture's history is born after 2026-10-21, but
/// before the history cutoff this load records, so it is still held: the
/// hold reaches the later of the two.
#[test]
fn quarantined_index_holds_history_born_after_the_no_list_cutoff() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-quarantine-real-cutoff");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.corrupt_index();
    let rebuilt = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
    assert_eq!(rebuilt.scan.scanned_file_count, HISTORY_SESSIONS.len());
    assert!(rebuilt.uploaded.is_empty(), "{:?}", rebuilt.uploaded);
    assert_eq!(rebuilt.corrections, 0);
    let again = fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2);
    assert_eq!(again.scan.scanned_file_count, 0, "no re-read storm");
    assert!(again.uploaded.is_empty());
}

/// SOURCE F1a: a quarantined sibling of this index is prior history by
/// itself, with no backfill state at all: the rebuilt files are owed history,
/// paced through the budget (one per page here), not re-sent as new.
#[test]
fn quarantined_index_sibling_alone_is_prior_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-sibling");
    fixture.baseline();
    fixture.corrupt_index();
    let rebuilt = crate::snapshots::with_body_witness_adoption_page_budget(1, || {
        fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                bootstrapped: false,
                ..HISTORY_REVISION_2
            },
        )
    });
    assert_eq!(rebuilt.uploaded.len(), 1, "{:?}", rebuilt.uploaded);
}

/// SOURCE F1a, StateMissing H1: an unreadable backfill state is prior
/// history, not a fresh install. With a quarantined index, or with the index
/// gone and no other evidence, no history is emitted; the state keeps its
/// marker and arms no bootstrap.
#[test]
fn unreadable_backfill_state_emits_no_history_from_a_rebuilt_index() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for (name, quarantine) in [
        ("history-upgrade-unreadable-quarantined", true),
        ("history-upgrade-unreadable-missing", false),
    ] {
        let fixture = HistoryFixture::new(name);
        fixture.baseline();
        fixture.corrupt_backfill_state();
        if quarantine {
            fixture.corrupt_index();
        } else {
            std::fs::remove_file(&fixture.index_path).expect("lose the index");
        }
        for hour in [9, 10] {
            let outcome = fixture.cycle(
                &format!("2026-08-02T{hour:02}:00:00Z"),
                HistoryCycle {
                    bootstrapped: false,
                    ..HISTORY_REVISION_2
                },
            );
            assert!(
                outcome.uploaded.is_empty(),
                "{name}: {:?}",
                outcome.uploaded
            );
            assert_eq!(outcome.corrections, 0);
        }
        let state = crate::backfill::load_backfill_state(&fixture.support);
        assert!(state.prior_history_unverified);
        assert!(
            !crate::backfill::pending_backfill_sources_for_destination(&state, HISTORY_DESTINATION)
                .contains(&SnapshotSource::ClaudeCode),
            "only Claude's bootstrap is suppressed (N2)"
        );
    }
}

/// StateMissing H1: an unreadable backfill state over a populated index arms
/// no replay (the entries stay, nothing is re-read) and uploads no old
/// history. The entries' births are old (the no-list cutoff seam).
#[test]
fn unreadable_backfill_state_arms_no_replay_over_a_populated_index() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-unreadable-populated");
    let baseline = fixture.baseline();
    fixture.corrupt_backfill_state();
    let outcome = crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                replay_generation: Some("history-replay-2"),
                bootstrapped: false,
                ..HISTORY_REVISION_2
            },
        )
    });
    assert!(outcome.uploaded.is_empty(), "{:?}", outcome.uploaded);
    assert_eq!(outcome.scan.scanned_file_count, 0, "nothing re-read");
    for (key, entry) in &outcome.index.files {
        assert_eq!(
            entry.source_file_fingerprint, baseline.files[key].source_file_fingerprint,
            "entries kept"
        );
        assert_eq!(
            entry.effective_upload_body_witness_revision, 1,
            "a replay would have zeroed it"
        );
    }
}

/// SOURCE F1b and its cross-org move ruling: a re-pair to a new destination
/// finds history born before the claim owed and gated, never re-sent
/// ungated: the other destination's completed bootstrap is prior history.
/// With no list and a claim policy other than an explicit `full` it is held
/// (`move_not_full`), also after the new destination's own bootstrap.
#[test]
fn new_destination_holds_history_born_before_the_claim() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-new-destination");
    fixture.baseline();
    // The first destination's bootstrap completes after its first cycle.
    let settled = fixture.cycle(
        "2026-08-02T08:30:00Z",
        HistoryCycle {
            bootstrapped: true,
            ..HISTORY_BASELINE
        },
    );
    assert!(settled.uploaded.is_empty());
    for (hour, bootstrapped) in [(9, false), (10, true)] {
        let moved = fixture.cycle(
            &format!("2026-08-02T{hour:02}:00:00Z"),
            HistoryCycle {
                destination: Some("history-upgrade-destination-b"),
                bootstrapped,
                ..HISTORY_REVISION_2
            },
        );
        assert!(moved.uploaded.is_empty(), "{:?}", moved.uploaded);
    }
}

/// SOURCE ruling (cross-org `full` move, no list), the named policy row: the
/// other destination's history is paced through the budget, counted, only
/// because the last claim was an explicit `full`.
#[test]
fn explicit_full_move_paces_history_born_before_the_claim() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-full-move");
    fixture.baseline();
    fixture.cycle(
        "2026-08-02T08:30:00Z",
        HistoryCycle {
            bootstrapped: true,
            ..HISTORY_BASELINE
        },
    );
    let mut state = crate::backfill::load_backfill_state(&fixture.support);
    state.claim_backfill_policy_full = true;
    crate::backfill::save_backfill_state(&fixture.support, &state).expect("save full claim");
    let mut sent = Vec::new();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        crate::snapshots::with_body_witness_adoption_page_budget(1, || {
            for hour in 9..13 {
                sent.push(
                    fixture
                        .cycle(
                            &format!("2026-08-02T{hour:02}:00:00Z"),
                            HistoryCycle {
                                destination: Some("history-upgrade-destination-b"),
                                bootstrapped: false,
                                ..HISTORY_REVISION_2
                            },
                        )
                        .uploaded
                        .len(),
                );
            }
        });
    });
    assert_eq!(
        sent,
        vec![1, 1, 1, 0],
        "paced, not held and not re-sent at once"
    );
}

/// SOURCE F1b: on the destination of the claim that recorded a
/// different-user cutoff, the previous user's history stays excluded by the
/// cutoff, as before, not by the history gate: a session with activity after
/// the cutoff is still sent whole. The claim binds its own destination
/// before any bootstrap completes.
#[test]
fn different_user_cutoff_excludes_history_without_the_gate() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-different-user");
    let mut state = crate::backfill::BackfillState::default();
    crate::backfill::mark_backfill_complete_for_destination(
        &mut state,
        SnapshotSource::ClaudeCode,
        HISTORY_DESTINATION,
    );
    crate::backfill::save_backfill_state(&fixture.support, &state).expect("save user A state");
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &fixture.support,
        Some("from"),
        Some("2026-08-02T07:00:15Z"),
        "user-b",
        Some("history-upgrade-destination-b"),
    )
    .expect("user B's claim records the cutoff");
    // The previous destination's Claude index stays behind, as in production.
    let previous = fixture.support.join("snapshots/destinations/destination-a");
    std::fs::create_dir_all(&previous).expect("create previous destination");
    std::fs::write(previous.join("claude_code-scan-index-v3.json"), b"{}")
        .expect("previous destination index");
    fixture.append(HISTORY_SESSIONS[0], "req_0_2");
    let moved = fixture.cycle(
        "2026-08-02T09:00:00Z",
        HistoryCycle {
            destination: Some("history-upgrade-destination-b"),
            bootstrapped: false,
            ..HISTORY_REVISION_2
        },
    );
    assert_eq!(
        moved.uploaded,
        BTreeSet::from([HISTORY_SESSIONS[0].to_string()]),
        "only the session active after the cutoff"
    );
}

/// SOURCE h695 N1: a same-user re-claim keeps the cutoff (the server answers
/// `full`) but mints a new destination. The cutoff belongs to the destination
/// of the claim that set it, so on the new one the history already sent to
/// that destination is prior history: gated and paced, never re-sent
/// ungated.
#[test]
fn same_user_reclaim_keeps_the_cutoff_but_gates_the_new_destination() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    same_user_reclaim_is_gated(true);
}

#[test]
fn same_user_reclaim_before_bootstrap_is_still_gated() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    same_user_reclaim_is_gated(false);
}

fn same_user_reclaim_is_gated(complete_bootstrap: bool) {
    let fixture = HistoryFixture::new(if complete_bootstrap {
        "history-upgrade-same-user-reclaim"
    } else {
        "history-upgrade-same-user-reclaim-interrupted"
    });
    fixture.baseline();
    fixture.cycle(
        "2026-08-02T08:30:00Z",
        HistoryCycle {
            bootstrapped: true,
            ..HISTORY_BASELINE
        },
    );
    crate::backfill::apply_claim_backfill_policy_for_destination(
        &fixture.support,
        Some("from"),
        Some("2026-08-02T07:00:15Z"),
        "user-b",
        Some("history-upgrade-destination-b"),
    )
    .expect("user B's claim records the cutoff");
    fixture.append(HISTORY_SESSIONS[0], "req_0_2");
    let claimed = fixture.cycle(
        "2026-08-02T09:00:00Z",
        HistoryCycle {
            destination: Some("history-upgrade-destination-b"),
            bootstrapped: false,
            ..HISTORY_REVISION_2
        },
    );
    assert_eq!(
        claimed.uploaded,
        BTreeSet::from([HISTORY_SESSIONS[0].to_string()]),
        "the claim's own destination keeps the cutoff exception"
    );
    // Completion is irrelevant to the already durable claim binding.
    if complete_bootstrap {
        fixture.cycle(
            "2026-08-02T09:30:00Z",
            HistoryCycle {
                destination: Some("history-upgrade-destination-b"),
                bootstrapped: true,
                ..HISTORY_REVISION_2
            },
        );
    }
    let state = crate::backfill::load_backfill_state(&fixture.support);
    assert_eq!(
        state.backfill_cutoff_destination_namespace.as_deref(),
        Some("history-upgrade-destination-b")
    );

    crate::backfill::apply_claim_backfill_policy_for_destination(
        &fixture.support,
        Some("full"),
        None,
        "user-b",
        Some("history-upgrade-destination-c"),
    )
    .expect("user B re-claims");
    let state = crate::backfill::load_backfill_state(&fixture.support);
    assert!(
        state.backfill_cutoff_at.is_some(),
        "a same-user cutoff is kept"
    );
    let reclaimed = |hour: u32, budget: usize| {
        crate::snapshots::with_body_witness_adoption_page_budget(budget, || {
            fixture
                .cycle(
                    &format!("2026-08-02T{hour:02}:00:00Z"),
                    HistoryCycle {
                        destination: Some("history-upgrade-destination-c"),
                        bootstrapped: false,
                        ..HISTORY_REVISION_2
                    },
                )
                .uploaded
        })
    };
    assert!(
        reclaimed(10, 0).is_empty(),
        "history already sent before the re-claim is gated"
    );
    assert_eq!(
        reclaimed(11, HISTORY_SESSIONS.len()),
        BTreeSet::from([HISTORY_SESSIONS[0].to_string()]),
        "and paced: the re-claim was an explicit full claim"
    );
}

/// An old state has no proof of which destination set its cutoff. It must
/// not grant the different-user exception, even after bootstrap completion.
#[test]
fn an_unbound_legacy_cutoff_does_not_exempt_a_new_destination() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::PriorHistory;
    let fixture = HistoryFixture::new("history-upgrade-unbound-cutoff");
    let mut state = crate::backfill::BackfillState {
        backfill_cutoff_at: Some("2026-08-02T07:00:15Z".to_string()),
        backfill_cutoff_user_id: Some("user-b".to_string()),
        ..Default::default()
    };
    crate::backfill::mark_backfill_complete_for_destination(
        &mut state,
        SnapshotSource::ClaudeCode,
        HISTORY_DESTINATION,
    );
    assert_eq!(state.backfill_cutoff_destination_namespace, None);
    assert_eq!(
        claude_prior_history(
            &state,
            "new-destination",
            &test_upload_progress(),
            &fixture.index_path_for(Some("new-destination")),
            &fixture.support
        ),
        PriorHistory::Moved,
    );
}

/// SOURCE h695 N2: a quarantined ledger of this index, a quarantined legacy
/// Claude index and an unreadable seen-marker path are prior history (fail
/// closed); a clean support state is not.
#[test]
fn quarantined_ledger_and_unreadable_marker_are_prior_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::PriorHistory;
    let fixture = HistoryFixture::new("history-upgrade-probes");
    let backfill = crate::backfill::BackfillState::default();
    let progress = test_upload_progress();
    let index_path = fixture.index_path_for(None);
    let prior = || {
        claude_prior_history(
            &backfill,
            HISTORY_DESTINATION,
            &progress,
            &index_path,
            &fixture.support,
        )
    };
    assert_eq!(prior(), PriorHistory::None);
    for quarantined in [
        "claude-scan-index-upload-progress.corrupt.1.2.json",
        "claude_code-scan-index-v2.corrupt.1.2.json",
    ] {
        let path = index_path.with_file_name(quarantined);
        std::fs::write(&path, b"{").expect("write quarantined copy");
        assert_eq!(prior(), PriorHistory::Here, "{quarantined}");
        std::fs::remove_file(&path).expect("remove quarantined copy");
    }
    assert_eq!(prior(), PriorHistory::None);
    let blocked_parent = fixture.base.join("not-a-directory");
    std::fs::write(&blocked_parent, b"").expect("block the sibling directory");
    assert_eq!(
        claude_prior_history(
            &backfill,
            HISTORY_DESTINATION,
            &progress,
            &blocked_parent.join("claude-scan-index.json"),
            &fixture.support
        ),
        PriorHistory::Here,
        "an unreadable sibling directory fails closed even without a seen marker"
    );
    let snapshots = fixture.support.join("snapshots");
    std::fs::remove_dir_all(&snapshots).expect("remove snapshots directory");
    std::fs::write(&snapshots, b"").expect("a file where the marker's directory is");
    assert_eq!(
        prior(),
        PriorHistory::Here,
        "a marker probe that cannot tell is prior history"
    );
}

/// SOURCE F1a, StateMissing N1: a server-attested record in this
/// destination's ledger is prior history. A generation or replay claim alone
/// is not: the ledger saves it before the scan, so a fresh install killed
/// before its first index save would otherwise hold its own history.
#[test]
fn only_server_attested_ledger_records_are_prior_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-ledger");
    let backfill = crate::backfill::BackfillState::default();
    let mut progress = test_upload_progress();
    let prior = |progress: &SnapshotUploadProgress| {
        claude_prior_history(
            &backfill,
            HISTORY_DESTINATION,
            progress,
            &fixture.index_path,
            &fixture.support,
        )
    };
    assert_eq!(
        prior(&progress),
        crate::snapshots::PriorHistory::None,
        "a positively empty support state"
    );
    progress.generation = 1;
    progress.historical_replay_generation = Some("claude_code:1:destination".into());
    assert_eq!(
        prior(&progress),
        crate::snapshots::PriorHistory::None,
        "a claimed generation alone is not evidence"
    );
    progress.accepted_fingerprints.insert("f".repeat(64));
    assert_eq!(prior(&progress), crate::snapshots::PriorHistory::Here);
}

/// SOURCE F1b, StateMissing M3 and N1 (a): a re-pair resuming a partial
/// index that a pre-gate daemon saved for the new destination loads as
/// `Loaded`, drops no entries and has no cutoff. Another destination's
/// completed bootstrap records the cutoff on this first gated load, at the
/// newest activity this index shows the destination receiving. A session
/// created after it is new and is uploaded, even with no history budget;
/// the indexed history stays held (a move without a `full` claim).
#[test]
fn resumed_pre_gate_index_on_a_new_destination_records_the_cutoff() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-resumed-pre-gate");
    let destination_b = Some("history-upgrade-destination-b");
    let partial = fixture.cycle(
        "2026-08-02T08:00:00Z",
        HistoryCycle {
            destination: destination_b,
            ..HISTORY_BASELINE
        },
    );
    assert_eq!(partial.uploaded.len(), HISTORY_SESSIONS.len());
    let mut state = crate::backfill::BackfillState::default();
    crate::backfill::mark_backfill_complete_for_destination(
        &mut state,
        SnapshotSource::ClaudeCode,
        HISTORY_DESTINATION,
    );
    crate::backfill::save_backfill_state(&fixture.support, &state).expect("save claim state");
    // As a pre-gate daemon saved it: no gate marker and no cutoff.
    let index_path = fixture.index_path_for(destination_b);
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).expect("read saved index"))
            .expect("decode saved index");
    let object = saved.as_object_mut().expect("index object");
    assert!(object.remove("claude_history_gate_loaded").is_some());
    object.remove("claude_history_cutoff_unix_seconds");
    std::fs::write(
        &index_path,
        serde_json::to_vec(&saved).expect("encode index"),
    )
    .expect("write pre-gate index");
    let newcomer = "a8888888-8888-4888-8888-888888888888";
    std::fs::write(
        fixture.root.join(format!("{newcomer}.jsonl")),
        history_line(newcomer, "req_new_1", 0),
    )
    .expect("write history the partial index has not reached");
    let resumed = crate::snapshots::with_body_witness_adoption_page_budget(0, || {
        fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                destination: destination_b,
                ..HISTORY_REVISION_2
            },
        )
    });
    assert_eq!(
        resumed.uploaded,
        BTreeSet::from([newcomer.to_string()]),
        "the session created after the last receipt is new"
    );
    let saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&index_path).expect("read saved index"))
            .expect("decode saved index");
    assert_eq!(
        saved["claude_history_cutoff_unix_seconds"], 1_785_654_000_u64,
        "2026-08-02T07:00:00Z, the newest accepted activity"
    );
    assert!(
        !std::fs::read_dir(&fixture.base)
            .expect("list fixture")
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
        "the index loaded; nothing was quarantined"
    );
}

/// SOURCE F1b (AutoReview): a bootstrap interrupted before a re-pair leaves
/// only its own destination's Claude index or ledger. That is prior history
/// for the new destination; the new destination's own files are not.
#[test]
fn another_destinations_claude_state_is_prior_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-other-destination");
    let backfill = crate::backfill::BackfillState::default();
    let progress = test_upload_progress();
    let destinations = fixture.support.join("snapshots/destinations");
    let own = destinations.join("destination-b");
    std::fs::create_dir_all(&own).expect("create own destination");
    let index_path = own.join("claude_code-scan-index-v3.json");
    std::fs::write(own.join("claude_code-scan-index-v3.lock"), b"").expect("own lock");
    let prior = || {
        claude_prior_history(
            &backfill,
            "destination-b",
            &progress,
            &index_path,
            &fixture.support,
        )
    };
    assert_eq!(
        prior(),
        crate::snapshots::PriorHistory::None,
        "this destination's own files are not evidence"
    );
    // I-r3-1: this destination's own v1/v2 leftovers are not a move.
    for legacy in [
        own.join("claude_code-scan-index.json"),
        own.join("claude_code-scan-index-v2.json"),
    ] {
        std::fs::write(&legacy, b"{}").expect("legacy leftover");
    }
    assert_eq!(
        prior(),
        crate::snapshots::PriorHistory::None,
        "a same-destination legacy leftover is not another destination"
    );
    // SOURCE h732 C3: an unscoped pre-scoping index names no destination, so
    // it is not a move, but it is this Mac's history: Here, so a cutoff keeps
    // it owed, list-gated and paced.
    std::fs::write(
        fixture
            .support
            .join("snapshots/claude_code-scan-index-no-titles.json"),
        b"{}",
    )
    .expect("unscoped legacy index");
    assert_eq!(prior(), crate::snapshots::PriorHistory::Here);
    let other = destinations.join("destination-a");
    std::fs::create_dir_all(&other).expect("create other destination");
    std::fs::write(
        other.join("claude_code-scan-index-v3-upload-progress.json"),
        b"{}",
    )
    .expect("other destination ledger");
    assert_eq!(prior(), crate::snapshots::PriorHistory::Moved);
}

/// StateMissing N1 (a), the upgrade after downtime: a pre-gate `Loaded`
/// index of this destination (its own bootstrap) and a session created
/// after its last receipt, no list. The new session is uploaded at once,
/// even with no history budget; the indexed history is paced, not held.
#[test]
fn session_created_after_a_pre_gate_index_last_receipt_is_uploaded() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-downtime");
    fixture.baseline();
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.index_path).expect("read saved index"))
            .expect("decode saved index");
    let object = saved.as_object_mut().expect("index object");
    object.remove("claude_history_gate_loaded");
    object.remove("claude_history_cutoff_unix_seconds");
    std::fs::write(
        &fixture.index_path,
        serde_json::to_vec(&saved).expect("encode index"),
    )
    .expect("write pre-gate index");
    let newcomer = "a9999999-9999-4999-8999-999999999999";
    std::fs::write(
        fixture.root.join(format!("{newcomer}.jsonl")),
        history_line(newcomer, "req_new_1", 0),
    )
    .expect("write a session created while the app was down");
    let upgraded = crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        crate::snapshots::with_body_witness_adoption_page_budget(0, || {
            fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2)
        })
    });
    assert_eq!(upgraded.uploaded, BTreeSet::from([newcomer.to_string()]));
    let paced = crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        fixture.cycle("2026-08-02T10:00:00Z", HISTORY_REVISION_2)
    });
    assert_eq!(
        paced.uploaded.len(),
        HISTORY_SESSIONS.len(),
        "owed history is paced through the budget, not held"
    );
}

/// SOURCE addendum 8, the incident M4 shape with the list intended: prior
/// uploads, the list installed (one family listed) and its seen-marker
/// written, then the index quarantined. The rebuild latches (#700): nothing
/// is emitted. After a restart, the listed family is never emitted and the
/// rest is paced through the budget.
#[test]
fn intended_list_holds_listed_families_and_paces_the_rest_after_a_quarantine() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-intended-list");
    fixture.baseline();
    fixture.install_list(&[HISTORY_SESSIONS[0]]);
    let marked = fixture.cycle("2026-08-02T08:30:00Z", HISTORY_BASELINE);
    assert!(marked.uploaded.is_empty(), "nothing changed or owed yet");
    assert!(fixture
        .support
        .join("snapshots/claude_code-reemission-exclusions.seen")
        .exists());
    fixture.corrupt_index();
    let latched = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
    assert!(latched.uploaded.is_empty(), "{:?}", latched.uploaded);
    crate::snapshots::restart_claude_reemission_stop_for_test();
    let mut sent = Vec::new();
    crate::snapshots::with_body_witness_adoption_page_budget(1, || {
        for hour in 10..14 {
            let outcome =
                fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), HISTORY_REVISION_2);
            assert!(!outcome.uploaded.contains(HISTORY_SESSIONS[0]));
            sent.push(outcome.uploaded.len());
        }
    });
    crate::snapshots::restart_claude_reemission_stop_for_test();
    assert_eq!(
        sent,
        vec![1, 1, 0, 0],
        "the two unlisted families, one per page"
    );
}

/// SOURCE addendum 8: the list's seen-marker present but the list file gone
/// (`MissingAfterInstall`) pauses: no history is emitted, whatever the
/// budget, after a quarantine as on an intact index.
#[test]
fn seen_marker_without_the_list_pauses_all_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("history-upgrade-list-missing");
    fixture.baseline();
    fixture.install_list(&[]);
    fixture.cycle("2026-08-02T08:30:00Z", HISTORY_BASELINE);
    std::fs::remove_file(
        fixture
            .support
            .join("snapshots/claude_code-reemission-exclusions.txt"),
    )
    .expect("lose the list");
    let intact = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
    assert!(intact.uploaded.is_empty(), "{:?}", intact.uploaded);
    fixture.corrupt_index();
    for hour in [10, 11] {
        // The rebuild latches on its first load; the restart before the
        // second shows the pause alone holds it.
        let outcome = fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), HISTORY_REVISION_2);
        assert!(outcome.uploaded.is_empty(), "{:?}", outcome.uploaded);
        crate::snapshots::restart_claude_reemission_stop_for_test();
    }
}

/// The lenient decoder's remaining budget rebuild must compose with the full
/// prior-history gate. NewFile-shaped history is never emitted on the held
/// paths; the allowed unlisted history is still paced at revision <= 2.
#[test]
fn over_budget_rebuild_preserves_history_holds_list_latch_and_pacing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    // No intended list plus unreadable prior evidence: fail closed, not fresh.
    let fixture = HistoryFixture::new("history-budget-unverified");
    fixture.baseline();
    fixture.corrupt_backfill_state();
    fixture.exceed_decode_hold_budget();
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let rebuilt = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
        assert_eq!(rebuilt.scan.scanned_file_count, HISTORY_SESSIONS.len());
        assert!(
            rebuilt.scan.snapshots.is_empty(),
            "no NewFile history emission"
        );
        assert!(rebuilt.uploaded.is_empty());
        assert_eq!(rebuilt.corrections, 0);
        assert!(rebuilt.index.current_snapshot_fingerprints().is_empty());
        assert!(rebuilt.index.files.values().all(|entry| {
            entry.effective_upload_body_witness_revision == 0
                && entry.last_upload_body_witness.is_none()
        }));
    });
    assert!(
        std::fs::read_dir(&fixture.base)
            .unwrap()
            .flatten()
            .any(|entry| { entry.file_name().to_string_lossy().contains(".corrupt.") }),
        "the excessive damage actually triggered a rebuild"
    );

    // An intended protected list first latches the rebuild; after restart,
    // only unlisted history can pass, within the normal page budget.
    let fixture = HistoryFixture::new("history-budget-intended-list");
    fixture.baseline();
    fixture.install_list(&[HISTORY_SESSIONS[0]]);
    fixture.cycle("2026-08-02T08:30:00Z", HISTORY_BASELINE);
    fixture.exceed_decode_hold_budget();
    let latched = fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2);
    assert_eq!(latched.scan.scanned_file_count, HISTORY_SESSIONS.len());
    assert!(
        latched.scan.snapshots.is_empty(),
        "latch denies NewFile history"
    );
    assert!(latched.uploaded.is_empty());
    crate::snapshots::restart_claude_reemission_stop_for_test();
    let mut sent = Vec::new();
    crate::snapshots::with_body_witness_adoption_page_budget(1, || {
        for hour in 10..14 {
            let outcome =
                fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), HISTORY_REVISION_2);
            assert!(!outcome.uploaded.contains(HISTORY_SESSIONS[0]));
            assert!(outcome
                .index
                .files
                .values()
                .all(|entry| { entry.effective_upload_body_witness_revision <= 2 }));
            sent.push(outcome.uploaded.len());
        }
    });
    crate::snapshots::restart_claude_reemission_stop_for_test();
    assert_eq!(sent, vec![1, 1, 0, 0]);

    // A lost intended list must keep holding after a restart too.
    let fixture = HistoryFixture::new("history-budget-missing-list");
    fixture.baseline();
    fixture.install_list(&[]);
    fixture.cycle("2026-08-02T08:30:00Z", HISTORY_BASELINE);
    std::fs::remove_file(
        fixture
            .support
            .join("snapshots/claude_code-reemission-exclusions.txt"),
    )
    .unwrap();
    fixture.exceed_decode_hold_budget();
    for hour in [9, 10] {
        let outcome = fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), HISTORY_REVISION_2);
        assert!(
            outcome.scan.snapshots.is_empty(),
            "missing list denies history"
        );
        assert!(outcome.uploaded.is_empty());
        crate::snapshots::restart_claude_reemission_stop_for_test();
    }
}
fn history_subagent_line(session: &str, agent: &str) -> String {
    format!(
        "{{\"timestamp\":\"2026-08-02T07:00:10Z\",\"type\":\"assistant\",\"sessionId\":\"{session}\",\"agentId\":\"{agent}\",\"isSidechain\":true,\"requestId\":\"req_{session}_{agent}\",\"message\":{{\"model\":\"claude-haiku-4-5\",\"usage\":{{\"input_tokens\":10,\"output_tokens\":10}}}}}}\n"
    )
}

/// The members the history gate held only through a listed family root
/// whose root file is absent, as the local diagnostics recorded them.
fn family_closure_root_absent_excluded(lines: &[serde_json::Value]) -> u64 {
    lines
        .iter()
        .filter(|line| line["stage"] == "claude_reemission_family_closure_root_absent_excluded")
        .map(|line| {
            line["counts"]["claude_reemission_family_closure_root_absent_excluded"]
                .as_u64()
                .expect("count")
        })
        .sum()
}

/// StateMissing M1 (SOURCE d680b524): the first family gets subagent files
/// `agents`, every file is sent at revision 1, then its root transcript is
/// removed, `listed` is installed as the list and the index is quarantined.
/// The rebuilt cycle runs the full prepare/finish path under the captured
/// local diagnostics.
fn rootless_family_rebuild(
    name: &str,
    agents: &[&str],
    listed: &str,
) -> (HistoryOutcome, Vec<serde_json::Value>) {
    let fixture = HistoryFixture::new(name);
    let family = HISTORY_SESSIONS[0];
    let subagents = fixture.root.join(family).join("subagents");
    std::fs::create_dir_all(&subagents).expect("create synthetic subagents");
    for agent in agents {
        std::fs::write(
            subagents.join(format!("{agent}.jsonl")),
            history_subagent_line(family, agent),
        )
        .expect("write synthetic subagent transcript");
    }
    let baseline = fixture.cycle("2026-08-02T08:00:00Z", HISTORY_BASELINE);
    for agent in agents {
        assert!(
            baseline.uploaded.contains(&format!("{family}_{agent}")),
            "the subagent is sent before the rebuild: {:?}",
            baseline.uploaded
        );
    }
    std::fs::remove_file(fixture.root.join(format!("{family}.jsonl")))
        .expect("remove the root transcript");
    fixture.install_list(&[listed]);
    fixture.corrupt_index();
    crate::local_resource_diagnostics::capture(|| {
        fixture.cycle("2026-08-02T09:00:00Z", HISTORY_REVISION_2)
    })
}

/// Nothing of the first family reached the upload or the emitted snapshots;
/// the unlisted families are paced through and sent.
fn assert_rootless_family_held(outcome: &HistoryOutcome) {
    let family = HISTORY_SESSIONS[0];
    assert!(
        outcome.uploaded.iter().all(|id| !id.starts_with(family)),
        "{:?}",
        outcome.uploaded
    );
    assert!(outcome
        .scan
        .snapshots
        .iter()
        .all(|item| !item.source_session_id.starts_with(family)));
    for session in &HISTORY_SESSIONS[1..] {
        assert!(
            outcome.uploaded.contains(*session),
            "{:?}",
            outcome.uploaded
        );
    }
}

/// SOURCE d680b524 (a): the list names only `R_agent-a`, `R.jsonl` is gone,
/// and the index is rebuilt. A sibling is not offered whether traversal
/// decides it after agent-a (`agent-b`) or before it (`agent-0`), and each
/// sibling counts once as held through the absent root. agent-a itself is
/// listed by its own line and is not counted.
#[test]
fn listed_member_holds_its_siblings_through_the_pipeline_without_the_root_file() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for (sibling, name) in [
        ("agent-b", "history-upgrade-rootless-after"),
        ("agent-0", "history-upgrade-rootless-before"),
    ] {
        let listed = format!("{}_agent-a", HISTORY_SESSIONS[0]);
        let (outcome, lines) = rootless_family_rebuild(name, &["agent-a", sibling], &listed);
        assert_rootless_family_held(&outcome);
        assert_eq!(family_closure_root_absent_excluded(&lines), 1, "{sibling}");
    }
}

/// SOURCE d680b524 (b), the reverse: the list names the root `R`, `R.jsonl`
/// is gone and only subagent files remain. None is offered, and each counts
/// as held through the absent root.
#[test]
fn listed_root_holds_every_subagent_through_the_pipeline_without_the_root_file() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (outcome, lines) = rootless_family_rebuild(
        "history-upgrade-rootless-listed-root",
        &["agent-a", "agent-b"],
        HISTORY_SESSIONS[0],
    );
    assert_rootless_family_held(&outcome);
    assert_eq!(family_closure_root_absent_excluded(&lines), 2);
}

// F2: native scan -> evidence -> finalization -> upload -> settlement -> reload.
// No accumulator or settlement disposition is supplied by these fixtures.
// Request-owned literals are intentionally denied below revision 3. These
// enabled-path tests use the existing future-revision test seam and an empty
// installed protected list, preserving the production activation guard.
const E2_HISTORY_UPGRADE: HistoryCycle<'static> = HistoryCycle {
    revision: 3,
    ..HISTORY_REVISION_2
};

fn with_e2_history<T>(fixture: &HistoryFixture, f: impl FnOnce() -> T) -> T {
    fixture.install_list(&[]);
    crate::snapshots::with_max_gated_claude_revision(3, || {
        crate::snapshots::claude_request_money::e2::with_enabled(f)
    })
}

fn e2_history_sidecar(support: &Path, root: &str, trace: bool) -> PathBuf {
    support
        .join(if trace {
            "local-otel/claude-code-trace-ownership"
        } else {
            crate::claude_local_otel::STORE_DIR
        })
        .join(format!("{}.jsonl", history_digest(root)))
}

fn e2_history_api(
    root: &str,
    request: &str,
    sequence: u64,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: root.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: format!("2026-08-02T07:00:{sequence:02}Z"),
        model: "claude-haiku-4-5".into(),
        effort: "high".into(),
        query_source: "user".into(),
        speed: "fast".into(),
        app_version: "2.1.226".into(),
        cost_usd_micros: Some(100),
        event_sequence: Some(sequence),
        input_tokens: 10,
        output_tokens: 10,
        request_count: 1,
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{}",
        history_digest(&serde_json::to_string(&row).unwrap())
    );
    row
}

fn e2_history_trace(
    root: &str,
    request: &str,
    agent: &str,
) -> crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
    let mut row = crate::claude_local_otel::ClaudeTraceOwnershipEvidence {
        capture_revision: "claude_llm_request_ownership:v1".into(),
        session_id: root.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        agent_id: agent.into(),
        observed_at: "2026-08-02T07:00:30Z".into(),
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{}",
        history_digest(&serde_json::to_string(&row).unwrap())
    );
    row
}

fn e2_history_reported(fixture: &HistoryFixture, root: &str, number: usize) {
    let request = format!("req_{number}_1");
    let api = e2_history_api(root, &request, 0);
    let trace = e2_history_trace(root, &request, "");
    for (path, line) in [
        (
            e2_history_sidecar(&fixture.support, root, false),
            serde_json::to_string(&api).unwrap(),
        ),
        (
            e2_history_sidecar(&fixture.support, root, true),
            serde_json::to_string(&trace).unwrap(),
        ),
    ] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, line + "\n").unwrap();
    }
}

fn e2_history_assert_prior_tuple(before: &ScanIndex, after: &ScanIndex, key: &str) {
    let old = &before.files[key];
    let held = &after.files[key];
    assert_eq!(
        held.effective_upload_body_witness_revision,
        old.effective_upload_body_witness_revision
    );
    assert_eq!(
        held.last_snapshot_fingerprint,
        old.last_snapshot_fingerprint
    );
    assert_eq!(held.last_upload_body_witness, old.last_upload_body_witness);
    assert_eq!(
        after.file_snapshot_fingerprints.get(key),
        before.file_snapshot_fingerprints.get(key)
    );
    assert_eq!(
        after.confirmed_empty_files.contains(key),
        before.confirmed_empty_files.contains(key)
    );
}

#[test]
fn e2_refused_twins_keep_prior_tuple_and_stay_owed_while_siblings_settle() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-refused-history-twins");
    let refused = HISTORY_SESSIONS[0];
    let copy = fixture.root.join("other-project");
    std::fs::create_dir_all(&copy).unwrap();
    std::fs::copy(
        fixture.root.join(format!("{refused}.jsonl")),
        copy.join(format!("{refused}.jsonl")),
    )
    .unwrap();
    let baseline = fixture.baseline();
    let keys = baseline
        .files
        .keys()
        .filter(|key| key.ends_with(&format!("{refused}.jsonl")))
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(keys.len(), 2);
    with_e2_history(&fixture, || {
        // Existing identity at the emitter boundary makes it refuse. Both
        // contributions came through the real file parser, not hand-fed folds.
        for hour in [9, 10] {
            let outcome = fixture.cycle_with_scan(
                &format!("2026-08-02T{hour:02}:00:00Z"),
                E2_HISTORY_UPGRADE,
                |scan| {
                    let twins = scan
                        .snapshots
                        .iter_mut()
                        .filter(|item| item.source_session_id == refused)
                        .collect::<Vec<_>>();
                    assert_eq!(twins.len(), 2, "both refused files are still owed");
                    for item in twins {
                        item.model_usage
                            .first_mut()
                            .expect("parsed native row")
                            .evidence_ref = Some(0);
                    }
                },
            );
            assert!(!outcome.uploaded.contains(refused));
            assert_eq!(outcome.uploaded.len(), if hour == 9 { 2 } else { 0 });
            for key in &keys {
                e2_history_assert_prior_tuple(&baseline, &outcome.index, key);
                assert!(!outcome.index.confirmed_empty_files.contains(key));
            }
            for sibling in &HISTORY_SESSIONS[1..] {
                let key = HistoryFixture::key(&outcome.index, sibling);
                assert_eq!(
                    outcome.index.files[&key].effective_upload_body_witness_revision,
                    3
                );
            }
        }
    });
}

#[test]
fn e2_ok_unhealthy_root_holds_history_then_healthy_read_settles_reported_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for failure in [
        "api-malformed",
        "trace-malformed",
        "api-cap",
        "trace-cap",
        "trace-nonfile",
        "partial-pair",
    ] {
        let fixture = HistoryFixture::new(&format!("e2-history-{failure}"));
        let baseline = fixture.baseline();
        let root = HISTORY_SESSIONS[0];
        let held_key = HistoryFixture::key(&baseline, root);
        for (number, session) in HISTORY_SESSIONS.iter().enumerate() {
            e2_history_reported(&fixture, session, number);
        }
        let broken = e2_history_sidecar(&fixture.support, root, failure.starts_with("trace"));
        match failure {
            "api-malformed" | "trace-malformed" => std::fs::write(&broken, "{broken\n").unwrap(),
            "api-cap" | "trace-cap" => std::fs::OpenOptions::new()
                .write(true)
                .open(&broken)
                .unwrap()
                .set_len(64 * 1024 * 1024)
                .unwrap(),
            "trace-nonfile" => {
                std::fs::remove_file(&broken).unwrap();
                std::fs::create_dir(&broken).unwrap();
            }
            "partial-pair" => {
                std::fs::remove_file(e2_history_sidecar(&fixture.support, root, true)).unwrap()
            }
            _ => unreachable!(),
        }
        // This is the gap: the permissive load SUCCEEDS, with a bad root.
        assert!(
            crate::claude_local_otel::ClaudeApiEvidenceRead::load(
                &fixture.support,
                HISTORY_SESSIONS.map(str::to_owned)
            )
            .is_ok(),
            "{failure}"
        );
        with_e2_history(&fixture, || {
            let failed = fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE);
            assert_eq!(
                failed.uploaded.len(),
                2,
                "{failure}: healthy siblings settle"
            );
            assert!(!failed.uploaded.contains(root), "{failure}");
            e2_history_assert_prior_tuple(&baseline, &failed.index, &held_key);
            if broken.is_dir() {
                std::fs::remove_dir(&broken).unwrap();
            }
            e2_history_reported(&fixture, root, 0);
            let recovered = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
            assert_eq!(
                recovered.uploaded,
                BTreeSet::from([root.to_owned()]),
                "{failure}"
            );
            let body = recovered
                .scan
                .snapshots
                .iter()
                .find(|item| item.source_session_id == root)
                .unwrap();
            assert_eq!(body.telemetry_owned_complete, Some(true), "{failure}");
            assert_eq!(
                body.cost.as_ref().unwrap().total_cost_usd.as_deref(),
                Some("0.0001"),
                "{failure}: reported money"
            );
            assert_eq!(
                recovered.index.files[&held_key].effective_upload_body_witness_revision,
                3
            );
            let again = fixture.cycle("2026-08-02T11:00:00Z", E2_HISTORY_UPGRADE);
            assert!(again.uploaded.is_empty(), "{failure}: settles exactly once");
            assert_eq!(
                again.scan.scanned_file_count, 0,
                "{failure}: no forced second reread"
            );
        });
    }
}

#[test]
fn e2_no_sidecar_old_history_settles_with_incomplete_token_estimates() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-history-no-sidecar");
    fixture.baseline();
    with_e2_history(&fixture, || {
        let outcome = fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(outcome.uploaded.len(), 3);
        for item in &outcome.scan.snapshots {
            assert_eq!(item.telemetry_owned_complete, Some(false));
            assert!(item.cost.is_none());
            assert_eq!(item.request_count, 1);
            assert_eq!(item.input_tokens + item.output_tokens, 20);
        }
        assert!(outcome
            .index
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 3));
        let again = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
        assert!(again.uploaded.is_empty());
        assert_eq!(again.scan.scanned_file_count, 0);
    });
}

/// Pages of `cycle` until one reads nothing; per page (uploaded sessions,
/// files read). Panics if the re-read does not finish within `hours`.
fn e2_history_pages(
    fixture: &HistoryFixture,
    hours: std::ops::Range<u32>,
    cycle: HistoryCycle<'_>,
) -> (Vec<(BTreeSet<String>, usize)>, HistoryOutcome) {
    let mut pages = Vec::new();
    for hour in hours {
        let page = fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), cycle);
        if page.scan.scanned_file_count == 0 {
            return (pages, page);
        }
        pages.push((page.uploaded.clone(), page.scan.scanned_file_count));
    }
    panic!("the paced re-read did not finish: {pages:?}");
}

/// Design item 8 at the switch-on: from revision 2, the revision-3 lever
/// re-reads every idle file once, paced by the history budget (one file a
/// page here; 2,000 files / 1 GiB in production), then reads nothing again:
/// no second re-read, no re-arm. Every settled body records its money-rule
/// marks; a later money rule re-owes only the files whose marks it names,
/// once, under the same budget.
#[test]
fn e2_switch_on_rereads_history_once_paced_and_money_rules_reread_only_marked_files() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::claude_money_birth_store::location_key;
    use crate::snapshots::claude_request_money::e2::{money_mark, with_money_rules};
    use crate::snapshots::{history_local_count, HistoryLocalCount};
    // Version 2 is #825's zero-mask row, kept for version stability.
    const RELEASE: &[(u16, u8)] = &[(1, 0), (2, 0), (3, money_mark::ESTIMATED)];
    let fixture = HistoryFixture::new("e2-switch-on-once");
    fixture.baseline();
    let at_two = fixture.cycle("2026-08-02T08:30:00Z", HISTORY_REVISION_2);
    assert!(at_two
        .index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 2));
    // Only the first session's telemetry is on disk: the others settle on
    // token estimates and carry that mark. Fixture files are created after
    // their records, so every session is also a disclosed all-copied file.
    e2_history_reported(&fixture, HISTORY_SESSIONS[0], 0);
    with_e2_history(&fixture, || {
        crate::snapshots::with_body_witness_adoption_page_budget(1, || {
            let (pages, done) = e2_history_pages(&fixture, 9..14, E2_HISTORY_UPGRADE);
            assert_eq!(pages.len(), HISTORY_SESSIONS.len(), "paced: {pages:?}");
            let mut sent = BTreeMap::<String, usize>::new();
            for (uploaded, read) in &pages {
                assert_eq!(*read, 1, "one file a page: {pages:?}");
                for session in uploaded {
                    *sent.entry(session.clone()).or_default() += 1;
                }
            }
            assert!(
                HISTORY_SESSIONS.iter().all(|s| sent.get(*s) == Some(&1)),
                "each idle file re-sent exactly once: {sent:?}"
            );
            assert!(done.uploaded.is_empty());
            let again = fixture.cycle("2026-08-02T14:30:00Z", E2_HISTORY_UPGRADE);
            assert_eq!(again.scan.scanned_file_count, 0, "no second re-read");
            assert!(again.uploaded.is_empty());
            let index = &again.index;
            let store = &index.claude_money_birth_store;
            assert_eq!(store.money_rule_version(), 2);
            let estimated = money_mark::DISCLOSED | money_mark::ESTIMATED;
            for (session, marks) in
                HISTORY_SESSIONS
                    .iter()
                    .zip([money_mark::DISCLOSED, estimated, estimated])
            {
                let key = HistoryFixture::key(index, session);
                assert_eq!(index.files[&key].effective_upload_body_witness_revision, 3);
                // The retired permit mark is never set (contract 5 always on).
                assert_eq!(store.money_marks(location_key(&key)), marks, "{session}");
            }

            // A later money fix: only the two estimated files are re-owed and
            // read once more, paced; the reported one is never touched.
            with_money_rules(RELEASE, || {
                let reowed = history_local_count(HistoryLocalCount::Reowed);
                let (pages, done) = e2_history_pages(&fixture, 15..19, E2_HISTORY_UPGRADE);
                assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed + 2);
                assert_eq!(pages.iter().map(|(_, read)| read).sum::<usize>(), 2);
                assert!(pages.iter().all(|(_, read)| *read == 1), "{pages:?}");
                assert!(pages
                    .iter()
                    .all(|(uploaded, _)| !uploaded.contains(HISTORY_SESSIONS[0])));
                let index = &done.index;
                assert_eq!(index.claude_money_birth_store.money_rule_version(), 3);
                assert!(index
                    .files
                    .values()
                    .all(|entry| entry.effective_upload_body_witness_revision == 3));
                let again = fixture.cycle("2026-08-02T19:30:00Z", E2_HISTORY_UPGRADE);
                assert_eq!(again.scan.scanned_file_count, 0, "each rule applies once");
                assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed + 2);
            });
        });
    });
}

/// The listed session's item on a page: read without an E2 fold, so it
/// publishes exactly as gate off (native hours, no request-owned literal).
impl HistoryFixture {
    /// The list as the cycle's load reads it. The returned index is reloaded
    /// from disk, and the list state is not persisted with it.
    fn list_status(&self, outcome: &HistoryOutcome) -> &'static str {
        let mut index = outcome.index.clone();
        index.load_claude_reemission_exclusions(&self.support);
        index.claude_reemission_list_status_for_test()
    }
}

fn e2_assert_ordinary_body(outcome: &HistoryOutcome, session: &str) {
    let items = outcome
        .scan
        .snapshots
        .iter()
        .filter(|item| item.source_session_id == session)
        .collect::<Vec<_>>();
    assert!(!items.is_empty(), "{session} was read");
    for item in items {
        assert!(item.claude_money.is_none(), "no E2 fold for {session}");
        assert_ne!(
            item.usage_accounting_contract.as_deref(),
            Some(crate::snapshots::REQUEST_OWNED_USAGE_CONTRACT)
        );
        assert!(!item.usage_buckets.is_empty(), "native hours for {session}");
    }
}

/// Owner B (SOURCE Amendment 14) with the gate on: a listed family keeps
/// ordinary money. Its genuine change uploads its ordinary body once; an
/// unlisted family changed on the same page uploads the E2 literal; the
/// listed file is never stamped 3 nor re-read by revision 3.
#[test]
fn e2_listed_family_keeps_ordinary_money_beside_an_unlisted_literal() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-listed-ordinary");
    fixture.baseline();
    fixture.cycle("2026-08-02T08:30:00Z", HISTORY_REVISION_2);
    with_e2_history(&fixture, || {
        fixture.install_list(&[HISTORY_SESSIONS[0]]);
        fixture.append(HISTORY_SESSIONS[0], "req_0_2");
        fixture.append(HISTORY_SESSIONS[1], "req_1_2");
        let changed = fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE);
        assert!(changed.uploaded.contains(HISTORY_SESSIONS[0]));
        assert!(!changed.uploaded_literal.contains(HISTORY_SESSIONS[0]));
        assert!(changed.uploaded_literal.contains(HISTORY_SESSIONS[1]));
        e2_assert_ordinary_body(&changed, HISTORY_SESSIONS[0]);
        let listed = HistoryFixture::key(&changed.index, HISTORY_SESSIONS[0]);
        let unlisted = HistoryFixture::key(&changed.index, HISTORY_SESSIONS[1]);
        assert_eq!(
            changed.index.files[&listed].effective_upload_body_witness_revision, 2,
            "the listed file is never stamped 3"
        );
        assert_eq!(
            changed.index.files[&unlisted].effective_upload_body_witness_revision,
            3
        );
        for hour in [10, 11] {
            let quiet = fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), E2_HISTORY_UPGRADE);
            assert!(
                quiet.uploaded.is_empty(),
                "uploaded once: {:?}",
                quiet.uploaded
            );
            assert_eq!(
                quiet.scan.scanned_file_count, 0,
                "never re-read by revision 3"
            );
            assert_eq!(
                quiet.index.files[&listed].effective_upload_body_witness_revision,
                2
            );
        }
    });
}

/// Owner B: a list seen once and now missing keeps today's pause and alarm
/// with the gate on. No owed file is re-read or stamped 3, and a genuine
/// change uploads its ordinary body (every family is kept on ordinary money
/// while the list pauses adoption), never the literal and never withheld.
#[test]
fn e2_missing_list_pauses_history_and_keeps_changes_on_ordinary_money() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-list-missing-ordinary");
    fixture.baseline();
    fixture.install_list(&[]);
    fixture.cycle("2026-08-02T08:30:00Z", HISTORY_REVISION_2);
    std::fs::remove_file(
        fixture
            .support
            .join("snapshots/claude_code-reemission-exclusions.txt"),
    )
    .expect("lose the list");
    crate::snapshots::with_max_gated_claude_revision(3, || {
        crate::snapshots::claude_request_money::e2::with_enabled(|| {
            fixture.append(HISTORY_SESSIONS[1], "req_1_2");
            let changed = fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE);
            assert_eq!(fixture.list_status(&changed), "missing_after_install");
            assert_eq!(
                changed.uploaded,
                BTreeSet::from([HISTORY_SESSIONS[1].to_string()]),
                "only the genuine change uploads"
            );
            assert!(changed.uploaded_literal.is_empty());
            assert_eq!(changed.scan.scanned_file_count, 1, "no owed file re-read");
            e2_assert_ordinary_body(&changed, HISTORY_SESSIONS[1]);
            assert!(changed
                .index
                .files
                .values()
                .all(|entry| entry.effective_upload_body_witness_revision == 2));
            let quiet = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
            assert_eq!(fixture.list_status(&quiet), "missing_after_install");
            assert!(quiet.uploaded.is_empty(), "{:?}", quiet.uploaded);
            assert_eq!(quiet.scan.scanned_file_count, 0);
        })
    });
}

#[test]
fn e2_live_trace_read_failure_keeps_body_but_never_claims_complete() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-live-bad-trace");
    e2_history_reported(&fixture, HISTORY_SESSIONS[0], 0);
    std::fs::write(
        e2_history_sidecar(&fixture.support, HISTORY_SESSIONS[0], true),
        "{bad\n",
    )
    .unwrap();
    with_e2_history(&fixture, || {
        let outcome = fixture.cycle(
            "2026-08-02T08:00:00Z",
            HistoryCycle {
                revision: 3,
                ..HISTORY_BASELINE
            },
        );
        assert_eq!(outcome.uploaded.len(), 3, "live uploads still proceed");
        let item = outcome
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == HISTORY_SESSIONS[0])
            .unwrap();
        assert_eq!(
            item.telemetry_owned_complete,
            Some(false),
            "a good API match cannot certify the failed trace read"
        );
    });
}

#[test]
fn e2_unhealthy_root_holds_owed_agent_history_too() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-history-agent-health");
    let root = HISTORY_SESSIONS[0];
    let agent = "a4d1585d310070d0f";
    let agent_path = fixture
        .root
        .join(root)
        .join("subagents")
        .join(format!("agent-{agent}.jsonl"));
    std::fs::create_dir_all(agent_path.parent().unwrap()).unwrap();
    std::fs::write(&agent_path, history_line(root, "req_child", 1)).unwrap();
    let baseline = fixture
        .cycle("2026-08-02T08:00:00Z", HISTORY_BASELINE)
        .index;
    let agent_key = baseline
        .files
        .keys()
        .find(|key| key.ends_with(&format!("agent-{agent}.jsonl")))
        .unwrap()
        .clone();
    assert_eq!(
        baseline.files[&agent_key].effective_upload_body_witness_revision,
        1
    );
    let root_key = HistoryFixture::key(&baseline, root);
    for (number, session) in HISTORY_SESSIONS.iter().enumerate() {
        e2_history_reported(&fixture, session, number);
    }
    let api_path = e2_history_sidecar(&fixture.support, root, false);
    let trace_path = e2_history_sidecar(&fixture.support, root, true);
    let api = e2_history_api(root, "req_child", 1);
    let trace = e2_history_trace(root, "req_child", agent);
    for (path, row) in [
        (&api_path, serde_json::to_string(&api).unwrap()),
        (&trace_path, serde_json::to_string(&trace).unwrap()),
    ] {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path).unwrap(),
            "{row}"
        )
        .unwrap();
    }
    let healthy_trace = std::fs::read(&trace_path).unwrap();
    std::fs::write(&trace_path, "{bad\n").unwrap();
    with_e2_history(&fixture, || {
        let failed = fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(
            failed.uploaded.len(),
            2,
            "neither root nor its owed agent uploads"
        );
        for key in [&root_key, &agent_key] {
            e2_history_assert_prior_tuple(&baseline, &failed.index, key);
        }
        std::fs::write(&trace_path, healthy_trace).unwrap();
        let recovered = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(
            recovered.uploaded,
            BTreeSet::from([root.to_owned(), format!("{root}_agent-{agent}")])
        );
        for key in [&root_key, &agent_key] {
            assert_eq!(
                recovered.index.files[key].effective_upload_body_witness_revision,
                3
            );
        }
        assert!(recovered
            .scan
            .snapshots
            .iter()
            .all(|item| item.telemetry_owned_complete == Some(true)));
    });
}

#[test]
fn e2_repaired_between_attachment_and_strict_read_stays_owed_until_next_page() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-history-repair-during-read");
    let baseline = fixture.baseline();
    let root = HISTORY_SESSIONS[0];
    for (number, session) in HISTORY_SESSIONS.iter().enumerate() {
        e2_history_reported(&fixture, session, number);
    }
    let api_path = e2_history_sidecar(&fixture.support, root, false);
    let healthy = std::fs::read(&api_path).unwrap();
    std::fs::write(&api_path, "{bad\n").unwrap();
    with_e2_history(&fixture, || {
        let held = fixture.cycle_with_scan("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE, |scan| {
            assert!(!scan.snapshots.is_empty());
            let path = api_path.clone();
            E2_AFTER_API_ATTACH.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    // Repair only after the canonical initial decode has
                    // actually reached attachment, before strict validation.
                    std::fs::write(path, healthy).unwrap();
                }));
            });
        });
        assert_eq!(held.uploaded.len(), 2);
        assert!(!held.uploaded.contains(root));
        e2_history_assert_prior_tuple(
            &baseline,
            &held.index,
            &HistoryFixture::key(&baseline, root),
        );
        let recovered = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(recovered.uploaded, BTreeSet::from([root.to_owned()]));
        let body = recovered
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == root)
            .unwrap();
        assert_eq!(
            body.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0001")
        );
        assert_eq!(body.telemetry_owned_complete, Some(true));
    });
}

#[test]
fn e2_side_call_census_deadline_holds_root_history_then_counts_side_call_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-history-side-call-deadline");
    let baseline = fixture.baseline();
    let root = HISTORY_SESSIONS[0];
    let held_key = HistoryFixture::key(&baseline, root);
    for (number, session) in HISTORY_SESSIONS.iter().enumerate().skip(1) {
        e2_history_reported(&fixture, session, number);
    }
    // The root's own request plus one side call no transcript holds.
    let rows = [
        e2_history_api(root, "req_0_1", 0),
        e2_history_api(root, "side", 1),
    ];
    let api = e2_history_sidecar(&fixture.support, root, false);
    let trace = e2_history_sidecar(&fixture.support, root, true);
    for path in [&api, &trace] {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    }
    std::fs::write(
        &api,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    std::fs::write(
        &trace,
        serde_json::to_string(&e2_history_trace(root, "req_0_1", "")).unwrap() + "\n",
    )
    .unwrap();
    with_e2_history(&fixture, || {
        // Only the side-call walk: these history files are all pre-birth on
        // Linux (statx birth), so the copy-decision walk would hold them all.
        let failed =
            crate::snapshots::claude_request_census::with_side_call_walk_deadline_for_test(|| {
                fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE)
            });
        assert_eq!(failed.uploaded.len(), 2, "healthy siblings settle");
        assert!(
            !failed.uploaded.contains(root),
            "a side-call census deadline holds the family, never counts or drops it"
        );
        e2_history_assert_prior_tuple(&baseline, &failed.index, &held_key);
        let recovered = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(recovered.uploaded, BTreeSet::from([root.to_owned()]));
        let body = recovered
            .scan
            .snapshots
            .iter()
            .find(|item| item.source_session_id == root)
            .unwrap();
        assert_eq!(
            body.request_count, 2,
            "the side call counts once, on the root"
        );
        assert_eq!(
            body.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0002")
        );
        assert_eq!(
            recovered.index.files[&held_key].effective_upload_body_witness_revision,
            3
        );
        let again = fixture.cycle("2026-08-02T11:00:00Z", E2_HISTORY_UPGRADE);
        assert!(again.uploaded.is_empty(), "settles exactly once");
    });
}

#[test]
fn e2_production_contract_and_revision_share_one_paced_reread_behind_closed_fence() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::claude_request_identity::{with_cycle_contract_for_test, E2_GROUPING};
    let fixture = HistoryFixture::new("e2-contract-one-paced-pass");
    fixture.install_list(&[HISTORY_SESSIONS[0]]);
    fixture.cycle(
        "2026-08-02T08:00:00Z",
        HistoryCycle {
            request_identity: true,
            ..HISTORY_REVISION_2
        },
    );
    let mut saved: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.index_path).unwrap()).unwrap();
    saved["claude_duplicate_request_witness_overflowed"] = serde_json::json!(true);
    saved["claude_duplicate_fence_next_full_rearm_unix_seconds"] = serde_json::json!(1785711600u64);
    std::fs::write(&fixture.index_path, serde_json::to_vec(&saved).unwrap()).unwrap();
    with_e2_history(&fixture, || {
        fixture.install_list(&[HISTORY_SESSIONS[0]]);
        with_cycle_contract_for_test(E2_GROUPING, || {
            crate::snapshots::with_body_witness_adoption_page_budget(1, || {
                let mut sent = BTreeMap::<String, usize>::new();
                let mut reads = 0;
                let cycle = HistoryCycle {
                    request_identity: true,
                    ..E2_HISTORY_UPGRADE
                };
                for hour in 9..15 {
                    let page = fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), cycle);
                    assert!(page.scan.scanned_file_count <= 1, "one paced file per page");
                    reads += page.scan.scanned_file_count;
                    assert!(
                        !page.uploaded.contains(HISTORY_SESSIONS[0]),
                        "listed history never emits"
                    );
                    for session in &page.uploaded {
                        *sent.entry(session.clone()).or_default() += 1;
                    }
                    if hour == 14 {
                        assert_eq!(
                            page.index.claude_request_identity_contract_for_test(),
                            (Some(E2_GROUPING), false),
                            "latch clears"
                        );
                        assert_eq!(page.scan.scanned_file_count, 0, "no second rearm");
                    }
                }
                assert_eq!(reads, 2, "each unlisted file read once");
                assert_eq!(
                    sent,
                    BTreeMap::from([
                        (HISTORY_SESSIONS[1].to_string(), 1),
                        (HISTORY_SESSIONS[2].to_string(), 1)
                    ])
                );
            });
        })
    });
}

#[test]
fn e2_unlisting_replays_the_legacy_money_mark_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::claude_money_birth_store::location_key;
    use crate::snapshots::claude_request_money::e2::money_mark;
    let fixture = HistoryFixture::new("e2-unlist-money-mark");
    fixture.baseline();
    with_e2_history(&fixture, || {
        fixture.cycle("2026-08-02T08:30:00Z", E2_HISTORY_UPGRADE);
        fixture.install_list(&[HISTORY_SESSIONS[0]]);
        let listed = fixture.cycle("2026-08-02T09:00:00Z", E2_HISTORY_UPGRADE);
        let key = HistoryFixture::key(&listed.index, HISTORY_SESSIONS[0]);
        assert_ne!(
            listed
                .index
                .claude_money_birth_store
                .money_marks(location_key(&key))
                & money_mark::LEGACY,
            0
        );
        fixture.install_list(&[]);
        let unlisted = fixture.cycle("2026-08-02T10:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(unlisted.scan.scanned_file_count, 1);
        assert_eq!(
            unlisted.uploaded_literal,
            BTreeSet::from([HISTORY_SESSIONS[0].to_string()])
        );
        assert_eq!(
            unlisted
                .index
                .claude_money_birth_store
                .money_marks(location_key(&key))
                & money_mark::LEGACY,
            0
        );
        let quiet = fixture.cycle("2026-08-02T11:00:00Z", E2_HISTORY_UPGRADE);
        assert_eq!(quiet.scan.scanned_file_count, 0);
        assert!(quiet.uploaded.is_empty());
    });
}

#[test]
fn e2_stem_listed_before_root_indexing_counts_each_session_request_once() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let fixture = HistoryFixture::new("e2-stem-first-cycle");
    let root = HISTORY_SESSIONS[0];
    let agent = "a4d1585d310070d0f";
    let member = fixture
        .root
        .join(root)
        .join("subagents")
        .join(format!("agent-{agent}.jsonl"));
    std::fs::create_dir_all(member.parent().unwrap()).unwrap();
    std::fs::write(&member, history_line(root, "req_child", 1)).unwrap();
    fixture.install_list(&[&format!("{root}_agent-{agent}")]);
    with_e2_history(&fixture, || {
        fixture.install_list(&[&format!("{root}_agent-{agent}")]);
        // No root or member has been indexed when the list is first loaded.
        let first = fixture.cycle(
            "2026-08-02T08:00:00Z",
            HistoryCycle {
                revision: 3,
                ..HISTORY_BASELINE
            },
        );
        for session in [root.to_string(), format!("{root}_agent-{agent}")] {
            let bodies = first
                .scan
                .snapshots
                .iter()
                .filter(|item| item.source_session_id == session)
                .collect::<Vec<_>>();
            assert_eq!(bodies.len(), 1, "one body for {session}");
            assert_eq!(bodies.iter().map(|item| item.request_count).sum::<u64>(), 1);
            assert!(!first.uploaded_literal.contains(&session));
            assert!(first.uploaded.contains(&session));
        }
        let next = fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                revision: 3,
                ..HISTORY_BASELINE
            },
        );
        assert!(
            next.uploaded.is_empty(),
            "next list closure adds no requests"
        );
        assert_eq!(next.scan.scanned_file_count, 0);
        // A genuine change after the next list load still uses ordinary money.
        fixture.append(root, "req_root_new");
        let changed = fixture.cycle(
            "2026-08-02T10:00:00Z",
            HistoryCycle {
                revision: 3,
                ..HISTORY_BASELINE
            },
        );
        let bodies = changed
            .scan
            .snapshots
            .iter()
            .filter(|item| item.source_session_id == root)
            .collect::<Vec<_>>();
        assert_eq!(bodies.len(), 1);
        assert_eq!(bodies[0].request_count, 2);
        assert!(!changed.uploaded_literal.contains(root));
    });
}

/// Contract-5 cutover, first run after upgrade (SOURCE §B; card G (b)):
/// revision-3 history stamped by a permit-era build without the permit
/// (recorded contract `""`, no capture), some carrying #825's retired
/// `STAMPED_WITHOUT_PERMIT` bit (64), meets the always-on contract. Nothing
/// is re-read or re-owed: a record that never captured is not "no marker
/// existed", and waits for real content change. The bit is decoded and kept
/// as stored, never cleared or replayed. Was
/// `e2_late_identity_permit_reowes_nothing_and_discloses_unpermitted_stamps`.
#[test]
fn e2_always_on_contract_reowes_no_uncaptured_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::claude_money_birth_store::location_key;
    use crate::snapshots::claude_request_identity::{with_cycle_contract_for_test, E2_GROUPING};
    use crate::snapshots::{history_local_count, HistoryLocalCount};
    const RETIRED_PERMIT_MARK: u8 = 64;
    let fixture = HistoryFixture::new("e2-always-on-contract");
    fixture.baseline();
    fixture.install_list(&[]);
    with_e2_history(&fixture, || {
        let before = fixture.cycle("2026-08-02T08:30:00Z", E2_HISTORY_UPGRADE);
        assert!(before
            .index
            .files
            .values()
            .all(|entry| entry.effective_upload_body_witness_revision == 3));
        // The permit-era record: contract `""`, and #825's bit on one file.
        let mut old = ScanIndex::load(&fixture.index_path).unwrap();
        let marked = HistoryFixture::key(&old, HISTORY_SESSIONS[0]);
        let kept = old
            .claude_money_birth_store
            .money_marks(location_key(&marked));
        old.claude_money_birth_store
            .set_money_marks(&marked, kept | RETIRED_PERMIT_MARK);
        old.save(&fixture.index_path).unwrap();
        let mut saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&fixture.index_path).unwrap()).unwrap();
        saved["claude_request_identity_contract"] = serde_json::json!("");
        saved["claude_duplicate_request_witness_overflowed"] = serde_json::json!(true);
        saved["claude_duplicate_fence_next_full_rearm_unix_seconds"] =
            serde_json::json!(1785711600u64);
        std::fs::write(&fixture.index_path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let witnesses = |index: &ScanIndex| {
            index
                .files
                .iter()
                .map(|(key, entry)| {
                    (
                        key.clone(),
                        (
                            entry.effective_upload_body_witness_revision,
                            entry.last_upload_body_witness.clone(),
                            index
                                .claude_money_birth_store
                                .money_marks(location_key(key)),
                        ),
                    )
                })
                .collect::<BTreeMap<_, _>>()
        };
        let stamped = witnesses(&ScanIndex::load(&fixture.index_path).unwrap());
        assert_eq!(
            stamped[&marked].2 & RETIRED_PERMIT_MARK,
            RETIRED_PERMIT_MARK,
            "the old bit decodes"
        );
        let reowed = history_local_count(HistoryLocalCount::Reowed);
        with_cycle_contract_for_test(E2_GROUPING, || {
            crate::snapshots::with_body_witness_adoption_page_budget(1, || {
                let cycle = HistoryCycle {
                    request_identity: true,
                    ..E2_HISTORY_UPGRADE
                };
                for hour in 9..15 {
                    let page = fixture.cycle(&format!("2026-08-02T{hour:02}:00:00Z"), cycle);
                    assert_eq!(page.scan.scanned_file_count, 0, "hour={hour}: no re-read");
                    assert!(page.uploaded.is_empty(), "hour={hour}: no body change");
                    assert_eq!(witnesses(&page.index), stamped, "hour={hour}");
                    if hour == 14 {
                        assert_eq!(
                            page.index.claude_request_identity_contract_for_test(),
                            (Some(E2_GROUPING), false)
                        );
                    }
                }
            })
        });
        assert_eq!(history_local_count(HistoryLocalCount::Reowed), reowed);
    });
}

/// Contract 5: a real content change restamps a file's money marks from its
/// new body. #825's retired bit is carried as stored through that restamp
/// (durable entry digests bind the raw byte), never cleared or set. The
/// stored byte keeps only the retired bit, so the body's own marks return
/// only if the restamp ran.
#[test]
fn e2_restamp_carries_the_retired_permit_bit() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::claude_money_birth_store::location_key;
    use crate::snapshots::claude_request_identity::{with_cycle_contract_for_test, E2_GROUPING};
    const RETIRED_PERMIT_MARK: u8 = 64;
    let fixture = HistoryFixture::new("e2-restamp-retired-bit");
    fixture.baseline();
    with_e2_history(&fixture, || {
        with_cycle_contract_for_test(E2_GROUPING, || {
            let cycle = HistoryCycle {
                request_identity: true,
                ..E2_HISTORY_UPGRADE
            };
            for at in ["08:30", "08:40", "08:50"] {
                fixture.cycle(&format!("2026-08-02T{at}:00Z"), cycle);
            }
            let mut old = ScanIndex::load(&fixture.index_path).unwrap();
            let marked = HistoryFixture::key(&old, HISTORY_SESSIONS[0]);
            assert_eq!(old.files[&marked].effective_upload_body_witness_revision, 3);
            let body_marks = old
                .claude_money_birth_store
                .money_marks(location_key(&marked));
            assert_ne!(body_marks, 0, "the body carries money marks");
            assert_eq!(
                body_marks & RETIRED_PERMIT_MARK,
                0,
                "the always-on build never sets it"
            );
            old.claude_money_birth_store
                .set_money_marks(&marked, RETIRED_PERMIT_MARK);
            old.save(&fixture.index_path).unwrap();
            let before = old.files[&marked].source_file_fingerprint.clone();
            fixture.append(HISTORY_SESSIONS[0], "req_0_2");
            let page = fixture.cycle("2026-08-02T09:00:00Z", cycle);
            let after = &page.index.files[&marked];
            let marks = page
                .index
                .claude_money_birth_store
                .money_marks(location_key(&marked));
            let state = format!(
                "uploaded={:?} read={} source {before}->{} rev {} marks {body_marks}->{marks}",
                page.uploaded,
                page.scan.scanned_file_count,
                after.source_file_fingerprint,
                after.effective_upload_body_witness_revision,
            );
            assert!(page.uploaded.contains(HISTORY_SESSIONS[0]), "{state}");
            assert_ne!(after.source_file_fingerprint, before, "re-read: {state}");
            assert_eq!(after.effective_upload_body_witness_revision, 3, "{state}");
            assert_ne!(
                marks & !RETIRED_PERMIT_MARK,
                0,
                "the restamp recomputes the body's marks: {state}"
            );
            assert_eq!(
                marks & RETIRED_PERMIT_MARK,
                RETIRED_PERMIT_MARK,
                "and keeps the retired bit: {state}"
            );
        })
    });
}
