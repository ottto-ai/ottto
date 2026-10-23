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
}

const HISTORY_BASELINE: HistoryCycle<'static> = HistoryCycle {
    revision: 1,
    upload_context: "history-context-1",
    replay_generation: None,
    bootstrapped: false,
    upload: PipelineUpload::Accept,
    destination: None,
};

struct HistoryOutcome {
    scan: crate::snapshots::SourceScanResult,
    index: ScanIndex,
    /// Sessions whose bodies reached the in-process upload.
    uploaded: BTreeSet<String>,
    /// Captured cutoff and proof corrections; no gated body may feed one.
    corrections: usize,
}

struct HistoryFixture {
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
        index.activate_upload_context(cycle.upload_context.to_string());
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
        // Production arms no bootstrap replay from an unreadable state.
        let replay_pending =
            cycle.replay_generation.is_some() && !backfill.prior_history_unverified;
        let replay_dropped = replay_pending
            && cycle
                .replay_generation
                .is_some_and(|generation| index.prepare_historical_replay(generation.to_string()));
        note_claude_history_cutoff_for_cycle(
            &mut index,
            SnapshotSource::ClaudeCode,
            prior_history,
            loaded_fresh || replay_dropped,
        );
        index.activate_effective_upload_body_witness_revision(cycle.revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        index.load_claude_reemission_exclusions(&self.support);
        let committed_index = index.clone();
        let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&self.root),
            &mut index,
            collected_at,
            183,
            100,
            true,
        )
        .expect("scan Claude page");
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
        index.retain_claude_history_emission_permitted(&mut scan.snapshots);
        let mut uploaded = BTreeSet::new();
        let mut accepted = 0;
        let result = upload_resumable_batches_with_body_witness(
            &scan.snapshots,
            &unique_poison_scope(),
            &mut progress,
            &mut accepted,
            |snapshot| snapshot.snapshot_fingerprint.as_str(),
            snapshot_upload_body_witness,
            |items| {
                uploaded.extend(items.iter().map(|item| item.source_session_id.clone()));
                Ok(accepted_batch(items.len()))
            },
            |_| Ok(()),
        )
        .expect("in-process upload");
        assert_eq!(result, ResumableUploadResult::Completed);
        let settlement = match cycle.upload {
            PipelineUpload::ServerDeferred => {
                settle_checkpointed_upload(index, &committed_index, &progress, &holds, false)
            }
            _ => settle_completed_upload(index, &committed_index, &progress, &holds),
        };
        let mut index = settlement.index;
        settle_index_after_upload(&mut index, &committed_index, &progress);
        index.save(&index_path).expect("save scan index");
        HistoryOutcome {
            scan,
            index: ScanIndex::load(&index_path).expect("reload scan index"),
            uploaded,
            corrections,
        }
    }

    /// Every file sent and stamped at revision 1 under a fresh install.
    fn baseline(&self) -> ScanIndex {
        let outcome = self.cycle("2026-08-02T08:00:00Z", HISTORY_BASELINE);
        assert_eq!(outcome.uploaded.len(), HISTORY_SESSIONS.len());
        assert!(outcome.scan.census_complete);
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
};

/// Primary incident shape (addendum 2): a bootstrapped destination's index is
/// quarantined, no list and no seen-marker, the active revision is bumped.
/// Every file comes back as a new file. On dba838f0 every body is re-sent
/// (`uploaded` holds all three sessions); here none is, every file is
/// recorded locally with its census record, and the next two cycles do not
/// re-read anything.
#[test]
fn quarantined_index_after_bootstrap_holds_all_history_without_a_list() {
    let fixture = HistoryFixture::new("history-upgrade-quarantine");
    fixture.baseline();
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
        assert!(rebuilt.scan.census_complete);
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
/// the generation, so every file is new again.
#[test]
fn historical_replay_after_bootstrap_holds_all_history_without_a_list() {
    let fixture = HistoryFixture::new("history-upgrade-replay");
    let baseline = fixture.baseline();
    assert!(baseline.generation > 0);
    crate::snapshots::with_no_list_cutoff(u64::MAX, || {
        let replayed = fixture.cycle(
            "2026-08-02T09:00:00Z",
            HistoryCycle {
                replay_generation: Some("history-replay-2"),
                ..HISTORY_REVISION_2
            },
        );
        assert_eq!(replayed.scan.scanned_file_count, HISTORY_SESSIONS.len());
        assert!(replayed.uploaded.is_empty(), "{:?}", replayed.uploaded);
        assert_eq!(replayed.corrections, 0);
        assert!(replayed.index.generation > baseline.generation, "no reset");
        assert_eq!(replayed.index.files.len(), HISTORY_SESSIONS.len());
        assert_eq!(HistoryFixture::census_keys(&replayed.index), 3);
        let again = fixture.cycle(
            "2026-08-02T10:00:00Z",
            HistoryCycle {
                replay_generation: Some("history-replay-2"),
                ..HISTORY_REVISION_2
            },
        );
        assert_eq!(again.scan.scanned_file_count, 0, "no re-read storm");
        assert!(again.uploaded.is_empty());
    });
}

/// Addendum 1 item 1 (secondary): existing revision-1 entries, an
/// independent second reason on every file (a changed upload context), no
/// list. Nothing is emitted, the old upload tuple stays, and the reason
/// settles: the next cycle reads nothing.
#[test]
fn upload_context_change_does_not_carry_history_past_the_gate() {
    let fixture = HistoryFixture::new("history-upgrade-upload-context");
    let baseline = fixture.baseline();
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
    let fixture = HistoryFixture::new("history-upgrade-rearmed");
    let mut baseline = fixture.baseline();
    for entry in baseline.files.values_mut() {
        entry.source_file_fingerprint.clear();
    }
    baseline
        .save(&fixture.index_path)
        .expect("save re-armed index");
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
    let fixture = HistoryFixture::new("history-upgrade-growth");
    fixture.baseline();
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

/// Addendum 1 items 2 and 5 (P2), SOURCE F2: revision 3 is above
/// `MAX_GATED_CLAUDE_REVISION`, so the gate holds every upgrade
/// (`ungated_revision`) and a listed family's genuine change is denied; no
/// file is stamped 3. A listed family's genuine change emits under revision
/// 2, and a stored 3 is never downgraded by revision 2.
#[test]
fn revision_three_policy_denies_listed_changes_and_never_downgrades() {
    let fixture = HistoryFixture::new("history-upgrade-revision-three");
    fixture.baseline();
    fixture.install_list(&[HISTORY_SESSIONS[0]]);
    fixture.append(HISTORY_SESSIONS[0], "req_0_2");
    let revision_3 = HistoryCycle {
        revision: 3,
        upload_context: "history-context-2",
        ..HISTORY_REVISION_2
    };
    let denied = fixture.cycle("2026-08-02T09:00:00Z", revision_3);
    assert!(
        denied.uploaded.is_empty(),
        "an ungated revision emits nothing: {:?}",
        denied.uploaded
    );
    assert!(denied
        .index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision <= 2));

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

/// Addendum 2 item 14 (#700): with the seen-marker present, an empty load
/// latches; held history stays held even with an installed list, while a
/// file born after the cutoff still ingests.
#[test]
fn seen_marker_rebuild_latch_and_cutoff_feed_one_decision() {
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
    let fixture = HistoryFixture::new("history-upgrade-deferred");
    fixture.baseline();
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

/// SOURCE F4a: the incident shape with no override of the no-list cutoff.
/// The fixture's history is born after 2026-10-21, but before the history
/// cutoff this load records, so it is still held: the hold reaches the later
/// of the two.
#[test]
fn quarantined_index_holds_history_born_after_the_no_list_cutoff() {
    let fixture = HistoryFixture::new("history-upgrade-quarantine-real-cutoff");
    fixture.baseline();
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
/// itself, with no backfill state at all.
#[test]
fn quarantined_index_sibling_alone_is_prior_history() {
    let fixture = HistoryFixture::new("history-upgrade-sibling");
    fixture.baseline();
    fixture.corrupt_index();
    let rebuilt = fixture.cycle(
        "2026-08-02T09:00:00Z",
        HistoryCycle {
            bootstrapped: false,
            ..HISTORY_REVISION_2
        },
    );
    assert!(rebuilt.uploaded.is_empty(), "{:?}", rebuilt.uploaded);
}

/// SOURCE F1a, StateMissing H1: an unreadable backfill state is prior
/// history, not a fresh install. With a quarantined index, or with the index
/// gone and no other evidence, no history is emitted; the state keeps its
/// marker and arms no bootstrap.
#[test]
fn unreadable_backfill_state_emits_no_history_from_a_rebuilt_index() {
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
        assert!(crate::backfill::pending_backfill_sources_for_destination(
            &state,
            HISTORY_DESTINATION
        )
        .is_empty());
    }
}

/// StateMissing H1: an unreadable backfill state over a populated index arms
/// no replay (the entries stay, nothing is re-read) and uploads no old
/// history. The entries' births are old (the no-list cutoff seam).
#[test]
fn unreadable_backfill_state_arms_no_replay_over_a_populated_index() {
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

/// SOURCE F1b: a re-pair to a new destination finds history born before the
/// claim owed and gated, never re-sent ungated: the other destination's
/// completed bootstrap is prior history.
#[test]
fn new_destination_holds_history_born_before_the_claim() {
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

/// SOURCE F1b: a claim that recorded a different-user cutoff keeps that
/// history excluded by the cutoff, as before, not by the history gate: a
/// session with activity after the cutoff is still sent whole.
#[test]
fn different_user_cutoff_excludes_history_without_the_gate() {
    let fixture = HistoryFixture::new("history-upgrade-different-user");
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
    crate::backfill::save_backfill_state(&fixture.support, &state).expect("save claim state");
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

/// SOURCE F1a (AutoReview): any record of an earlier upload in this
/// destination's ledger is prior history, not only a replay generation or a
/// refusal.
#[test]
fn any_upload_ledger_record_is_prior_history() {
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
    assert!(!prior(&progress), "a positively empty support state");
    progress.accepted_fingerprints.insert("f".repeat(64));
    assert!(prior(&progress));
}

/// SOURCE F1b, StateMissing M3 (AutoReview): a re-pair resuming a partial
/// index that a pre-gate daemon saved for the new destination loads as
/// `Loaded`, drops no entries and has no cutoff. Another destination's
/// completed bootstrap still records the cutoff on this first gated load, so
/// history not yet indexed is held, not sent as fresh.
#[test]
fn resumed_pre_gate_index_on_a_new_destination_records_the_cutoff() {
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
    let resumed = fixture.cycle(
        "2026-08-02T09:00:00Z",
        HistoryCycle {
            destination: destination_b,
            ..HISTORY_REVISION_2
        },
    );
    assert!(resumed.uploaded.is_empty(), "{:?}", resumed.uploaded);
    assert!(
        !std::fs::read_dir(&fixture.base)
            .expect("list fixture")
            .flatten()
            .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
        "the index loaded; nothing was quarantined"
    );
}
