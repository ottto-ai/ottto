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
use sha2::Digest as _;
use std::io::Write as _;

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
    /// This destination already completed its Claude history bootstrap.
    bootstrapped: bool,
    upload: PipelineUpload,
}

const HISTORY_BASELINE: HistoryCycle<'static> = HistoryCycle {
    revision: 1,
    upload_context: "history-context-1",
    replay_generation: None,
    bootstrapped: false,
    upload: PipelineUpload::Accept,
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

    fn cycle(&self, collected_at: &str, cycle: HistoryCycle<'_>) -> HistoryOutcome {
        let mut index = ScanIndex::load_for_snapshot_source(
            &self.index_path,
            SnapshotSource::ClaudeCode,
            &self.support,
        )
        .expect("load scan index");
        let loaded_fresh = index.generation == 0 && index.files.is_empty();
        index.activate_upload_context(cycle.upload_context.to_string());
        let replay_dropped = cycle
            .replay_generation
            .is_some_and(|generation| index.prepare_historical_replay(generation.to_string()));
        let mut backfill = crate::backfill::BackfillState::default();
        if cycle.bootstrapped {
            crate::backfill::mark_backfill_complete_for_destination(
                &mut backfill,
                SnapshotSource::ClaudeCode,
                HISTORY_DESTINATION,
            );
        }
        note_claude_history_cutoff_for_cycle(
            &mut index,
            SnapshotSource::ClaudeCode,
            &backfill,
            HISTORY_DESTINATION,
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
        let mut progress = test_upload_progress();
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
        index.save(&self.index_path).expect("save scan index");
        HistoryOutcome {
            scan,
            index: ScanIndex::load(&self.index_path).expect("reload scan index"),
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

/// Addendum 2 item 13 and addendum 3 item 19: a genuinely fresh install (no
/// bootstrap recorded for this destination) ingests new files normally, even
/// after a quarantine and with old births.
#[test]
fn fresh_install_without_a_prior_bootstrap_ingests_new_files() {
    let fixture = HistoryFixture::new("history-upgrade-fresh");
    fixture.corrupt_index();
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

/// Addendum 1 items 2 and 5 (P2): under revision 3 the gate holds history the
/// same way, a listed family's genuine change is denied (it emits under
/// revision 2), and a stored 3 is never downgraded by revision 2.
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
        !denied.uploaded.contains(HISTORY_SESSIONS[0]),
        "revision 3 never emits a listed root, even changed"
    );
    assert_eq!(
        denied.uploaded.len(),
        HISTORY_SESSIONS.len() - 1,
        "unlisted history upgrades within budget"
    );

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
