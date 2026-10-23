//! Fold-level regressions for the Claude history-upgrade gate: every file is
//! selected for a reason other than the revision (a changed upload context),
//! so only the reason-independent gate can hold it. Fixtures are synthetic.

use super::claude_history_upgrade::revision_policy;
use super::claude_reemission_exclusions::{with_no_list_cutoff, ListState, ReemissionExclusions};
use super::*;

const COLLECTED_AT: &str = "2026-08-23T18:40:00Z";

fn session(slot: usize) -> String {
    format!("bbbbbbbb-cccc-4ddd-8eee-{slot:012x}")
}

/// `roots` families of a root and one subagent, all sent and stamped at
/// revision 1 under upload context `ctx-1`.
fn families(name: &str, roots: usize) -> (PathBuf, PathBuf, ScanIndex) {
    let home = crate::test_scratch::unique_path(&format!("ottto-{name}"));
    let root = home.join("project");
    for slot in 0..roots {
        let session = session(slot);
        for agent in [None, Some(format!("{slot:016x}"))] {
            let path = match &agent {
                Some(agent) => root
                    .join(&session)
                    .join("subagents")
                    .join(format!("agent-{agent}.jsonl")),
                None => root.join(format!("{session}.jsonl")),
            };
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let request = agent.as_deref().unwrap_or("root");
            fs::write(
                &path,
                format!(
                    "{}\n",
                    json!({
                        "timestamp": "2026-08-23T18:20:00Z",
                        "type": "assistant",
                        "sessionId": session,
                        "agentId": agent,
                        "isSidechain": agent.is_some(),
                        "requestId": format!("request-{slot}-{request}"),
                        "message": {
                            "id": format!("message-{slot}-{request}"),
                            "model": "claude-haiku-4-5",
                            "usage": {"input_tokens": 10, "output_tokens": 1}
                        }
                    })
                ),
            )
            .unwrap();
        }
    }
    let mut index = ScanIndex::default();
    let mut first = scan(&root, &mut index, "ctx-1", 1);
    assert_eq!(first.snapshots.len(), roots * 2);
    let index = settle(&home, &ScanIndex::default(), &mut first, &mut index);
    assert!(index
        .files
        .values()
        .all(|entry| entry.effective_upload_body_witness_revision == 1));
    (home, root, index)
}

fn scan(root: &Path, index: &mut ScanIndex, context: &str, revision: u64) -> SourceScanResult {
    index.activate_upload_context(context.into());
    index.activate_effective_upload_body_witness_revision(revision);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    scan_source_roots_with_limit(
        SnapshotSource::ClaudeCode,
        &[root.to_path_buf()],
        index,
        COLLECTED_AT,
        BACKFILL_WINDOW_DAYS,
        MAX_BACKFILL_FILES_PER_SOURCE,
        true,
    )
    .unwrap()
}

/// Finalize (the emission backstop runs first), keep what the server
/// accepted, save and reload.
fn settle(
    home: &Path,
    previous: &ScanIndex,
    scan: &mut SourceScanResult,
    index: &mut ScanIndex,
) -> ScanIndex {
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, scan, index);
    let accepted = scan
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let mut settled = index.committable_subset(previous, &accepted, &BTreeMap::new());
    let path = home.join("scan-index.json");
    settled.save(&path).unwrap();
    ScanIndex::load(&path).unwrap()
}

fn support(name: &str) -> crate::test_scratch::ScratchDir {
    let support = crate::test_scratch::ScratchDir::new(name);
    fs::create_dir_all(ReemissionExclusions::path(&support).parent().unwrap()).unwrap();
    support
}

fn digest(id: &str) -> String {
    format!("{:x}", Sha256::digest(id.as_bytes()))
}

fn revisions(index: &ScanIndex) -> Vec<u64> {
    index
        .files
        .values()
        .map(|entry| entry.effective_upload_body_witness_revision)
        .collect()
}

/// Group 2: a member-only line closes over its root; the listed family's
/// root and sibling are selected by the changed upload context, still parse
/// (their census records refresh), emit nothing, keep revision 1 and spend
/// no budget, while the unlisted family upgrades.
#[test]
fn listed_family_selected_for_another_reason_emits_nothing() {
    let (home, root, mut index) = families("history-gate-listed", 2);
    let support = support("history-gate-listed-support");
    let listed_member = index
        .files
        .keys()
        .filter_map(|key| claude_index_path_family_member(Path::new(key)))
        .find(|(family, member)| *family == session(1) && *member != session(1))
        .map(|(_, member)| member)
        .unwrap();
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&listed_member)),
    )
    .unwrap();
    index.load_claude_reemission_exclusions(&support);
    let previous = index.clone();
    let mut result =
        with_body_witness_adoption_page_budget(2, || scan(&root, &mut index, "ctx-2", 2));
    assert_eq!(result.scanned_file_count, 4, "every file parses locally");
    assert_eq!(result.snapshots.len(), 4, "parsed, not yet vetoed");
    let mut resend = result.snapshots.clone();
    index.retain_claude_history_emission_permitted(&mut resend);
    assert_eq!(resend.len(), 2, "the resend hook drops the listed family");
    let settled = settle(&home, &previous, &mut result, &mut index);
    assert_eq!(result.snapshots.len(), 2, "only the unlisted family emits");
    for (key, entry) in &settled.files {
        let listed = claude_index_path_family_member(Path::new(key))
            .is_some_and(|(family, _)| family == session(1));
        assert_eq!(
            entry.effective_upload_body_witness_revision,
            if listed { 1 } else { 2 }
        );
        assert!(settled.claude_request_census_for_test().get(key).is_some());
        if listed {
            assert_eq!(
                entry.last_snapshot_fingerprint,
                previous.files[key].last_snapshot_fingerprint
            );
        }
    }
    let _ = fs::remove_dir_all(home);
}

/// Group 3: no list. Old or unknown births are held whatever the reason;
/// newer births pass. A malformed list, a list missing after install and an
/// unrecordable install hold everything even with budget available.
#[test]
fn no_list_and_paused_list_states_hold_history_selected_for_another_reason() {
    let (home, root, index) = families("history-gate-no-list", 2);
    let held = |support: &Path, cutoff: u64| {
        let mut index = index.clone();
        index.load_claude_reemission_exclusions(support);
        let state = index.claude_reemission_exclusions.state();
        let mut result = with_no_list_cutoff(cutoff, || scan(&root, &mut index, "ctx-2", 2));
        assert_eq!(result.scanned_file_count, 4);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut index);
        (state, result.snapshots.len(), revisions(&index))
    };
    let never = support("history-gate-never");
    assert_eq!(
        held(&never, u64::MAX),
        (ListState::NotInstalled, 0, vec![1; 4])
    );
    assert_eq!(
        held(&never, 0),
        (ListState::NotInstalled, 4, vec![2; 4]),
        "newer births are not held without a list"
    );

    let malformed = support("history-gate-malformed");
    fs::write(ReemissionExclusions::path(&malformed), "not-a-digest\n").unwrap();
    assert_eq!(held(&malformed, 0), (ListState::Unreadable, 0, vec![1; 4]));

    let missing = support("history-gate-missing");
    fs::write(ReemissionExclusions::path(&missing), "").unwrap();
    assert_eq!(
        ReemissionExclusions::load(&missing).state(),
        ListState::Installed
    );
    fs::remove_file(ReemissionExclusions::path(&missing)).unwrap();
    let ((state, emitted, stamps), _) =
        crate::local_resource_diagnostics::capture(|| held(&missing, 0));
    assert_eq!(
        (state, emitted, stamps),
        (ListState::MissingAfterInstall, 0, vec![1; 4])
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let unwritable = support("history-gate-unwritable");
        let list = ReemissionExclusions::path(&unwritable);
        fs::write(&list, "").unwrap();
        let snapshots = list.parent().unwrap().to_path_buf();
        fs::set_permissions(&snapshots, fs::Permissions::from_mode(0o500)).unwrap();
        let outcome = held(&unwritable, 0);
        fs::set_permissions(&snapshots, fs::Permissions::from_mode(0o700)).unwrap();
        // A privileged runner can still write the marker; then it installs.
        if outcome.0 == ListState::MarkerUnwritable {
            assert_eq!(outcome, (ListState::MarkerUnwritable, 0, vec![1; 4]));
        }
    }
    let _ = fs::remove_dir_all(home);
}

/// Group 4 (M1): an installed empty list paces history selected for another
/// reason, one file per page under budget 1; the rest keep their tuples and
/// census records. A missing (never installed) list is not the same: old
/// births are held.
#[test]
fn installed_empty_list_paces_history_and_differs_from_a_missing_list() {
    let (home, root, mut index) = families("history-gate-empty-list", 2);
    let empty = support("history-gate-empty");
    fs::write(ReemissionExclusions::path(&empty), "").unwrap();
    let mut per_page = Vec::new();
    with_no_list_cutoff(u64::MAX, || {
        with_body_witness_adoption_page_budget(1, || {
            for _ in 0..6 {
                index.load_claude_reemission_exclusions(&empty);
                assert_eq!(
                    index.claude_reemission_exclusions.state(),
                    ListState::Installed
                );
                let previous = index.clone();
                let mut result = scan(&root, &mut index, "ctx-2", 2);
                index = settle(&home, &previous, &mut result, &mut index);
                assert_eq!(
                    index.files.len(),
                    4,
                    "held files keep their entries and census"
                );
                assert!(index
                    .files
                    .keys()
                    .all(|key| index.claude_request_census_for_test().get(key).is_some()));
                per_page.push(result.snapshots.len());
            }
        });
    });
    assert_eq!(per_page, vec![1, 1, 1, 1, 0, 0]);
    assert_eq!(revisions(&index), vec![2; 4]);

    let (home_missing, root_missing, mut missing_index) = families("history-gate-missing-list", 2);
    let never = support("history-gate-missing-list-support");
    missing_index.load_claude_reemission_exclusions(&never);
    let mut result = with_no_list_cutoff(u64::MAX, || {
        with_body_witness_adoption_page_budget(1, || {
            scan(&root_missing, &mut missing_index, "ctx-2", 2)
        })
    });
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut missing_index);
    assert_eq!(result.snapshots.len(), 0, "absence is not an empty list");
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(home_missing);
}

/// A fold that latches the stop after the candidate loop permitted an
/// upgrade blocks its emission at the seam.
#[test]
fn a_latch_set_after_the_candidate_loop_blocks_permitted_history() {
    let (home, root, mut index) = families("history-gate-late-latch", 1);
    let empty = support("history-gate-late-latch-support");
    fs::write(ReemissionExclusions::path(&empty), "").unwrap();
    index.load_claude_reemission_exclusions(&empty);
    let previous = index.clone();
    let mut result = scan(&root, &mut index, "ctx-2", 2);
    assert_eq!(result.snapshots.len(), 2, "permitted before the fold");
    note_claude_reemission_stop_with_cause_at(
        &ClaudeContextFileBirthCounts::default(),
        &BTreeSet::new(),
        Some(ClaudeReemissionStopCause::EvidenceBound),
        std::time::Instant::now(),
    );
    let settled = settle(&home, &previous, &mut result, &mut index);
    assert!(result.snapshots.is_empty());
    assert_eq!(revisions(&settled), vec![1; 2]);
    restart_claude_reemission_stop_for_test();
    let _ = fs::remove_dir_all(home);
}

/// The shared stamp never downgrades a Claude revision and refuses a file
/// the gate holds; Codex and Pi keep the exact stamp.
#[test]
fn the_shared_stamp_never_downgrades_and_refuses_held_files() {
    let (home, root, mut index) = families("history-gate-stamp", 1);
    let key = index.files.keys().next().unwrap().clone();
    let fingerprint = index.files[&key].source_file_fingerprint.clone();
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = 3;
    index.activate_effective_upload_body_witness_revision(2);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    assert!(index.stamp_effective_upload_body_witness_revision(&key, &fingerprint, 2));
    assert_eq!(index.files[&key].effective_upload_body_witness_revision, 3);
    index.activate_effective_upload_body_witness_revision(2);
    assert!(index.stamp_effective_upload_body_witness_revision(&key, &fingerprint, 2));
    assert_eq!(
        index.files[&key].effective_upload_body_witness_revision, 2,
        "the exact (Codex and Pi) comparison assigns"
    );
    assert!(!index.stamp_effective_upload_body_witness_revision(&key, &fingerprint, 0));

    // A held file never stamps, whatever path settles it.
    let never = support("history-gate-stamp-support");
    index.load_claude_reemission_exclusions(&never);
    index
        .files
        .get_mut(&key)
        .unwrap()
        .effective_upload_body_witness_revision = 1;
    let _held = with_no_list_cutoff(u64::MAX, || scan(&root, &mut index, "ctx-3", 2));
    let held = index
        .files
        .iter()
        .find(|(_, entry)| entry.effective_upload_body_witness_revision == 1)
        .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
        .unwrap();
    assert!(index.claude_history_emission_held(&held.1).is_some());
    assert!(!index.stamp_effective_upload_body_witness_revision(&held.0, &held.1, 2));
    let _ = fs::remove_dir_all(home);
}

/// Release gate: a release that raises the active Claude revision must also
/// give it a row in the history policy table. Without one this fails, and the
/// gate itself holds every upgrade (`ungated_revision`).
#[test]
fn active_claude_revision_has_a_history_policy_row() {
    let active =
        crate::snapshot_sync::effective_upload_body_witness_revision(SnapshotSource::ClaudeCode);
    assert!(active <= MAX_GATED_CLAUDE_REVISION, "active {active}");
    assert!(revision_policy(active).is_some());
}

/// The listed family's subagent member id (`root_stem`).
fn listed_member(index: &ScanIndex, family: &str) -> String {
    index
        .files
        .keys()
        .filter_map(|key| claude_index_path_family_member(Path::new(key)))
        .find(|(root, member)| root == family && member != family)
        .map(|(_, member)| member)
        .unwrap()
}

/// StateMissing M1: on a fresh index a list line naming only a member
/// (`root_stem`) still protects its root, which is decided before the
/// member is indexed: no root body is emitted, and the unlisted family
/// upgrades.
#[test]
fn member_only_line_protects_its_root_on_a_fresh_index() {
    let (home, root, index) = families("history-gate-member-only", 2);
    let support = support("history-gate-member-only-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&listed_member(&index, &session(1)))),
    )
    .unwrap();
    let mut fresh = ScanIndex::default();
    fresh.note_claude_history_cutoff(true, true);
    fresh.load_claude_reemission_exclusions(&support);
    let mut result = scan(&root, &mut fresh, "ctx-1", 2);
    assert_eq!(result.scanned_file_count, 4, "new files parse locally");
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut fresh);
    assert!(
        result
            .snapshots
            .iter()
            .all(|item| !item.source_session_id.starts_with(&session(1))),
        "{:?}",
        result
            .snapshots
            .iter()
            .map(|item| &item.source_session_id)
            .collect::<Vec<_>>()
    );
    assert_eq!(result.snapshots.len(), 2, "the unlisted family upgrades");
    let _ = fs::remove_dir_all(home);
}

/// M1 (AutoReview): a member directory the closure cannot read may hold a
/// listed member, so its root is held, not sent.
#[cfg(unix)]
#[test]
fn unreadable_member_directory_holds_its_root() {
    use std::os::unix::fs::PermissionsExt;
    let (home, root, index) = families("history-gate-member-unreadable", 2);
    let support = support("history-gate-member-unreadable-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&listed_member(&index, &session(1)))),
    )
    .unwrap();
    let subagents = root.join(session(1)).join("subagents");
    fs::set_permissions(&subagents, fs::Permissions::from_mode(0o000)).unwrap();
    let mut fresh = ScanIndex::default();
    fresh.note_claude_history_cutoff(true, true);
    fresh.load_claude_reemission_exclusions(&support);
    let mut result = scan(&root, &mut fresh, "ctx-1", 2);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut fresh);
    fs::set_permissions(&subagents, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result
        .snapshots
        .iter()
        .all(|item| !item.source_session_id.starts_with(&session(1))));
    let _ = fs::remove_dir_all(home);
}

/// StateMissing M2: a listed (held) family member owed only a proof
/// correction is not re-read every traversal: it is skipped like any held
/// adoption, and its correction is deferred to the history gate (disclosed)
/// instead of blocking a fully settled upload.
#[test]
fn held_member_owed_a_proof_correction_is_skipped_and_deferred() {
    let (home, root, mut index) = families("history-gate-correction", 2);
    let support = support("history-gate-correction-support");
    let family = session(1);
    let owed = listed_member(&index, &family);
    let members = index
        .files
        .iter()
        .filter_map(|(key, entry)| {
            claude_index_path_family_member(Path::new(key))
                .filter(|(root, _)| *root == family)
                .map(|(_, member)| (member, entry.source_file_fingerprint.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(members.len(), 2);
    let witness = claude_usage_family_witness_fingerprint(
        index
            .claude_usage_family_witnesses
            .entry(family.clone())
            .or_insert_with(|| ClaudeUsageFamilyWitness {
                evidence_fingerprint: "e".repeat(64),
                member_request_id_fingerprints: BTreeMap::new(),
                member_occurrence_fingerprints: BTreeMap::new(),
                assigned_request_id_fingerprints: BTreeMap::new(),
                legacy_excluded_request_id_hashes: BTreeMap::new(),
                legacy_exclusion_evidence_fingerprint: None,
                legacy_owner_roots: BTreeSet::new(),
            }),
    );
    index.claude_usage_authority_quarantine.insert(
        family.clone(),
        ClaudeUsageAuthorityQuarantineRecord {
            contract: CLAUDE_USAGE_AUTHORITY_CORRECTION_CONTRACT_VERSION.to_string(),
            proven_witness_fingerprint: witness.clone(),
            member_source_file_fingerprints: members,
            failed_reconstruction_count: MAX_CLAUDE_USAGE_AUTHORITY_FAILURES,
            disposition: ClaudeUsageAuthorityQuarantineDisposition::UnprovenTerminal,
            retry_after_unix_seconds: 0,
            proof_correction: Some(ClaudeAuthorityProofCorrection {
                proof_witness_fingerprint: witness,
                owed_member_ids: BTreeSet::from([owed]),
            }),
        },
    );
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&family)),
    )
    .unwrap();
    index.load_claude_reemission_exclusions(&support);
    let mut scanned = Vec::new();
    for _ in 0..2 {
        let mut result = scan(&root, &mut index, "ctx-1", 2);
        scanned.push(result.scanned_file_count);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut index);
        assert!(result
            .snapshots
            .iter()
            .all(|item| !item.source_session_id.starts_with(&family)));
    }
    assert_eq!(
        scanned,
        vec![2, 0],
        "only the unlisted family parses, once; the held member is never re-read"
    );
    assert_eq!(
        index.claude_authority_proof_correction_blocking(),
        (false, 1),
        "the held member's correction is deferred, not blocking"
    );
    // A re-armed member (cleared fingerprint) is still found by identity.
    let member_key = index
        .files
        .keys()
        .find(|key| {
            claude_index_path_family_member(Path::new(key))
                .is_some_and(|(root, member)| root == family && member != family)
        })
        .unwrap()
        .clone();
    index
        .files
        .get_mut(&member_key)
        .unwrap()
        .source_file_fingerprint
        .clear();
    assert_eq!(
        index.claude_authority_proof_correction_blocking(),
        (false, 1)
    );
    let _ = fs::remove_dir_all(home);
}

/// StateMissing L1: a stored cutoff ahead of the clock is pulled back to
/// now, and only prior history records one.
#[test]
fn history_cutoff_is_bounded_by_the_clock() {
    let now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let mut index = ScanIndex::default();
    index.note_claude_history_cutoff(false, true);
    assert_eq!(
        index.claude_history_cutoff_unix_seconds, None,
        "fresh install"
    );
    index.note_claude_history_cutoff(true, false);
    assert_eq!(index.claude_history_cutoff_unix_seconds, None);
    index.claude_history_cutoff_unix_seconds = Some(u64::MAX);
    index.note_claude_history_cutoff(false, false);
    assert!(index.claude_history_cutoff_unix_seconds.unwrap() <= now());
    // StateMissing M3: prior history records a cutoff on the first gated
    // load of an index without one, never on an index a gated daemon already
    // loaded (a fresh install's after its bootstrap).
    let mut pre_gate = ScanIndex::default();
    pre_gate.note_claude_history_cutoff(true, false);
    assert!(pre_gate.claude_history_cutoff_unix_seconds.is_some());
    let mut gated = ScanIndex::default();
    gated.note_claude_history_cutoff(false, false);
    gated.note_claude_history_cutoff(true, false);
    assert_eq!(gated.claude_history_cutoff_unix_seconds, None);
}
