//! Fold-level regressions for the Claude history-upgrade gate: every file is
//! selected for a reason other than the revision (a changed upload context),
//! so only the reason-independent gate can hold it. Fixtures are synthetic.

use super::claude_history_upgrade::{
    local_count, revision_policy, with_max_gated_claude_revision, LocalCount,
    REQUEST_OWNED_USAGE_CONTRACT,
};
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
    if crate::snapshots::ClaudeTerminalOffForTest::active() {
        return terminal_off_on_scan(root, index, context, revision);
    }
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

fn terminal_off_on_scan(
    root: &Path,
    index: &mut ScanIndex,
    context: &str,
    revision: u64,
) -> SourceScanResult {
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, context.into());
    index.activate_effective_upload_body_witness_revision(revision);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    // This fixed-clock classifier driver requests the next bounded history
    // discovery walk; keep its body-byte, privacy and pacing assertions exact.
    expire_terminal_off_discovery_for_test(index);
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
    if crate::snapshots::ClaudeTerminalOffForTest::active() {
        terminal_off_ack_emitted(&mut settled, &scan.snapshots);
    }
    let path = home.join("scan-index.json");
    settled.save(&path).unwrap();
    ScanIndex::load(&path).unwrap()
}

// C6 adapter: production file-context activation and validated uploader ACKs.
fn terminal_off_ack_emitted(index: &mut ScanIndex, items: &[SnapshotItem]) {
    let candidates = index.file_upload_context_ack_candidates(items);
    let acks = crate::snapshot_sync::upload_context_receipt_tests::exact_acks(
        SnapshotSource::ClaudeCode,
        items,
    );
    index
        .accepted_snapshot_fingerprints
        .extend(acks.keys().cloned());
    index.accept_file_upload_context_acks(&candidates, &acks);
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

/// Group 2: a member-only line closes over its root; the listed family's
/// root and sibling are selected by the changed upload context, still parse
/// (their census records refresh), emit nothing, keep revision 1 and spend
/// no budget, while the unlisted family upgrades.
#[test]
fn terminal_off_on_listed_family_selected_for_another_reason_emits_nothing() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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

/// Group 3: no list on an unverified Mac (SOURCE F4a as narrowed by
/// Amendment 16). Old or unknown births are held whatever the reason; newer
/// births pass. A malformed list, a list missing after install and an
/// unrecordable install hold everything even with budget available. On a
/// verified Mac without a list, old history is paced instead (N1).
#[test]
fn no_list_and_paused_list_states_hold_history_selected_for_another_reason() {
    let (home, root, index) = families("history-gate-no-list", 2);
    let held_under = |policy: NoListPolicy, support: &Path, cutoff: u64| {
        let mut index = index.clone();
        index.claude_no_list_policy = policy;
        index.load_claude_reemission_exclusions(support);
        let state = index.claude_reemission_exclusions.state();
        let mut result = with_no_list_cutoff(cutoff, || scan(&root, &mut index, "ctx-2", 2));
        assert_eq!(result.scanned_file_count, 4);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut index);
        (state, result.snapshots.len(), revisions(&index))
    };
    let held =
        |support: &Path, cutoff: u64| held_under(NoListPolicy::HoldUnverified, support, cutoff);
    let never = support("history-gate-never");
    assert_eq!(
        held(&never, u64::MAX),
        (ListState::NotInstalled, 0, vec![1; 4])
    );
    assert_eq!(
        held_under(NoListPolicy::HoldMoveNotFull, &never, u64::MAX),
        (ListState::NotInstalled, 0, vec![1; 4])
    );
    assert_eq!(
        held_under(NoListPolicy::Pace, &never, u64::MAX),
        (ListState::NotInstalled, 4, vec![2; 4]),
        "a verified Mac without a list paces old history"
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

/// Group 3: no list on an unverified Mac (SOURCE F4a as narrowed by
/// Amendment 16). Old or unknown births are held whatever the reason; newer
/// births pass. A malformed list, a list missing after install and an
/// unrecordable install hold everything even with budget available. On a
/// verified Mac without a list, old history is paced instead (N1).
#[test]
#[ignore = "terminal-off ON-readiness: r25-code-unclassified"]
fn terminal_off_on_no_list_and_paused_list_states_hold_history_selected_for_another_reason() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (home, root, index) = families("history-gate-no-list", 2);
    let held_under = |policy: NoListPolicy, support: &Path, cutoff: u64| {
        let mut index = index.clone();
        index.claude_no_list_policy = policy;
        index.load_claude_reemission_exclusions(support);
        let state = index.claude_reemission_exclusions.state();
        let mut result = with_no_list_cutoff(cutoff, || scan(&root, &mut index, "ctx-2", 2));
        assert_eq!(result.scanned_file_count, 4);
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut index);
        (state, result.snapshots.len(), revisions(&index))
    };
    let held =
        |support: &Path, cutoff: u64| held_under(NoListPolicy::HoldUnverified, support, cutoff);
    let never = support("history-gate-never");
    assert_eq!(
        held(&never, u64::MAX),
        (ListState::NotInstalled, 0, vec![1; 4])
    );
    assert_eq!(
        held_under(NoListPolicy::HoldMoveNotFull, &never, u64::MAX),
        (ListState::NotInstalled, 0, vec![1; 4])
    );
    assert_eq!(
        held_under(NoListPolicy::Pace, &never, u64::MAX),
        (ListState::NotInstalled, 4, vec![2; 4]),
        "a verified Mac without a list paces old history"
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

    let (home_missing, root_missing, missing_index) = families("history-gate-missing-list", 2);
    let never = support("history-gate-missing-list-support");
    for (policy, expected) in [(NoListPolicy::HoldUnverified, 0), (NoListPolicy::Pace, 1)] {
        let mut missing_index = missing_index.clone();
        missing_index.claude_no_list_policy = policy;
        missing_index.load_claude_reemission_exclusions(&never);
        let mut result = with_no_list_cutoff(u64::MAX, || {
            with_body_witness_adoption_page_budget(1, || {
                scan(&root_missing, &mut missing_index, "ctx-2", 2)
            })
        });
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut missing_index);
        assert_eq!(
            result.snapshots.len(),
            expected,
            "{policy:?}: absence is not an empty list, and only holds an unverified Mac"
        );
    }
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(home_missing);
}

/// Group 4 (M1): an installed empty list paces history selected for another
/// reason, one file per page under budget 1; the rest keep their tuples and
/// census records. A missing (never installed) list is not the same: old
/// births are held.
#[test]
#[ignore = "terminal-off ON-readiness: r25-code-unclassified"]
fn terminal_off_on_installed_empty_list_paces_history_and_differs_from_a_missing_list() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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

    let (home_missing, root_missing, missing_index) = families("history-gate-missing-list", 2);
    let never = support("history-gate-missing-list-support");
    for (policy, expected) in [(NoListPolicy::HoldUnverified, 0), (NoListPolicy::Pace, 1)] {
        let mut missing_index = missing_index.clone();
        missing_index.claude_no_list_policy = policy;
        missing_index.load_claude_reemission_exclusions(&never);
        let mut result = with_no_list_cutoff(u64::MAX, || {
            with_body_witness_adoption_page_budget(1, || {
                scan(&root_missing, &mut missing_index, "ctx-2", 2)
            })
        });
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut missing_index);
        assert_eq!(
            result.snapshots.len(),
            expected,
            "{policy:?}: absence is not an empty list, and only holds an unverified Mac"
        );
    }
    let _ = fs::remove_dir_all(home);
    let _ = fs::remove_dir_all(home_missing);
}

/// Design E2 item 8, the switch-on re-read: a revision bump (2 to 3) on an
/// M4-shaped index (families of a root and 0-3 subagents, empty files, and a
/// walk longer than one page, as 13,424 files are on the M4 against 10,000 per
/// page) re-reads every stamped file once, paced by the byte budget, in
/// ceil(bytes / budget) reading pages, and then a complete walk reads nothing.
/// A budget hold queues the file again as a re-read for the next page of its
/// walk, so pacing does not wait for the next walk. Each page commits as a
/// fully accepted page without holds does (the upload context is adopted).
#[test]
fn revision_bump_rereads_every_stamped_file_paced_then_stops() {
    const FAMILIES: usize = 20;
    const EMPTY_FILES: usize = 3;
    const FILE_BYTES: usize = 2_048;
    const FILES_PER_BUDGET: u64 = 5;
    const PAGE_FILES: usize = 40;
    let home = crate::test_scratch::unique_path("ottto-history-gate-switch-on");
    let root = home.join("project");
    let mut nonempty = 0_u64;
    for slot in 0..FAMILIES {
        let session = session(slot);
        let agents = (0..slot % 4).map(|n| Some(format!("{slot:08x}{n:08x}")));
        for agent in std::iter::once(None).chain(agents) {
            let path = match &agent {
                Some(agent) => root
                    .join(&session)
                    .join("subagents")
                    .join(format!("agent-{agent}.jsonl")),
                None => root.join(format!("{session}.jsonl")),
            };
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let request = agent.as_deref().unwrap_or("root");
            let mut line = json!({
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
                },
                "pad": ""
            });
            let pad = FILE_BYTES - 1 - line.to_string().len();
            line["pad"] = json!("x".repeat(pad));
            let text = format!("{line}\n");
            assert_eq!(text.len(), FILE_BYTES);
            fs::write(&path, text).unwrap();
            nonempty += 1;
        }
    }
    for slot in FAMILIES..FAMILIES + EMPTY_FILES {
        fs::write(root.join(format!("{}.jsonl", session(slot))), "").unwrap();
    }
    let at = |index: &ScanIndex, revision: u64| {
        index
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision >= revision)
            .count()
    };
    let page = |index: &mut ScanIndex, revision: u64| {
        index.activate_upload_context("ctx-1".into());
        index.activate_effective_upload_body_witness_revision(revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        let mut result = scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            COLLECTED_AT,
            BACKFILL_WINDOW_DAYS,
            PAGE_FILES,
            true,
        )
        .unwrap();
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&accepted);
        result
    };
    let mut index = ScanIndex::default();
    with_max_gated_claude_revision(3, || {
        // Sent and stamped at revision 2, then settled: whole walks until
        // one reads no file.
        let (mut stamp_pages, mut walk_reads) = (0, 0);
        loop {
            stamp_pages += 1;
            assert!(stamp_pages <= 12, "the stamped corpus settles");
            let result = page(&mut index, 2);
            walk_reads += result.scanned_file_count;
            if result.census_complete {
                if walk_reads == 0 {
                    break;
                }
                walk_reads = 0;
            }
        }
        let files = index.files.len();
        assert_eq!(files as u64, nonempty + EMPTY_FILES as u64);
        assert_eq!(at(&index, 2), files);

        // The switch-on: an installed, empty list and revision 3.
        let list = support("history-gate-switch-on-list");
        fs::write(ReemissionExclusions::path(&list), "").unwrap();
        index.load_claude_reemission_exclusions(&list);
        let budget = FILES_PER_BUDGET * FILE_BYTES as u64;
        let bound = (nonempty * FILE_BYTES as u64).div_ceil(budget) as usize;
        with_body_witness_adoption_byte_budget(budget, || {
            let mut receipts = Vec::new();
            let mut reads = 0;
            while at(&index, 3) < files {
                assert!(
                    receipts.len() < 4 * bound,
                    "every file upgrades: {receipts:?}"
                );
                let before = index.clone();
                let result = page(&mut index, 3);
                let bytes = index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        entry.effective_upload_body_witness_revision >= 3
                            && before.files[*key].effective_upload_body_witness_revision < 3
                    })
                    .map(|(_, entry)| entry.size_bytes)
                    .sum::<u64>();
                reads += result.scanned_file_count;
                receipts.push((
                    at(&index, 3) - at(&before, 3),
                    bytes,
                    result.scanned_file_count,
                    result.census_complete,
                ));
                assert!(bytes <= budget, "paced by the byte budget: {receipts:?}");
            }
            let reading = receipts.iter().filter(|receipt| receipt.0 > 0).count();
            assert_eq!(
                reading, bound,
                "ceil(bytes / budget) reading pages: {receipts:?}"
            );
            assert!(
                receipts.len() <= bound + 1,
                "pages without a read only close a walk: {receipts:?}"
            );
            assert_eq!(
                reads, files,
                "every stamped file is read once: {receipts:?}"
            );
            // Then nothing more: the walk in flight completes, and so does
            // one whole walk after it, reading no file.
            let mut complete = 0;
            let mut after = Vec::new();
            while complete < 2 {
                assert!(after.len() < 8, "the walks complete: {after:?}");
                let result = page(&mut index, 3);
                complete += usize::from(result.census_complete);
                after.push((result.scanned_file_count, result.snapshots.len()));
            }
            assert!(
                after.iter().all(|&(read, sent)| read == 0 && sent == 0),
                "no second re-read: {after:?}"
            );
            assert_eq!(at(&index, 3), files);
        });
    });
    let _ = fs::remove_dir_all(home);
}

/// Design E2 item 8, the switch-on re-read: a revision bump (2 to 3) on an
/// M4-shaped index (families of a root and 0-3 subagents, empty files, and a
/// walk longer than one page, as 13,424 files are on the M4 against 10,000 per
/// page) re-reads every stamped file once, paced by the byte budget, in
/// ceil(bytes / budget) reading pages, and then a complete walk reads nothing.
/// A budget hold queues the file again as a re-read for the next page of its
/// walk, so pacing does not wait for the next walk. Each page commits as a
/// fully accepted page without holds does (the upload context is adopted).
#[test]
#[ignore = "terminal-off ON-readiness: P3"]
fn terminal_off_on_revision_bump_rereads_every_stamped_file_paced_then_stops() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    const FAMILIES: usize = 20;
    const EMPTY_FILES: usize = 3;
    const FILE_BYTES: usize = 2_048;
    const FILES_PER_BUDGET: u64 = 5;
    const PAGE_FILES: usize = 40;
    let home = crate::test_scratch::unique_path("ottto-history-gate-switch-on");
    let root = home.join("project");
    let mut nonempty = 0_u64;
    for slot in 0..FAMILIES {
        let session = session(slot);
        let agents = (0..slot % 4).map(|n| Some(format!("{slot:08x}{n:08x}")));
        for agent in std::iter::once(None).chain(agents) {
            let path = match &agent {
                Some(agent) => root
                    .join(&session)
                    .join("subagents")
                    .join(format!("agent-{agent}.jsonl")),
                None => root.join(format!("{session}.jsonl")),
            };
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let request = agent.as_deref().unwrap_or("root");
            let mut line = json!({
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
                },
                "pad": ""
            });
            let pad = FILE_BYTES - 1 - line.to_string().len();
            line["pad"] = json!("x".repeat(pad));
            let text = format!("{line}\n");
            assert_eq!(text.len(), FILE_BYTES);
            fs::write(&path, text).unwrap();
            nonempty += 1;
        }
    }
    for slot in FAMILIES..FAMILIES + EMPTY_FILES {
        fs::write(root.join(format!("{}.jsonl", session(slot))), "").unwrap();
    }
    let at = |index: &ScanIndex, revision: u64| {
        index
            .files
            .values()
            .filter(|entry| entry.effective_upload_body_witness_revision >= revision)
            .count()
    };
    let page = |index: &mut ScanIndex, revision: u64| {
        index.activate_upload_context("ctx-1".into());
        index.activate_effective_upload_body_witness_revision(revision);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        let mut result = scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            COLLECTED_AT,
            BACKFILL_WINDOW_DAYS,
            PAGE_FILES,
            true,
        )
        .unwrap();
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, index);
        let accepted = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&accepted);
        result
    };
    let mut index = ScanIndex::default();
    with_max_gated_claude_revision(3, || {
        // Sent and stamped at revision 2, then settled: whole walks until
        // one reads no file.
        let (mut stamp_pages, mut walk_reads) = (0, 0);
        loop {
            stamp_pages += 1;
            assert!(stamp_pages <= 12, "the stamped corpus settles");
            let result = page(&mut index, 2);
            walk_reads += result.scanned_file_count;
            if result.census_complete {
                if walk_reads == 0 {
                    break;
                }
                walk_reads = 0;
            }
        }
        let files = index.files.len();
        assert_eq!(files as u64, nonempty + EMPTY_FILES as u64);
        assert_eq!(at(&index, 2), files);

        // The switch-on: an installed, empty list and revision 3.
        let list = support("history-gate-switch-on-list");
        fs::write(ReemissionExclusions::path(&list), "").unwrap();
        index.load_claude_reemission_exclusions(&list);
        let budget = FILES_PER_BUDGET * FILE_BYTES as u64;
        let bound = (nonempty * FILE_BYTES as u64).div_ceil(budget) as usize;
        with_body_witness_adoption_byte_budget(budget, || {
            let mut receipts = Vec::new();
            let mut reads = 0;
            while at(&index, 3) < files {
                assert!(
                    receipts.len() < 4 * bound,
                    "every file upgrades: {receipts:?}"
                );
                let before = index.clone();
                let result = page(&mut index, 3);
                let bytes = index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        entry.effective_upload_body_witness_revision >= 3
                            && before.files[*key].effective_upload_body_witness_revision < 3
                    })
                    .map(|(_, entry)| entry.size_bytes)
                    .sum::<u64>();
                reads += result.scanned_file_count;
                receipts.push((
                    at(&index, 3) - at(&before, 3),
                    bytes,
                    result.scanned_file_count,
                    result.census_complete,
                ));
                assert!(bytes <= budget, "paced by the byte budget: {receipts:?}");
            }
            let reading = receipts.iter().filter(|receipt| receipt.0 > 0).count();
            assert_eq!(
                reading, bound,
                "ceil(bytes / budget) reading pages: {receipts:?}"
            );
            assert!(
                receipts.len() <= bound + 1,
                "pages without a read only close a walk: {receipts:?}"
            );
            assert_eq!(
                reads, files,
                "every stamped file is read once: {receipts:?}"
            );
            // Then nothing more: the walk in flight completes, and so does
            // one whole walk after it, reading no file.
            let mut complete = 0;
            let mut after = Vec::new();
            while complete < 2 {
                assert!(after.len() < 8, "the walks complete: {after:?}");
                let result = page(&mut index, 3);
                complete += usize::from(result.census_complete);
                after.push((result.scanned_file_count, result.snapshots.len()));
            }
            assert!(
                after.iter().all(|&(read, sent)| read == 0 && sent == 0),
                "no second re-read: {after:?}"
            );
            assert_eq!(at(&index, 3), files);
        });
    });
    let _ = fs::remove_dir_all(home);
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

/// A fold that latches the stop after the candidate loop permitted an
/// upgrade blocks its emission at the seam.
#[test]
fn terminal_off_on_a_latch_set_after_the_candidate_loop_blocks_permitted_history() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    index.claude_no_list_policy = NoListPolicy::HoldUnverified;
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

/// The shared stamp never downgrades a Claude revision and refuses a file
/// the gate holds; Codex and Pi keep the exact stamp.
#[test]
fn terminal_off_on_the_shared_stamp_never_downgrades_and_refuses_held_files() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    index.claude_no_list_policy = NoListPolicy::HoldUnverified;
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

/// Release gate: a release that raises the active Claude revision must also
/// give it a row in the history policy table. Without one this fails, and the
/// gate itself holds every upgrade (`ungated_revision`).
#[test]
fn terminal_off_on_active_claude_revision_has_a_history_policy_row() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
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

/// StateMissing M1: on a fresh index a list line naming only a member
/// (`root_stem`) still protects its root, which is decided before the
/// member is indexed: no root body is emitted, and the unlisted family
/// upgrades.
#[test]
#[ignore = "terminal-off ON-readiness: r25-code-unclassified"]
fn terminal_off_on_member_only_line_protects_its_root_on_a_fresh_index() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (home, root, index) = families("history-gate-member-only", 2);
    let support = support("history-gate-member-only-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&listed_member(&index, &session(1)))),
    )
    .unwrap();
    let mut fresh = ScanIndex::default();
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
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
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
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

/// M1 (AutoReview): a member directory the closure cannot read may hold a
/// listed member, so its root is held, not sent.
#[cfg(unix)]
#[test]
fn terminal_off_on_unreadable_member_directory_holds_its_root() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
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

/// One synthetic usage line for subagent `agent` of family `family`.
fn subagent_line(family: &str, agent: &str) -> String {
    format!(
        "{}\n",
        json!({
            "timestamp": "2026-08-23T18:20:00Z",
            "type": "assistant",
            "sessionId": family,
            "agentId": agent,
            "isSidechain": true,
            "requestId": format!("request-{family}-{agent}"),
            "message": {
                "id": format!("message-{family}-{agent}"),
                "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10, "output_tokens": 1}
            }
        })
    )
}

/// A family `<project>/<family>/subagents/<stem>.jsonl` for each stem, with
/// no root file unless `with_root`. Returns the project dir and each file's
/// candidate, by stem (the root's under `""`).
fn family_on_disk(
    project: &Path,
    family: &str,
    stems: &[&str],
    with_root: bool,
) -> BTreeMap<String, CandidateFile> {
    let candidate = |path: PathBuf| CandidateFile {
        physical_identity: None,
        scan_root: project.to_path_buf(),
        source_file_fingerprint: path.display().to_string(),
        path,
        size_bytes: 1,
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
    };
    let subagents = project.join(family).join("subagents");
    fs::create_dir_all(&subagents).unwrap();
    let mut candidates = BTreeMap::new();
    for stem in stems {
        let path = subagents.join(format!("{stem}.jsonl"));
        fs::write(&path, subagent_line(family, stem)).unwrap();
        candidates.insert((*stem).to_owned(), candidate(path));
    }
    if with_root {
        let path = project.join(format!("{family}.jsonl"));
        fs::write(&path, subagent_line(family, "root")).unwrap();
        candidates.insert(String::new(), candidate(path));
    }
    candidates
}

/// A fresh index with prior history on this Mac and `list` installed: every
/// new file born before the cutoff is owed history.
fn fresh_with_list(name: &str, list: &str) -> (crate::test_scratch::ScratchDir, ScanIndex) {
    let support = support(name);
    fs::write(ReemissionExclusions::path(&support), list).unwrap();
    let mut fresh = ScanIndex::default();
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
    fresh.activate_effective_upload_body_witness_revision(2);
    fresh.adopt_effective_upload_body_witness_revision_monotonically();
    fresh.load_claude_reemission_exclusions(&support);
    assert_eq!(
        fresh.claude_reemission_exclusions.state(),
        ListState::Installed
    );
    (support, fresh)
}

fn decide(index: &mut ScanIndex, candidate: &CandidateFile) -> HistoryDecision {
    index.claude_history_upgrade_decision(candidate, Some(0), &mut HistoryPage::default())
}

/// Move a directory's modification time an hour back, as a family whose
/// members were all written before this pass.
fn age_directory(directory: &Path) {
    fs::File::open(directory)
        .unwrap()
        .set_modified(SystemTime::now() - std::time::Duration::from_secs(3_600))
        .unwrap();
}

/// StateMissing M1, a family with no root file: the list names only
/// `R_agent-a`, and the fresh index has not seen agent-a. Its sibling agent-b
/// is held whichever member is decided first, the root is listed, and an
/// unlisted rootless family is not held. Before the fix, agent-b was decided
/// as unlisted (`Owed`) in both orders.
#[test]
fn listed_member_holds_its_sibling_when_the_root_file_is_absent() {
    for order in [["agent-b", "agent-a"], ["agent-a", "agent-b"]] {
        let home = crate::test_scratch::unique_path("ottto-history-gate-rootless");
        let project = home.join("project");
        let family = session(1);
        let members = family_on_disk(&project, &family, &["agent-a", "agent-b"], false);
        let other = family_on_disk(&project, &session(2), &["agent-c"], false);
        let (_support, mut fresh) = fresh_with_list(
            "history-gate-rootless-support",
            &format!("{}\n", digest(&format!("{family}_agent-a"))),
        );
        for stem in order {
            assert_eq!(
                decide(&mut fresh, &members[stem]),
                HistoryDecision::Held(HistoryHold::Listed),
                "{stem} in order {order:?}"
            );
        }
        assert!(fresh.claude_reemission_exclusions.excludes(&family, None));
        assert_ne!(
            decide(&mut fresh, &other["agent-c"]),
            HistoryDecision::Held(HistoryHold::Listed),
            "an unlisted rootless family is not held"
        );
        assert!(!fresh
            .claude_reemission_exclusions
            .excludes(&session(2), None));
        let _ = fs::remove_dir_all(home);
    }
}

/// StateMissing M1, a family with no root file: the list names only
/// `R_agent-a`, and the fresh index has not seen agent-a. Its sibling agent-b
/// is held whichever member is decided first, the root is listed, and an
/// unlisted rootless family is not held. Before the fix, agent-b was decided
/// as unlisted (`Owed`) in both orders.
#[test]
fn terminal_off_on_listed_member_holds_its_sibling_when_the_root_file_is_absent() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    for order in [["agent-b", "agent-a"], ["agent-a", "agent-b"]] {
        let home = crate::test_scratch::unique_path("ottto-history-gate-rootless");
        let project = home.join("project");
        let family = session(1);
        let members = family_on_disk(&project, &family, &["agent-a", "agent-b"], false);
        let other = family_on_disk(&project, &session(2), &["agent-c"], false);
        let (_support, mut fresh) = fresh_with_list(
            "history-gate-rootless-support",
            &format!("{}\n", digest(&format!("{family}_agent-a"))),
        );
        for stem in order {
            assert_eq!(
                decide(&mut fresh, &members[stem]),
                HistoryDecision::Held(HistoryHold::Listed),
                "{stem} in order {order:?}"
            );
        }
        assert!(fresh.claude_reemission_exclusions.excludes(&family, None));
        assert_ne!(
            decide(&mut fresh, &other["agent-c"]),
            HistoryDecision::Held(HistoryHold::Listed),
            "an unlisted rootless family is not held"
        );
        assert!(!fresh
            .claude_reemission_exclusions
            .excludes(&session(2), None));
        let _ = fs::remove_dir_all(home);
    }
}

/// The same family through the whole scan: no root file, the listed member
/// between two siblings in traversal order. No body of the listed family is
/// emitted; the unlisted rootless family still emits.
#[test]
fn rootless_listed_family_emits_no_sibling_through_the_scan() {
    let (home, root, index) = families("history-gate-rootless-scan", 2);
    let listed = listed_member(&index, &session(1));
    for slot in 0..2 {
        let family = session(slot);
        fs::remove_file(root.join(format!("{family}.jsonl"))).unwrap();
        for agent in ["agent-0", "agent-z"] {
            fs::write(
                root.join(&family)
                    .join("subagents")
                    .join(format!("{agent}.jsonl")),
                subagent_line(&family, agent),
            )
            .unwrap();
        }
    }
    let support = support("history-gate-rootless-scan-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&listed)),
    )
    .unwrap();
    let mut fresh = ScanIndex::default();
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
    fresh.load_claude_reemission_exclusions(&support);
    let mut result = scan(&root, &mut fresh, "ctx-1", 2);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut fresh);
    let emitted = result
        .snapshots
        .iter()
        .map(|item| item.source_session_id.as_str())
        .collect::<Vec<_>>();
    assert!(
        emitted.iter().all(|id| !id.starts_with(&session(1))),
        "{emitted:?}"
    );
    assert!(
        emitted.iter().any(|id| id.starts_with(&session(0))),
        "the unlisted family upgrades: {emitted:?}"
    );
    let _ = fs::remove_dir_all(home);
}

/// The same family through the whole scan: no root file, the listed member
/// between two siblings in traversal order. No body of the listed family is
/// emitted; the unlisted rootless family still emits.
#[test]
fn terminal_off_on_rootless_listed_family_emits_no_sibling_through_the_scan() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (home, root, index) = families("history-gate-rootless-scan", 2);
    let listed = listed_member(&index, &session(1));
    for slot in 0..2 {
        let family = session(slot);
        fs::remove_file(root.join(format!("{family}.jsonl"))).unwrap();
        for agent in ["agent-0", "agent-z"] {
            fs::write(
                root.join(&family)
                    .join("subagents")
                    .join(format!("{agent}.jsonl")),
                subagent_line(&family, agent),
            )
            .unwrap();
        }
    }
    let support = support("history-gate-rootless-scan-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&listed)),
    )
    .unwrap();
    let mut fresh = ScanIndex::default();
    fresh.note_claude_history_cutoff(PriorHistory::Here, false, true);
    fresh.load_claude_reemission_exclusions(&support);
    let mut result = scan(&root, &mut fresh, "ctx-1", 2);
    finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, &mut fresh);
    let emitted = result
        .snapshots
        .iter()
        .map(|item| item.source_session_id.as_str())
        .collect::<Vec<_>>();
    assert!(
        emitted.iter().all(|id| !id.starts_with(&session(1))),
        "{emitted:?}"
    );
    assert!(
        emitted.iter().any(|id| id.starts_with(&session(0))),
        "the unlisted family upgrades: {emitted:?}"
    );
    let _ = fs::remove_dir_all(home);
}

/// With the root file present and a member listed, the root and every
/// member are held as before, and the family is walked once.
#[test]
fn listed_member_with_its_root_present_holds_the_whole_family() {
    let home = crate::test_scratch::unique_path("ottto-history-gate-rooted");
    let project = home.join("project");
    let family = session(1);
    let members = family_on_disk(&project, &family, &["agent-a", "agent-b"], true);
    let (_support, mut fresh) = fresh_with_list(
        "history-gate-rooted-support",
        &format!("{}\n", digest(&format!("{family}_agent-a"))),
    );
    let walks = claude_reemission_member_walks_for_test();
    for stem in ["", "agent-b", "agent-a"] {
        assert_eq!(
            decide(&mut fresh, &members[stem]),
            HistoryDecision::Held(HistoryHold::Listed),
            "{stem:?}"
        );
    }
    assert_eq!(claude_reemission_member_walks_for_test() - walks, 1);
    let _ = fs::remove_dir_all(home);
}

/// With the root file present and a member listed, the root and every
/// member are held as before, and the family is walked once.
#[test]
fn terminal_off_on_listed_member_with_its_root_present_holds_the_whole_family() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let home = crate::test_scratch::unique_path("ottto-history-gate-rooted");
    let project = home.join("project");
    let family = session(1);
    let members = family_on_disk(&project, &family, &["agent-a", "agent-b"], true);
    let (_support, mut fresh) = fresh_with_list(
        "history-gate-rooted-support",
        &format!("{}\n", digest(&format!("{family}_agent-a"))),
    );
    let walks = claude_reemission_member_walks_for_test();
    for stem in ["", "agent-b", "agent-a"] {
        assert_eq!(
            decide(&mut fresh, &members[stem]),
            HistoryDecision::Held(HistoryHold::Listed),
            "{stem:?}"
        );
    }
    assert_eq!(claude_reemission_member_walks_for_test() - walks, 1);
    let _ = fs::remove_dir_all(home);
}

/// A rootless family whose member walk cannot finish holds its root: an
/// unreadable nested directory (it may hold the listed member), or more
/// entries than the walk's bound.
#[test]
fn rootless_family_walk_that_cannot_finish_holds_the_root() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let home = crate::test_scratch::unique_path("ottto-history-gate-rootless-unreadable");
        let project = home.join("project");
        let family = session(1);
        let members = family_on_disk(&project, &family, &["agent-b"], false);
        let nested = project.join(&family).join("subagents").join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("agent-a.jsonl"),
            subagent_line(&family, "agent-a"),
        )
        .unwrap();
        let (_support, mut fresh) = fresh_with_list(
            "history-gate-rootless-unreadable-support",
            &format!("{}\n", digest(&format!("{family}_agent-a"))),
        );
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).unwrap();
        let decision = decide(&mut fresh, &members["agent-b"]);
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(decision, HistoryDecision::Held(HistoryHold::Listed));
        assert!(fresh.claude_reemission_exclusions.excludes(&family, None));
        let _ = fs::remove_dir_all(home);
    }

    let home = crate::test_scratch::unique_path("ottto-history-gate-rootless-bound");
    let project = home.join("project");
    let family = session(1);
    let members = family_on_disk(&project, &family, &["agent-b"], false);
    let subagents = project.join(&family).join("subagents");
    for slot in 0..4_096 {
        fs::write(subagents.join(format!("pad-{slot}")), "").unwrap();
    }
    // Nothing on disk is listed: only the bound holds the root.
    let (_support, mut fresh) = fresh_with_list(
        "history-gate-rootless-bound-support",
        &format!("{}\n", digest(&format!("{family}_agent-absent"))),
    );
    assert_eq!(
        decide(&mut fresh, &members["agent-b"]),
        HistoryDecision::Held(HistoryHold::Listed)
    );
    assert!(fresh.claude_reemission_exclusions.excludes(&family, None));
    let _ = fs::remove_dir_all(home);
}

/// A rootless family whose member walk cannot finish holds its root: an
/// unreadable nested directory (it may hold the listed member), or more
/// entries than the walk's bound.
#[test]
fn terminal_off_on_rootless_family_walk_that_cannot_finish_holds_the_root() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let home = crate::test_scratch::unique_path("ottto-history-gate-rootless-unreadable");
        let project = home.join("project");
        let family = session(1);
        let members = family_on_disk(&project, &family, &["agent-b"], false);
        let nested = project.join(&family).join("subagents").join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("agent-a.jsonl"),
            subagent_line(&family, "agent-a"),
        )
        .unwrap();
        let (_support, mut fresh) = fresh_with_list(
            "history-gate-rootless-unreadable-support",
            &format!("{}\n", digest(&format!("{family}_agent-a"))),
        );
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).unwrap();
        let decision = decide(&mut fresh, &members["agent-b"]);
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(decision, HistoryDecision::Held(HistoryHold::Listed));
        assert!(fresh.claude_reemission_exclusions.excludes(&family, None));
        let _ = fs::remove_dir_all(home);
    }

    let home = crate::test_scratch::unique_path("ottto-history-gate-rootless-bound");
    let project = home.join("project");
    let family = session(1);
    let members = family_on_disk(&project, &family, &["agent-b"], false);
    let subagents = project.join(&family).join("subagents");
    for slot in 0..4_096 {
        fs::write(subagents.join(format!("pad-{slot}")), "").unwrap();
    }
    // Nothing on disk is listed: only the bound holds the root.
    let (_support, mut fresh) = fresh_with_list(
        "history-gate-rootless-bound-support",
        &format!("{}\n", digest(&format!("{family}_agent-absent"))),
    );
    assert_eq!(
        decide(&mut fresh, &members["agent-b"]),
        HistoryDecision::Held(HistoryHold::Listed)
    );
    assert!(fresh.claude_reemission_exclusions.excludes(&family, None));
    let _ = fs::remove_dir_all(home);
}

/// An installed list with no line (most Macs) walks no member directory.
#[test]
fn empty_list_walks_no_member_directory() {
    let home = crate::test_scratch::unique_path("ottto-history-gate-empty-walk");
    let project = home.join("project");
    let members = family_on_disk(&project, &session(1), &["agent-a", "agent-b"], true);
    let (_support, mut fresh) = fresh_with_list("history-gate-empty-walk-support", "# none\n");
    let walks = claude_reemission_member_walks_for_test();
    for candidate in members.values() {
        assert_ne!(
            decide(&mut fresh, candidate),
            HistoryDecision::Held(HistoryHold::Listed)
        );
    }
    assert_eq!(claude_reemission_member_walks_for_test(), walks);
    let _ = fs::remove_dir_all(home);
}

/// An installed list with no line (most Macs) walks no member directory.
#[test]
fn terminal_off_on_empty_list_walks_no_member_directory() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let home = crate::test_scratch::unique_path("ottto-history-gate-empty-walk");
    let project = home.join("project");
    let members = family_on_disk(&project, &session(1), &["agent-a", "agent-b"], true);
    let (_support, mut fresh) = fresh_with_list("history-gate-empty-walk-support", "# none\n");
    let walks = claude_reemission_member_walks_for_test();
    for candidate in members.values() {
        assert_ne!(
            decide(&mut fresh, candidate),
            HistoryDecision::Held(HistoryHold::Listed)
        );
    }
    assert_eq!(claude_reemission_member_walks_for_test(), walks);
    let _ = fs::remove_dir_all(home);
}

/// A big unlisted family is walked once per pass, not once per member. A
/// member created after the walk changes the directory's stamp, so the next
/// sibling walks again and is held when that member is listed; a new pass
/// walks again.
#[test]
fn member_walk_is_remembered_per_pass_until_the_directory_changes() {
    let home = crate::test_scratch::unique_path("ottto-history-gate-walk-memo");
    let project = home.join("project");
    let family = session(1);
    let stems = (0..32)
        .map(|slot| format!("agent-{slot:02}"))
        .collect::<Vec<_>>();
    let members = family_on_disk(
        &project,
        &family,
        &stems.iter().map(String::as_str).collect::<Vec<_>>(),
        false,
    );
    let subagents = project.join(&family).join("subagents");
    age_directory(&subagents);
    let (_support, mut fresh) = fresh_with_list(
        "history-gate-walk-memo-support",
        &format!("{}\n", digest(&format!("{family}_agent-late"))),
    );
    let walks = claude_reemission_member_walks_for_test();
    for candidate in members.values() {
        assert_ne!(
            decide(&mut fresh, candidate),
            HistoryDecision::Held(HistoryHold::Listed)
        );
    }
    assert_eq!(
        claude_reemission_member_walks_for_test() - walks,
        1,
        "one walk for the whole family this pass"
    );

    // The listed member appears mid-pass: the memo cannot hide it.
    fs::write(
        subagents.join("agent-late.jsonl"),
        subagent_line(&family, "agent-late"),
    )
    .unwrap();
    assert_eq!(
        decide(&mut fresh, &members["agent-00"]),
        HistoryDecision::Held(HistoryHold::Listed)
    );
    assert_eq!(claude_reemission_member_walks_for_test() - walks, 2);

    // A new pass forgets the walks of the last one.
    fs::remove_file(subagents.join("agent-late.jsonl")).unwrap();
    age_directory(&subagents);
    let (_support, mut next) = fresh_with_list(
        "history-gate-walk-memo-next-support",
        &format!("{}\n", digest(&format!("{family}_agent-late"))),
    );
    for _ in 0..2 {
        next.activate_effective_upload_body_witness_revision(2);
        next.adopt_effective_upload_body_witness_revision_monotonically();
        for stem in ["agent-01", "agent-02"] {
            decide(&mut next, &members[stem]);
        }
    }
    assert_eq!(
        claude_reemission_member_walks_for_test() - walks,
        4,
        "one walk in each of two passes"
    );
    let _ = fs::remove_dir_all(home);
}

/// A big unlisted family is walked once per pass, not once per member. A
/// member created after the walk changes the directory's stamp, so the next
/// sibling walks again and is held when that member is listed; a new pass
/// walks again.
#[test]
fn terminal_off_on_member_walk_is_remembered_per_pass_until_the_directory_changes() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let home = crate::test_scratch::unique_path("ottto-history-gate-walk-memo");
    let project = home.join("project");
    let family = session(1);
    let stems = (0..32)
        .map(|slot| format!("agent-{slot:02}"))
        .collect::<Vec<_>>();
    let members = family_on_disk(
        &project,
        &family,
        &stems.iter().map(String::as_str).collect::<Vec<_>>(),
        false,
    );
    let subagents = project.join(&family).join("subagents");
    age_directory(&subagents);
    let (_support, mut fresh) = fresh_with_list(
        "history-gate-walk-memo-support",
        &format!("{}\n", digest(&format!("{family}_agent-late"))),
    );
    let walks = claude_reemission_member_walks_for_test();
    for candidate in members.values() {
        assert_ne!(
            decide(&mut fresh, candidate),
            HistoryDecision::Held(HistoryHold::Listed)
        );
    }
    assert_eq!(
        claude_reemission_member_walks_for_test() - walks,
        1,
        "one walk for the whole family this pass"
    );

    // The listed member appears mid-pass: the memo cannot hide it.
    fs::write(
        subagents.join("agent-late.jsonl"),
        subagent_line(&family, "agent-late"),
    )
    .unwrap();
    assert_eq!(
        decide(&mut fresh, &members["agent-00"]),
        HistoryDecision::Held(HistoryHold::Listed)
    );
    assert_eq!(claude_reemission_member_walks_for_test() - walks, 2);

    // A new pass forgets the walks of the last one.
    fs::remove_file(subagents.join("agent-late.jsonl")).unwrap();
    age_directory(&subagents);
    let (_support, mut next) = fresh_with_list(
        "history-gate-walk-memo-next-support",
        &format!("{}\n", digest(&format!("{family}_agent-late"))),
    );
    for _ in 0..2 {
        next.activate_effective_upload_body_witness_revision(2);
        next.adopt_effective_upload_body_witness_revision_monotonically();
        for stem in ["agent-01", "agent-02"] {
            decide(&mut next, &members[stem]);
        }
    }
    assert_eq!(
        claude_reemission_member_walks_for_test() - walks,
        4,
        "one walk in each of two passes"
    );
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

/// StateMissing M2: a listed (held) family member owed only a proof
/// correction is not re-read every traversal: it is skipped like any held
/// adoption, and its correction is deferred to the history gate (disclosed)
/// instead of blocking a fully settled upload.
#[test]
fn terminal_off_on_held_member_owed_a_proof_correction_is_skipped_and_deferred() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

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
        terminal_off_ack_emitted(&mut index, &result.snapshots);
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
    index.note_claude_history_cutoff(PriorHistory::None, false, true);
    assert_eq!(
        index.claude_history_cutoff_unix_seconds, None,
        "fresh install"
    );
    index.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(index.claude_history_cutoff_unix_seconds, None);
    index.claude_history_cutoff_unix_seconds = Some(u64::MAX - 1);
    index.note_claude_history_cutoff(PriorHistory::None, false, false);
    assert!(index.claude_history_cutoff_unix_seconds.unwrap() <= now());
    // StateMissing M3: prior history records a cutoff on the first gated
    // load of an index without one, never on an index a gated daemon already
    // loaded (a fresh install's after its bootstrap).
    let mut pre_gate = ScanIndex::default();
    pre_gate.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert!(pre_gate.claude_history_cutoff_unix_seconds.is_some());
    let mut gated = ScanIndex::default();
    gated.note_claude_history_cutoff(PriorHistory::None, false, false);
    gated.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(gated.claude_history_cutoff_unix_seconds, None);
}

/// StateMissing L1: a stored cutoff ahead of the clock is pulled back to
/// now, and only prior history records one.
#[test]
fn terminal_off_on_history_cutoff_is_bounded_by_the_clock() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let now = || {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    };
    let mut index = ScanIndex::default();
    index.note_claude_history_cutoff(PriorHistory::None, false, true);
    assert_eq!(
        index.claude_history_cutoff_unix_seconds, None,
        "fresh install"
    );
    index.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(index.claude_history_cutoff_unix_seconds, None);
    index.claude_history_cutoff_unix_seconds = Some(u64::MAX - 1);
    index.note_claude_history_cutoff(PriorHistory::None, false, false);
    assert!(index.claude_history_cutoff_unix_seconds.unwrap() <= now());
    // StateMissing M3: prior history records a cutoff on the first gated
    // load of an index without one, never on an index a gated daemon already
    // loaded (a fresh install's after its bootstrap).
    let mut pre_gate = ScanIndex::default();
    pre_gate.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert!(pre_gate.claude_history_cutoff_unix_seconds.is_some());
    let mut gated = ScanIndex::default();
    gated.note_claude_history_cutoff(PriorHistory::None, false, false);
    gated.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(gated.claude_history_cutoff_unix_seconds, None);
}

/// StateMissing N1: the first gated load of an intact index records the last
/// moment it shows this destination receiving history (the newest valid
/// activity clock among its accepted entities), so sessions created after it
/// are new. A fresh index, a replay drop, or an index with no accepted
/// activity records now.
#[test]
fn history_cutoff_is_the_last_received_activity() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let received = |activity: &[(&str, Option<&str>, bool)]| {
        let mut index = ScanIndex::default();
        for (fingerprint, at, accepted) in activity {
            index
                .snapshot_activity_at
                .insert(fingerprint.repeat(64), at.map(str::to_owned));
            if *accepted {
                index
                    .accepted_snapshot_fingerprints
                    .insert(fingerprint.repeat(64));
            }
        }
        index
    };
    let activity = [
        ("a", Some("2026-08-02T07:00:00Z"), true),
        ("b", Some("2026-08-02T07:30:00Z"), true),
        ("c", Some("2026-08-02T09:00:00Z"), false),
        ("d", Some("not a clock"), true),
        ("e", None, true),
    ];
    let mut pre_gate = received(&activity);
    pre_gate.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(
        pre_gate.claude_history_cutoff_unix_seconds,
        Some(1_785_655_800),
        "2026-08-02T07:30:00Z: the newest accepted activity, not an unaccepted one"
    );
    let mut lost = received(&activity);
    lost.note_claude_history_cutoff(PriorHistory::Here, false, true);
    assert!(lost.claude_history_cutoff_unix_seconds.unwrap() >= now);
    let mut unknown = received(&[("a", Some("2026-08-02T07:00:00Z"), false)]);
    unknown.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert!(unknown.claude_history_cutoff_unix_seconds.unwrap() >= now);
    let mut future = received(&[("a", Some("2999-01-01T00:00:00Z"), true)]);
    future.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert!(future.claude_history_cutoff_unix_seconds.unwrap() <= now + 60);
}

/// StateMissing N1: the first gated load of an intact index records the last
/// moment it shows this destination receiving history (the newest valid
/// activity clock among its accepted entities), so sessions created after it
/// are new. A fresh index, a replay drop, or an index with no accepted
/// activity records now.
#[test]
fn terminal_off_on_history_cutoff_is_the_last_received_activity() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let received = |activity: &[(&str, Option<&str>, bool)]| {
        let mut index = ScanIndex::default();
        for (fingerprint, at, accepted) in activity {
            index
                .snapshot_activity_at
                .insert(fingerprint.repeat(64), at.map(str::to_owned));
            if *accepted {
                index
                    .accepted_snapshot_fingerprints
                    .insert(fingerprint.repeat(64));
            }
        }
        index
    };
    let activity = [
        ("a", Some("2026-08-02T07:00:00Z"), true),
        ("b", Some("2026-08-02T07:30:00Z"), true),
        ("c", Some("2026-08-02T09:00:00Z"), false),
        ("d", Some("not a clock"), true),
        ("e", None, true),
    ];
    let mut pre_gate = received(&activity);
    pre_gate.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(
        pre_gate.claude_history_cutoff_unix_seconds,
        Some(1_785_655_800),
        "2026-08-02T07:30:00Z: the newest accepted activity, not an unaccepted one"
    );
    let mut lost = received(&activity);
    lost.note_claude_history_cutoff(PriorHistory::Here, false, true);
    assert!(lost.claude_history_cutoff_unix_seconds.unwrap() >= now);
    let mut unknown = received(&[("a", Some("2026-08-02T07:00:00Z"), false)]);
    unknown.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert!(unknown.claude_history_cutoff_unix_seconds.unwrap() >= now);
    let mut future = received(&[("a", Some("2999-01-01T00:00:00Z"), true)]);
    future.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert!(future.claude_history_cutoff_unix_seconds.unwrap() <= now + 60);
}

/// SOURCE Amendment 16 and its cross-org move ruling: the cycle's no-list
/// policy. An unverified Mac holds; a move under a claim policy other than
/// an explicit `full` holds, and its index keeps that after its own
/// bootstrap until a `full` claim; everything else is paced.
#[test]
fn no_list_policy_follows_the_prior_history_evidence() {
    let policy = |prior: PriorHistory, full: bool, index: &mut ScanIndex| {
        index.note_claude_history_cutoff(prior, full, true);
        index.claude_no_list_policy
    };
    let mut index = ScanIndex::default();
    assert_eq!(
        policy(PriorHistory::None, false, &mut index),
        NoListPolicy::Pace
    );
    assert_eq!(
        policy(PriorHistory::Here, false, &mut index),
        NoListPolicy::Pace
    );
    assert_eq!(
        policy(PriorHistory::Unverified, false, &mut index),
        NoListPolicy::HoldUnverified
    );
    let mut full_move = ScanIndex::default();
    assert_eq!(
        policy(PriorHistory::Moved, true, &mut full_move),
        NoListPolicy::Pace
    );
    assert!(!full_move.claude_history_move_not_full);
    assert_eq!(
        policy(PriorHistory::Moved, false, &mut index),
        NoListPolicy::HoldMoveNotFull
    );
    assert!(index.claude_history_move_not_full);
    assert_eq!(
        policy(PriorHistory::Here, false, &mut index),
        NoListPolicy::HoldMoveNotFull,
        "the moved history stays held after this destination's bootstrap"
    );
    assert_eq!(
        policy(PriorHistory::Here, true, &mut index),
        NoListPolicy::Pace,
        "an explicit full claim lifts it"
    );
    assert!(!index.claude_history_move_not_full, "and clears it");
    assert_eq!(
        policy(PriorHistory::Here, false, &mut index),
        NoListPolicy::Pace,
        "a later claim with another policy does not bring it back"
    );
    let scratch = crate::test_scratch::ScratchDir::new("history-gate-move-kept");
    let path = scratch.join("index.json");
    let mut moved = ScanIndex::default();
    moved.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    moved.save(&path).unwrap();
    let mut reloaded = ScanIndex::load(&path).unwrap();
    assert!(reloaded.claude_history_move_not_full, "persisted");
    assert!(
        reloaded
            .committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new())
            .claude_history_move_not_full
    );
    // Move, then `full`, then save, reload and a same-destination claim with
    // another policy: the hold stays lifted.
    let previous = reloaded.clone();
    reloaded.note_claude_history_cutoff(PriorHistory::Here, true, false);
    let mut lifted = reloaded.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert!(
        !lifted.claude_history_move_not_full,
        "a partial commit keeps it lifted"
    );
    lifted.save(&path).unwrap();
    let mut again = ScanIndex::load(&path).unwrap();
    again.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(again.claude_no_list_policy, NoListPolicy::Pace);

    // The evidence may still read as a move after the `full` claim (its own
    // bootstrap and uploads not done yet): the release holds all the same,
    // across a save, a reload and a replay drop.
    let mut moving = ScanIndex::default();
    moving.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    assert_eq!(moving.claude_no_list_policy, NoListPolicy::HoldMoveNotFull);
    moving.note_claude_history_cutoff(PriorHistory::Moved, true, false);
    assert_eq!(moving.claude_no_list_policy, NoListPolicy::Pace);
    let moving_path = scratch.join("moving.json");
    moving.save(&moving_path).unwrap();
    let mut reloaded = ScanIndex::load(&moving_path).unwrap();
    for entries_lost in [false, true] {
        reloaded.note_claude_history_cutoff(PriorHistory::Moved, false, entries_lost);
        assert_eq!(reloaded.claude_no_list_policy, NoListPolicy::Pace);
        assert!(!reloaded.claude_history_move_not_full);
    }
}

/// SOURCE Amendment 16 and its cross-org move ruling: the cycle's no-list
/// policy. An unverified Mac holds; a move under a claim policy other than
/// an explicit `full` holds, and its index keeps that after its own
/// bootstrap until a `full` claim; everything else is paced.
#[test]
fn terminal_off_on_no_list_policy_follows_the_prior_history_evidence() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let policy = |prior: PriorHistory, full: bool, index: &mut ScanIndex| {
        index.note_claude_history_cutoff(prior, full, true);
        index.claude_no_list_policy
    };
    let mut index = ScanIndex::default();
    assert_eq!(
        policy(PriorHistory::None, false, &mut index),
        NoListPolicy::Pace
    );
    assert_eq!(
        policy(PriorHistory::Here, false, &mut index),
        NoListPolicy::Pace
    );
    assert_eq!(
        policy(PriorHistory::Unverified, false, &mut index),
        NoListPolicy::HoldUnverified
    );
    let mut full_move = ScanIndex::default();
    assert_eq!(
        policy(PriorHistory::Moved, true, &mut full_move),
        NoListPolicy::Pace
    );
    assert!(!full_move.claude_history_move_not_full);
    assert_eq!(
        policy(PriorHistory::Moved, false, &mut index),
        NoListPolicy::HoldMoveNotFull
    );
    assert!(index.claude_history_move_not_full);
    assert_eq!(
        policy(PriorHistory::Here, false, &mut index),
        NoListPolicy::HoldMoveNotFull,
        "the moved history stays held after this destination's bootstrap"
    );
    assert_eq!(
        policy(PriorHistory::Here, true, &mut index),
        NoListPolicy::Pace,
        "an explicit full claim lifts it"
    );
    assert!(!index.claude_history_move_not_full, "and clears it");
    assert_eq!(
        policy(PriorHistory::Here, false, &mut index),
        NoListPolicy::Pace,
        "a later claim with another policy does not bring it back"
    );
    let scratch = crate::test_scratch::ScratchDir::new("history-gate-move-kept");
    let path = scratch.join("index.json");
    let mut moved = ScanIndex::default();
    moved.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    moved.save(&path).unwrap();
    let mut reloaded = ScanIndex::load(&path).unwrap();
    assert!(reloaded.claude_history_move_not_full, "persisted");
    assert!(
        reloaded
            .committable_subset(&ScanIndex::default(), &BTreeSet::new(), &BTreeMap::new())
            .claude_history_move_not_full
    );
    // Move, then `full`, then save, reload and a same-destination claim with
    // another policy: the hold stays lifted.
    let previous = reloaded.clone();
    reloaded.note_claude_history_cutoff(PriorHistory::Here, true, false);
    let mut lifted = reloaded.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert!(
        !lifted.claude_history_move_not_full,
        "a partial commit keeps it lifted"
    );
    lifted.save(&path).unwrap();
    let mut again = ScanIndex::load(&path).unwrap();
    again.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(again.claude_no_list_policy, NoListPolicy::Pace);

    // The evidence may still read as a move after the `full` claim (its own
    // bootstrap and uploads not done yet): the release holds all the same,
    // across a save, a reload and a replay drop.
    let mut moving = ScanIndex::default();
    moving.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    assert_eq!(moving.claude_no_list_policy, NoListPolicy::HoldMoveNotFull);
    moving.note_claude_history_cutoff(PriorHistory::Moved, true, false);
    assert_eq!(moving.claude_no_list_policy, NoListPolicy::Pace);
    let moving_path = scratch.join("moving.json");
    moving.save(&moving_path).unwrap();
    let mut reloaded = ScanIndex::load(&moving_path).unwrap();
    for entries_lost in [false, true] {
        reloaded.note_claude_history_cutoff(PriorHistory::Moved, false, entries_lost);
        assert_eq!(reloaded.claude_no_list_policy, NoListPolicy::Pace);
        assert!(!reloaded.claude_history_move_not_full);
    }
}

/// StateMissing M3 (lenient decode): a malformed gate marker, move marker or
/// cutoff never fails the whole index decode. The cutoff and the gate marker
/// drop together, so the next gated load re-derives them (fail closed).
#[test]
fn malformed_history_gate_fields_decode_leniently() {
    let scratch = crate::test_scratch::ScratchDir::new("history-gate-lenient");
    let path = scratch.join("index.json");
    let mut gated = ScanIndex::default();
    gated.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    gated.save(&path).unwrap();
    let kept = ScanIndex::load(&path).unwrap();
    assert!(kept.claude_history_gate_loaded);
    assert!(kept.claude_history_move_not_full);
    assert!(kept.claude_history_cutoff_unix_seconds.is_some());
    for (gate, cutoff, moved) in [
        (json!("yes"), json!("soon"), json!(1)),
        (json!(true), json!(-5), json!({"x": 1})),
        (json!(null), json!(1.5), json!(null)),
    ] {
        let released = moved.clone();
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        saved["claude_history_gate_loaded"] = gate;
        saved["claude_history_cutoff_unix_seconds"] = cutoff;
        saved["claude_history_move_not_full"] = moved;
        saved["claude_history_move_released"] = released;
        let malformed = scratch.join("malformed.json");
        fs::write(&malformed, serde_json::to_vec(&saved).unwrap()).unwrap();
        let loaded = ScanIndex::load(&malformed).unwrap();
        assert!(
            !fs::read_dir(&*scratch)
                .unwrap()
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
            "not quarantined"
        );
        assert_eq!(loaded.claude_history_cutoff_unix_seconds, None);
        assert!(!loaded.claude_history_gate_loaded, "re-derived");
        assert!(
            loaded.claude_history_move_not_full,
            "malformed hold fails closed (K4)"
        );
        assert!(!loaded.claude_history_move_released);
    }
}

/// StateMissing M3 (lenient decode): a malformed gate marker, move marker or
/// cutoff never fails the whole index decode. The cutoff and the gate marker
/// drop together, so the next gated load re-derives them (fail closed).
#[test]
fn terminal_off_on_malformed_history_gate_fields_decode_leniently() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scratch = crate::test_scratch::ScratchDir::new("history-gate-lenient");
    let path = scratch.join("index.json");
    let mut gated = ScanIndex::default();
    gated.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    gated.save(&path).unwrap();
    let kept = ScanIndex::load(&path).unwrap();
    assert!(kept.claude_history_gate_loaded);
    assert!(kept.claude_history_move_not_full);
    assert!(kept.claude_history_cutoff_unix_seconds.is_some());
    for (gate, cutoff, moved) in [
        (json!("yes"), json!("soon"), json!(1)),
        (json!(true), json!(-5), json!({"x": 1})),
        (json!(null), json!(1.5), json!(null)),
    ] {
        let released = moved.clone();
        let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        saved["claude_history_gate_loaded"] = gate;
        saved["claude_history_cutoff_unix_seconds"] = cutoff;
        saved["claude_history_move_not_full"] = moved;
        saved["claude_history_move_released"] = released;
        let malformed = scratch.join("malformed.json");
        fs::write(&malformed, serde_json::to_vec(&saved).unwrap()).unwrap();
        let loaded = ScanIndex::load(&malformed).unwrap();
        assert!(
            !fs::read_dir(&*scratch)
                .unwrap()
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().contains(".corrupt.")),
            "not quarantined"
        );
        assert_eq!(loaded.claude_history_cutoff_unix_seconds, None);
        assert!(!loaded.claude_history_gate_loaded, "re-derived");
        assert!(
            loaded.claude_history_move_not_full,
            "malformed hold fails closed (K4)"
        );
        assert!(!loaded.claude_history_move_released);
    }
}

/// K4: after bootstrap, only the persisted move flag remembers the hold.
/// Keep an intact cutoff and gate marker, so nothing can re-derive the hold.
#[test]
fn malformed_move_hold_stays_held_with_an_intact_cutoff_after_bootstrap() {
    let scratch = crate::test_scratch::ScratchDir::new("history-move-hold-malformed");
    let path = scratch.join("index.json");
    let mut index = ScanIndex::default();
    index.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    index.save(&path).unwrap();
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["claude_history_move_not_full"] = json!("damaged");
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    let cutoff = loaded.claude_history_cutoff_unix_seconds;
    loaded.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(loaded.claude_no_list_policy, NoListPolicy::HoldMoveNotFull);
    assert_eq!(loaded.claude_history_cutoff_unix_seconds, cutoff);
    loaded.save(&path).unwrap();
    let mut reloaded = ScanIndex::load(&path).unwrap();
    reloaded.note_claude_history_cutoff(PriorHistory::Here, true, false);
    assert_eq!(
        reloaded.claude_no_list_policy,
        NoListPolicy::Pace,
        "explicit full still releases"
    );
}

/// K4: after bootstrap, only the persisted move flag remembers the hold.
/// Keep an intact cutoff and gate marker, so nothing can re-derive the hold.
#[test]
fn terminal_off_on_malformed_move_hold_stays_held_with_an_intact_cutoff_after_bootstrap() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let scratch = crate::test_scratch::ScratchDir::new("history-move-hold-malformed");
    let path = scratch.join("index.json");
    let mut index = ScanIndex::default();
    index.note_claude_history_cutoff(PriorHistory::Moved, false, true);
    index.save(&path).unwrap();
    let mut saved: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    saved["claude_history_move_not_full"] = json!("damaged");
    fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    let mut loaded = ScanIndex::load(&path).unwrap();
    let cutoff = loaded.claude_history_cutoff_unix_seconds;
    loaded.note_claude_history_cutoff(PriorHistory::Here, false, false);
    assert_eq!(loaded.claude_no_list_policy, NoListPolicy::HoldMoveNotFull);
    assert_eq!(loaded.claude_history_cutoff_unix_seconds, cutoff);
    loaded.save(&path).unwrap();
    let mut reloaded = ScanIndex::load(&path).unwrap();
    reloaded.note_claude_history_cutoff(PriorHistory::Here, true, false);
    assert_eq!(
        reloaded.claude_no_list_policy,
        NoListPolicy::Pace,
        "explicit full still releases"
    );
}

/// Owner B ruling 2: activating a revision with no history-policy row keeps
/// the previous active revision, raises one local alarm and counts it; with
/// a row it activates. The static release check above stays the second line.
#[test]
fn activation_without_a_policy_row_keeps_the_previous_revision_and_alarms() {
    with_max_gated_claude_revision(3, || {
        let mut index = ScanIndex::default();
        index.activate_effective_upload_body_witness_revision(2);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        // Per-pass state a refused activation must still reset (R6).
        index
            .effective_upload_body_witness_revision_excluded_source_files
            .insert("held-source".into());
        index.claude_history_emission.files.insert(
            "gated-source".into(),
            super::claude_history_upgrade::GatedHistory::default(),
        );
        let stamp = None;
        index
            .claude_reemission_exclusions
            .note_members_walked("walked-root", stamp);
        assert!(index
            .claude_reemission_exclusions
            .members_walked("walked-root", &stamp));
        let refused = local_count(LocalCount::ActivationRefused);
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            with_max_gated_claude_revision(2, || {
                index.activate_effective_upload_body_witness_revision(3);
            });
        });
        assert_eq!(index.active_effective_upload_body_witness_revision, 2);
        assert!(
            index.active_effective_upload_body_witness_revision_monotone,
            "the kept revision keeps its flag"
        );
        assert!(index
            .effective_upload_body_witness_revision_excluded_source_files
            .is_empty());
        assert!(index.claude_history_emission.files.is_empty());
        assert!(
            !index
                .claude_reemission_exclusions
                .members_walked("walked-root", &stamp),
            "begin_pass runs on a refused activation too"
        );
        assert_eq!(alarms.len(), 1, "{alarms:?}");
        assert_eq!(
            alarms[0]["stage"],
            "claude_history_revision_activation_refused"
        );
        assert_eq!(alarms[0]["counts"]["refused_revision"], 3);
        assert_eq!(alarms[0]["counts"]["kept_revision"], 2);
        assert_eq!(local_count(LocalCount::ActivationRefused), refused + 1);

        let ((), none) = crate::local_resource_diagnostics::capture(|| {
            index.activate_effective_upload_body_witness_revision(3);
        });
        assert_eq!(index.active_effective_upload_body_witness_revision, 3);
        assert!(none.is_empty());
        assert_eq!(local_count(LocalCount::ActivationRefused), refused + 1);
        let _ = crate::local_resource_diagnostics::capture(|| {
            index.activate_effective_upload_body_witness_revision(4);
        });
        assert_eq!(index.active_effective_upload_body_witness_revision, 3);
    });
}

/// Owner B ruling 2: activating a revision with no history-policy row keeps
/// the previous active revision, raises one local alarm and counts it; with
/// a row it activates. The static release check above stays the second line.
#[test]
fn terminal_off_on_activation_without_a_policy_row_keeps_the_previous_revision_and_alarms() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_max_gated_claude_revision(3, || {
        let mut index = ScanIndex::default();
        index.activate_effective_upload_body_witness_revision(2);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        // Per-pass state a refused activation must still reset (R6).
        index
            .effective_upload_body_witness_revision_excluded_source_files
            .insert("held-source".into());
        index.claude_history_emission.files.insert(
            "gated-source".into(),
            super::claude_history_upgrade::GatedHistory::default(),
        );
        let stamp = None;
        index
            .claude_reemission_exclusions
            .note_members_walked("walked-root", stamp);
        assert!(index
            .claude_reemission_exclusions
            .members_walked("walked-root", &stamp));
        let refused = local_count(LocalCount::ActivationRefused);
        let ((), alarms) = crate::local_resource_diagnostics::capture(|| {
            with_max_gated_claude_revision(2, || {
                index.activate_effective_upload_body_witness_revision(3);
            });
        });
        assert_eq!(index.active_effective_upload_body_witness_revision, 2);
        assert!(
            index.active_effective_upload_body_witness_revision_monotone,
            "the kept revision keeps its flag"
        );
        assert!(index
            .effective_upload_body_witness_revision_excluded_source_files
            .is_empty());
        assert!(index.claude_history_emission.files.is_empty());
        assert!(
            !index
                .claude_reemission_exclusions
                .members_walked("walked-root", &stamp),
            "begin_pass runs on a refused activation too"
        );
        assert_eq!(alarms.len(), 1, "{alarms:?}");
        assert_eq!(
            alarms[0]["stage"],
            "claude_history_revision_activation_refused"
        );
        assert_eq!(alarms[0]["counts"]["refused_revision"], 3);
        assert_eq!(alarms[0]["counts"]["kept_revision"], 2);
        assert_eq!(local_count(LocalCount::ActivationRefused), refused + 1);

        let ((), none) = crate::local_resource_diagnostics::capture(|| {
            index.activate_effective_upload_body_witness_revision(3);
        });
        assert_eq!(index.active_effective_upload_body_witness_revision, 3);
        assert!(none.is_empty());
        assert_eq!(local_count(LocalCount::ActivationRefused), refused + 1);
        let _ = crate::local_resource_diagnostics::capture(|| {
            index.activate_effective_upload_body_witness_revision(4);
        });
        assert_eq!(index.active_effective_upload_body_witness_revision, 3);
    });
}

/// Owner B ruling 3: the named re-owe only lowers, only below the active
/// revision, counts `history_reowed`, and leaves the file owed and gated: a
/// listed re-owed file is held, an unlisted one upgrades again.
#[test]
fn re_owe_lowers_a_stamp_and_the_file_is_owed_and_gated_again() {
    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-reowe", 2);
        let empty = support("history-gate-reowe-empty");
        fs::write(ReemissionExclusions::path(&empty), "").unwrap();
        index.load_claude_reemission_exclusions(&empty);
        let previous = index.clone();
        let mut upgraded = scan(&root, &mut index, "ctx-1", 3);
        let mut index = settle(&home, &previous, &mut upgraded, &mut index);
        assert_eq!(revisions(&index), vec![3; 4]);

        index.activate_effective_upload_body_witness_revision(3);
        let reowed = local_count(LocalCount::Reowed);
        let root_key = |slot: usize| {
            index
                .files
                .keys()
                .find(|key| key.ends_with(&format!("{}.jsonl", session(slot))))
                .unwrap()
                .clone()
        };
        let (listed, unlisted) = (root_key(1), root_key(0));
        assert!(!index.re_owe_effective_upload_body_witness_revision(&listed, 3));
        assert!(!index.re_owe_effective_upload_body_witness_revision(&listed, 4));
        assert!(index.re_owe_effective_upload_body_witness_revision(&listed, 2));
        assert!(index.re_owe_effective_upload_body_witness_revision(&unlisted, 2));
        assert!(!index.re_owe_effective_upload_body_witness_revision("missing", 1));
        assert_eq!(local_count(LocalCount::Reowed), reowed + 2);
        assert_eq!(
            index.files[&listed].effective_upload_body_witness_revision,
            2
        );

        let support = support("history-gate-reowe-listed");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(1))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        let previous = index.clone();
        let mut result = scan(&root, &mut index, "ctx-1", 3);
        let listed_file = previous.files[&listed].source_file_fingerprint.clone();
        let settled = settle(&home, &previous, &mut result, &mut index);
        assert!(
            result
                .snapshots
                .iter()
                .any(|item| item.source_session_id == session(0)),
            "the unlisted re-owed root upgrades again"
        );
        assert!(result
            .snapshots
            .iter()
            .all(|item| item.source_file_fingerprint.as_deref() != Some(listed_file.as_str())));
        assert_eq!(
            settled.files[&listed].effective_upload_body_witness_revision,
            2
        );
        assert_eq!(
            settled.files[&unlisted].effective_upload_body_witness_revision,
            3
        );
        let _ = fs::remove_dir_all(home);
    });
}

/// Owner B ruling 3: the named re-owe only lowers, only below the active
/// revision, counts `history_reowed`, and leaves the file owed and gated: a
/// listed re-owed file is held, an unlisted one upgrades again.
#[test]
fn terminal_off_on_re_owe_lowers_a_stamp_and_the_file_is_owed_and_gated_again() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-reowe", 2);
        let empty = support("history-gate-reowe-empty");
        fs::write(ReemissionExclusions::path(&empty), "").unwrap();
        index.load_claude_reemission_exclusions(&empty);
        let previous = index.clone();
        let mut upgraded = scan(&root, &mut index, "ctx-1", 3);
        let mut index = settle(&home, &previous, &mut upgraded, &mut index);
        assert_eq!(revisions(&index), vec![3; 4]);

        index.activate_effective_upload_body_witness_revision(3);
        let reowed = local_count(LocalCount::Reowed);
        let root_key = |slot: usize| {
            index
                .files
                .keys()
                .find(|key| key.ends_with(&format!("{}.jsonl", session(slot))))
                .unwrap()
                .clone()
        };
        let (listed, unlisted) = (root_key(1), root_key(0));
        assert!(!index.re_owe_effective_upload_body_witness_revision(&listed, 3));
        assert!(!index.re_owe_effective_upload_body_witness_revision(&listed, 4));
        assert!(index.re_owe_effective_upload_body_witness_revision(&listed, 2));
        assert!(index.re_owe_effective_upload_body_witness_revision(&unlisted, 2));
        assert!(!index.re_owe_effective_upload_body_witness_revision("missing", 1));
        assert_eq!(local_count(LocalCount::Reowed), reowed + 2);
        assert_eq!(
            index.files[&listed].effective_upload_body_witness_revision,
            2
        );

        let support = support("history-gate-reowe-listed");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(1))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        let previous = index.clone();
        let mut result = scan(&root, &mut index, "ctx-1", 3);
        let listed_file = previous.files[&listed].source_file_fingerprint.clone();
        let settled = settle(&home, &previous, &mut result, &mut index);
        assert!(
            result
                .snapshots
                .iter()
                .any(|item| item.source_session_id == session(0)),
            "the unlisted re-owed root upgrades again"
        );
        assert!(result
            .snapshots
            .iter()
            .all(|item| item.source_file_fingerprint.as_deref() != Some(listed_file.as_str())));
        assert_eq!(
            settled.files[&listed].effective_upload_body_witness_revision,
            2
        );
        assert_eq!(
            settled.files[&unlisted].effective_upload_body_witness_revision,
            3
        );
        let _ = fs::remove_dir_all(home);
    });
}

fn append_root_response(root: &Path, slot: usize) {
    let session = session(slot);
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(root.join(format!("{session}.jsonl")))
        .unwrap();
    writeln!(
        file,
        "{}",
        json!({
            "timestamp": "2026-08-23T18:30:00Z",
            "type": "assistant",
            "sessionId": session,
            "requestId": format!("request-{slot}-root-2"),
            "message": {
                "id": format!("message-{slot}-root-2"),
                "model": "claude-haiku-4-5",
                "usage": {"input_tokens": 10, "output_tokens": 1}
            }
        })
    )
    .unwrap();
}

/// Stand-in for MONEY's emitter (#699), which builds request-owned items
/// after the emission seam: one literal copy of every item. It ignores
/// #699's own protected-root skip, so only the gate removes it.
fn mint_request_owned_copies(snapshots: &mut Vec<SnapshotItem>) {
    let copies = snapshots
        .iter()
        .map(|item| {
            let mut copy = item.clone();
            copy.usage_accounting_contract = Some(REQUEST_OWNED_USAGE_CONTRACT.into());
            copy
        })
        .collect::<Vec<_>>();
    snapshots.extend(copies);
}

/// SOURCE Amendment 14 at the fold: under revision 3 a listed root's genuine
/// change emits its ordinary body, loses only its request-owned items, does
/// not stamp 3, counts `listed_literal`, and is owed and held next cycle.
/// Its unchanged member stays held history.
#[test]
fn listed_genuine_change_under_revision_three_loses_only_its_literal() {
    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-literal", 2);
        let support = support("history-gate-literal-support");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(1))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        append_root_response(&root, 1);
        let denied = local_count(LocalCount::ListedLiteralDenied);
        let previous = index.clone();
        let mut result = scan(&root, &mut index, "ctx-1", 3);
        assert_eq!(local_count(LocalCount::ListedLiteralDenied), denied + 1);
        mint_request_owned_copies(&mut result.snapshots);
        let mut resend = result.snapshots.clone();
        index.retain_claude_history_emission_permitted(&mut resend);
        let settled = settle(&home, &previous, &mut result, &mut index);
        for emitted in [&resend, &result.snapshots] {
            let listed = emitted
                .iter()
                .filter(|item| item.source_session_id == session(1))
                .collect::<Vec<_>>();
            assert_eq!(listed.len(), 1, "the listed root's ordinary body only");
            assert_ne!(
                listed[0].usage_accounting_contract.as_deref(),
                Some(REQUEST_OWNED_USAGE_CONTRACT)
            );
            assert!(emitted
                .iter()
                .any(|item| item.source_session_id == session(0)
                    && item.usage_accounting_contract.as_deref()
                        == Some(REQUEST_OWNED_USAGE_CONTRACT)));
        }
        for (key, entry) in &settled.files {
            let listed = claude_index_path_family_member(Path::new(key))
                .is_some_and(|(family, _)| family == session(1));
            assert_eq!(
                entry.effective_upload_body_witness_revision,
                if listed { 1 } else { 3 },
                "{key}"
            );
        }

        let mut index = settled;
        index.load_claude_reemission_exclusions(&support);
        let previous = index.clone();
        let listed_files = previous
            .files
            .iter()
            .filter(|(key, _)| {
                claude_index_path_family_member(Path::new(key))
                    .is_some_and(|(family, _)| family == session(1))
            })
            .map(|(_, entry)| entry.source_file_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let mut next = scan(&root, &mut index, "ctx-1", 3);
        let settled = settle(&home, &previous, &mut next, &mut index);
        // The fold harness never settles the upload context, so the settled
        // family re-syncs; the listed family is owed and held.
        assert!(
            next.snapshots.iter().all(|item| item
                .source_file_fingerprint
                .as_ref()
                .is_some_and(|file| !listed_files.contains(file))),
            "owed and held, never settled at 3"
        );
        assert!(settled
            .files
            .iter()
            .filter(|(key, _)| claude_index_path_family_member(Path::new(key))
                .is_some_and(|(family, _)| family == session(1)))
            .all(|(_, entry)| entry.effective_upload_body_witness_revision == 1));
        let _ = fs::remove_dir_all(home);
    });
}

/// SOURCE Amendment 14 at the fold: under revision 3 a listed root's genuine
/// change emits its ordinary body, loses only its request-owned items, does
/// not stamp 3, counts `listed_literal`, and is owed and held next cycle.
/// Its unchanged member stays held history.
#[test]
fn terminal_off_on_listed_genuine_change_under_revision_three_loses_only_its_literal() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-literal", 2);
        let support = support("history-gate-literal-support");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(1))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        append_root_response(&root, 1);
        let denied = local_count(LocalCount::ListedLiteralDenied);
        let previous = index.clone();
        let mut result = scan(&root, &mut index, "ctx-1", 3);
        assert_eq!(local_count(LocalCount::ListedLiteralDenied), denied + 1);
        mint_request_owned_copies(&mut result.snapshots);
        let mut resend = result.snapshots.clone();
        index.retain_claude_history_emission_permitted(&mut resend);
        let settled = settle(&home, &previous, &mut result, &mut index);
        for emitted in [&resend, &result.snapshots] {
            let listed = emitted
                .iter()
                .filter(|item| item.source_session_id == session(1))
                .collect::<Vec<_>>();
            assert_eq!(listed.len(), 1, "the listed root's ordinary body only");
            assert_ne!(
                listed[0].usage_accounting_contract.as_deref(),
                Some(REQUEST_OWNED_USAGE_CONTRACT)
            );
            assert!(emitted
                .iter()
                .any(|item| item.source_session_id == session(0)
                    && item.usage_accounting_contract.as_deref()
                        == Some(REQUEST_OWNED_USAGE_CONTRACT)));
        }
        for (key, entry) in &settled.files {
            let listed = claude_index_path_family_member(Path::new(key))
                .is_some_and(|(family, _)| family == session(1));
            assert_eq!(
                entry.effective_upload_body_witness_revision,
                if listed { 1 } else { 3 },
                "{key}"
            );
        }

        let mut index = settled;
        index.load_claude_reemission_exclusions(&support);
        let previous = index.clone();
        let listed_files = previous
            .files
            .iter()
            .filter(|(key, _)| {
                claude_index_path_family_member(Path::new(key))
                    .is_some_and(|(family, _)| family == session(1))
            })
            .map(|(_, entry)| entry.source_file_fingerprint.clone())
            .collect::<BTreeSet<_>>();
        let mut next = scan(&root, &mut index, "ctx-1", 3);
        let settled = settle(&home, &previous, &mut next, &mut index);
        // The fold harness never settles the upload context, so the settled
        // family re-syncs; the listed family is owed and held.
        assert!(
            next.snapshots.iter().all(|item| item
                .source_file_fingerprint
                .as_ref()
                .is_some_and(|file| !listed_files.contains(file))),
            "owed and held, never settled at 3"
        );
        assert!(settled
            .files
            .iter()
            .filter(|(key, _)| claude_index_path_family_member(Path::new(key))
                .is_some_and(|(family, _)| family == session(1)))
            .all(|(_, entry)| entry.effective_upload_body_witness_revision == 1));
        let _ = fs::remove_dir_all(home);
    });
}

/// F5: a same-size file whose mtime alone moved is not a genuine change. A
/// listed root touched this way is held history under revision 3: nothing
/// emits and its tuple and stamp stay.
#[test]
fn a_touched_listed_file_is_held_history_not_a_genuine_change() {
    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-touched", 1);
        let support = support("history-gate-touched-support");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(0))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        let path = root.join(format!("{}.jsonl", session(0)));
        let size = fs::metadata(&path).unwrap().len();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(120))
            .unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), size);
        let previous = index.clone();
        let denied = local_count(LocalCount::ListedLiteralDenied);
        let mut result = scan(&root, &mut index, "ctx-1", 3);
        let settled = settle(&home, &previous, &mut result, &mut index);
        assert!(result.snapshots.is_empty(), "held, not ordinary sync");
        assert_eq!(local_count(LocalCount::ListedLiteralDenied), denied);
        assert_eq!(revisions(&settled), vec![1; 2]);
        let suffix = format!("{}.jsonl", session(0));
        let key = settled
            .files
            .keys()
            .find(|key| key.ends_with(&suffix))
            .unwrap();
        assert_eq!(
            settled.files[key].last_snapshot_fingerprint,
            previous.files[key].last_snapshot_fingerprint
        );
        let _ = fs::remove_dir_all(home);
    });
}

/// F5: a same-size file whose mtime alone moved is not a genuine change. A
/// listed root touched this way is held history under revision 3: nothing
/// emits and its tuple and stamp stay.
#[test]
fn terminal_off_on_a_touched_listed_file_is_held_history_not_a_genuine_change() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-touched", 1);
        let support = support("history-gate-touched-support");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(0))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        let path = root.join(format!("{}.jsonl", session(0)));
        let size = fs::metadata(&path).unwrap().len();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(120))
            .unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), size);
        let previous = index.clone();
        let denied = local_count(LocalCount::ListedLiteralDenied);
        let mut result = scan(&root, &mut index, "ctx-1", 3);
        let settled = settle(&home, &previous, &mut result, &mut index);
        assert!(result.snapshots.is_empty(), "held, not ordinary sync");
        assert_eq!(local_count(LocalCount::ListedLiteralDenied), denied);
        assert_eq!(revisions(&settled), vec![1; 2]);
        let suffix = format!("{}.jsonl", session(0));
        let key = settled
            .files
            .keys()
            .find(|key| key.ends_with(&suffix))
            .unwrap();
        assert_eq!(
            settled.files[key].last_snapshot_fingerprint,
            previous.files[key].last_snapshot_fingerprint
        );
        let _ = fs::remove_dir_all(home);
    });
}

/// SOURCE h732 C2: a literal item and a covering stamp for a listed root that
/// is not a candidate this cycle (a settlement, a re-offer outside the scan
/// hints, a #692 in-place resend): no literal of the listed family passes
/// either upload path and it never stamps revision 3, while an unlisted
/// family keeps both. A paused list denies every literal and every
/// revision-3 stamp.
#[test]
fn a_listed_root_outside_this_cycle_gets_no_literal_and_no_revision_three() {
    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-c2", 2);
        // Items with the indexed source files, as a resend would carry them.
        let mut probe = index.clone();
        let mut items = scan(&root, &mut probe, "ctx-probe", 1).snapshots;
        assert_eq!(items.len(), 4);
        mint_request_owned_copies(&mut items);
        let support = support("history-gate-c2-support");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(1))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        // No file was decided this cycle.
        index.claude_history_emission = HistoryEmission::default();
        let listed_sources = index
            .files
            .iter()
            .filter(|(key, _)| key.contains(&session(1)))
            .map(|(_, entry)| entry.source_file_fingerprint.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(listed_sources.len(), 2);
        let literals = |items: &[SnapshotItem]| {
            items
                .iter()
                .filter(|item| {
                    item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_USAGE_CONTRACT)
                })
                .map(|item| item.source_file_fingerprint.clone().unwrap())
                .collect::<Vec<_>>()
        };

        let mut resend = items.clone();
        index.retain_claude_history_emission_permitted(&mut resend);
        let mut seam = items.clone();
        index.veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut seam);
        for kept in [&resend, &seam] {
            assert_eq!(kept.len(), 6, "every body plus the unlisted literals");
            let kept_literals = literals(kept.as_slice());
            assert_eq!(kept_literals.len(), 2, "{kept_literals:?}");
            assert!(kept_literals
                .iter()
                .all(|source| !listed_sources.contains(source)));
        }
        for (key, entry) in index.files.clone() {
            let listed = listed_sources.contains(&entry.source_file_fingerprint);
            assert_eq!(
                index.stamp_effective_upload_body_witness_revision(
                    &key,
                    &entry.source_file_fingerprint,
                    3
                ),
                !listed,
                "{key}"
            );
        }
        for (key, entry) in &index.files {
            let expected = if listed_sources.contains(&entry.source_file_fingerprint) {
                1
            } else {
                3
            };
            assert_eq!(
                entry.effective_upload_body_witness_revision, expected,
                "{key}"
            );
        }

        // The list goes missing after install: paused, so no literal passes
        // and nothing stamps revision 3.
        fs::remove_file(ReemissionExclusions::path(&support)).unwrap();
        index.load_claude_reemission_exclusions(&support);
        assert!(index.claude_reemission_exclusions.pauses_adoption());
        let mut paused = items.clone();
        index.retain_claude_history_emission_permitted(&mut paused);
        assert!(literals(paused.as_slice()).is_empty());
        assert_eq!(paused.len(), 4, "the bodies stay");
        let (key, entry) = index
            .files
            .iter()
            .find(|(_, entry)| !listed_sources.contains(&entry.source_file_fingerprint))
            .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
            .unwrap();
        index.re_owe_effective_upload_body_witness_revision(&key, 2);
        assert!(!index.stamp_effective_upload_body_witness_revision(&key, &entry, 3));
        assert_eq!(index.files[&key].effective_upload_body_witness_revision, 2);
        let _ = fs::remove_dir_all(home);
    });
}

/// SOURCE h732 C2: a literal item and a covering stamp for a listed root that
/// is not a candidate this cycle (a settlement, a re-offer outside the scan
/// hints, a #692 in-place resend): no literal of the listed family passes
/// either upload path and it never stamps revision 3, while an unlisted
/// family keeps both. A paused list denies every literal and every
/// revision-3 stamp.
#[test]
#[ignore = "terminal-off ON-readiness: C6"]
fn terminal_off_on_a_listed_root_outside_this_cycle_gets_no_literal_and_no_revision_three() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    with_max_gated_claude_revision(3, || {
        let (home, root, mut index) = families("history-gate-c2", 2);
        // Items with the indexed source files, as a resend would carry them.
        let mut probe = index.clone();
        let mut items = scan(&root, &mut probe, "ctx-probe", 1).snapshots;
        assert_eq!(items.len(), 4);
        mint_request_owned_copies(&mut items);
        let support = support("history-gate-c2-support");
        fs::write(
            ReemissionExclusions::path(&support),
            format!("{}\n", digest(&session(1))),
        )
        .unwrap();
        index.load_claude_reemission_exclusions(&support);
        index.activate_effective_upload_body_witness_revision(3);
        index.adopt_effective_upload_body_witness_revision_monotonically();
        // No file was decided this cycle.
        index.claude_history_emission = HistoryEmission::default();
        let listed_sources = index
            .files
            .iter()
            .filter(|(key, _)| key.contains(&session(1)))
            .map(|(_, entry)| entry.source_file_fingerprint.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(listed_sources.len(), 2);
        let literals = |items: &[SnapshotItem]| {
            items
                .iter()
                .filter(|item| {
                    item.usage_accounting_contract.as_deref() == Some(REQUEST_OWNED_USAGE_CONTRACT)
                })
                .map(|item| item.source_file_fingerprint.clone().unwrap())
                .collect::<Vec<_>>()
        };

        let mut resend = items.clone();
        index.retain_claude_history_emission_permitted(&mut resend);
        let mut seam = items.clone();
        index.veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut seam);
        for kept in [&resend, &seam] {
            assert_eq!(kept.len(), 6, "every body plus the unlisted literals");
            let kept_literals = literals(kept.as_slice());
            assert_eq!(kept_literals.len(), 2, "{kept_literals:?}");
            assert!(kept_literals
                .iter()
                .all(|source| !listed_sources.contains(source)));
        }
        for (key, entry) in index.files.clone() {
            let listed = listed_sources.contains(&entry.source_file_fingerprint);
            assert_eq!(
                index.stamp_effective_upload_body_witness_revision(
                    &key,
                    &entry.source_file_fingerprint,
                    3
                ),
                !listed,
                "{key}"
            );
        }
        for (key, entry) in &index.files {
            let expected = if listed_sources.contains(&entry.source_file_fingerprint) {
                1
            } else {
                3
            };
            assert_eq!(
                entry.effective_upload_body_witness_revision, expected,
                "{key}"
            );
        }

        // The list goes missing after install: paused, so no literal passes
        // and nothing stamps revision 3.
        fs::remove_file(ReemissionExclusions::path(&support)).unwrap();
        index.load_claude_reemission_exclusions(&support);
        assert!(index.claude_reemission_exclusions.pauses_adoption());
        let mut paused = items.clone();
        index.retain_claude_history_emission_permitted(&mut paused);
        assert!(literals(paused.as_slice()).is_empty());
        assert_eq!(paused.len(), 4, "the bodies stay");
        let (key, entry) = index
            .files
            .iter()
            .find(|(_, entry)| !listed_sources.contains(&entry.source_file_fingerprint))
            .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
            .unwrap();
        index.re_owe_effective_upload_body_witness_revision(&key, 2);
        assert!(!index.stamp_effective_upload_body_witness_revision(&key, &entry, 3));
        assert_eq!(index.files[&key].effective_upload_body_witness_revision, 2);
        let _ = fs::remove_dir_all(home);
    });
}

/// S-726-1: under revision 2 no request-owned literal reaches an upload
/// path, for a listed root or an unlisted one, decided this cycle or not:
/// both the emission check and the retain hook drop every literal item and
/// keep every ordinary body the gate does not hold.
#[test]
fn revision_two_drops_every_request_owned_literal_on_both_upload_paths() {
    let (home, root, mut index) = families("history-gate-s726", 2);
    // Items with the indexed source files, both families.
    let mut probe = index.clone();
    let mut items = scan(&root, &mut probe, "ctx-probe", 1).snapshots;
    assert_eq!(items.len(), 4);
    mint_request_owned_copies(&mut items);
    let support = support("history-gate-s726-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&session(1))),
    )
    .unwrap();
    index.load_claude_reemission_exclusions(&support);
    let listed_sources = index
        .files
        .iter()
        .filter(|(key, _)| key.contains(&session(1)))
        .map(|(_, entry)| entry.source_file_fingerprint.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(listed_sources.len(), 2);

    // Not decided this cycle: a fresh revision-2 pass.
    let mut outside = index.clone();
    outside.activate_effective_upload_body_witness_revision(2);
    outside.adopt_effective_upload_body_witness_revision_monotonically();
    assert!(outside.claude_history_emission.files.is_empty());
    // Decided this cycle: a revision-2 scan of both families.
    let mut decided = index.clone();
    let _ = scan(&root, &mut decided, "ctx-2", 2);
    for (label, cycle) in [("outside", &mut outside), ("decided", &mut decided)] {
        let bodies = items
            .iter()
            .filter(|item| {
                item.usage_accounting_contract.as_deref() != Some(REQUEST_OWNED_USAGE_CONTRACT)
            })
            .filter(|item| {
                cycle
                    .claude_history_emission_held(item.source_file_fingerprint.as_deref().unwrap())
                    .is_none()
            })
            .count();
        let mut resend = items.clone();
        cycle.retain_claude_history_emission_permitted(&mut resend);
        let mut seam = items.clone();
        cycle.veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut seam);
        for kept in [&resend, &seam] {
            assert!(
                kept.iter()
                    .all(|item| item.usage_accounting_contract.as_deref()
                        != Some(REQUEST_OWNED_USAGE_CONTRACT)),
                "{label}: no literal, listed or unlisted"
            );
            assert_eq!(kept.len(), bodies, "{label}: the permitted bodies stay");
        }
    }
    assert_eq!(
        items
            .iter()
            .filter(|item| item.usage_accounting_contract.as_deref()
                == Some(REQUEST_OWNED_USAGE_CONTRACT))
            .filter(
                |item| !listed_sources.contains(item.source_file_fingerprint.as_deref().unwrap())
            )
            .count(),
        2,
        "the unlisted family's literals were offered too"
    );
    let _ = fs::remove_dir_all(home);
}

/// S-726-1: under revision 2 no request-owned literal reaches an upload
/// path, for a listed root or an unlisted one, decided this cycle or not:
/// both the emission check and the retain hook drop every literal item and
/// keep every ordinary body the gate does not hold.
#[test]
#[ignore = "terminal-off ON-readiness: C6"]
fn terminal_off_on_revision_two_drops_every_request_owned_literal_on_both_upload_paths() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let (home, root, mut index) = families("history-gate-s726", 2);
    // Items with the indexed source files, both families.
    let mut probe = index.clone();
    let mut items = scan(&root, &mut probe, "ctx-probe", 1).snapshots;
    assert_eq!(items.len(), 4);
    mint_request_owned_copies(&mut items);
    let support = support("history-gate-s726-support");
    fs::write(
        ReemissionExclusions::path(&support),
        format!("{}\n", digest(&session(1))),
    )
    .unwrap();
    index.load_claude_reemission_exclusions(&support);
    let listed_sources = index
        .files
        .iter()
        .filter(|(key, _)| key.contains(&session(1)))
        .map(|(_, entry)| entry.source_file_fingerprint.clone())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(listed_sources.len(), 2);

    // Not decided this cycle: a fresh revision-2 pass.
    let mut outside = index.clone();
    outside.activate_effective_upload_body_witness_revision(2);
    outside.adopt_effective_upload_body_witness_revision_monotonically();
    assert!(outside.claude_history_emission.files.is_empty());
    // Decided this cycle: a revision-2 scan of both families.
    let mut decided = index.clone();
    let _ = scan(&root, &mut decided, "ctx-2", 2);
    for (label, cycle) in [("outside", &mut outside), ("decided", &mut decided)] {
        let bodies = items
            .iter()
            .filter(|item| {
                item.usage_accounting_contract.as_deref() != Some(REQUEST_OWNED_USAGE_CONTRACT)
            })
            .filter(|item| {
                cycle
                    .claude_history_emission_held(item.source_file_fingerprint.as_deref().unwrap())
                    .is_none()
            })
            .count();
        let mut resend = items.clone();
        cycle.retain_claude_history_emission_permitted(&mut resend);
        let mut seam = items.clone();
        cycle.veto_claude_history_emission(SnapshotSource::ClaudeCode, &mut seam);
        for kept in [&resend, &seam] {
            assert!(
                kept.iter()
                    .all(|item| item.usage_accounting_contract.as_deref()
                        != Some(REQUEST_OWNED_USAGE_CONTRACT)),
                "{label}: no literal, listed or unlisted"
            );
            assert_eq!(kept.len(), bodies, "{label}: the permitted bodies stay");
        }
    }
    assert_eq!(
        items
            .iter()
            .filter(|item| item.usage_accounting_contract.as_deref()
                == Some(REQUEST_OWNED_USAGE_CONTRACT))
            .filter(
                |item| !listed_sources.contains(item.source_file_fingerprint.as_deref().unwrap())
            )
            .count(),
        2,
        "the unlisted family's literals were offered too"
    );
    let _ = fs::remove_dir_all(home);
}

/// Copies that share a copied request are cross-family duplicates. Under a
/// duplicate fence that stays closed the witness is cleared at every complete
/// census, so a duplicate the census detects compared as changed against
/// nothing and re-armed its owners: the copies were read again on every walk.
/// Read once (here: re-armed while the fence is closed), they now settle and
/// two complete walks after read none of them. A real append to one copy is
/// still read once under the closed fence, and once the fence's liveness
/// re-arm is due, a whole covered walk reopens the fence and the appended
/// request stays in the accepted bodies exactly once, across pages and a
/// reload. Walks span two pages.
#[test]
fn copies_read_under_a_closed_duplicate_fence_settle_after_one_walk() {
    use std::cell::{Cell, RefCell};
    use std::io::Write as _;
    /// The appended request's input tokens: the rest of the corpus sums to
    /// less than one of them, so the accepted total counts it.
    const APPENDED_INPUT: u64 = 1_000_000;
    let root = crate::test_scratch::unique_path("ottto-closed-fence-copies");
    fs::create_dir_all(&root).unwrap();
    let line = |session: &str, request: &str, at: &str, input: u64| {
        format!(
            "{}\n",
            json!({
                "timestamp": at,
                "type": "assistant",
                "sessionId": session,
                "requestId": request,
                "message": {
                    "id": format!("msg-{request}"),
                    "model": "claude-haiku-4-5",
                    "usage": {"input_tokens": input, "output_tokens": 1}
                }
            })
        )
    };
    let source = session(1);
    fs::write(
        root.join(format!("{source}.jsonl")),
        line(&source, "req-a", "2026-08-20T09:00:00Z", 10)
            + &line(&source, "req-b", "2026-08-20T09:01:00Z", 10),
    )
    .unwrap();
    let copies = [session(2), session(3)];
    for (n, copy) in copies.iter().enumerate() {
        fs::write(
            root.join(format!("{copy}.jsonl")),
            line(copy, "req-a", "2026-08-20T09:00:00Z", 10)
                + &line(copy, &format!("req-own-{n}"), "2026-08-20T09:05:00Z", 10),
        )
        .unwrap();
    }
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    // Minutes after 10:00 on the census clock.
    let minute = Cell::new(0_u32);
    // Last accepted body per session: (fingerprint, input tokens).
    let accepted = RefCell::new(BTreeMap::<String, (String, u64)>::new());
    // One page of two files: scan, fold, finalize, and accept every body
    // the page sends, as the server does.
    let page = |index: &mut ScanIndex| {
        minute.set(minute.get() + 1);
        let at = format!(
            "2026-08-20T{:02}:{:02}:00Z",
            10 + minute.get() / 60,
            minute.get() % 60
        );
        let mut result = scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            &at,
            BACKFILL_WINDOW_DAYS,
            2,
            true,
        )
        .unwrap();
        let window = result.census_window_end.clone();
        apply_claude_reported_usage_with_index(
            &mut result.snapshots,
            &api,
            &trace,
            index,
            result.census_complete,
            &window,
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, index);
        let fingerprints = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&fingerprints);
        let mut accepted = accepted.borrow_mut();
        for item in &result.snapshots {
            accepted.insert(
                item.source_session_id.clone(),
                (item.snapshot_fingerprint.clone(), item.input_tokens),
            );
        }
        result
    };
    // Whole walks: per walk, the files it reads, its pages, and the input
    // tokens each session it sends reports.
    #[derive(Debug, Default)]
    struct Walk {
        reads: usize,
        pages: usize,
        sent: BTreeMap<String, u64>,
    }
    let walks = |index: &mut ScanIndex, count: usize| {
        let (mut done, mut current, mut pages) = (Vec::new(), Walk::default(), 0);
        while done.len() < count {
            pages += 1;
            assert!(pages <= 8 * count, "the walks complete: {done:?}");
            let result = page(index);
            current.reads += result.scanned_file_count;
            current.pages += 1;
            for item in &result.snapshots {
                current
                    .sent
                    .insert(item.source_session_id.clone(), item.input_tokens);
            }
            if result.census_complete {
                done.push(std::mem::take(&mut current));
            }
        }
        done
    };
    let reads = |walks: &[Walk]| walks.iter().map(|walk| walk.reads).collect::<Vec<_>>();
    let accepted_total = || {
        accepted
            .borrow()
            .values()
            .map(|(_, input)| input)
            .sum::<u64>()
    };
    let mut index = ScanIndex::default();
    let mut settle = Vec::new();
    while settle.last() != Some(&0) {
        assert!(settle.len() < 6, "the corpus settles: {settle:?}");
        settle.extend(reads(&walks(&mut index, 1)));
    }
    assert_eq!(settle[0], 3, "the first walk reads every file: {settle:?}");

    // Close the fence (its liveness re-arm not due) and re-arm the copies,
    // as the switch-on re-read does.
    index.claude_duplicate_request_owners.clear();
    index.claude_duplicate_request_witness_overflowed = true;
    index.claude_duplicate_fence_next_full_rearm_unix_seconds =
        rfc3339_unix_seconds("2026-08-20T23:00:00Z");
    for copy in &copies {
        index
            .files
            .get_mut(&local_index_key(&root.join(format!("{copy}.jsonl"))))
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    let closed = walks(&mut index, 3);
    assert!(
        index.claude_duplicate_request_witness_overflowed,
        "the fence stays closed: only the copies were read"
    );
    assert_eq!(
        reads(&closed),
        [2, 0, 0],
        "the copies are read once, then two complete walks read none: {closed:?}"
    );

    // A real change under the closed fence: append a request to the first
    // copy (on the walk's first page); nothing else is touched.
    let appended = &copies[0];
    fs::OpenOptions::new()
        .append(true)
        .open(root.join(format!("{appended}.jsonl")))
        .unwrap()
        .write_all(
            line(
                appended,
                "req-appended",
                "2026-08-20T09:30:00Z",
                APPENDED_INPUT,
            )
            .as_bytes(),
        )
        .unwrap();
    let deadline = index.claude_duplicate_fence_next_full_rearm_unix_seconds;
    let changed = walks(&mut index, 3);
    assert!(
        index.claude_duplicate_request_witness_overflowed,
        "the fence stays closed through the append: {changed:?}"
    );
    assert_eq!(
        index.claude_duplicate_fence_next_full_rearm_unix_seconds, deadline,
        "the liveness deadline is untouched"
    );
    assert_eq!(
        reads(&changed),
        [1, 0, 0],
        "only the appended copy is read, then the copies settle again: {changed:?}"
    );
    let sent = changed[0].sent.get(appended).copied().unwrap_or(0);
    assert!(
        sent >= APPENDED_INPUT,
        "the appended request is in the sent body: {changed:?}"
    );
    assert!(
        changed[1..].iter().all(|walk| walk.sent.is_empty()),
        "settled walks send nothing: {changed:?}"
    );
    assert_eq!(
        accepted_total() / APPENDED_INPUT,
        1,
        "the appended request is accepted once: {:?}",
        accepted.borrow()
    );

    // Recovery: past the deadline the liveness full re-arm runs, a whole
    // covered walk reopens the fence, and the walks settle.
    minute.set(13 * 60);
    let mut recovery = Vec::new();
    while index.claude_duplicate_request_witness_overflowed {
        assert!(recovery.len() < 6, "the fence reopens: {recovery:?}");
        recovery.extend(walks(&mut index, 1));
    }
    assert!(
        recovery
            .iter()
            .any(|walk| walk.reads == 3 && walk.pages > 1),
        "the full re-arm reads every file across pages: {recovery:?}"
    );
    assert_eq!(
        index.claude_duplicate_fence_next_full_rearm_unix_seconds,
        None
    );
    let mut after = Vec::new();
    while after.last().map(|walk: &Walk| walk.reads) != Some(0) {
        assert!(after.len() < 4, "the open fence settles: {after:?}");
        after.extend(walks(&mut index, 1));
    }
    assert!(
        !index.claude_duplicate_request_witness_overflowed,
        "the fence stays open: {after:?}"
    );
    assert!(
        after.last().unwrap().sent.is_empty(),
        "a settled walk sends nothing: {after:?}"
    );
    assert_eq!(
        accepted_total() / APPENDED_INPUT,
        1,
        "accepted once after reopening: {recovery:?} {after:?} {:?}",
        accepted.borrow()
    );
    assert!(
        accepted.borrow()[appended].1 >= APPENDED_INPUT,
        "the appended copy's accepted body keeps the request: {:?}",
        accepted.borrow()
    );

    // The accepted checkpoint survives a save and reload: nothing is read
    // or sent again, and the appended copy's accepted body is still current.
    let path = root.join("scan-index.json");
    index.save(&path).unwrap();
    let mut index = ScanIndex::load(&path).unwrap();
    let reloaded = walks(&mut index, 2);
    assert_eq!(reads(&reloaded), [0, 0], "{reloaded:?}");
    assert!(
        reloaded.iter().all(|walk| walk.sent.is_empty()),
        "a reload sends nothing again: {reloaded:?}"
    );
    assert!(!index.claude_duplicate_request_witness_overflowed);
    assert!(index
        .accepted_snapshot_fingerprints
        .contains(&accepted.borrow()[appended].0));
    assert_eq!(accepted_total() / APPENDED_INPUT, 1);
    let _ = fs::remove_dir_all(root);
}

/// Copies that share a copied request are cross-family duplicates. Under a
/// duplicate fence that stays closed the witness is cleared at every complete
/// census, so a duplicate the census detects compared as changed against
/// nothing and re-armed its owners: the copies were read again on every walk.
/// Read once (here: re-armed while the fence is closed), they now settle and
/// two complete walks after read none of them. A real append to one copy is
/// still read once under the closed fence, and once the fence's liveness
/// re-arm is due, a whole covered walk reopens the fence and the appended
/// request stays in the accepted bodies exactly once, across pages and a
/// reload. Walks span two pages.
#[test]
#[ignore = "terminal-off ON-readiness: P3"]
fn terminal_off_on_copies_read_under_a_closed_duplicate_fence_settle_after_one_walk() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use std::cell::{Cell, RefCell};
    use std::io::Write as _;
    /// The appended request's input tokens: the rest of the corpus sums to
    /// less than one of them, so the accepted total counts it.
    const APPENDED_INPUT: u64 = 1_000_000;
    let root = crate::test_scratch::unique_path("ottto-closed-fence-copies");
    fs::create_dir_all(&root).unwrap();
    let line = |session: &str, request: &str, at: &str, input: u64| {
        format!(
            "{}\n",
            json!({
                "timestamp": at,
                "type": "assistant",
                "sessionId": session,
                "requestId": request,
                "message": {
                    "id": format!("msg-{request}"),
                    "model": "claude-haiku-4-5",
                    "usage": {"input_tokens": input, "output_tokens": 1}
                }
            })
        )
    };
    let source = session(1);
    fs::write(
        root.join(format!("{source}.jsonl")),
        line(&source, "req-a", "2026-08-20T09:00:00Z", 10)
            + &line(&source, "req-b", "2026-08-20T09:01:00Z", 10),
    )
    .unwrap();
    let copies = [session(2), session(3)];
    for (n, copy) in copies.iter().enumerate() {
        fs::write(
            root.join(format!("{copy}.jsonl")),
            line(copy, "req-a", "2026-08-20T09:00:00Z", 10)
                + &line(copy, &format!("req-own-{n}"), "2026-08-20T09:05:00Z", 10),
        )
        .unwrap();
    }
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    // Minutes after 10:00 on the census clock.
    let minute = Cell::new(0_u32);
    // Last accepted body per session: (fingerprint, input tokens).
    let accepted = RefCell::new(BTreeMap::<String, (String, u64)>::new());
    // One page of two files: scan, fold, finalize, and accept every body
    // the page sends, as the server does.
    let page = |index: &mut ScanIndex| {
        minute.set(minute.get() + 1);
        let at = format!(
            "2026-08-20T{:02}:{:02}:00Z",
            10 + minute.get() / 60,
            minute.get() % 60
        );
        let mut result = scan_source_roots_with_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&root),
            index,
            &at,
            BACKFILL_WINDOW_DAYS,
            2,
            true,
        )
        .unwrap();
        let window = result.census_window_end.clone();
        apply_claude_reported_usage_with_index(
            &mut result.snapshots,
            &api,
            &trace,
            index,
            result.census_complete,
            &window,
        );
        finalize_scan_after_policy(SnapshotSource::ClaudeCode, &mut result, index);
        let fingerprints = result
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&fingerprints);
        let mut accepted = accepted.borrow_mut();
        for item in &result.snapshots {
            accepted.insert(
                item.source_session_id.clone(),
                (item.snapshot_fingerprint.clone(), item.input_tokens),
            );
        }
        result
    };
    // Whole walks: per walk, the files it reads, its pages, and the input
    // tokens each session it sends reports.
    #[derive(Debug, Default)]
    struct Walk {
        reads: usize,
        pages: usize,
        sent: BTreeMap<String, u64>,
    }
    let walks = |index: &mut ScanIndex, count: usize| {
        let (mut done, mut current, mut pages) = (Vec::new(), Walk::default(), 0);
        while done.len() < count {
            pages += 1;
            assert!(pages <= 8 * count, "the walks complete: {done:?}");
            let result = page(index);
            current.reads += result.scanned_file_count;
            current.pages += 1;
            for item in &result.snapshots {
                current
                    .sent
                    .insert(item.source_session_id.clone(), item.input_tokens);
            }
            if result.census_complete {
                done.push(std::mem::take(&mut current));
            }
        }
        done
    };
    let reads = |walks: &[Walk]| walks.iter().map(|walk| walk.reads).collect::<Vec<_>>();
    let accepted_total = || {
        accepted
            .borrow()
            .values()
            .map(|(_, input)| input)
            .sum::<u64>()
    };
    let mut index = ScanIndex::default();
    let mut settle = Vec::new();
    while settle.last() != Some(&0) {
        assert!(settle.len() < 6, "the corpus settles: {settle:?}");
        settle.extend(reads(&walks(&mut index, 1)));
    }
    assert_eq!(settle[0], 3, "the first walk reads every file: {settle:?}");

    // Close the fence (its liveness re-arm not due) and re-arm the copies,
    // as the switch-on re-read does.
    index.claude_duplicate_request_owners.clear();
    index.claude_duplicate_request_witness_overflowed = true;
    index.claude_duplicate_fence_next_full_rearm_unix_seconds =
        rfc3339_unix_seconds("2026-08-20T23:00:00Z");
    for copy in &copies {
        index
            .files
            .get_mut(&local_index_key(&root.join(format!("{copy}.jsonl"))))
            .unwrap()
            .source_file_fingerprint
            .clear();
    }
    let closed = walks(&mut index, 3);
    assert!(
        index.claude_duplicate_request_witness_overflowed,
        "the fence stays closed: only the copies were read"
    );
    assert_eq!(
        reads(&closed),
        [2, 0, 0],
        "the copies are read once, then two complete walks read none: {closed:?}"
    );

    // A real change under the closed fence: append a request to the first
    // copy (on the walk's first page); nothing else is touched.
    let appended = &copies[0];
    fs::OpenOptions::new()
        .append(true)
        .open(root.join(format!("{appended}.jsonl")))
        .unwrap()
        .write_all(
            line(
                appended,
                "req-appended",
                "2026-08-20T09:30:00Z",
                APPENDED_INPUT,
            )
            .as_bytes(),
        )
        .unwrap();
    let deadline = index.claude_duplicate_fence_next_full_rearm_unix_seconds;
    let changed = walks(&mut index, 3);
    assert!(
        index.claude_duplicate_request_witness_overflowed,
        "the fence stays closed through the append: {changed:?}"
    );
    assert_eq!(
        index.claude_duplicate_fence_next_full_rearm_unix_seconds, deadline,
        "the liveness deadline is untouched"
    );
    assert_eq!(
        reads(&changed),
        [1, 0, 0],
        "only the appended copy is read, then the copies settle again: {changed:?}"
    );
    let sent = changed[0].sent.get(appended).copied().unwrap_or(0);
    assert!(
        sent >= APPENDED_INPUT,
        "the appended request is in the sent body: {changed:?}"
    );
    assert!(
        changed[1..].iter().all(|walk| walk.sent.is_empty()),
        "settled walks send nothing: {changed:?}"
    );
    assert_eq!(
        accepted_total() / APPENDED_INPUT,
        1,
        "the appended request is accepted once: {:?}",
        accepted.borrow()
    );

    // Recovery: past the deadline the liveness full re-arm runs, a whole
    // covered walk reopens the fence, and the walks settle.
    minute.set(13 * 60);
    let mut recovery = Vec::new();
    while index.claude_duplicate_request_witness_overflowed {
        assert!(recovery.len() < 6, "the fence reopens: {recovery:?}");
        recovery.extend(walks(&mut index, 1));
    }
    assert!(
        recovery
            .iter()
            .any(|walk| walk.reads == 3 && walk.pages > 1),
        "the full re-arm reads every file across pages: {recovery:?}"
    );
    assert_eq!(
        index.claude_duplicate_fence_next_full_rearm_unix_seconds,
        None
    );
    let mut after = Vec::new();
    while after.last().map(|walk: &Walk| walk.reads) != Some(0) {
        assert!(after.len() < 4, "the open fence settles: {after:?}");
        after.extend(walks(&mut index, 1));
    }
    assert!(
        !index.claude_duplicate_request_witness_overflowed,
        "the fence stays open: {after:?}"
    );
    assert!(
        after.last().unwrap().sent.is_empty(),
        "a settled walk sends nothing: {after:?}"
    );
    assert_eq!(
        accepted_total() / APPENDED_INPUT,
        1,
        "accepted once after reopening: {recovery:?} {after:?} {:?}",
        accepted.borrow()
    );
    assert!(
        accepted.borrow()[appended].1 >= APPENDED_INPUT,
        "the appended copy's accepted body keeps the request: {:?}",
        accepted.borrow()
    );

    // The accepted checkpoint survives a save and reload: nothing is read
    // or sent again, and the appended copy's accepted body is still current.
    let path = root.join("scan-index.json");
    index.save(&path).unwrap();
    let mut index = ScanIndex::load(&path).unwrap();
    let reloaded = walks(&mut index, 2);
    assert_eq!(reads(&reloaded), [0, 0], "{reloaded:?}");
    assert!(
        reloaded.iter().all(|walk| walk.sent.is_empty()),
        "a reload sends nothing again: {reloaded:?}"
    );
    assert!(!index.claude_duplicate_request_witness_overflowed);
    assert!(index
        .accepted_snapshot_fingerprints
        .contains(&accepted.borrow()[appended].0));
    assert_eq!(accepted_total() / APPENDED_INPUT, 1);
    let _ = fs::remove_dir_all(root);
}

// R11: each refusal to skip has its own control. All receipts below come
// through the real validated uploader, never a synthetic persisted receipt.
#[test]
fn terminal_off_r11_current_exact_ack_skips_semantic_clear_and_base_keeps_it() {
    let _on = ClaudeTerminalOffForTest::enabled();
    assert!(claude_terminal_off());
    let (home, _, mut index) = families("r11-accepted", 1);
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, "ctx-1".into());
    index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
    assert!(index
        .files
        .iter()
        .all(|(key, entry)| terminal_off_stale_member_can_skip_clear(&index, key, entry)));
    for (key, entry) in &index.files {
        assert!(terminal_off_stale_member_can_skip_clear(&index, key, entry));
        let _base = KeepStaleClaudeFamilyRearmForTest::new();
        assert!(!terminal_off_stale_member_can_skip_clear(
            &index, key, entry
        ));
    }
    let mut changed = index.clone();
    changed.activate_file_upload_context(SnapshotSource::ClaudeCode, "ctx-2".into());
    for (key, entry) in &changed.files {
        assert!(!terminal_off_stale_member_can_skip_clear(
            &changed, key, entry
        ));
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn terminal_off_r11_ackless_member_keeps_semantic_clear() {
    let _on = ClaudeTerminalOffForTest::enabled();
    assert!(claude_terminal_off());
    let (home, _, mut index) = families("r11-ackless", 1);
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, "ctx-1".into());
    index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
    assert!(index
        .files
        .iter()
        .all(|(key, entry)| terminal_off_stale_member_can_skip_clear(&index, key, entry)));
    index.accepted_snapshot_fingerprints.clear();
    for (key, entry) in &index.files {
        assert!(!terminal_off_stale_member_can_skip_clear(
            &index, key, entry
        ));
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn terminal_off_r11_held_member_keeps_semantic_clear() {
    let _on = ClaudeTerminalOffForTest::enabled();
    assert!(claude_terminal_off());
    let (home, _, mut index) = families("r11-held", 1);
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, "ctx-1".into());
    index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
    assert!(index
        .files
        .iter()
        .all(|(key, entry)| terminal_off_stale_member_can_skip_clear(&index, key, entry)));
    index.claude_reemission_exclusions = ReemissionExclusions::with_state(ListState::Unreadable);
    for (key, entry) in &index.files {
        assert!(!terminal_off_stale_member_can_skip_clear(
            &index, key, entry
        ));
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn terminal_off_r11_listed_member_keeps_semantic_clear() {
    let _on = ClaudeTerminalOffForTest::enabled();
    assert!(claude_terminal_off());
    let (home, _, mut index) = families("r11-listed", 1);
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, "ctx-1".into());
    index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
    assert!(index
        .files
        .iter()
        .all(|(key, entry)| terminal_off_stale_member_can_skip_clear(&index, key, entry)));
    index.claude_reemission_exclusions =
        ReemissionExclusions::parse(format!("{}\n", digest(&session(0))).as_bytes());
    for (key, entry) in &index.files {
        assert!(!terminal_off_stale_member_can_skip_clear(
            &index, key, entry
        ));
    }
    let _ = fs::remove_dir_all(home);
}

#[test]
fn terminal_off_r11_no_list_held_member_keeps_semantic_clear() {
    let _on = ClaudeTerminalOffForTest::enabled();
    assert!(claude_terminal_off());
    let (home, _, mut index) = families("r11-no-list-held", 1);
    index.activate_file_upload_context(SnapshotSource::ClaudeCode, "ctx-1".into());
    index.claude_reemission_exclusions = ReemissionExclusions::parse(b"");
    assert!(index
        .files
        .iter()
        .all(|(key, entry)| terminal_off_stale_member_can_skip_clear(&index, key, entry)));
    index.claude_reemission_exclusions = ReemissionExclusions::with_state(ListState::NotInstalled);
    // Synthetic births must be old on every platform, independent of the
    // fixture file's real creation time on the branch Mac/Linux runner.
    with_no_list_cutoff(u64::MAX, || {
        for (key, entry) in &index.files {
            assert!(!terminal_off_stale_member_can_skip_clear(
                &index, key, entry
            ));
        }
    });
    let _ = fs::remove_dir_all(home);
}
