// The streamed Claude terminal over a real cold session (the state-v2
// money harness): sliced one family at a time it decides what one whole
// visit decides, it installs only the page's families, a changed token
// refuses the sweep, and a refused terminal keeps the census open with its
// traversal. The fixture is the legacy fork: the child's first request is
// the parent's `req_shared`, so the two families share a request and a
// legacy divergent prefix, in two different slices.
use super::claude_request_identity_tests::{
    legacy_fork_fixture, LEGACY_CHILD, LEGACY_PARENT, LEGACY_WINDOW,
};
use super::*;
use crate::claude_local_otel::{ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipLoadReport};
use crate::snapshots::state_v2::money_test_support as v2;
use crate::snapshots::state_v2::SliceBudget;
use crate::snapshots::terminal_join as tj;

const ONE_FAMILY: SliceBudget = SliceBudget {
    families: 1,
    bytes: usize::MAX,
};

/// The legacy fork after a non-terminal page accumulated both families:
/// (fixture dir, the child's page item, reports, index).
fn accumulated() -> (
    PathBuf,
    SnapshotItem,
    ClaudeLocalOtelLoadReport,
    ClaudeTraceOwnershipLoadReport,
    ScanIndex,
) {
    let (dir, items, api, trace, mut index) = legacy_fork_fixture(0);
    let mut page = items.clone();
    let disposition = apply_claude_reported_usage_with_identity(
        &mut page,
        &api,
        &trace,
        &mut index,
        false,
        LEGACY_WINDOW,
        None,
    );
    assert_eq!(disposition.terminal, ClaudeTerminalOutcome::NotTerminal);
    for root in [LEGACY_PARENT, LEGACY_CHILD] {
        assert!(
            index.claude_usage_family_pending.contains_key(root),
            "{root}"
        );
    }
    let child = items
        .into_iter()
        .find(|item| claude_snapshot_family_root(item) == LEGACY_CHILD)
        .unwrap();
    (dir, child, api, trace, index)
}

/// A complete terminal over the child's page only: the parent family is
/// read from the store.
fn terminal(
    index: &mut ScanIndex,
    child: &SnapshotItem,
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    budget: SliceBudget,
) -> (Vec<SnapshotItem>, ClaudeUsageAuthorityDisposition) {
    let mut page = vec![child.clone()];
    let disposition = tj::with_slice_budget(budget, || {
        apply_claude_reported_usage_with_identity(
            &mut page,
            api,
            trace,
            index,
            true,
            LEGACY_WINDOW,
            None,
        )
    });
    (page, disposition)
}

/// What a terminal decides: witnesses, duplicate owners, fence and file
/// fingerprints (the re-arms).
fn decided(index: &ScanIndex) -> Value {
    json!({
        "witnesses": index.claude_usage_family_witnesses,
        "duplicate_owners": index.claude_duplicate_request_owners,
        "fence": index.claude_duplicate_request_witness_overflowed,
        "files": index
            .files
            .iter()
            .map(|(key, entry)| (key.clone(), entry.source_file_fingerprint.clone()))
            .collect::<BTreeMap<_, _>>(),
    })
}

/// The census state a terminal commits, read back resident: what it
/// decided, the retained pending, the quarantine and the re-arm progress.
fn committed(view: &ScanIndex) -> Value {
    json!({
        "decided": decided(view),
        "pending": view.claude_usage_family_pending,
        "quarantined": view.claude_usage_authority_quarantine.keys().collect::<Vec<_>>(),
        "progress": view.claude_full_rearm_progress,
    })
}

/// [money] Over one family per slice the streamed terminal emits and commits
/// what one whole visit does: the money oracle (totals and placement) holds
/// on the page, and the committed census state, saved and reloaded, is
/// equal. The child's legacy prefix is excluded in both (its raw item counts
/// the parent's request), so the cross-family joins ran on both arms.
#[test]
fn streamed_terminal_equals_one_whole_visit() {
    let (dir, child, api, trace, index) = accumulated();
    assert_eq!(child.request_count, 3, "the raw child counts the prefix");
    let mut arms = Vec::new();
    for (name, budget) in [("whole", SliceBudget::WHOLE), ("sliced", ONE_FAMILY)] {
        let scratch = crate::test_scratch::canonical_private_dir(&format!("terminal-join-{name}"));
        let (custody, mut cold) = v2::ColdSession::publish(&index, &scratch);
        assert!(v2::usage_head_only(&cold, LEGACY_PARENT));
        let (page, disposition) = terminal(&mut cold, &child, &api, &trace, budget);
        assert_eq!(
            disposition.terminal,
            ClaudeTerminalOutcome::Complete,
            "{name}"
        );
        let (_, view) = custody.save_reload(&mut cold);
        arms.push((page, disposition, committed(&view)));
        drop(custody);
        let _ = fs::remove_dir_all(scratch);
    }
    let (sliced, whole) = (arms.pop().unwrap(), arms.pop().unwrap());
    assert_eq!(whole.0[0].request_count, 2, "the prefix is the parent's");
    super::stale_family_carry_tests::assert_bodies_equal_a_full(&whole.0, &sliced.0);
    assert_eq!(sliced.2, whole.2, "committed census state");
    assert_eq!(
        sliced.1.quarantined_source_session_ids,
        whole.1.quarantined_source_session_ids
    );
    assert_eq!(
        sliced.1.terminal_stream.terminal_slices,
        2 * whole.1.terminal_stream.terminal_slices,
        "two families, each visit one slice per family"
    );
    let _ = fs::remove_dir_all(dir);
}

/// [regress] The terminal holds no family it streams: over a cold store it
/// installs only the page's family while reading every other one from its
/// row, where the whole-kind load installed every family before the joins.
#[test]
fn streamed_terminal_installs_only_the_page_families() {
    let (dir, child, api, trace, index) = accumulated();
    let scratch = crate::test_scratch::canonical_private_dir("terminal-join-installs");
    let (custody, mut cold) = v2::ColdSession::publish(&index, &scratch);
    assert_eq!(v2::cold_usage_families(&cold), Some(2));
    let (_, disposition) = terminal(&mut cold, &child, &api, &trace, ONE_FAMILY);
    assert_eq!(disposition.terminal, ClaudeTerminalOutcome::Complete);
    let stream = disposition.terminal_stream;
    assert_eq!(
        stream.terminal_installed_families, 1,
        "the child's page only"
    );
    assert!(
        stream.terminal_peak_slice_bytes > 0,
        "the parent was decoded"
    );
    drop(custody);
    let _ = fs::remove_dir_all(scratch);
    let _ = fs::remove_dir_all(dir);
}

/// [behaviour] Every slice must read under the first slice's token: a family
/// count that changes between slices refuses the sweep, which decided
/// nothing. The unchanged control sweeps both families and joins them.
#[test]
fn a_changed_token_between_slices_refuses_the_sweep() {
    let (dir, _, _, _, mut index) = accumulated();
    let complete_families = complete_claude_usage_family_members(&index);
    let item_roots = BTreeSet::new();
    let inputs = tj::TerminalInputs {
        census_window_end: LEGACY_WINDOW,
        complete_families: &complete_families,
        item_roots: &item_roots,
        legacy_request_owners: None,
        proof: None,
    };
    tj::with_slice_budget(ONE_FAMILY, || {
        let mut sweep = tj::Sweep::new(&inputs);
        assert_eq!(sweep.slice(&index), Ok(false), "the parent");
        assert_eq!(sweep.slice(&index), Ok(true), "the child");
        let join = sweep.finish(&index).unwrap();
        assert_eq!(join.slices, 4, "two sweep slices, two targeted");
        assert_eq!(join.native_duplicate_request_owners.len(), 1, "req_shared");

        let mut sweep = tj::Sweep::new(&inputs);
        assert_eq!(sweep.slice(&index), Ok(false));
        index.claude_usage_family_pending.discard(LEGACY_CHILD);
        assert_eq!(sweep.slice(&index), Err(tj::Refused));
    });
    let _ = fs::remove_dir_all(dir);
}

/// [behaviour] A family row gone mid-sweep refuses the terminal: the page is
/// held, the census stays incomplete, no census state changes, and the
/// traversal the scan retired goes back so the next pass re-enters it. That
/// next pass, over a readable store, commits what one whole visit commits.
#[test]
fn a_refused_terminal_keeps_its_traversal_and_the_retry_commits() {
    let (dir, child, api, trace, index) = accumulated();
    let retired = || ClaudeTerminalCustody {
        traversal: Some(crate::snapshots::claude_family_census_shadow_tests::traversal()),
        resume_after_path: Some("resume-after".to_string()),
        resume_upper_bound_path: None,
        resume_census_window_end: Some(LEGACY_WINDOW.to_string()),
    };
    let scan = || {
        let mut scan = SourceScanResult::empty(SnapshotSource::ClaudeCode);
        scan.snapshots = vec![child.clone()];
        scan.census_complete = true;
        scan.census_window_end = LEGACY_WINDOW.to_string();
        scan.claude_terminal_custody = Some(Box::new(retired()));
        scan
    };
    let fold = |scan: &mut SourceScanResult, index: &mut ScanIndex, budget| {
        tj::with_slice_budget(budget, || {
            apply_claude_reported_usage_to_scan_with_identity(scan, &api, &trace, index, None)
        })
    };

    let scratch = crate::test_scratch::canonical_private_dir("terminal-join-refused");
    let (custody, mut cold) = v2::ColdSession::publish(&index, &scratch);
    let before = decided(&cold);
    v2::delete_usage_row_in_session(&cold, LEGACY_PARENT);
    let unknown = v2::usage_unknown_count();
    let mut refused = scan();
    let disposition = fold(&mut refused, &mut cold, ONE_FAMILY);
    assert_eq!(disposition.terminal, ClaudeTerminalOutcome::Refused);
    assert!(v2::usage_unknown_count() > unknown, "counted");
    assert!(!refused.census_complete && refused.scan_cap_hit);
    assert!(disposition
        .quarantined_source_session_ids
        .contains(&child.source_session_id));
    assert_eq!(
        serde_json::to_value(&cold.traversal).unwrap(),
        serde_json::to_value(&retired().traversal).unwrap(),
        "the traversal is back"
    );
    assert_eq!(cold.resume_after_path.as_deref(), Some("resume-after"));
    assert_eq!(decided(&cold), before, "nothing decided");
    drop(custody);
    let _ = fs::remove_dir_all(scratch);

    let mut arms = Vec::new();
    for (name, budget) in [("retry-whole", SliceBudget::WHOLE), ("retry", ONE_FAMILY)] {
        let scratch = crate::test_scratch::canonical_private_dir(&format!("terminal-join-{name}"));
        let (custody, mut cold) = v2::ColdSession::publish(&index, &scratch);
        let mut retry = scan();
        let disposition = fold(&mut retry, &mut cold, budget);
        assert_eq!(
            disposition.terminal,
            ClaudeTerminalOutcome::Complete,
            "{name}"
        );
        assert!(
            retry.census_complete && cold.traversal.is_none(),
            "{name}: retired"
        );
        let (_, view) = custody.save_reload(&mut cold);
        arms.push((retry.snapshots, committed(&view)));
        drop(custody);
        let _ = fs::remove_dir_all(scratch);
    }
    super::stale_family_carry_tests::assert_bodies_equal_a_full(&arms[0].0, &arms[1].0);
    assert_eq!(
        arms[1].1, arms[0].1,
        "the retry commits what the whole visit does"
    );
    let _ = fs::remove_dir_all(dir);
}
