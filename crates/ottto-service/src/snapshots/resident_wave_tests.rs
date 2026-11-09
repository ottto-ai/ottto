//! Resident admission at the real shared scan seam, using synthetic files.
use super::e2_pipeline_scan_fixture::E2ScanFixture;
use super::*;

const B: f64 = 230.0;
const FILE_CHARGE: f64 = 0.0871;

/// [behaviour] A mass re-fold wave whose file charges alone exceed 3 B
/// must defer work. This test predates the resident meter: on the base all
/// selected files finish in one page, retaining more than B + one unit.
#[test]
fn resident_wave_shape_defers_before_three_b_of_refolds() {
    let home = crate::test_scratch::private_dir("resident-wave-shape")
        .canonicalize()
        .unwrap();
    let root = home.join("transcripts");
    fs::create_dir_all(&root).unwrap();
    let n = (3.0 * B / FILE_CHARGE).ceil() as usize;
    for i in 0..n {
        fs::write(root.join(format!("session-{i:05}.jsonl")), format!(
            "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n", i + 1
        )).unwrap();
    }
    let fixture = E2ScanFixture::with_identity_capture(false);
    let roots = [root];
    let state = home.join("state");
    fs::create_dir_all(&state).unwrap();
    let (session, mut index) = StateV2ColdSession::publish(
        scan_index_persistence::Source::Pi,
        &ScanIndex::default(),
        &state,
    );
    let route = session.path().to_owned();
    fixture.on_committed_route(&route);
    index.activate_upload_context("resident-wave".into());
    for _ in 0..100 {
        let (next, mut page, _) =
            fixture.scan_other_page(SnapshotSource::Pi, &roots, &home, index, true, 1000, &[]);
        index = next;
        finalize_scan_after_policy(SnapshotSource::Pi, &mut page, &mut index);
        let mut ledger = crate::snapshot_sync::tail_ack_ledger::AckLedger::new(SnapshotSource::Pi);
        ledger.deliver(&page.snapshots);
        assert!(page.snapshots.iter().all(|item| ledger.settled(item)));
        index.record_accepted_snapshot_fingerprints(
            &page
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect(),
        );
        e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
            &mut index,
            &page.snapshots,
            &e2_pipeline_scan_fixture::exact_acks_for_test(&page.snapshots),
        );
        index.save(&route).unwrap();
        index = ScanIndex::load(&route).unwrap();
        index.activate_upload_context("resident-wave".into());
        if page.census_complete {
            break;
        }
    }
    assert_eq!(index.files.len(), n, "seed every stored reduction");
    for entry in index.files.values_mut() {
        entry.source_file_fingerprint = "source-changed".into();
    }
    index.traversal = None;
    let (index, page, modes) =
        fixture.scan_other_page(SnapshotSource::Pi, &roots, &home, index, true, n + 1, &[]);
    let q = page.scanned_file_count as f64 * FILE_CHARGE;
    let deferred = index
        .traversal
        .as_ref()
        .map_or(0, |walk| walk.pending_candidates.len());
    assert!(q <= B + FILE_CHARGE, "resident charge {q} > B + U_max");
    assert!(deferred > 0, "a 3 B wave must leave pending work");
    assert!(
        !page.census_complete,
        "deferred first-read membership holds census"
    );
    assert_eq!(
        modes.0, 0,
        "unchanged transcripts re-fold from their stored Tail"
    );
    fs::remove_dir_all(home).unwrap();
}

fn synthetic_candidate(path: &str) -> CandidateFile {
    tail_source::codex::tests::candidate(Path::new(path))
}

/// [behaviour] The first-unit exemption uses resident charge, independently
/// of history adoption reservations; loaded and completed bytes are maxed.
#[test]
fn resident_meter_charges_every_source_once_and_admits_the_first_unit() {
    use claude_history_upgrade::{with_resident_budget, HistoryPage};
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        with_resident_budget(0.0, || {
            let mut page = HistoryPage::default();
            assert!(page.reserve("adoption", 12));
            assert!(page.resident_can_start(), "adoption is not resident work");
            page.charge_resident(source, 0, 0, 1);
            assert!(!page.resident_can_start(), "every completed file pays c_f");
        });
        with_resident_budget(0.6, || {
            for (loaded, reduced) in [(104_858, 90_000), (90_000, 104_858)] {
                let mut page = HistoryPage::default();
                page.charge_resident(source, loaded, reduced, 1);
                assert!(page.resident_can_start(), "max(L, R), never L + R");
                page.charge_resident(source, 0, 0, 1);
                assert!(!page.resident_can_start(), "charges never decrement");
            }
        });
    }
}

/// [money] A quarantine-only seed has zero selected files. Restore only
/// consumed pending entries, including their original census/hint flags.
/// Index-only members must never become new census obligations.
#[test]
fn resident_forced_deferral_restores_consumed_flags_with_zero_selected_seed() {
    use claude_history_upgrade::HistoryPage;
    const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let dir = crate::test_scratch::unique_path("resident-forced-flags");
    fs::create_dir_all(&dir).unwrap();
    let mut index = OwnedSourceScan::new(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&dir),
        ScanIndex::default(),
        "2026-10-27T08:00:00Z",
        183,
        100,
        None,
        &[],
        false,
    )
    .index;
    let root = synthetic_candidate(&format!("/synthetic/{ROOT}.jsonl"));
    let a = synthetic_candidate(&format!("/synthetic/{ROOT}/subagents/agent-a.jsonl"));
    let b = synthetic_candidate(&format!("/synthetic/{ROOT}/subagents/agent-b.jsonl"));
    let original = [&a, &b]
        .into_iter()
        .zip([(true, false), (false, true)])
        .map(|(file, (census_member, watcher_hint))| ScanTraversalPath {
            scan_root: file.scan_root.clone(),
            path: file.path.clone(),
            census_member,
            watcher_hint,
        })
        .collect::<Vec<_>>();
    for selected in [false, true] {
        index.traversal.as_mut().unwrap().pending_candidates.clear();
        let mut page = HistoryPage::default().with_forced_pending(original.clone());
        page.charge_resident(SnapshotSource::ClaudeCode, 0, 100 * 1024 * 1024, 1);
        let flags = if selected {
            [(local_index_key(&root.path), (false, true))].into()
        } else {
            BTreeMap::new()
        };
        let mut candidates = [root.clone(), a.clone(), b.clone()].into();
        page.defer_resident(
            SnapshotSource::ClaudeCode,
            &mut index,
            &flags,
            &mut candidates,
        );
        assert!(candidates.is_empty());
        let pending = &index.traversal.as_ref().unwrap().pending_candidates;
        assert_eq!(pending.len(), 2 + usize::from(selected));
        for entry in &original {
            assert_eq!(pending.iter().find(|p| p.path == entry.path), Some(entry));
        }
        assert_eq!(pending.iter().any(|p| p.path == root.path), selected);
        let pending_count = pending.len();
        // A repeated deferral never duplicates pending membership.
        let mut candidates = [root.clone(), a.clone(), b.clone()].into();
        page.defer_resident(
            SnapshotSource::ClaudeCode,
            &mut index,
            &flags,
            &mut candidates,
        );
        assert_eq!(
            index.traversal.as_ref().unwrap().pending_candidates.len(),
            pending_count
        );
    }
    fs::remove_dir_all(dir).unwrap();
}

/// [behaviour] Forced units finish contiguously before another unit starts,
/// including the case where the last member takes the estimate above B.
#[test]
fn resident_forced_family_is_indivisible_and_oversize_first_unit_progresses() {
    use claude_history_upgrade::{with_resident_budget, HistoryPage};
    const ROOT: &str = "1338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let root = synthetic_candidate(&format!("/synthetic/{ROOT}.jsonl"));
    let child = synthetic_candidate(&format!("/synthetic/{ROOT}/subagents/agent-a.jsonl"));
    let other = synthetic_candidate("/synthetic/2338a80a-f36e-4cbc-a5bb-50fc66430ba5.jsonl");
    with_resident_budget(0.05, || {
        let mut page = HistoryPage::default();
        let mut remaining = [other.clone(), child.clone()].into();
        let forced = [ROOT.to_owned()].into();
        assert!(page.admit_resident_unit(&root, &mut remaining, &forced));
        page.charge_resident(SnapshotSource::ClaudeCode, 0, 0, 1);
        assert_eq!(remaining.front().unwrap().path, child.path);
        assert!(page.admit_resident_unit(&remaining.pop_front().unwrap(), &mut remaining, &forced));
        page.charge_resident(SnapshotSource::ClaudeCode, 0, 0, 1);
        assert!(!page.admit_resident_unit(&other, &mut remaining, &forced));
    });
}

fn collect_source_wave(
    source: SnapshotSource,
    root: &Path,
    budget: f64,
) -> (ScanIndex, SourceScanResult, usize) {
    let fixture = E2ScanFixture::with_identity_capture(false);
    let mut index = ScanIndex::default();
    let mut aggregate = None;
    let mut pages = 0;
    let mut ledger = crate::snapshot_sync::tail_ack_ledger::AckLedger::new(source);
    for _ in 0..32 {
        let (mut next, mut scan, _) = claude_history_upgrade::with_resident_budget(budget, || {
            fixture.scan_other_page(source, &[root.to_owned()], root, index, true, 100, &[])
        });
        finalize_scan_after_policy(source, &mut scan, &mut next);
        ledger.deliver(&scan.snapshots);
        assert!(scan.snapshots.iter().all(|item| ledger.settled(item)));
        pages += 1;
        let complete = scan.census_complete;
        if let Some(all) = aggregate.as_mut() {
            let all: &mut SourceScanResult = all;
            all.snapshots.extend(scan.snapshots);
            all.scanned_file_count += scan.scanned_file_count;
            all.census_complete = complete;
        } else {
            aggregate = Some(scan);
        }
        index = next;
        if complete {
            break;
        }
    }
    let mut aggregate = aggregate.unwrap();
    assert!(aggregate.census_complete);
    aggregate
        .snapshots
        .sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
    assert_eq!(
        ledger.posts(),
        aggregate.snapshots.len(),
        "no extra unchanged copy"
    );
    (index, aggregate, pages)
}

/// [money] Codex groups cross the resident target whole, and Pi shares the
/// same meter. Final bodies and Codex receipts/ownership match a wide page.
#[test]
fn resident_wave_codex_join_group_straddles_budget_and_pi_drains() {
    use sampled_scan::transition_fixture::{money_oracle, scan_money};
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        let root = crate::test_scratch::unique_path("resident-three-source");
        fs::create_dir_all(&root).unwrap();
        if source == SnapshotSource::Codex {
            for (owner, prefix) in [
                ("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "a"),
                ("ffffffff-1111-4111-8111-ffffffffffff", "b"),
            ] {
                for (member, input, cumulative) in [("0", 100, 100), ("1", 200, 300)] {
                    let rows = codex_file_join::tests::member(
                        owner,
                        &format!("{prefix}{member}"),
                        input,
                        cumulative,
                    );
                    fs::write(
                        root.join(format!("{prefix}{member}.jsonl")),
                        rows.iter()
                            .map(|v| v.to_string() + "\n")
                            .collect::<String>(),
                    )
                    .unwrap();
                }
            }
        } else {
            for n in 0..6 {
                fs::write(root.join(format!("pi-{n}.jsonl")), format!(
                    "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n", n + 1)).unwrap();
            }
        }
        let (wide_index, wide, w_pages) = collect_source_wave(source, &root, f64::INFINITY);
        let (small_index, small, s_pages) = collect_source_wave(source, &root, 0.05);
        assert_eq!(w_pages, 1);
        assert!(s_pages >= 2);
        assert_eq!(wide.scanned_file_count, small.scanned_file_count);
        assert_eq!(
            wide.scanned_file_count,
            if source == SnapshotSource::Codex {
                4
            } else {
                6
            }
        );
        assert_eq!(
            wide.snapshots.len(),
            if source == SnapshotSource::Codex {
                2
            } else {
                6
            }
        );
        money_oracle::assert_equivalent(
            &scan_money(source, &wide_index, &wide),
            &scan_money(source, &small_index, &small),
        );
        fs::remove_dir_all(root).unwrap();
    }
}

/// [money] The non-member re-read flag used by history-upgrade holds stays
/// distinct from first-read membership through actual deferral and retirement.
#[test]
fn resident_deferral_preserves_hu_nonmember_and_first_read_census_semantics() {
    let root = crate::test_scratch::private_dir("resident-membership");
    for n in 0..2 {
        fs::write(root.join(format!("session-{n}.jsonl")),
            "{\"type\":\"message_end\",\"message\":{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{\"input\":12,\"output\":1}}}\n").unwrap();
    }
    for member in [false, true] {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            ScanIndex::default(),
            "2026-10-27T08:00:00Z",
            183,
            100,
            None,
            &[],
            false,
        );
        assert_eq!(scan.identified_candidates.len(), 2);
        for flags in scan.selected_flags.values_mut() {
            *flags = (member, true);
        }
        scan.history_upgrade
            .charge_resident(SnapshotSource::Pi, 0, 64 * 1024 * 1024, 1);
        let (index, page) = loop {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { index, scan } => break (index, scan),
            }
        };
        assert_eq!(page.scanned_file_count, 0);
        assert!(page.snapshots.is_empty());
        assert!(page.charge_deferred);
        assert_eq!(page.census_complete, !member);
        if member {
            let pending = &index.traversal.as_ref().unwrap().pending_candidates;
            assert_eq!(pending.len(), 2);
            assert!(pending.iter().all(|p| p.census_member && p.watcher_hint));
        }
        let fixture = E2ScanFixture::default();
        let (_, drained, _) = fixture.scan_other_page(
            SnapshotSource::Pi,
            std::slice::from_ref(&root),
            &root,
            index,
            true,
            100,
            &[],
        );
        assert!(drained.census_complete);
        assert_eq!(drained.scanned_file_count, 2);
    }
    fs::remove_dir_all(root).unwrap();
}
