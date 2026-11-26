//! Sampled reads without the hourly audit: an older build's tags, growth after
//! a first read, a vanished formerly tagged file, and the hold-only absence
//! inventory that shares the absence proof.
use super::*;

/// [money] An entry an older build left with a complete sampled tag grows
/// long after the tag's deadline: each page reads only the appended bytes as
/// a Tail, its body equals the cold Full's in totals and placement, the tag
/// is gone, and no page reads Full.
#[test]
fn a_tagged_first_read_then_growth_tails_and_equals_cold_full() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for source in [SnapshotSource::ClaudeCode, SnapshotSource::Codex] {
        let fixture = ScanFixture::new(source);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        fixture.file.append(&usage(source, 100, 0, "fixture-model"));
        let (mut index, _, modes) = production_scan(
            &fixture,
            source,
            ScanIndex::default(),
            Some(cache.clone()),
            "account-a",
        );
        assert_eq!(modes, (1, 0, 0), "first read {source:?}");
        let key = local_index_key(&fixture.file.0);
        index.files.get_mut(&key).unwrap().scan_identity_version = Some(format!(
            "{LOCAL_SCAN_INDEX_IDENTITY_VERSION}+sampled_unverified:v2:1:c"
        ));
        // Two hours on: past any deadline an older build stored.
        sampled_scan::set_test_now(Some(sampled_scan::now_seconds() + 7_200));
        for id in 1..3 {
            fixture
                .file
                .append(&usage(source, 100 + id as u64 * 30, id, "fixture-model"));
            let (next, scan, modes) =
                production_scan(&fixture, source, index, Some(cache.clone()), "account-a");
            assert_eq!(modes, (0, 1, 0), "growth tails {source:?} append {id}");
            let (_, cold, _) =
                production_scan(&fixture, source, ScanIndex::default(), None, "account-a");
            assert_eq!(
                production_body(source, scan),
                production_body(source, cold),
                "Tail equals cold Full {source:?} append {id}"
            );
            assert_eq!(
                next.files[&key].scan_identity_version.as_deref(),
                Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
            );
            index = next;
        }
        sampled_scan::set_test_now(None);
    }
}

/// [behaviour] Hold-only removal requires stable rooted absence twice.
#[test]
fn hold_only_inventory_requires_two_secure_absence_observations() {
    use std::os::unix::fs::symlink;
    for ancestor in [
        "present",
        "missing",
        "symlink",
        "dangling",
        "file",
        "root_missing",
    ] {
        let fixture = ScanFixture::new(SnapshotSource::ClaudeCode);
        let parent = fixture.root.join("held-parent");
        fs::create_dir(&parent).unwrap();
        let path = parent.join("held-new.jsonl");
        match ancestor {
            "missing" => fs::remove_dir(&parent).unwrap(),
            "symlink" => {
                fs::remove_dir(&parent).unwrap();
                symlink(&fixture.dir, &parent).unwrap();
            }
            "dangling" => {
                fs::remove_dir(&parent).unwrap();
                symlink("unavailable-target", &parent).unwrap();
            }
            "file" => {
                fs::remove_dir(&parent).unwrap();
                fs::write(&parent, b"not a directory").unwrap();
            }
            "root_missing" => fs::remove_dir_all(&fixture.root).unwrap(),
            _ => {}
        }
        let key = local_index_key(&path);
        let mut index = ScanIndex::default();
        index
            .claude_account_deferred_holds
            .insert(key.clone(), "withheld-new-revision".into());
        ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.root),
            &mut index,
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        crate::snapshots::scan::lines::delivery::tests::walk_all(&mut index, BACKFILL_WINDOW_DAYS);
        assert!(index.files.is_empty(), "held-new has no committed entry");
        withheld_account::support::clock(&index.withheld_memo);
        sampled_scan::set_test_now(Some(1_000));
        withheld_account::support::clock(&index.withheld_memo);
        index.probe_absent_claude_account_deferred_holds();
        assert!(
            index.claude_account_deferred_holds.contains_key(&key),
            "one observation keeps custody"
        );
        crate::snapshots::scan::lines::delivery::tests::next_walk(
            &mut index,
            std::slice::from_ref(&fixture.root),
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        sampled_scan::set_test_now(Some(1_600));
        crate::local_resource_diagnostics::withheld_support::take_withheld();
        withheld_account::support::clock(&index.withheld_memo);
        index.probe_absent_claude_account_deferred_holds();
        let removed = matches!(ancestor, "present" | "missing");
        assert_eq!(
            !index.claude_account_deferred_holds.contains_key(&key),
            removed,
            "{ancestor}"
        );
        assert_eq!(
            crate::local_resource_diagnostics::withheld_support::take_withheld()[0],
            if removed {
                BTreeMap::from([("deleted", 1)])
            } else {
                BTreeMap::new()
            }
        );
        assert!(index.files.is_empty(), "no membership invented");
        sampled_scan::set_test_now(None);
    }
}

/// [behaviour] Inventory never probes an imported tail beyond the existing cap.
#[test]
fn hold_only_absence_inventory_never_exceeds_existing_4096_bound() {
    let fixture = ScanFixture::new(SnapshotSource::ClaudeCode);
    let blocked = fixture.root.join("a-unavailable");
    fs::write(&blocked, b"not a directory").unwrap();
    let eligible = local_index_key(&fixture.root.join("z-positively-missing.jsonl"));
    let mut index = ScanIndex::default();
    for n in 0..MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS {
        index.claude_account_deferred_holds.insert(
            local_index_key(&blocked.join(format!("{n:05}.jsonl"))),
            "held".into(),
        );
    }
    index
        .claude_account_deferred_holds
        .insert(eligible.clone(), "held-new".into());
    ensure_bounded_traversal(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.root),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    crate::snapshots::scan::lines::delivery::tests::walk_all(&mut index, BACKFILL_WINDOW_DAYS);
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    assert_eq!(
        index.claude_account_deferred_holds.len(),
        MAX_CLAUDE_ACCOUNT_DEFERRED_HOLDS + 1
    );
    assert!(
        index.claude_account_deferred_holds.contains_key(&eligible),
        "over-bound imported tail was not probed or dropped"
    );
    // Indexed/hint callers can name an imported tail too; the central gate
    // must keep it even with memo capacity and two spaced secure absences.
    let members = index.observed_account_members();
    for now in [1_000, 1_600] {
        sampled_scan::set_test_now(Some(now));
        assert!(!index.retire_absent_account_hold(&eligible, &members));
        assert!(index.claude_account_deferred_holds.contains_key(&eligible));
    }
    index
        .claude_account_deferred_holds
        .retain(|key, _| key == &eligible);
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    assert_eq!(index.claude_account_deferred_hold_count(), 1);
    crate::snapshots::scan::lines::delivery::tests::next_walk(
        &mut index,
        std::slice::from_ref(&fixture.root),
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    sampled_scan::set_test_now(Some(sampled_scan::now_seconds() + 600));
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    sampled_scan::set_test_now(None);
    assert!(
        index.claude_account_deferred_holds.is_empty(),
        "the next bounded inventory proves eligible absence"
    );
    // A large missing population must leave some debt unadmitted rather than
    // pin a descriptor for every key; admitted batches must still make progress.
    for n in 0..80 {
        index.claude_account_deferred_holds.insert(
            local_index_key(&fixture.root.join(format!("missing-{n}.jsonl"))),
            "held".into(),
        );
    }
    sampled_scan::set_test_now(Some(1_000));
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    crate::snapshots::scan::lines::delivery::tests::next_walk(
        &mut index,
        std::slice::from_ref(&fixture.root),
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    sampled_scan::set_test_now(Some(1_600));
    withheld_account::support::clock(&index.withheld_memo);
    index.probe_absent_claude_account_deferred_holds();
    let remaining = index.claude_account_deferred_hold_count();
    assert!(
        remaining > 0 && remaining < 80,
        "descriptor admission keeps debt and makes progress"
    );
    for step in 2..=80 {
        crate::snapshots::scan::lines::delivery::tests::next_walk(
            &mut index,
            std::slice::from_ref(&fixture.root),
            NOW,
            BACKFILL_WINDOW_DAYS,
        );
        sampled_scan::set_test_now(Some(1_000 + step * 600));
        withheld_account::support::clock(&index.withheld_memo);
        index.probe_absent_claude_account_deferred_holds();
        if index.claude_account_deferred_hold_count() == 0 {
            break;
        }
    }
    assert_eq!(index.claude_account_deferred_hold_count(), 0);
    sampled_scan::set_test_now(None);
}
