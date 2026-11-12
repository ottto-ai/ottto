//! First-read progress on a fresh destination, through the real paged scan,
//! listing, ACK settle and save: the import list fills from the first page,
//! reaches done only after every file is acknowledged, and changes no money.
use super::e2_pipeline_scan_fixture::{self as fixture, E2ScanFixture};
use super::*;
use sampled_scan::transition_fixture::{money_oracle, scan_money};

const DAY: u64 = 24 * 60 * 60;

fn seconds(rfc3339: &str) -> u64 {
    rfc3339_unix_seconds(rfc3339).unwrap()
}

fn set_mtime(path: &Path, unix_seconds: u64) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(unix_seconds))
        .unwrap();
}

/// One cold first read in pages of `limit` files to its end. Every page is
/// finalized, ACKed exactly, settled at the ACK seam (as the daemon does
/// before its save) and committed; a few extra passes settle re-decisions.
struct FirstRead {
    index: ScanIndex,
    scan: SourceScanResult,
    /// The committed summary after the first page.
    first_page: Option<state_v2::FirstReadSummary>,
    /// The committed summary at the end, read while the route is open.
    last: std::result::Result<Option<state_v2::FirstReadSummary>, String>,
}

fn first_read(source: SnapshotSource, root: &Path, limit: usize, pending: bool) -> FirstRead {
    let fixture = E2ScanFixture::with_identity_capture(false);
    let mut index = ScanIndex {
        first_read_pending: pending,
        ..ScanIndex::default()
    };
    let mut latest = BTreeMap::new();
    let mut last = None;
    let mut settle = 0;
    let mut first_page = None;
    let dir = std::env::temp_dir().join(format!("ottto-fixture-routes-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    // The daemon saves between passes: the page's stage commits on the
    // route, and the summary is read from what committed.
    let committed =
        |index: &ScanIndex| state_v2::first_read_summary(index).map_err(|error| error.to_string());
    for pass in 0..64 {
        let prior = index.clone();
        let (mut next, mut scan, _) =
            fixture.scan_other_page(source, &[root.to_owned()], root, index, true, limit, &[]);
        finalize_scan_after_policy(source, &mut scan, &mut next);
        scan.finish_codex_capture_boundary(&mut next);
        let accepted = scan
            .snapshots
            .iter()
            .map(|item| item.snapshot_fingerprint.clone())
            .collect();
        next.record_accepted_snapshot_fingerprints(&accepted);
        fixture::accept_upload_context_acks_for_test(
            &mut next,
            &scan.snapshots,
            &fixture::exact_acks_for_test(&scan.snapshots),
        );
        let keys = next.files.keys().cloned().collect::<Vec<_>>();
        settle_first_read(source, &next, keys.iter().map(String::as_str));
        next = next.committable_subset(&prior, &accepted, &BTreeMap::new());
        next = fixture.routed(next, &dir);
        if pass == 0 {
            first_page = committed(&next).unwrap();
        }
        let emitted = !scan.snapshots.is_empty();
        for item in std::mem::take(&mut scan.snapshots) {
            latest.insert(item.source_session_id.clone(), item);
        }
        let complete = scan.census_complete;
        last = Some(scan);
        index = next;
        if complete {
            settle += 1;
            if !emitted || settle > 3 {
                break;
            }
        }
    }
    let mut scan = last.unwrap();
    assert!(scan.census_complete, "first read finished");
    let last = committed(&index);
    let mut bodies = BTreeSet::new();
    scan.snapshots = latest
        .into_values()
        .filter(|item| bodies.insert(item.snapshot_fingerprint.clone()))
        .collect();
    FirstRead {
        index,
        scan,
        first_page,
        last,
    }
}

/// The money with the import list on equals the money with it off, and the
/// list really ran: members from the first page, all done at the end.
fn assert_progress_changes_no_money(source: SnapshotSource, root: &Path, files: u64) {
    let off = first_read(source, root, 1, false);
    let on = first_read(source, root, 1, true);
    let cold = scan_money(source, &off.index, &off.scan);
    let other = scan_money(source, &on.index, &on.scan);
    money_oracle::assert_equivalent(&cold, &other);
    money_oracle::assert_no_smaller_reemit("", &cold, &other, &cold, false);

    assert!(off.first_page.is_none());
    assert_eq!(off.last, Ok(None));
    let first = on
        .first_page
        .expect("the first page anchored the first read");
    assert!(
        first.counts.members > 0,
        "first page admitted members: {first:?}"
    );
    assert!(
        first.done_at_ms.is_none(),
        "the first page froze: {first:?}"
    );
    let last = on.last.clone().unwrap().expect("summary");
    assert_eq!(last.counts.members, files, "{last:?}");
    assert_eq!(last.counts.done, files, "every member done: {last:?}");
}

/// [money] Pi, one file per page: the import list on a fresh destination
/// (anchor, listing, ACK settle, freeze) changes no body, receipt or
/// placement against the same first read without it.
#[test]
fn pi_first_read_progress_changes_no_money() {
    let source = SnapshotSource::Pi;
    let root = crate::test_scratch::unique_path("first-read-progress-pi");
    fs::create_dir_all(&root).unwrap();
    let base = seconds("2026-10-01T00:00:00Z");
    for n in 0..4u64 {
        let path = root.join(format!("pi-{n}.jsonl"));
        fs::write(&path, format!(
            "{{\"type\":\"message_end\",\"message\":{{\"model\":\"gpt-5.4\",\"timestamp\":1793088001000,\"usage\":{{\"input\":{},\"output\":1}}}}}}\n", n + 1)).unwrap();
        set_mtime(&path, base + n * DAY);
    }
    assert_progress_changes_no_money(source, &root, 4);
    let _ = fs::remove_dir_all(root);
}

/// [money] Codex, join groups with cumulative chains, one file per page: the
/// import list changes no body, receipt, ownership or placement.
#[test]
fn codex_first_read_progress_changes_no_money() {
    let source = SnapshotSource::Codex;
    let root = crate::test_scratch::unique_path("first-read-progress-codex");
    fs::create_dir_all(&root).unwrap();
    let base = seconds("2026-10-20T00:00:00Z");
    for (slot, (owner, prefix)) in [
        ("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "a"),
        ("ffffffff-1111-4111-8111-ffffffffffff", "b"),
    ]
    .into_iter()
    .enumerate()
    {
        for (member, input, cumulative) in [("0", 100, 100), ("1", 200, 300)] {
            let rows = codex_file_join::tests::member(
                owner,
                &format!("{prefix}{member}"),
                input,
                cumulative,
            );
            let path = root.join(format!("{prefix}{member}.jsonl"));
            fs::write(
                &path,
                rows.iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            set_mtime(&path, base + slot as u64 * DAY + u64::from(member == "1"));
        }
    }
    assert_progress_changes_no_money(source, &root, 4);
    let _ = fs::remove_dir_all(root);
}
