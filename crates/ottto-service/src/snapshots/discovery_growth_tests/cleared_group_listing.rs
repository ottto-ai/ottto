use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::{
    age_listing_for_test, continue_route_for_test, route_of, save_reload_for_test,
    tail_counter_for_test,
};

/// Days the aged arm's corpus is dated back, past the 7-day visit window.
const AGED_DAYS: u64 = 10;

/// A kept generation over a target, a finalized sibling and a confirmed-empty
/// sibling, read once and walked again with an empty queue. The aged corpus
/// is dated before its first read, which a wider window still admits, so the
/// read and the index own the same physical stamp.
fn read_generation(f: &Fixture, source: SnapshotSource, aged: bool) -> ScanIndex {
    let now = OffsetDateTime::now_utc();
    for session in [UNCHANGED, GROWN, REARMED] {
        let path = f.root.join(format!("{session}.jsonl"));
        append_records(&path, &usage_records(source, session, 1, true));
        if aged {
            let modified = SystemTime::now() - std::time::Duration::from_secs(AGED_DAYS * 86_400);
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(modified))
                .unwrap();
        }
    }
    let first_read = if aged {
        OffsetDateTime::from_unix_timestamp(now.unix_timestamp() - (AGED_DAYS as i64 - 1) * 86_400)
            .unwrap()
    } else {
        now
    };
    let (mut index, _, reads, _) = f.page_at(
        source,
        ScanIndex::default(),
        &first_read.format(&Rfc3339).unwrap(),
    );
    assert_eq!(
        reads.0.lock().unwrap().0.len(),
        3,
        "{source:?}: first reads"
    );
    // The visit's generation starts now, with the 7-day window.
    index.traversal = None;
    ensure_bounded_traversal(
        source,
        std::slice::from_ref(&f.root),
        &mut index,
        &now.format(&Rfc3339).unwrap(),
        7,
    );
    advance_bounded_directory_traversal(source, &mut index, 7, None);
    let traversal = index.traversal.as_mut().unwrap();
    assert!(traversal.pending_directories.is_empty());
    traversal.pending_candidates.clear();
    index
}

/// [regress] A nonempty file whose final snapshot group was cleared for
/// re-parse (source and stamp unchanged, not confirmed empty) is listed by a
/// due re-listing into an empty queue, inside the window and aged past it,
/// for every source, and decided `UnknownOutcome`. A finalized and a
/// confirmed-empty sibling stay unlisted. Claude replays it from its durable
/// Tail with no transcript payload bytes and restores the group; the next
/// listing and a restart are quiet. Before the fix the listing dropped it.
#[test]
fn cleared_group_file_is_listed_and_replayed_from_its_tail() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        for aged in [false, true] {
            let mut f = Fixture::new();
            let mut index = read_generation(&f, source, aged);
            let target = f.root.join(format!("{REARMED}.jsonl"));
            let finalized = f.root.join(format!("{UNCHANGED}.jsonl"));
            let empty = f.root.join(format!("{GROWN}.jsonl"));
            let key = local_index_key(&target);
            let empty_key = local_index_key(&empty);
            let source_fingerprint = index.files[&key].source_file_fingerprint.clone();
            assert!(!source_fingerprint.is_empty());
            assert!(index.files[&key].last_snapshot_fingerprint.is_some());
            // The held-probe re-arm's persisted result: only the group and
            // body witness are cleared.
            let entry = index.files.get_mut(&key).unwrap();
            entry.last_snapshot_fingerprint = None;
            entry.last_upload_body_witness = None;
            let sibling = index.files.get_mut(&empty_key).unwrap();
            sibling.last_snapshot_fingerprint = None;
            sibling.last_upload_body_witness = None;
            index.confirmed_empty_files.insert(empty_key.clone());
            let saved = f.root.join("index.json");
            let mut index = save_reload_for_test(&mut index, &saved);

            let case = format!("{source:?} aged {aged}");
            let metadata = fs::metadata(&target).unwrap();
            assert!(index.listing_stamp_matches(&target, &metadata), "{case}");
            assert_eq!(
                index.files[&key].source_file_fingerprint, source_fingerprint,
                "{case}"
            );
            assert!(index.files[&key].last_snapshot_fingerprint.is_none());
            assert!(index.files[&key].size_bytes > 0);
            assert!(!index.confirmed_empty_files.contains(&key), "{case}");
            assert!(index.confirmed_empty_files.contains(&empty_key), "{case}");
            let walk = index.traversal.as_ref().expect("a kept generation");
            assert!(walk.pending_candidates.is_empty(), "{case}: empty queue");
            assert!(walk.pending_directories.is_empty(), "{case}");
            let window_end = rfc3339_unix_seconds(&walk.census_window_end).unwrap();
            let modified = unix_seconds(metadata.modified().unwrap()).unwrap();
            assert_eq!(
                !is_recent_enough_at(modified, window_end, 7),
                aged,
                "{case}: outside the visit's window only when aged"
            );
            let generations = walk.counts.listing_generations;

            relist(source, &mut index);
            let walk = index.traversal.as_ref().unwrap();
            assert_eq!(
                walk.counts.listing_generations,
                generations + 1,
                "{case}: a re-listing pass ran"
            );
            let queued = |path: &Path| {
                walk.pending_candidates
                    .iter()
                    .filter(|pending| pending.path == path)
                    .count()
            };
            assert_eq!(queued(&target), 1, "{case}: the cleared file is listed");
            assert_eq!(queued(&finalized), 0, "{case}: finalized sibling");
            assert_eq!(queued(&empty), 0, "{case}: confirmed-empty sibling");
            let entry = &index.files[&key];
            let candidate = CandidateFile {
                physical_identity: None,
                scan_root: f.root.clone(),
                path: target.clone(),
                size_bytes: entry.size_bytes,
                modified_unix_seconds: entry.modified_unix_seconds,
                modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
                source_file_fingerprint: entry.source_file_fingerprint.clone(),
                legacy_source_file_fingerprint: String::new(),
                legacy_config_reconciliation_required: false,
                opened_object_identity: String::new(),
                fingerprint_changed_nanos: 0,
                fingerprint_birth_nanos: 0,
                withheld_content_stamp: None,
            };
            assert_eq!(
                index.candidate_decision_with_reason(&candidate),
                (
                    CandidateDecision::Parse,
                    Some(CandidateParseReason::UnknownOutcome)
                ),
                "{case}"
            );
            if source != SnapshotSource::ClaudeCode {
                continue;
            }

            // A restart: the read continues from the committed Tail on disk.
            let route = route_of(&index).expect("a routed index");
            f.cache = Arc::new(sampled_scan::SharedCache::default());
            continue_route_for_test(&f.cache, &route);
            let hits = tail_counter_for_test("tail_db_loads", "hit");
            let (mut replayed, _, reads, rows) = f.page(source, index);
            assert!(
                tail_counter_for_test("tail_db_loads", "hit") > hits,
                "{case}: a durable Tail hit"
            );
            assert!(
                !modes(&reads).iter().any(|mode| mode.starts_with("Full")),
                "{case}: {:?}",
                modes(&reads)
            );
            let page = rows
                .iter()
                .find(|row| row["stage"] == "native_collection_page")
                .unwrap();
            assert_eq!(
                page["counts"]["sampled_acquisition"]["completed_native_bytes"], 0,
                "{case}: no transcript payload bytes"
            );
            let entry = &replayed.files[&key];
            assert!(entry.last_snapshot_fingerprint.is_some(), "{case}: group");
            assert_eq!(entry.source_file_fingerprint, source_fingerprint);

            // The next due listing, then a restart, read nothing.
            for restart in [false, true] {
                if restart {
                    let route = route_of(&replayed).expect("a routed index");
                    f.cache = Arc::new(sampled_scan::SharedCache::default());
                    continue_route_for_test(&f.cache, &route);
                }
                age_listing_for_test(&mut replayed);
                let (next, scan, reads, _) = f.page(source, replayed);
                replayed = next;
                assert_eq!(scan.scanned_file_count, 0, "{case} restart {restart}");
                assert!(modes(&reads).is_empty(), "{case} restart {restart}");
                assert!(replayed
                    .files
                    .get(&key)
                    .map_or(true, |entry| entry.last_snapshot_fingerprint.is_some()));
            }
        }
    }
}
