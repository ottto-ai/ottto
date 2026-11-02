//! R6's hold, counted (§12): a file shorter than its accepted floor holds
//! with its bytes behind the floor, a restart keeps the hold, and the hold
//! ends by name when the file grows past the floor or the census proves the
//! shrink. No timer ends it.
use super::super::seam::tests::{route, Route, NOW};
use super::settlement_tests::candidate;
use super::tests::{append, committed, len, loaded};
use super::*;
use crate::snapshots::claude_request_census::{
    proves_indexed_shrink, ClaudeRequestBirth, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};
use crate::snapshots::tail_source::counters;
use crate::snapshots::tail_source::floor::{release, AcceptedFloor};
use crate::snapshots::tests::manifest_index_entry;
use std::os::unix::fs::MetadataExt;

const BEHIND: u64 = 10;

/// A committed file whose accepted entry is `BEHIND` bytes longer than it.
fn below_floor(route: &mut Route) -> (PathBuf, String) {
    let (path, key) = committed(route, "a.jsonl", 3);
    let mut accepted = manifest_index_entry(None);
    accepted.size_bytes = len(&path) + BEHIND;
    accepted.source_file_fingerprint = "a".repeat(64);
    route.index.files.insert(key.clone(), accepted);
    (path, key)
}

/// The scan's floor check at the file's length.
fn holds(index: &ScanIndex, path: &Path, key: &str) -> bool {
    let floor = AcceptedFloor::of(index, key).expect("an accepted entry");
    floor.holds(index, key, Some(len(path)))
}

/// [money] Below the floor the file holds and is counted with its bytes; once
/// it grows past the floor the hold ends once, as `grew_past_floor`, and the
/// read continues from the committed head.
#[test]
fn a_file_below_its_floor_holds_until_it_grows_past_it() {
    let mut route = route();
    let (path, key) = below_floor(&mut route);
    assert!(holds(&route.index, &path, &key));
    assert_eq!(counters::total("tail_floor_held", "files"), 1);
    assert_eq!(counters::total("tail_floor_held", "bytes"), BEHIND);

    append(&path, 3);
    assert!(!holds(&route.index, &path, &key));
    release(&route.index, &key, false);
    release(&route.index, &key, false);
    assert_eq!(
        counters::total("tail_floor_hold_exit", "grew_past_floor"),
        1
    );
    assert_eq!(counters::total("tail_floor_held", "files"), 1);
    let (load, _) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Reused(_, Some(_)) | Load::Cold(_)));
}

/// [money] A current census that proves the shrink ends the hold as
/// `proven_shrink`; without the proof nothing ends it.
#[test]
fn a_proven_shrink_ends_the_hold() {
    let mut route = route();
    let (path, key) = below_floor(&mut route);
    assert!(holds(&route.index, &path, &key));
    let metadata = std::fs::metadata(&path).unwrap();
    let physical = Some([metadata.dev(), metadata.ino()]);
    assert!(!proves_indexed_shrink(
        &route.index,
        &key,
        len(&path),
        physical
    ));

    let modified = route.index.files[&key].modified_unix_seconds;
    let record = ClaudeRequestCensusRecord::synthetic_for_test(
        &"a".repeat(64),
        7,
        ClaudeRequestCensusShape::Exact,
        vec![1],
    )
    .with_modified_for_test(Some(modified))
    .with_birth_for_test(Some(ClaudeRequestBirth {
        unix_seconds: 0,
        device: metadata.dev(),
        inode: metadata.ino(),
    }));
    route
        .index
        .claude_request_census_mut_for_test()
        .insert_for_test(&key, record);
    let proven = proves_indexed_shrink(&route.index, &key, len(&path), physical);
    assert!(proven);
    release(&route.index, &key, proven);
    assert_eq!(counters::total("tail_floor_hold_exit", "proven_shrink"), 1);
    assert_eq!(
        counters::total("tail_floor_hold_exit", "grew_past_floor"),
        0
    );
}

/// [money] The floor is the committed entry: after a restart the file is
/// still selected, still held and counted again, and its later exit is named.
#[test]
fn a_restart_keeps_the_hold() {
    let mut route = route();
    let (path, key) = below_floor(&mut route);
    assert!(holds(&route.index, &path, &key));
    route.save(false);
    state_v2::forget_ram_for_test(&route.path);
    let restarted = ScanIndex::load(&route.path).unwrap();

    let (decision, _) = restarted.candidate_decision_with_reason_at(&candidate(&path), NOW);
    assert_eq!(decision, CandidateDecision::Parse);
    assert!(holds(&restarted, &path, &key));
    assert_eq!(counters::total("tail_floor_held", "files"), 2);
    assert_eq!(counters::total("tail_floor_held", "bytes"), 2 * BEHIND);

    append(&path, 3);
    assert!(!holds(&restarted, &path, &key));
    release(&restarted, &key, false);
    assert_eq!(
        counters::total("tail_floor_hold_exit", "grew_past_floor"),
        1
    );
}
