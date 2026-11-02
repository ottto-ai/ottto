//! Settlement on real committed Tail state: a first-read crash leaves nothing
//! to trust, the accepted floor is replayed through and never relaxed, a load
//! earns no credit, lower revisions reconstruct or migrate, and a stored reuse
//! either finishes the ACKed body with no native byte or owes one native Full.
use super::super::claude::tests::lines;
use super::super::seam::tests::{route, scope, Route, NOW};
use super::tests::{append, cold, committed, counted, len, loaded, read};
use super::*;
use crate::snapshots::claude_request_census::{
    forced_member_needs_native, ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
};
use crate::snapshots::sampled_jsonl::durable::test_finish_items;
use crate::snapshots::state_v2::BaselineRelease;
use crate::snapshots::stored_refinalize::{reuse_label, reuses_stored, take_native};
use crate::snapshots::tail_source::counters;
use crate::snapshots::tail_source::floor::AcceptedFloor;
use crate::snapshots::tests::manifest_index_entry;
use crate::transcript_acquisition::ReadMode;

const REASON: CandidateParseReason = CandidateParseReason::Rearmed;

pub(super) fn candidate(path: &Path) -> CandidateFile {
    CandidateFile {
        physical_identity: None,
        scan_root: path.parent().unwrap().to_owned(),
        path: path.to_owned(),
        size_bytes: len(path),
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: "a".repeat(64),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    }
}

/// The bodies a stored read of a committed file finishes, and its native bytes.
fn stored_finish(route: &Route, path: &Path, key: &str) -> (Vec<SnapshotItem>, u64) {
    let (Load::Reused(taken, Some(base)), _) = loaded(route, path, key) else {
        panic!("the committed head is reused");
    };
    let (parser, _, _) = read(route, path, Some(taken));
    let native_bytes = parser.reader.consumed_bytes();
    let (_, native) = route.finish(path, parser, Some(base), |_| {});
    (native.unwrap().snapshots, native_bytes)
}

/// One finalization of `items` for an entry whose ACKed tuple is theirs, or
/// another body when `identical` is false.
fn finalize(
    route: &mut Route,
    key: &str,
    mut items: Vec<SnapshotItem>,
    identical: bool,
    stored_reuse: Option<CandidateParseReason>,
) -> SourceScanResult {
    for item in &mut items {
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    }
    let group: BTreeSet<_> = items
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let bodies: BTreeSet<_> = items.iter().map(snapshot_upload_body_witness).collect();
    let previous_body = if identical {
        snapshot_file_upload_body_set_hex(&bodies)
    } else {
        "acked-before".to_owned()
    };
    let previous_group = snapshot_file_entity_set_hex(&group);
    let mut entry = manifest_index_entry(None);
    entry.source_file_fingerprint = "a".repeat(64);
    entry.last_snapshot_fingerprint = Some(previous_group.clone());
    entry.last_upload_body_witness = Some(previous_body.clone());
    route.index.files.insert(key.to_owned(), entry);
    route
        .index
        .file_snapshot_fingerprints
        .insert(key.to_owned(), group);
    let empty = route.dir.join("empty-root");
    std::fs::create_dir_all(&empty).unwrap();
    let mut scan = scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        &[empty],
        &mut ScanIndex::default(),
        "2026-10-22T00:00:00Z",
        BACKFILL_WINDOW_DAYS,
        4,
        false,
    )
    .unwrap();
    let parsed_snapshot_count = items.len();
    scan.snapshots = items;
    scan.pending_finalization.push(PendingIndexFinalization {
        restored_behind_accepted: false,
        withheld_content: None,
        sampled_audit_verified: false,
        codex_pending_recovery: false,
        index_key: key.to_owned(),
        source_file_fingerprint: "a".repeat(64),
        previous_snapshot_fingerprint: Some(previous_group),
        previous_upload_body_witness: Some(previous_body),
        parse_complete: true,
        diagnostic_reason: FileReason::Complete,
        parsed_snapshot_count,
        effective_upload_body_witness_revision: 0,
        stored_reuse,
    });
    finalize_scan_after_policy_with_body_witness(
        SnapshotSource::ClaudeCode,
        &mut scan,
        &mut route.index,
        snapshot_upload_body_witness,
    );
    scan
}

/// [money] R5: a crash before the first save leaves no head and no marker. The
/// file is still discovered and read whole, counted as a bootstrap.
#[test]
fn a_first_read_crash_reads_whole_again() {
    let route = route();
    let (tail, native) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let key = tail.key_for_test().to_owned();
    assert!(tail.publish(&native));
    drop(BaselineRelease::new(&route.path, &route.index));
    assert!(route.head(&key).is_none() && route.marker(&key).is_none());

    let path = route.dir.join("a.jsonl");
    let (decision, _) = route
        .index
        .candidate_decision_with_reason_at(&candidate(&path), NOW);
    assert_eq!(decision, CandidateDecision::Parse);
    let (load, records) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Cold(None)));
    assert_eq!(counted(&records), ("miss".into(), vec!["no_head".into()]));
    assert_eq!(counters::total("tail_bootstrap_full", "no_head"), 1);
    let (_, mode, start) = read(&route, &path, None);
    assert!(matches!(mode, ReadMode::Full(_)) && start == 0);
}

/// [money] R5: a head ahead of the graph is selected by its stamp and resumes
/// from the head.
#[test]
fn a_head_ahead_of_progress_resumes_from_the_head() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let sealed = len(&path);
    let mut behind = manifest_index_entry(None);
    behind.size_bytes = sealed - 1;
    route.index.files.insert(key.clone(), behind);
    let (decision, _) = route
        .index
        .candidate_decision_with_reason_at(&candidate(&path), NOW);
    assert_eq!(decision, CandidateDecision::Parse);
    let (load, _) = loaded(&route, &path, &key);
    let Load::Reused(taken, Some(_)) = load else {
        panic!("the head is reused");
    };
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Unchanged));
    assert_eq!(parser.reader.consumed_bytes(), 0);
}

/// [money] R6: a head behind the floor replays through it to the cold Full's
/// body; an evidence clear does not relax the floor; a file shorter than the
/// floor or an entry from a newer body revision stays behind it.
#[test]
fn below_the_floor_replays_through_it_and_never_relaxes() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let sealed = len(&path);
    append(&path, 3);
    append(&path, 4);
    let mut accepted = manifest_index_entry(None);
    accepted.size_bytes = len(&path) - 1;
    route.index.files.insert(key.clone(), accepted);
    let floor = AcceptedFloor::of(&route.index, &key).unwrap();
    assert!(floor.behind(sealed) && !floor.behind(len(&path)));

    let (Load::Reused(taken, Some(_)), _) = loaded(&route, &path, &key) else {
        panic!("a head below the floor is reused");
    };
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail) && start == sealed);
    let warm = test_finish_items(parser, &path, SnapshotSource::ClaudeCode);
    assert_eq!(warm, cold(&route, &path));

    let entry = route.index.files.get_mut(&key).unwrap();
    entry.source_file_fingerprint.clear();
    assert_eq!(
        AcceptedFloor::of(&route.index, &key)
            .unwrap()
            .behind(sealed),
        floor.behind(sealed),
    );

    // No smaller re-emit: a shorter file proves its change and stays behind.
    let short = sealed - 1;
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(short)
        .unwrap();
    let (load, _) = loaded(&route, &path, &key);
    assert!(matches!(load, Load::Cold(Some(FullReason::Shrunk))));
    assert!(floor.behind(short));

    let entry = route.index.files.get_mut(&key).unwrap();
    entry.effective_upload_body_witness_revision = u64::MAX;
    let future = AcceptedFloor::of(&route.index, &key).unwrap();
    assert!(future.behind(u64::MAX) && !future.permits_real_edit());
}

/// [money] R8: load plus a zero suffix restates nothing, and load plus an
/// append keeps the committed verification clock: no Full credit either way.
#[test]
fn a_load_earns_no_credit() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let committed_head = route.head(&key).unwrap().body;
    let certificate = |body: &[u8]| {
        let mut acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
        Claude::decode_head(Claude::REDUCTION_REVISION, body, &mut acc)
            .unwrap()
            .certificate
    };
    let verified = certificate(&committed_head).verified_unix_seconds;

    let (Load::Reused(taken, Some(base)), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Unchanged));
    let (tail, native) = route.finish(&path, parser, Some(base), |_| {});
    assert!(tail.staged_for_test().is_none(), "nothing to restate");
    assert!(tail.publish(&native));
    route.save(false);
    assert_eq!(route.head(&key).unwrap().body, committed_head);

    append(&path, 3);
    let (Load::Reused(taken, Some(base)), _) = loaded(&route, &path, &key) else {
        panic!("the committed head is reused");
    };
    let mut parser = route.open(&path);
    let Ok(mode) = parser.prepare_acquisition_owned(Some(taken), &scope(), None, NOW + 1_000)
    else {
        panic!("the read prepares");
    };
    assert!(matches!(mode, ReadMode::Tail));
    while !parser.step().unwrap() {}
    let (tail, _) = route.finish(&path, parser, Some(base), |_| {});
    let staged = tail.staged_for_test().expect("an append restates");
    assert_eq!(
        certificate(&staged.head).verified_unix_seconds,
        verified,
        "a Tail keeps the committed clock",
    );
}

/// [behaviour] R9: a lower revision this build cannot decode is a counted
/// reconstruction, then an ordinary Full.
#[test]
fn a_lower_revision_without_a_decoder_reconstructs() {
    let mut route = route();
    let (mut tail, _native) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let key = tail.key_for_test().to_owned();
    let mut staged = tail.take_staged_for_test();
    staged.revision = Claude::REDUCTION_REVISION - 1;
    state_v2::stage_tail(&route.path, &key, staged).unwrap();
    route.save(false);
    let (load, records) = loaded(&route, &route.dir.join("a.jsonl"), &key);
    assert!(matches!(load, Load::Cold(None)));
    assert_eq!(counted(&records), ("error".into(), vec!["revision".into()]));
}

/// [behaviour] R9: an unchanged file over a lower-revision head writes the
/// head alone, with the same certificate and no page; a same-revision read of
/// the same file writes nothing.
#[test]
fn an_unchanged_lower_revision_migrates_the_head_alone() {
    let mut route = route();
    let (mut tail, _native) = route.complete("a.jsonl", &lines(3), None, |_| {});
    let key = tail.key_for_test().to_owned();
    let mut staged = tail.take_staged_for_test();
    staged.revision = Claude::REDUCTION_REVISION - 1;
    state_v2::stage_tail(&route.path, &key, staged).unwrap();
    route.save(false);
    let path = route.dir.join("a.jsonl");
    let base = |route: &Route, migrate| {
        let head = route.head(&key).unwrap();
        let mut base = TailBase::new(&head.body, migrate);
        state_v2::load_tail(&route.index, &key, &head, |collection, page, bytes| {
            base.observe::<Claude>(collection, page, &bytes).unwrap();
            Ok(())
        })
        .unwrap();
        base
    };
    let body = route.head(&key).unwrap().body;

    let (parser, _, _) = read(&route, &path, None);
    let (tail, native) = route.finish(&path, parser, Some(base(&route, false)), |_| {});
    assert!(tail.staged_for_test().is_none());
    assert_eq!(counters::total("tail_head_migrated", "claude_code"), 0);
    drop((tail, native));

    let (parser, _, _) = read(&route, &path, None);
    let (tail, native) = route.finish(&path, parser, Some(base(&route, true)), |_| {});
    let staged = tail.staged_for_test().expect("the head is restated");
    assert!(staged.pages.is_empty());
    assert_eq!(counters::total("tail_head_migrated", "claude_code"), 1);
    assert!(tail.publish(&native));
    route.save(false);
    let head = route.head(&key).unwrap();
    assert_eq!(head.revision, Claude::REDUCTION_REVISION);
    assert_eq!(head.body, body);
}

/// [money] D142: a stored reuse that finishes the ACKed body reads no native
/// byte and sends nothing.
#[test]
fn an_identical_stored_body_takes_the_ack_path() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (items, native_bytes) = stored_finish(&route, &path, &key);
    assert_eq!(native_bytes, 0);
    let count = items.len();
    assert!(count > 0);
    let scan = finalize(&mut route, &key, items, true, Some(REASON));
    assert!(scan.snapshots.is_empty());
    assert_eq!(scan.semantic_noop_count, count);
    assert!(!route.index.files[&key].rearmed());
    assert!(!take_native(&route.path, &key));
    assert_eq!(counters::total("tail_reuse_differs", "rearmed"), 0);
}

/// [money] D142: a stored reuse that finishes another body sends nothing and
/// never claims a rescan: the entry keeps its ACKed tuple, stays selected, and
/// owes exactly one native read, which then sends the body as a Full does.
/// §12: that read's wait is counted, one pass here.
#[test]
fn a_differing_stored_body_falls_back_to_one_native_read() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (items, _) = stored_finish(&route, &path, &key);
    let scan = finalize(&mut route, &key, items.clone(), false, Some(REASON));
    assert!(scan.snapshots.is_empty(), "the differing body is withheld");
    assert_eq!(scan.semantic_noop_count, 0);
    let entry = &route.index.files[&key];
    assert!(entry.rearmed());
    assert_eq!(
        entry.last_upload_body_witness.as_deref(),
        Some("acked-before")
    );
    assert_eq!(counters::total("tail_reuse_differs", "rearmed"), 1);
    counters::begin_pass();
    assert!(take_native(&route.path, &key));
    assert!(!take_native(&route.path, &key), "one use");
    assert_eq!(counters::total("tail_reuse_wait", "reads"), 1);
    assert_eq!(counters::total("tail_reuse_wait", "passes"), 1);
    assert_eq!(counters::total("tail_reuse_wait", "max_passes"), 1);

    let count = items.len();
    let scan = finalize(&mut route, &key, items, false, None);
    assert_eq!(
        scan.snapshots.len(),
        count,
        "the native read's body is sent"
    );
    assert!(!take_native(&route.path, &key));
    assert_eq!(counters::total("tail_reuse_differs", "rearmed"), 1);
    let wire = serde_json::to_value(snapshot_semantic_envelope(
        SnapshotSource::ClaudeCode,
        &scan.snapshots[0],
        SnapshotUploadPolicy::default(),
    ))
    .unwrap();
    assert!(wire.get("forced_full_rescan").is_none());
}

/// [behaviour] A file proven changed takes its Full under the proven reason.
#[test]
fn a_proven_change_names_its_full() {
    let route = route();
    let path = route.dir.join("a.jsonl");
    std::fs::write(&path, lines(3).join("\n") + "\n").unwrap();
    let mut parser = route.open(&path);
    let Ok(ReadMode::Full(FullReason::StateMissing)) =
        parser.prepare_acquisition_owned(None, &scope(), None, NOW)
    else {
        panic!("no checkpoint");
    };
    let plan = parser.reader.acquisition.as_mut().unwrap();
    assert_eq!(
        plan.name_proven_full(FullReason::Shrunk),
        ReadMode::Full(FullReason::Shrunk),
    );
}

/// [behaviour] §6: which selections continue from stored state.
#[test]
fn the_shipped_selections_reuse_stored_state() {
    for reason in [
        CandidateParseReason::TranscriptChanged,
        CandidateParseReason::SourceChanged,
        CandidateParseReason::Rearmed,
        CandidateParseReason::ForcedFamily,
        CandidateParseReason::AuthorityQuarantine,
        CandidateParseReason::ActivityOrQuarantineRetry,
    ] {
        assert!(reuses_stored(Some(reason)), "{reason:?}");
    }
    assert!(reuse_label(CandidateParseReason::TranscriptChanged).is_none());
    for reason in [
        CandidateParseReason::Audit,
        CandidateParseReason::NewFile,
        CandidateParseReason::UploadContext,
        CandidateParseReason::BodyWitnessAdoption,
    ] {
        assert!(!reuses_stored(Some(reason)), "{reason:?}");
    }
}

/// D138: runs once upload-context and body-witness selections are enabled.
#[test]
#[ignore = "D138"]
fn the_held_selections_reuse_stored_state_when_enabled() {
    assert!(reuses_stored(Some(CandidateParseReason::UploadContext)));
    assert!(reuses_stored(Some(
        CandidateParseReason::BodyWitnessAdoption
    )));
}

/// [money] §6: a forced member reads natively only for evidence stored state
/// cannot supply; the rest recompose.
#[test]
fn a_forced_member_reads_natively_only_for_missing_evidence() {
    let fingerprint = "a".repeat(64);
    let record =
        |shape| ClaudeRequestCensusRecord::synthetic_for_test(&fingerprint, 7, shape, vec![1]);
    let cases = [
        (
            "verified.jsonl",
            record(ClaudeRequestCensusShape::Exact),
            false,
        ),
        (
            "bindable.jsonl",
            record(ClaudeRequestCensusShape::Exact).with_unverified_for_test(true),
            false,
        ),
        (
            "incomplete.jsonl",
            record(ClaudeRequestCensusShape::IdentityIncomplete).with_unverified_for_test(true),
            true,
        ),
        (
            "old.jsonl",
            record(ClaudeRequestCensusShape::Exact)
                .with_unverified_for_test(true)
                .with_derivation_for_test(0),
            true,
        ),
    ];
    let mut index = ScanIndex::default();
    for (key, record, _) in &cases {
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(key, record.clone());
    }
    for (key, _, native) in &cases {
        assert_eq!(forced_member_needs_native(&index, key), *native, "{key}");
    }
    assert!(forced_member_needs_native(&index, "absent.jsonl"));
}
