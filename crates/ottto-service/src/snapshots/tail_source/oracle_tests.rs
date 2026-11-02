//! Committed Claude Tail transitions, compared with independently parsed Fulls.
//! Scan, account and ACK rows live beside the end-to-end pipeline fixture.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};
use crate::snapshots::tail_source::seam::PendingTail;

const SOURCE: SnapshotSource = SnapshotSource::ClaudeCode;

fn emitted(mode: Mode, items: &[SnapshotItem]) -> RouteResult {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SOURCE.api_slug().into(),
        machine_id: "a".repeat(64),
        collector_version: Some("0.1.synthetic".into()),
        snapshots: items.to_vec(),
        upload_policy: SnapshotUploadPolicy::default(),
        client_report: crate::client_report::ClientReport::empty(),
    };
    RouteResult::emitted(
        mode,
        SOURCE,
        vec![serde_json::to_vec(&request).unwrap()],
        items,
    )
}

fn full(route: &Route, path: &Path) -> RouteResult {
    let (parser, mode, start) = read(route, path, None);
    assert!(matches!(mode, ReadMode::Full(_)) && start == 0);
    let (_, native) = route.finish(path, parser, None, |_| {});
    emitted(Mode::ColdFull, &native.unwrap().snapshots)
}

fn stored(route: &Route, path: &Path, key: &str) -> (PendingTail, RouteResult, ReadMode, u64) {
    let (Load::Reused(taken, base), records) = loaded(route, path, key) else {
        panic!("committed Tail must load");
    };
    assert_eq!(counted(&records), ("hit".into(), vec![]));
    // The load receipt counts X re-derivation independently of native bytes.
    assert!(records
        .iter()
        .any(|record| record["counts"]["rederive_bytes"].as_u64().is_some()));
    let (parser, mode, _) = read(route, path, Some(taken));
    let consumed = parser.reader.consumed_bytes();
    let (tail, native) = route.finish(path, parser, base, |_| {});
    (
        tail,
        emitted(Mode::DiskRestore, &native.unwrap().snapshots),
        mode,
        consumed,
    )
}

/// [money] Restart, eviction and a long/non-ASCII skill all use the same
/// durable continuation. No RAM admission is required; expected totals are
/// independent of either serializer or finalizer.
#[test]
fn restart_append_eviction_and_skill_labels_match_full() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 300);
    let sealed = len(&path);
    route.index = ScanIndex::load(&route.path).unwrap();
    append(&path, 300);
    let cold = full(&route, &path);
    let (_, warm, mode, end) = stored(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Tail));
    assert_eq!(end, len(&path) - sealed);
    assert!(len(&path) > sealed);
    money_oracle::assert_equivalent(&cold, &warm);
    let body = cold.snapshots.values().next().unwrap();
    assert_eq!(body["request_count"], 301);
    assert_eq!(
        body["input_tokens"],
        (0..301u64).map(|i| 10 + i).sum::<u64>()
    );
    assert_eq!(body["output_tokens"], 301 * 5);
    let mut acc = SnapshotAccumulator::new(SOURCE);
    let head = route.head(&key).unwrap();
    Claude::decode_head(head.revision, &head.body, &mut acc).unwrap();
    assert!(acc
        .provider_skills
        .iter()
        .any(|name| !name.is_ascii() && name.len() > 96));
    let cache = sampled_scan::SharedCache::default();
    cache.clear();
    let (_, evicted, mode, _) = stored(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Tail));
    money_oracle::assert_equivalent(&cold, &evicted);
}

/// [money] An explicitly selected quiet file is Unchanged, consumes zero
/// native reduction bytes, and its stored finalization equals the cold Full.
#[test]
fn quiet_selected_restart_is_unchanged_and_matches_full() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    route.index = ScanIndex::load(&route.path).unwrap();
    let head = route.head(&key).unwrap().body;
    let (tail, warm, mode, _) = stored(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Unchanged));
    assert!(tail.staged_for_test().is_none());
    money_oracle::assert_equivalent(&full(&route, &path), &warm);
    assert_eq!(route.head(&key).unwrap().body, head);
    // read() does not step an Unchanged parser; verify its real byte counter.
    let (Load::Reused(taken, _), _) = loaded(&route, &path, &key) else {
        unreachable!()
    };
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Unchanged));
    assert_eq!(parser.reader.consumed_bytes(), 0);
}

/// [money] Crash at the existing stage/commit boundary discards only the
/// uncommitted successor. Replay starts at the previous seal and counts once.
#[test]
fn staged_successor_crash_replays_from_the_previous_head() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let previous = route.head(&key).unwrap().body;
    let sealed = len(&path);
    append(&path, 3);
    let (Load::Reused(taken, base), _) = loaded(&route, &path, &key) else {
        unreachable!()
    };
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail) && start == sealed);
    let (tail, native) = route.finish(&path, parser, base, |_| {});
    assert!(tail.publish(&native));
    drop(BaselineRelease::new(&route.path, &route.index));
    route.index = ScanIndex::load(&route.path).unwrap();
    assert_eq!(route.head(&key).unwrap().body, previous);
    let (Load::Reused(taken, base), _) = loaded(&route, &path, &key) else {
        unreachable!()
    };
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail) && start == sealed);
    assert_eq!(parser.reader.consumed_bytes(), len(&path) - sealed);
    let (tail, native) = route.finish(&path, parser, base, |_| {});
    let warm = emitted(Mode::Restart, &native.as_ref().unwrap().snapshots);
    money_oracle::assert_equivalent(&full(&route, &path), &warm);
    assert!(tail.publish(&native));
    route.save(false);
    let (_, after, mode, _) = stored(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Unchanged));
    money_oracle::assert_equivalent(&full(&route, &path), &after);
}

/// [money] A head behind accepted progress replays through the floor even
/// after an evidence-only fingerprint clear; the record stays eligible.
#[test]
fn evidence_clear_does_not_relax_the_floor_or_invalidate_the_head() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let sealed = len(&path);
    append(&path, 3);
    let mut accepted = manifest_index_entry(None);
    accepted.size_bytes = len(&path);
    accepted.source_file_fingerprint.clear();
    route.index.files.insert(key.clone(), accepted);
    let floor = AcceptedFloor::of(&route.index, &key).unwrap();
    assert!(floor.behind(sealed));
    let (Load::Reused(taken, base), _) = loaded(&route, &path, &key) else {
        unreachable!()
    };
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail) && start == sealed);
    assert!(!floor.behind(start + parser.reader.consumed_bytes()));
    let (_, native) = route.finish(&path, parser, base, |_| {});
    money_oracle::assert_equivalent(
        &full(&route, &path),
        &emitted(Mode::Restart, &native.unwrap().snapshots),
    );
}

/// [money] Consent filters uploads and never rewrites the stored head. Each
/// labels × attribution mode compares independently filtered Full and Tail.
#[test]
fn consent_matrix_preserves_head_and_money() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let head = route.head(&key).unwrap().body;
    append(&path, 3);
    let (Load::Reused(taken, base), _) = loaded(&route, &path, &key) else {
        unreachable!()
    };
    let (parser, _, _) = read(&route, &path, Some(taken));
    let (_, native) = route.finish(&path, parser, base, |_| {});
    let (parser, _, _) = read(&route, &path, None);
    let (_, cold) = route.finish(&path, parser, None, |_| {});
    for labels in [false, true] {
        for attribution in [false, true] {
            let policy = SnapshotUploadPolicy {
                session_attribution_labels_enabled: labels,
                session_attribution_enabled: attribution,
                ..Default::default()
            };
            let mut a = cold.as_ref().unwrap().snapshots.clone();
            let mut b = native.as_ref().unwrap().snapshots.clone();
            apply_upload_policy(SOURCE, &mut a, policy);
            apply_upload_policy(SOURCE, &mut b, policy);
            money_oracle::assert_equivalent(
                &emitted(Mode::ColdFull, &a),
                &emitted(Mode::Restart, &b),
            );
            if !attribution {
                assert!(b.iter().all(|item| item.attribution_facts.is_empty()));
            }
            if !labels {
                assert!(!serde_json::to_string(&b).unwrap().contains("ünïcödé"));
            }
            assert_eq!(route.head(&key).unwrap().body, head);
        }
    }
}

/// [money] Lower unknown revisions reconstruct; future revisions retain
/// custody. Neither path may invent a smaller accepted body.
#[test]
fn lower_and_future_revisions_keep_their_distinct_contracts() {
    for future in [false, true] {
        let mut route = route();
        let (mut tail, native) = route.complete("a.jsonl", &lines(3), None, |_| {});
        let key = tail.key_for_test().to_owned();
        let path = route.dir.join("a.jsonl");
        let prior_items = native.unwrap().snapshots;
        let mut prior = emitted(Mode::ColdFull, &prior_items);
        for item in &prior_items {
            prior.accepted.insert(
                item.source_session_id.clone(),
                crate::snapshots::sampled_scan::transition_fixture::Accepted {
                    body: prior.snapshots[&item.source_session_id].clone(),
                    witness: snapshot_upload_body_witness(item),
                },
            );
        }
        let mut staged = tail.take_staged_for_test();
        staged.revision = if future {
            Claude::REDUCTION_REVISION + 1
        } else {
            Claude::REDUCTION_REVISION - 1
        };
        state_v2::stage_tail(&route.path, &key, staged).unwrap();
        route.save(false);
        let head = route.head(&key).unwrap().body;
        let (load, records) = loaded(&route, &path, &key);
        if future {
            assert!(matches!(load, Load::Held));
            assert_eq!(counted(&records), ("held".into(), vec![]));
            let mut held = RouteResult::emitted(Mode::Restart, SOURCE, vec![], &[]);
            held.accepted = prior.accepted.clone();
            money_oracle::assert_no_smaller_reemit(
                &prior_items[0].source_session_id,
                &prior,
                &held,
                &full(&route, &path),
                true,
            );
        } else {
            assert!(matches!(load, Load::Cold(None)));
            assert_eq!(counted(&records), ("error".into(), vec!["revision".into()]));
            let (parser, mode, _) = read(&route, &path, None);
            assert!(matches!(mode, ReadMode::Full(_)));
            let (_, native) = route.finish(&path, parser, None, |_| {});
            money_oracle::assert_equivalent(
                &full(&route, &path),
                &emitted(Mode::Restart, &native.unwrap().snapshots),
            );
        }
        assert_eq!(route.head(&key).unwrap().body, head);
    }
}

/// [money] Differing stored bodies are withheld, then the one-use native
/// obligation produces the same whole body as cold Full, without Full credit.
#[test]
fn differing_stored_body_native_fallback_matches_full() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (items, bytes) = stored_finish(&route, &path, &key);
    assert_eq!(bytes, 0);
    let scan = finalize(&mut route, &key, items, false, Some(REASON));
    assert!(scan.snapshots.is_empty());
    assert!(state_v2::take_native_read(&route.path, &key));
    assert!(!state_v2::take_native_read(&route.path, &key));
    let (parser, mode, _) = read(&route, &path, None);
    assert!(matches!(mode, ReadMode::Full(_)));
    assert_eq!(parser.reader.consumed_bytes(), len(&path));
    let (_, native) = route.finish(&path, parser, None, |_| {});
    let scan = finalize(&mut route, &key, native.unwrap().snapshots, false, None);
    money_oracle::assert_equivalent(
        &full(&route, &path),
        &emitted(Mode::Restart, &scan.snapshots),
    );
}

fn held_selection(reason: CandidateParseReason) {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    assert!(reuses_stored(Some(reason)), "held selection not enabled");
    let (tail, warm, mode, _) = stored(&route, &path, &key);
    assert!(matches!(mode, ReadMode::Unchanged));
    assert!(tail.staged_for_test().is_none());
    money_oracle::assert_equivalent(&full(&route, &path), &warm);
    // Upload inputs are outside the leading identity.
    HeadIdentity::new(&route.path, SOURCE, &route.dir, &path, false)
        .check(&route.head(&key).unwrap().body)
        .unwrap();
}

#[test]
#[ignore = "D138"]
fn upload_context_stored_oracle() {
    held_selection(CandidateParseReason::UploadContext);
}

#[test]
#[ignore = "D138"]
fn body_witness_adoption_stored_oracle() {
    held_selection(CandidateParseReason::BodyWitnessAdoption);
}
