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
    // The load counts database bytes independently of native bytes; content
    // is a stored session fact, never re-read from the file.
    assert!(counters::total("tail_db_load_bytes", "head") > 0);
    assert!(records
        .records
        .iter()
        .all(|record| record["counts"].get("rederive_bytes").is_none()));
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

/// [money] Restart and a long/non-ASCII skill use the same
/// durable continuation. No RAM admission is required; expected totals are
/// independent of either serializer or finalizer.
#[test]
fn restart_append_and_skill_labels_match_full() {
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

/// [money] A head behind accepted progress continues from its seal to the
/// end of the file even after an evidence-only fingerprint clear; the record
/// stays eligible. No floor holds it (D158).
#[test]
fn evidence_clear_keeps_a_head_behind_accepted_progress_eligible() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let sealed = len(&path);
    append(&path, 3);
    let mut accepted = manifest_index_entry(None);
    accepted.size_bytes = len(&path);
    accepted.source_file_fingerprint.clear();
    route.index.files.insert(key.clone(), accepted);
    assert!(route.index.files[&key].size_bytes > sealed);
    let (Load::Reused(taken, base), _) = loaded(&route, &path, &key) else {
        unreachable!()
    };
    let (parser, mode, start) = read(&route, &path, Some(taken));
    assert!(matches!(mode, ReadMode::Tail) && start == sealed);
    assert_eq!(start + parser.reader.consumed_bytes(), len(&path));
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
        let head = state_v2::load_head(&route.index, &key, u32::MAX)
            .unwrap()
            .unwrap()
            .body;
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
            assert_eq!(
                counted(&records),
                ("error".into(), vec!["incompatible".into()])
            );
            let (parser, mode, _) = read(&route, &path, None);
            assert!(matches!(mode, ReadMode::Full(_)));
            let (_, native) = route.finish(&path, parser, None, |_| {});
            money_oracle::assert_equivalent(
                &full(&route, &path),
                &emitted(Mode::Restart, &native.unwrap().snapshots),
            );
        }
        assert_eq!(
            state_v2::load_head(&route.index, &key, u32::MAX)
                .unwrap()
                .unwrap()
                .body,
            head
        );
    }
}

/// [money] A late-evidence re-fold whose body is not the ACKed one reads 0
/// native bytes and is sent as an ordinary update (L02): its body is the
/// cold Full's whole body, never a rescan claim or a challenge answer,
/// counted by its reason, and nothing is owed afterwards. An append's body
/// is not a re-fold.
#[test]
fn differing_stored_body_is_sent_as_the_cold_full_body() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    let (items, bytes) = stored_finish(&route, &path, &key);
    assert_eq!(bytes, 0);
    let count = items.len();
    let scan = finalize(&mut route, &key, items.clone(), false, Some(REASON));
    assert_eq!(scan.snapshots.len(), count, "the re-fold is sent");
    assert_eq!(scan.semantic_noop_count, 0);
    assert_eq!(counters::total("tail_refold", "rearmed"), 1);
    money_oracle::assert_equivalent(
        &full(&route, &path),
        &emitted(Mode::Restart, &scan.snapshots),
    );
    for item in &scan.snapshots {
        let envelope = serde_json::to_value(snapshot_semantic_envelope(
            SOURCE,
            item,
            SnapshotUploadPolicy::default(),
        ))
        .unwrap();
        assert!(envelope.get("forced_full_rescan").is_none());
        assert!(envelope.get("conflict_head_challenge").is_none());
        assert!(envelope.get("rescan_from_revision_hash").is_none());
    }
    assert!(reuses_stored(&route.index, &key, Some(REASON), false));

    let scan = finalize(&mut route, &key, items, false, None);
    assert_eq!(scan.snapshots.len(), count);
    assert_eq!(counters::total("tail_refold", "rearmed"), 1);
}
