//! One copy route: a copied prefix goes only on request-id proof from an
//! earlier accepted main file of another session in the copy's own folder
//! (whatever Claude Code version wrote it), however early it was decided.

use super::*;

/// Another session that is never a holder: a queued, unscanned main file.
const OTHER: &str = "d0000000-0000-4000-8000-00000000000d";
/// 2026-11-05: a first own turn after `COPY_PROOF_FROM`.
const AFTER_CUTOFF: &str = "2026-11-05T07:00:00Z";

/// The same response as a listed-version writer stored it.
fn listed(mut value: Value) -> Value {
    value["version"] = json!("2.1.309");
    value
}
/// The two copied requests of the shared fixtures.
fn copies() -> [Value; 2] {
    [line("copy-a", &at(1), 10), line("copy-b", &at(2), 11)]
}
/// One page's copy decision over `lines`, as `decide_pass` makes it.
fn pass(index: &mut ScanIndex, path: &Path, lines: &[Value]) -> Vec<SnapshotItem> {
    let mut items = read_file(path, index, lines);
    decide_page_copies(&mut items, index).apply(index);
    items
}
/// (removed, counted, held, flagged) requests of the copy.
fn outcome(items: &[SnapshotItem]) -> (u64, u64, u64) {
    let fold = fold(items);
    (
        fold.entity.removed_requests,
        fold.entity.totals().1,
        fold.prefix.unproven_requests,
    )
}

/// [regress] A resume whose own turns a formerly listed version wrote takes
/// the request-id proof like any other: an accepted holder removes the
/// prefix, a local unaccepted one removes it, and without a holder it counts,
/// flagged, never dropped on timestamps alone.
#[test]
fn listed_writer_copy_needs_a_holder() {
    let lines = [
        listed(line("copy-a", &at(1), 10)),
        listed(line("copy-b", &at(2), 11)),
        listed(line("own", &at(101), 20)),
    ];
    // (holder holds the copies, holder accepted, expected outcome)
    for (holds, accepted, expected) in [
        (true, true, (2, 1, 0)),
        (true, false, (2, 1, 0)),
        (false, false, (0, 3, 2)),
    ] {
        let dir = scratch();
        let path = copy_at(&dir);
        let ids: &[&str] = if holds { &["copy-a", "copy-b"] } else { &[] };
        let mut index = index_holding(&dir, ids);
        if accepted {
            accepted_receipt(&mut index, &dir);
        }
        let items = pass(&mut index, &path, &lines);
        assert_eq!(
            outcome(&items),
            expected,
            "holds {holds} accepted {accepted}"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

/// [behaviour] Only a holder in the copy's folder proves its prefix: a
/// holder in a folder whose name extends the copy's proves nothing.
#[test]
fn holder_outside_the_copys_folder_proves_nothing() {
    for (neighbour, removed) in [(false, 2), (true, 0)] {
        let dir = scratch();
        let path = copy_at(&dir);
        let holder_dir = if neighbour {
            PathBuf::from(format!("{}-y", dir.display()))
        } else {
            dir.clone()
        };
        fs::create_dir_all(&holder_dir).unwrap();
        let mut index = index_holding(&holder_dir, &["copy-a", "copy-b"]);
        accepted_receipt(&mut index, &holder_dir);
        let items = decide_pass(&mut index, &path);
        assert_eq!(
            fold(&items).entity.removed_requests,
            removed,
            "neighbour {neighbour}"
        );
        assert_eq!(
            fold(&items).prefix.unproven_requests,
            2 - removed,
            "neighbour {neighbour}"
        );
        let _ = fs::remove_dir_all(&holder_dir);
        let _ = fs::remove_dir_all(dir);
    }
}

/// [behaviour] Unscanned files provide no positive ownership proof. A copy
/// counts its prefix immediately, in either folder.
#[test]
fn unscanned_files_do_not_hold_the_copy_prefix() {
    for same_folder in [true, false] {
        let dir = scratch();
        let path = copy_at(&dir);
        let elsewhere = PathBuf::from(format!("{}-elsewhere", dir.display()));
        let queued = if same_folder { &dir } else { &elsewhere };
        let mut index = ScanIndex {
            traversal: Some(crate::snapshots::tests::traversal_checkpoint()),
            ..ScanIndex::default()
        };
        index
            .traversal
            .as_mut()
            .unwrap()
            .pending_candidates
            .push_back(crate::snapshots::ScanTraversalPath {
                scan_root: dir.clone(),
                path: queued.join(format!("{OTHER}.jsonl")),
                census_member: true,
                watcher_hint: false,
            });
        let items = decide_pass(&mut index, &path);
        assert_eq!(
            fold(&items).entity.totals().1,
            3,
            "same folder {same_folder}"
        );
        assert_eq!(
            fold(&items).prefix.unproven_requests,
            2,
            "same folder {same_folder}"
        );
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&local_index_key(&path))));
        let _ = fs::remove_dir_all(dir);
    }
}

/// [regress] A save selects a disagreeing counted copy once. A removal
/// already decided on this page, and an ordinary overlapping own turn, do
/// not become new read obligations when their holder commits or is ACKed.
#[test]
fn save_marks_only_disagreeing_copy_decisions() {
    for (removed, disclosed, marked, other_carrier) in [
        (true, false, false, false),
        (false, true, true, false),
        (false, false, false, false),
        (true, false, false, true),
    ] {
        let dir = scratch();
        let path = copy_at(&dir);
        let key = local_index_key(&path);
        let location = location_key(&key);
        let mut next = index_holding(&dir, &["copy-a"]);
        let holder = holder_key(&dir);
        next.files.insert(key.clone(), next.files[&holder].clone());
        next.file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from(["copy-body".into()]));
        next.claude_money_birth_store
            .record_observation(ROOT, &key, t0() + 100_000_000_000);
        next.claude_money_birth_store.set_money_marks(
            &key,
            if removed {
                money_mark::COPY
            } else if disclosed {
                money_mark::DISCLOSED
            } else {
                0
            },
        );
        next.claude_request_census_mut_for_test().insert_for_test(
            &key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &"a".repeat(64),
                1,
                ClaudeRequestCensusShape::Exact,
                vec![claude_request_hash("copy-a")],
            ),
        );
        if removed {
            next.claude_copy_removals.store(
                location,
                BTreeMap::from([(
                    location_key(&holder),
                    BTreeSet::from([claude_request_hash("copy-a")]),
                )]),
            );
        }
        if other_carrier {
            // Discovery order can put the summed body on a later location.
            // The earlier location still counts this id for its session.
            let carrier = local_index_key(&dir.join("other").join(format!("{HOLDER}.jsonl")));
            next.files
                .insert(carrier.clone(), next.files[&holder].clone());
            next.file_snapshot_fingerprints.insert(
                carrier.clone(),
                next.file_snapshot_fingerprints[&holder].clone(),
            );
            next.file_snapshot_fingerprints
                .insert(holder.clone(), BTreeSet::new());
            next.claude_money_birth_store.record_observation(
                HOLDER,
                &carrier,
                t0() + 200_000_000_000,
            );
            next.claude_request_census_mut_for_test().insert_for_test(
                &carrier,
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    ClaudeRequestCensusShape::Exact,
                    vec![claude_request_hash("copy-a")],
                ),
            );
            assert!(!origin_owned(&next, &[], &holder, true));
            assert!(saved_removal_applies(
                &next,
                &indexed_main_files(&next),
                &key,
                claude_request_hash("copy-a"),
            ));
        }
        reconcile_copy_ownership(&ScanIndex::default(), &mut next);
        assert_eq!(next.claude_copy_removals.pending(location), marked);
        next.claude_copy_removals.clear_hold(location);
        let previous = CopyOwnership::capture(&next);
        accepted_receipt(&mut next, &dir);
        previous.reconcile(&mut next, &mut |_| Carriers::default());
        assert!(
            !next.claude_copy_removals.pending(location),
            "an ACK adds no ownership change"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

/// [regress] Restored positive census proof changes a counted copy's answer
/// even when the holder's acceptance already kept ownership true throughout.
#[test]
fn restored_census_marks_an_accepted_holders_counted_copy_once() {
    for missing in [false, true] {
        let dir = scratch();
        let key = local_index_key(&copy_at(&dir));
        let location = location_key(&key);
        let mut next = index_holding(&dir, &["copy-a"]);
        let holder = holder_key(&dir);
        accepted_receipt(&mut next, &dir);
        next.files.insert(key.clone(), next.files[&holder].clone());
        next.file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from(["copy-body".into()]));
        next.claude_money_birth_store
            .record_observation(ROOT, &key, t0() + 100_000_000_000);
        next.claude_money_birth_store
            .set_money_marks(&key, money_mark::DISCLOSED);
        next.claude_request_census_mut_for_test().insert_for_test(
            &key,
            ClaudeRequestCensusRecord::synthetic_for_test(
                &"a".repeat(64),
                1,
                ClaudeRequestCensusShape::Exact,
                vec![claude_request_hash("copy-a")],
            ),
        );
        let mut previous = next.clone();
        if missing {
            previous
                .claude_request_census_mut_for_test()
                .remove(&holder);
        } else {
            previous
                .claude_request_census_mut_for_test()
                .insert_for_test(
                    &holder,
                    ClaudeRequestCensusRecord::synthetic_for_test(
                        &"a".repeat(64),
                        1,
                        ClaudeRequestCensusShape::Exact,
                        vec![],
                    ),
                );
        }
        assert!(origin_owned(&previous, &[], &holder, true));
        assert!(origin_owned(&next, &[], &holder, true));
        reconcile_copy_ownership(&previous, &mut next);
        assert!(next.claude_copy_removals.pending(location));
        next.claude_copy_removals.clear_hold(location);
        let unchanged = CopyOwnership::capture(&next);
        unchanged.reconcile(&mut next, &mut |_| Carriers::default());
        assert!(!next.claude_copy_removals.pending(location));
        let _ = fs::remove_dir_all(dir);
    }
}

/// [regress] A non-counting in-folder location leads to its session's owner
/// elsewhere. When that owner commits, the previously counted copy must be
/// selected even though the local location itself never becomes owned.
#[test]
fn save_marks_copy_when_holder_session_gains_an_owner_in_another_folder() {
    for (different, saved) in [(false, false), (true, false), (false, true), (true, true)] {
        let dir = scratch();
        let elsewhere = dir.join("origin");
        let local = dir.join("local");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(&local).unwrap();
        let mut next = index_holding(
            &elsewhere,
            if different { &["copy-b"] } else { &["copy-a"] },
        );
        let holder = holder_key(&elsewhere);
        let local_holder = local.join(format!("{HOLDER}.jsonl"));
        let copy = copy_at(&local);
        for (path, session, birth, counted) in [
            (local_holder, HOLDER, t0() + 50_000_000_000, false),
            (copy.clone(), ROOT, t0() + 100_000_000_000, true),
        ] {
            let key = local_index_key(&path);
            next.files.insert(key.clone(), next.files[&holder].clone());
            next.file_snapshot_fingerprints.insert(
                key.clone(),
                if counted {
                    BTreeSet::from(["copy-body".into()])
                } else {
                    BTreeSet::new()
                },
            );
            next.claude_money_birth_store
                .record_observation(session, &key, birth);
            next.claude_money_birth_store
                .set_money_marks(&key, if counted { money_mark::DISCLOSED } else { 0 });
            let mut hashes = vec![claude_request_hash("copy-a")];
            if counted && different {
                hashes.push(claude_request_hash("copy-b"));
            }
            hashes.sort_unstable();
            next.claude_request_census_mut_for_test().insert_for_test(
                &key,
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    ClaudeRequestCensusShape::Exact,
                    hashes,
                ),
            );
        }
        let copy_key = location_key(&local_index_key(&copy));
        if saved {
            // A same-session body elsewhere now validates the bridge location's
            // stored groups. Use a genuinely disproven holder for the invalid
            // old-group arms, while preserving the in-folder session bridge.
            let invalid = local_index_key(&elsewhere.join(format!("{OTHER}.jsonl")));
            next.files
                .insert(invalid.clone(), next.files[&holder].clone());
            next.claude_request_census_mut_for_test().insert_for_test(
                &invalid,
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    ClaudeRequestCensusShape::Exact,
                    vec![],
                ),
            );
            next.claude_copy_removals.store(
                copy_key,
                BTreeMap::from([(
                    location_key(&invalid),
                    BTreeSet::from([claude_request_hash(if different {
                        "copy-b"
                    } else {
                        "copy-a"
                    })]),
                )]),
            );
        } else if different {
            // The bridge id's stable historical removal does not hide the new id.
            next.claude_copy_removals.store(
                copy_key,
                BTreeMap::from([(
                    location_key("historical-holder"),
                    BTreeSet::from([claude_request_hash("copy-a")]),
                )]),
            );
        }
        let mut previous = next.clone();
        previous
            .file_snapshot_fingerprints
            .insert(holder.clone(), BTreeSet::new());
        assert!(!origin_owned(&previous, &[], &holder, true));
        assert!(origin_owned(&next, &[], &holder, true));
        reconcile_copy_ownership(&previous, &mut next);
        assert!(next
            .claude_copy_removals
            .pending(location_key(&local_index_key(&copy))));
        let _ = fs::remove_dir_all(dir);
    }
}

/// One indexed main of `session` in `dir`, born `birth`, whose census holds
/// `copy-a`. No body of its own unless it carries the summed session body.
fn main_in(index: &mut ScanIndex, dir: &Path, session: &str, birth: i128, carries: bool) -> String {
    fs::create_dir_all(dir).unwrap();
    let path = dir.join(format!("{session}.jsonl"));
    fs::write(&path, b"fixture\n").unwrap();
    let key = local_index_key(&path);
    index.files.insert(
        key.clone(),
        serde_json::from_value(json!({"size_bytes":8,"modified_unix_seconds":1,
            "source_file_fingerprint":"a".repeat(64)}))
        .unwrap(),
    );
    // The synthetic accepted slot's body fingerprint.
    let bodies = if carries {
        BTreeSet::from(["c".repeat(64)])
    } else {
        BTreeSet::new()
    };
    index.file_snapshot_fingerprints.insert(key.clone(), bodies);
    index
        .claude_money_birth_store
        .record_observation(session, &key, birth);
    index.claude_request_census_mut_for_test().insert_for_test(
        &key,
        ClaudeRequestCensusRecord::synthetic_for_test(
            &"a".repeat(64),
            1,
            ClaudeRequestCensusShape::Exact,
            vec![claude_request_hash("copy-a")],
        ),
    );
    key
}

/// [money] A same-session path twin decided while its earlier twin was not
/// yet owned counts the copied request at its own location. The summed
/// body's mark sits on whichever twin carries it, so the counting copy may
/// have no mark. Once the earlier twin's row is accepted, a save selects
/// the copy once, whichever twin carries the body. A copy of another
/// session with the same rows and no mark stays unselected, and a repeated
/// save adds no second mark.
#[test]
fn save_marks_a_counted_path_twin_without_its_own_mark() {
    let hash = claude_request_hash("copy-a");
    // (the copy carries the summed body, the earlier main is the same session)
    for (copy_carries, twins) in [(false, true), (true, true), (false, false)] {
        let dir = scratch();
        let mut next = ScanIndex::default();
        let (original_dir, session) = if twins {
            (dir.join("a-original"), ROOT)
        } else {
            (dir.join("z-copy"), HOLDER)
        };
        let original = main_in(&mut next, &original_dir, session, t0(), !copy_carries);
        let copy = main_in(
            &mut next,
            &dir.join("z-copy"),
            ROOT,
            t0() + 100_000_000_000,
            copy_carries,
        );
        let carrier = if copy_carries { &copy } else { &original };
        next.claude_money_birth_store
            .set_money_marks(carrier, money_mark::DISCLOSED);
        let previous = next.clone();
        // The ACK accepts the summed body: the copied request counts at both.
        for (key, session) in [(&original, session), (&copy, ROOT)] {
            crate::snapshots::e2_pipeline_scan_fixture::accepted_origin_hashes_for_test(
                &mut next,
                key,
                session,
                &[hash],
            );
        }
        let location = location_key(&copy);
        let case = format!("copy carries {copy_carries}, twins {twins}");
        reconcile_copy_ownership(&previous, &mut next);
        assert_eq!(next.claude_copy_removals.pending(location), twins, "{case}");
        assert!(
            !next.claude_copy_removals.pending(location_key(&original)),
            "{case}: the earlier main owes nothing"
        );
        next.claude_copy_removals.clear_hold(location);
        let unchanged = CopyOwnership::capture(&next);
        unchanged.reconcile(&mut next, &mut |_| Carriers::default());
        assert!(
            !next.claude_copy_removals.pending(location),
            "{case}: a repeated save adds no second mark"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

/// [money] A resume whose first own response (provider time) is before
/// `COPY_PROOF_FROM`, settled with its copies removed and accepted, takes
/// the request-id proof like any other copy: with no holder it counts,
/// flagged. Only a saved removal under an accepted holder stays removed.
#[test]
fn accepted_pre_cutoff_copy_takes_the_request_id_proof() {
    let [copy_a, copy_b] = copies();
    let own = line("own", &at(101), 20);
    let late = line("own-late", AFTER_CUTOFF, 20);
    let resumed = [copy_a.clone(), copy_b.clone(), own.clone()];
    // (case, lines, COPY mark, accepted body, saved removal, removed)
    let cases = [
        (
            "later own after cutoff",
            vec![copy_a.clone(), copy_b.clone(), own, late],
            true,
            true,
            false,
            0,
        ),
        ("no copy mark", resumed.to_vec(), false, true, false, 0),
        ("no accepted body", resumed.to_vec(), true, false, false, 0),
        ("saved removal", resumed.to_vec(), true, true, true, 1),
        ("all copy", vec![copy_a, copy_b], true, true, false, 0),
    ];
    for (case, lines, mark, accepted, saved, removed) in cases {
        let dir = scratch();
        let path = copy_at(&dir);
        let key = local_index_key(&path);
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            serde_json::from_value(json!({"size_bytes":8,"modified_unix_seconds":1,
                "source_file_fingerprint":"c".repeat(64)}))
            .unwrap(),
        );
        if mark {
            index
                .claude_money_birth_store
                .set_money_marks(&key, money_mark::COPY);
        }
        if accepted {
            crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test(&mut index, &key);
        }
        if saved {
            // One request under an accepted holder no longer indexed stays removed.
            crate::snapshots::e2_pipeline_scan_fixture::accepted_origin_hashes_for_test(
                &mut index,
                "gone",
                "gone",
                &[claude_request_hash("copy-a")],
            );
            index.claude_copy_removals.store(
                location_key(&key),
                BTreeMap::from([(
                    location_key("gone"),
                    BTreeSet::from([claude_request_hash("copy-a")]),
                )]),
            );
        }
        let items = pass(&mut index, &path, &lines);
        assert_eq!(fold(&items).entity.removed_requests, removed, "{case}");
        assert_eq!(
            fold(&items).prefix.unproven_requests,
            2 - removed,
            "{case}: what stays counts, flagged"
        );
        let _ = fs::remove_dir_all(dir);
    }
}
