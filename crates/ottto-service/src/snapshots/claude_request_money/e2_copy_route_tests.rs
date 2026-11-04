//! One copy route: a copied prefix goes only on request-id proof from an
//! earlier accepted main file of another session in the copy's own folder
//! (whatever Claude Code version wrote it), and an accepted copy decided
//! before `COPY_PROOF_FROM` keeps its decision.

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
    decide_page_copies(&mut items, index, None).apply(index);
    items
}
/// (removed, counted, held, flagged) requests of the copy.
fn outcome(items: &[SnapshotItem]) -> (u64, u64, u64, u64) {
    let fold = fold(items);
    (
        fold.entity.removed_requests,
        fold.entity.totals().1,
        fold.prefix.held_requests,
        fold.prefix.unproven_requests,
    )
}

/// [regress] A resume whose own turns a formerly listed version wrote takes
/// the request-id proof like any other: an accepted holder removes the
/// prefix, an unaccepted one defers it, and without a holder it counts,
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
        (true, true, (2, 1, 0, 0)),
        (true, false, (0, 1, 2, 0)),
        (false, false, (0, 3, 0, 2)),
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

/// [behaviour] A copy waits only for an unscanned main file of another
/// session in its own folder; one queued in another folder cannot hold
/// its prefix, so the copy decides now.
#[test]
fn only_an_unscanned_file_in_the_copys_folder_waits() {
    for (same_folder, held) in [(true, 2), (false, 0)] {
        let dir = scratch();
        let path = copy_at(&dir);
        let elsewhere = PathBuf::from(format!("{}-elsewhere", dir.display()));
        let queued = if same_folder { &dir } else { &elsewhere };
        let mut index = ScanIndex {
            traversal: Some(crate::snapshots::claude_family_census_shadow_tests::traversal()),
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
            fold(&items).prefix.held_requests,
            held,
            "same folder {same_folder}"
        );
        assert_eq!(
            fold(&items).prefix.unproven_requests,
            2 - held,
            "same folder {same_folder}"
        );
        let _ = fs::remove_dir_all(dir);
    }
}

/// [money] The grandfather's gates: a resume whose first own response
/// (provider time) is before `COPY_PROOF_FROM`, settled with its copies
/// removed and accepted, with no saved removal, keeps that decision with no
/// holder to prove it, whatever later own turns follow. Any missing
/// condition or an all-copy file takes the request-id proof (here: none, so
/// it counts). The cutoff itself is in the pipeline oracle.
#[test]
fn accepted_pre_cutoff_copy_keeps_its_decision() {
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
            2,
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
            // One request under a holder no longer indexed: that removal stands.
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
