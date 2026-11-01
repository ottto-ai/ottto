// Header-cache identity and production output regression fixtures.
use super::*;
#[cfg(target_os = "macos")]
use crate::transcript_acquisition::Scope;
use std::os::unix::fs::MetadataExt;

#[test]
fn same_size_new_owner_rereads_and_changes_group_key() {
    let (root, inventory) = tests::fixture();
    let paths = inventory
        .headers
        .iter()
        .map(|header| local_index_key(&header.candidate.path))
        .collect();
    let baseline = std::time::UNIX_EPOCH
        + std::time::Duration::from_secs(1_800_000_000)
        + std::time::Duration::from_nanos(100);
    fs::File::options()
        .write(true)
        .open(&inventory.headers[0].candidate.path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(baseline))
        .unwrap();
    let cache = sampled_scan::SharedCache::default();
    let first = header_cache_tests::page(&root, &paths, &cache);
    let old = &first.headers[0];
    let path = &old.candidate.path;
    let before = fs::metadata(path).unwrap();
    let new_owner = "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    assert_ne!(old.owner, new_owner);
    let bytes = fs::read_to_string(path).unwrap();
    let (header, rest) = bytes.split_once('\n').unwrap();
    let header = header.replace(&old.owner, new_owner);
    let replacement = format!("{header}\n{rest}");
    assert_eq!(replacement.len(), bytes.len());
    fs::write(path, replacement).unwrap();
    let modified = before.modified().unwrap() + std::time::Duration::from_nanos(1);
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(fs::FileTimes::new().set_modified(modified))
        .unwrap();
    let after = fs::metadata(path).unwrap();
    assert_eq!(before.dev(), after.dev());
    assert_eq!(before.ino(), after.ino());
    assert_eq!(before.len(), after.len());
    assert_eq!(before.mtime(), after.mtime());
    assert_ne!(before.mtime_nsec(), after.mtime_nsec());
    header_cache_tests::READ_CALLS.with(|calls| calls.set(0));
    let changed = header_cache_tests::page(&root, &paths, &cache);
    assert!(changed.complete);
    assert_eq!(changed.reuse_misses, 1);
    assert_eq!(changed.reuse_hits, paths.len() - 1);
    assert!(changed.read_bytes > 0);
    header_cache_tests::READ_CALLS.with(|calls| assert_eq!(calls.get(), 1));
    assert_eq!(changed.owner_for_path(path), Some(new_owner));
    let new_key = group_key(&old.home, new_owner);
    assert_ne!(new_key, group_key(&old.home, &old.owner));
    let groups = changed.groups();
    let group = &groups[&new_key];
    assert_eq!(group.owner, new_owner);
    assert_eq!(group.members.len(), 1);
    assert_eq!(&group.members[0].path, path);
    assert!(!groups[&group_key(&old.home, &old.owner)]
        .members
        .iter()
        .any(|member| &member.path == path));
    let quiet = header_cache_tests::page(&root, &paths, &cache);
    assert_eq!(quiet.read_bytes, 0);
    assert_eq!(quiet.reuse_hits, paths.len());
    assert_eq!(quiet.owner_for_path(path), Some(new_owner));
    fs::remove_dir_all(root).unwrap();
}

/// Drive the real wake, finalize/policy boundary and production wire serializer.
/// Only owning headers are primed: neither arm has retained transcript state.
#[cfg(target_os = "macos")]
#[test]
fn header_cache_production_wake_output_equivalence_join_parent_counting() {
    let (root, group_keys) = tests::counting_v2_fixture();
    // Acquire the real parent ledger before introducing the fork and joined
    // members. A fresh fork intentionally needs a later parent-prepass wake.
    let group_files = group_keys
        .iter()
        .map(|key| {
            let bytes = fs::read(key).unwrap();
            fs::remove_file(key).unwrap();
            (key, bytes)
        })
        .collect::<Vec<_>>();
    let parent = "019fd6a0-0000-7000-8000-000000000001";
    let child = "019fd6a0-0000-7000-8000-000000000002";
    let turn = json!({"timestamp":"2026-08-02T08:00:01Z","type":"turn_context",
        "payload":{"turn_id":"parent-turn","model":"gpt-5.6-sol"}});
    let usage = |at: &str, total: u64, last: u64| {
        json!({
        "timestamp":at,"type":"event_msg","payload":{"type":"token_count","info":{
            "model":"gpt-5.6-sol","total_token_usage":tests::usage(total),
            "last_token_usage":tests::usage(last)}}})
    };
    let first_usage = usage("2026-08-02T08:00:02Z", 100, 100);
    let mut prior = ScanIndex::default();
    assert!(prior.record_codex_parent_ref(parent));
    for (id, rows) in [
        (
            parent,
            vec![
                json!({"timestamp":"2026-08-02T08:00:00Z","type":"session_meta",
                "payload":{"id":parent,"timestamp":"2026-08-02T08:00:00Z","thread_source":"user"}}),
                turn.clone(),
                first_usage.clone(),
                json!({"timestamp":"2026-08-02T08:30:01Z","type":"turn_context",
                "payload":{"turn_id":"parent-later","model":"gpt-5.6-sol"}}),
                usage("2026-08-02T08:30:02Z", 150, 50),
            ],
        ),
        (
            child,
            vec![
                json!({"timestamp":"2026-08-02T08:20:00Z","type":"session_meta",
                "payload":{"id":child,"timestamp":"2026-08-02T08:20:00Z",
                    "forked_from_id":parent,"thread_source":"user"}}),
                turn,
                first_usage,
                json!({"timestamp":"2026-08-02T08:20:01Z","type":"turn_context",
                "payload":{"turn_id":"child-local","model":"gpt-5.6-sol"}}),
                usage("2026-08-02T08:20:02Z", 115, 15),
            ],
        ),
    ] {
        fs::write(
            root.join("sessions").join(format!("rollout-{id}.jsonl")),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        if id == parent {
            let (mut index, mut scan) = tests::scan(&root, prior, 100);
            finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
            scan.finish_codex_capture_boundary(&mut index);
            assert!(index.codex_parent_ownership_ledgers[parent].scan_complete);
            assert!(!index.codex_parent_ownership_ledgers[parent]
                .signatures
                .is_empty());
            prior = index;
        }
    }
    for (key, bytes) in group_files {
        fs::write(key, bytes).unwrap();
    }
    // Between the August fork and October join: exercise Legacy parent
    // ownership and a non-empty V2 group in the same production scan.
    let _cutover = codex_counting_version::TestCutover::set(1_790_000_000_000);
    let paths = fs::read_dir(root.join("sessions"))
        .unwrap()
        .map(|entry| local_index_key(&entry.unwrap().path()))
        .collect::<BTreeSet<_>>();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let primed = header_cache_tests::page(&root, &paths, &cache);
    assert!(primed.complete);
    assert_eq!(primed.reuse_misses, paths.len());
    assert!(primed.read_bytes > 0);
    let run = |cached: bool| {
        let mut owned = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
            prior.clone(),
            "2026-10-06T23:00:00Z",
            183,
            100,
            false,
            None,
            &[],
            false,
        );
        if cached {
            owned =
                owned.with_sampled_acquisition(Arc::clone(&cache), Scope("header-output".into()));
        }
        for _ in 0..10_000 {
            match owned.step(None) {
                OwnedSourceScanStep::Pending(next) => owned = next,
                OwnedSourceScanStep::Complete {
                    mut index,
                    mut scan,
                    ..
                } => {
                    let inventory = &scan.codex_join_validation.as_ref().unwrap().inventory;
                    assert!(inventory.complete);
                    assert_eq!(inventory.headers.len(), paths.len());
                    assert_eq!(inventory.reuse_hits, if cached { paths.len() } else { 0 });
                    assert_eq!(inventory.reuse_misses, if cached { 0 } else { paths.len() });
                    if cached {
                        assert_eq!(inventory.read_bytes, 0);
                    } else {
                        assert_eq!(inventory.read_bytes, primed.read_bytes);
                    }
                    scan.codex_joining_validator()
                        .unwrap()
                        .validate(&scan.snapshots)
                        .unwrap();
                    let counting = scan.codex_counting_v2.as_deref().unwrap();
                    assert_eq!(counting.v2_sessions, 1);
                    assert_eq!(counting.native_counted, 2);
                    assert_eq!(counting.ui_in_unbound_span, 0);
                    let counting = serde_json::to_value(counting).unwrap();
                    for key in &group_keys {
                        assert!(index.files[key].codex_counting_v2);
                        assert!(index.files[key].codex_joined_member_set.is_some());
                    }
                    let joined = scan
                        .snapshots
                        .iter()
                        .filter(|item| {
                            item.source_session_id == "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(joined.len(), 2, "both physical joined aliases emit");
                    assert!(joined.iter().all(|item| item.input_tokens == 300));
                    assert!(index.codex_parent_ownership_refs.contains(parent));
                    assert!(index.codex_parent_ownership_ledgers[parent].scan_complete);
                    assert!(!index.codex_parent_ownership_ledgers[parent]
                        .signatures
                        .is_empty());
                    assert!(scan
                        .snapshots
                        .iter()
                        .any(|item| item.source_session_id == child && item.input_tokens == 15));
                    index.bind_session_accounts(
                        SnapshotSource::Codex,
                        "header-output-machine",
                        &mut scan.snapshots,
                        &[],
                    );
                    let policy = SnapshotUploadPolicy::default();
                    apply_upload_policy(SnapshotSource::Codex, &mut scan.snapshots, policy);
                    finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                    scan.finish_codex_capture_boundary(&mut index);
                    assert!(
                        !scan.snapshots.is_empty(),
                        "empty output is no equality proof"
                    );
                    let request = SnapshotBatchRequest {
                        schema_version: SNAPSHOT_SCHEMA_VERSION,
                        source: SnapshotSource::Codex.api_slug().into(),
                        machine_id: "a".repeat(64),
                        collector_version: Some("0.1.synthetic".into()),
                        snapshots: scan.snapshots,
                        upload_policy: policy,
                        client_report: crate::client_report::ClientReport::empty(),
                    };
                    validate_snapshot_batch_request(&request).unwrap();
                    let body = serde_json::to_vec(&request).unwrap();
                    let evidence = serde_json::to_vec(&json!({
                        "parent_refs":index.codex_parent_ownership_refs,
                        "parent_ledgers":index.codex_parent_ownership_ledgers,
                        "counting":counting,
                        "join_members":group_keys.iter().map(|key| &index.files[key].codex_joined_member_set).collect::<Vec<_>>(),
                    })).unwrap();
                    return (body, evidence);
                }
            }
        }
        panic!("production wake did not finish");
    };
    let (cached_body, cached_evidence) = run(true);
    let (uncached_body, uncached_evidence) = run(false);
    assert_eq!(cached_body, uncached_body, "complete emitted wire body");
    assert_eq!(Sha256::digest(&cached_body), Sha256::digest(&uncached_body));
    assert_eq!(
        cached_evidence, uncached_evidence,
        "join, parent and counting evidence"
    );
    fs::remove_dir_all(root).unwrap();
}
