//! Synthetic admission/retention fixtures. Discovery deliberately stays off.
use super::*;
use crate::local_resource_diagnostics::capture;
use codex_compressed_input::{ArchiveEvidence, ValidatedHeader};

const OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
const PARENT: &str = "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee";

fn member(root: &Path, directory: &str, owner: &str, archive: bool) -> PathBuf {
    let dir = root.join(directory);
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!(
        "rollout-{owner}.jsonl{}",
        if archive { ".zst" } else { "" }
    ));
    let rows = codex_file_join::tests::member(owner, "response", 100, 100);
    let bytes = rows
        .iter()
        .map(|v| v.to_string() + "\n")
        .collect::<String>();
    fs::write(
        &path,
        if archive {
            zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap()
        } else {
            bytes.into_bytes()
        },
    )
    .unwrap();
    path
}
fn seed_archive(index: &mut ScanIndex, path: &Path, owner: &str) {
    let mut evidence = ArchiveEvidence::begin(&File::open(path).unwrap(), path, None).unwrap();
    evidence.header_validated = Some(
        ValidatedHeader::from_line(
            json!({"type":"session_meta", "payload":{"id":owner}})
                .to_string()
                .as_bytes(),
        )
        .unwrap(),
    );
    evidence.disposition = ArchiveDisposition::HeaderValidated;
    index
        .files
        .entry(local_index_key(path))
        .or_default()
        .archive = Some(Box::new(evidence));
}
fn inventory(
    root: &Path,
    paths: &[PathBuf],
    index: &mut ScanIndex,
) -> codex_file_join::HeaderInventory {
    let paths = paths.iter().map(|p| local_index_key(p)).collect();
    let mut directories = codex_file_join::DirectoryCensus::new();
    directories.observe(root, &fs::metadata(root).unwrap());
    let mut inventory =
        codex_file_join::HeaderInventory::new(&[root.to_owned()], &paths, Some(&directories));
    while !inventory.step_with_archive(&CodexTitleMetadata::default(), index, None) {}
    assert!(inventory.complete);
    assert!(inventory.refused.is_empty());
    inventory
}
fn run(mut scan: OwnedSourceScan) -> (ScanIndex, SourceScanResult) {
    for _ in 0..1000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
    panic!("synthetic scan did not complete");
}
fn staged(root: &Path, index: ScanIndex, paths: &[PathBuf]) -> OwnedSourceScan {
    let mut scan = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[],
        index,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
        None,
        &[],
        false,
        false,
    );
    scan.identified_candidates = paths
        .iter()
        .map(|p| codex_zst_refusal_tests::candidate(p))
        .collect();
    for candidate in &mut scan.identified_candidates {
        candidate.scan_root = root.to_owned();
        candidate.size_bytes = fs::metadata(&candidate.path).map_or(0, |s| s.len());
    }
    scan.census_unix_seconds = None;
    scan
}
fn assert_no_red(result: &SourceScanResult, rows: &[Value]) {
    assert_eq!(result.unreadable_path_count, 0, "{result:?}");
    assert!(
        result.snapshots.is_empty(),
        "held history must never upload $0 or smaller"
    );
    assert!(!rows
        .iter()
        .any(|r| r["stage"] == "codex_zst_input" || r["stage"] == "codex_zst_inventory"));
}

#[test]
fn two_archive_and_mixed_families_hold_every_member_before_publish() {
    for mixed in [false, true] {
        let root = crate::test_scratch::private_dir("zst-family-custody");
        let a = member(&root, "sessions", OWNER, true);
        let b = member(&root, "archived_sessions", OWNER, !mixed);
        let paths = [a.clone(), b.clone()];
        let mut index = ScanIndex::default();
        seed_archive(&mut index, &a, OWNER);
        if !mixed {
            seed_archive(&mut index, &b, OWNER);
        }
        let inv = inventory(&root, &paths, &mut index);
        assert_eq!(
            inv.headers.len(),
            2,
            "both validated owners must reach family admission"
        );
        let mut scan = staged(&root, index, &paths);
        scan.codex_join_inventory = Some(inv);
        assert!(
            !scan.codex_join_prepared,
            "exercise ordinary production admission"
        );
        let ((index, result), rows) = capture(|| run(scan));
        assert_no_red(&result, &rows);
        assert!(rows.iter().any(
            |r| r["counts"]["codex_zst_held"]["CompressedFamilyUnproven"]
                .as_u64()
                .is_some_and(|n| n > 0)
        ));
        for path in &paths {
            assert_eq!(
                index.files[&local_index_key(path)].codex_compressed_hold,
                Some(CodexZstCause::FamilyUnproven)
            );
        }
        // Save/restart and a newly encountered member cannot release the owner.
        let saved = root.join("index.json");
        index.clone().save(&saved).unwrap();
        let mut restarted = ScanIndex::load(&saved).unwrap();
        let c = member(&root, "copy/sessions", OWNER, false);
        let mut inv = inventory(&root, std::slice::from_ref(&c), &mut restarted);
        inv.hold_compressed_families(&mut restarted);
        assert_eq!(
            restarted.files[&local_index_key(&c)].codex_compressed_hold,
            Some(CodexZstCause::FamilyUnproven)
        );
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn single_archive_control_keeps_first_read_eligibility() {
    let root = crate::test_scratch::private_dir("zst-single-control");
    let a = member(&root, "sessions", OWNER, true);
    let mut index = ScanIndex::default();
    seed_archive(&mut index, &a, OWNER);
    let mut inv = inventory(&root, std::slice::from_ref(&a), &mut index);
    inv.hold_compressed_families(&mut index);
    assert!(inv.held_owners.is_empty());
    assert!(inv.held_archives.is_empty());
    assert!(index.files[&local_index_key(&a)]
        .codex_compressed_hold
        .is_none());
    assert!(matches!(
        index.files[&local_index_key(&a)]
            .archive
            .as_ref()
            .unwrap()
            .disposition,
        ArchiveDisposition::HeaderValidated
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parent_hold_preserves_accepted_body_incidence_and_is_quiet_after_restart() {
    for archive_child in [false, true] {
        let root = crate::test_scratch::private_dir("zst-parent-custody");
        let child = member(&root, "sessions", OWNER, archive_child);
        let parent = member(&root, "sessions", PARENT, true);
        let mut previous = ScanIndex::default();
        let key = local_index_key(&child);
        // Ordinary emitted money supplies a real positive body and its fingerprint.
        let control = member(&root, "plain/sessions", OWNER, false);
        let (_, positive) =
            codex_file_join::tests::scan(&root.join("plain"), ScanIndex::default(), 10);
        assert_eq!(positive.snapshots.len(), 1);
        assert!(positive.snapshots[0].input_tokens > 0);
        let fp = positive.snapshots[0].snapshot_fingerprint.clone();
        previous.files.insert(
            key.clone(),
            ScanIndexEntry {
                last_snapshot_fingerprint: Some(fp.clone()),
                last_upload_body_witness: Some(snapshot_upload_body_witness(
                    &positive.snapshots[0],
                )),
                source_file_fingerprint: "accepted-object".into(),
                ..Default::default()
            },
        );
        previous
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([fp.clone()]));
        let before = serde_json::to_value(&previous.files[&key]).unwrap();
        let mut working = previous.clone();
        if archive_child {
            seed_archive(&mut working, &child, OWNER);
        }
        let mut metadata = CodexTitleMetadata::default();
        metadata.spawn_parents.insert(OWNER.into(), PARENT.into());
        metadata.state_threads.insert(
            PARENT.into(),
            CodexStateThread {
                rollout_path: Some(local_index_key(&parent)),
                ..Default::default()
            },
        );
        let mut directories = codex_file_join::DirectoryCensus::new();
        directories.observe(&root, &fs::metadata(&root).unwrap());
        let mut inv = codex_file_join::HeaderInventory::new(
            std::slice::from_ref(&root),
            &BTreeSet::from([key.clone()]),
            Some(&directories),
        );
        // Parent sidecar knowledge holds BEFORE even the child's header is read.
        let (_, rows) = capture(
            || {
                while !inv.step_with_archive(&metadata, &mut working, None) {}
            },
        );
        assert_eq!(inv.read_bytes, 0);
        assert!(inv.headers.is_empty());
        assert!(inv.complete);
        assert!(rows.iter().any(|r| r["counts"]["codex_zst_held"]
            ["CompressedParentLedgerUnbound"]
            .as_u64()
            .is_some_and(|n| n > 0)));
        let mut scan = staged(&root, working, std::slice::from_ref(&child));
        scan.codex_join_inventory = Some(inv);
        scan.codex_title_metadata = metadata;
        let ((working, result), rows) = capture(|| run(scan));
        assert_no_red(&result, &rows);
        let committed = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            committed.file_snapshot_fingerprints[&key],
            BTreeSet::from([fp])
        );
        assert_eq!(
            committed.files[&key]
                .last_upload_body_witness
                .as_ref()
                .unwrap(),
            before["last_upload_body_witness"].as_str().unwrap()
        );
        assert_eq!(
            committed.files[&key].source_file_fingerprint,
            "accepted-object"
        );
        let saved = root.join("index.json");
        committed.clone().save(&saved).unwrap();
        let mut restarted = ScanIndex::load(&saved).unwrap();
        // Failing I/O seams: opener/header reads would observe missing files.
        fs::remove_file(&child).unwrap();
        fs::remove_file(&parent).unwrap();
        fs::remove_file(control).unwrap();
        for _ in 0..5 {
            let mut census = ScanCensus::default();
            assert!(open_and_identify_scan_candidate(
                SnapshotSource::Codex,
                codex_zst_refusal_tests::candidate(&child),
                &mut census,
                None,
                7,
                &restarted.files
            )
            .is_none());
            assert_eq!(census.unreadable_path_count, 0);
            assert_eq!(census.disappeared_file_count, 0, "the opener must not run");
            let mut inv = codex_file_join::HeaderInventory::new(
                std::slice::from_ref(&root),
                &BTreeSet::from([key.clone()]),
                Some(&directories),
            );
            while !inv.step_with_archive(&CodexTitleMetadata::default(), &mut restarted, None) {}
            assert!(inv.complete);
            assert!(inv.refused.is_empty());
            assert_eq!(inv.read_bytes, 0);
            assert_eq!(
                restarted.files[&key].codex_compressed_hold,
                Some(CodexZstCause::ParentLedgerUnbound)
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn archive_parent_is_no_ledger_and_plain_twin_is_a_control() {
    let root = crate::test_scratch::private_dir("zst-parent-matching");
    let parent = member(&root, "sessions", PARENT, true);
    let roots = [root.clone()];
    let paths = BTreeSet::from([local_index_key(&parent)]);
    assert!(codex_compressed_holds::parent_unbound(
        PARENT,
        CodexParentCensus::new(&roots, &paths),
        &CodexTitleMetadata::default()
    ));
    assert_eq!(
        codex_parent_candidate_match(
            CodexParentCensus::new(&roots, &paths),
            CodexCensusMatch::One(paths.first().unwrap())
        )
        .unwrap_err(),
        CodexParentUnresolvable::NoLedger
    );
    let plain = member(&root, "sessions", PARENT, false);
    let paths = BTreeSet::from([local_index_key(&parent), local_index_key(&plain)]);
    assert!(!codex_compressed_holds::parent_unbound(
        PARENT,
        CodexParentCensus::new(&roots, &paths),
        &CodexTitleMetadata::default()
    ));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn header_only_fork_link_latches_custody_before_red_finish() {
    let root = crate::test_scratch::private_dir("zst-header-fork");
    let child = member(&root, "sessions", OWNER, false);
    let parent = member(&root, "sessions", PARENT, true);
    let mut rows = codex_file_join::tests::member(OWNER, "response", 100, 100);
    rows[0]["payload"]["forked_from_id"] = json!(PARENT);
    fs::write(
        &child,
        rows.iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let mut index = ScanIndex::default();
    seed_archive(&mut index, &parent, PARENT);
    let paths = [child.clone(), parent.clone()];
    let inv = inventory(&root, &paths, &mut index);
    let mut scan = staged(&root, index, std::slice::from_ref(&child));
    let traversal = scan
        .index
        .traversal
        .as_mut()
        .expect("production traversal exists");
    traversal.scan_roots = vec![root.clone()];
    traversal.codex_rollout_paths = paths.iter().map(|p| local_index_key(p)).collect();
    traversal.pending_directories.clear();
    scan.codex_parent_identities.census_valid = true;
    scan.codex_join_inventory = Some(inv);
    let ((index, result), rows) = capture(|| run(scan));
    assert_eq!(
        result.scanned_file_count, 1,
        "child link discovered by its authorized first parse"
    );
    assert_no_red(&result, &rows);
    assert_eq!(
        index.files[&local_index_key(&child)].codex_compressed_hold,
        Some(CodexZstCause::ParentLedgerUnbound)
    );
    assert!(
        !index
            .traversal
            .as_ref()
            .unwrap()
            .codex_parent_resolution_retry_required
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn legacy_entry_defaults_to_no_custody_and_archive_discovery_stays_off() {
    let root = crate::test_scratch::private_dir("zst-discovery-still-off");
    let path = member(&root, "sessions", OWNER, true);
    let entry: ScanIndexEntry = serde_json::from_value(json!({"size_bytes":1,"modified_unix_seconds":1,"source_file_fingerprint":"old","last_snapshot_fingerprint":null})).unwrap();
    assert!(entry.codex_compressed_hold.is_none());
    let (index, result) = codex_file_join::tests::scan(&root, ScanIndex::default(), 10);
    assert!(result.snapshots.is_empty());
    assert!(
        !index.files.contains_key(&local_index_key(&path)),
        "no archive candidate or decode enabled by this slice"
    );
    fs::remove_dir_all(root).unwrap();
}
