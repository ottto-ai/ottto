//! Synthetic admission/retention fixtures. Discovery deliberately stays off.
use super::*;
use crate::local_resource_diagnostics::capture;
use codex_compressed_input::{ArchiveEvidence, ValidatedHeader};

const OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
thread_local! { static DENY_OPEN: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) }; }
pub(super) fn opening(path: &Path) {
    DENY_OPEN.with(|slot| {
        assert_ne!(
            slot.borrow().as_deref(),
            Some(path),
            "custodied file opened"
        )
    });
}
pub(super) fn no_open<T>(path: &Path, run: impl FnOnce() -> T) -> T {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            DENY_OPEN.with(|s| s.replace(None));
        }
    }
    DENY_OPEN.with(|s| s.replace(Some(path.to_owned())));
    let _reset = Reset;
    run()
}
thread_local! { static FILE_CAP: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
pub(super) fn file_cap() -> Option<u64> {
    FILE_CAP.with(std::cell::Cell::get)
}
pub(super) fn with_file_cap<T>(cap: Option<u64>, run: impl FnOnce() -> T) -> T {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            FILE_CAP.with(|slot| slot.set(self.0));
        }
    }
    let _reset = Reset(FILE_CAP.with(|slot| slot.replace(cap)));
    run()
}
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

fn run(mut scan: OwnedSourceScan) -> (ScanIndex, SourceScanResult) {
    for _ in 0..1000 {
        match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => scan = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
    panic!("synthetic scan did not complete");
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

fn accepted(root: &Path, path: &Path) -> ScanIndex {
    let control = member(root, "control/sessions", OWNER, false);
    let (_, result) = codex_file_join::tests::scan(&root.join("control"), ScanIndex::default(), 10);
    assert_eq!(result.snapshots.len(), 1);
    let body = &result.snapshots[0];
    assert!(body.input_tokens > 0);
    let fp = body.snapshot_fingerprint.clone();
    let key = local_index_key(path);
    let mut index = ScanIndex::default();
    index.files.insert(
        key.clone(),
        ScanIndexEntry {
            source_file_fingerprint: "accepted-source".into(),
            last_snapshot_fingerprint: Some(fp.clone()),
            last_upload_body_witness: Some(snapshot_upload_body_witness(body)),
            ..Default::default()
        },
    );
    index
        .file_snapshot_fingerprints
        .insert(key, BTreeSet::from([fp.clone()]));
    let activity = snapshot_semantic_activity_at(body);
    assert!(activity.is_some(), "genuine accepted semantic activity");
    index.snapshot_activity_at.insert(fp.clone(), activity);
    index.accepted_snapshot_fingerprints.insert(fp);
    fs::remove_file(control).unwrap();
    index
}
fn latch(index: &mut ScanIndex, path: &Path) {
    let key = local_index_key(path);
    index
        .files
        .entry(key.clone())
        .or_default()
        .codex_compressed_hold = Some(CodexZstCause::ParentLedgerUnbound);
    index.extend_codex_blocked_attribution(&key, BTreeSet::from([OWNER.into()]));
}
fn normal(root: &Path, index: ScanIndex, hints: &[PathBuf]) -> (ScanIndex, SourceScanResult) {
    run(OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        10,
        false,
        None,
        hints,
        false,
        false,
    ))
}

#[test]
fn watcher_removal_full_save_restart_recreation_keeps_unprotected_accepted_evidence() {
    let root = crate::test_scratch::private_dir("custody-watcher");
    let path = member(&root, "sessions", OWNER, false);
    let mut index = accepted(&root, &path);
    assert!(!index.files[&local_index_key(&path)].codex_history_is_protected());
    let before = index.files[&local_index_key(&path)].clone();
    let incidence = index.file_snapshot_fingerprints.clone();
    latch(&mut index, &path);
    fs::rename(&path, root.join("renamed-away")).unwrap();
    let ((mut index, result), rows) = capture(|| normal(&root, index, std::slice::from_ref(&path)));
    assert_no_red(&result, &rows);
    assert_eq!(index.file_snapshot_fingerprints, incidence);
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    for pass in 0..5 {
        let index = ScanIndex::load(&saved).unwrap();
        if pass == 0 {
            fs::write(&path, b"unreadable replacement is deliberately not JSON\n").unwrap();
        }
        let ((mut next, result), rows) =
            capture(|| normal(&root, index, std::slice::from_ref(&path)));
        assert_no_red(&result, &rows);
        assert_eq!(
            next.files[&local_index_key(&path)].last_snapshot_fingerprint,
            before.last_snapshot_fingerprint
        );
        assert_eq!(
            next.files[&local_index_key(&path)].last_upload_body_witness,
            before.last_upload_body_witness
        );
        assert_eq!(next.file_snapshot_fingerprints, incidence);
        assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_held"));
        next.save(&saved).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replay_retains_historical_coverage_without_new_ack_credit() {
    let root = crate::test_scratch::private_dir("custody-replay");
    let path = member(&root, "sessions", OWNER, false);
    let mut index = accepted(&root, &path);
    latch(&mut index, &path);
    let before = index.files[&local_index_key(&path)].clone();
    let incidence = index.file_snapshot_fingerprints.clone();
    let activity = index.snapshot_activity_at.clone();
    assert_eq!(activity.len(), 1);
    let prior_manifest = index
        .manifest_for_window(
            SnapshotSource::Codex,
            "2000-01-01T00:00:00Z",
            "2100-01-01T00:00:00Z",
        )
        .unwrap();
    assert_eq!(prior_manifest.entity_count, 1);
    index.snapshot_activity_at.insert(
        "obsolete-unheld".into(),
        Some("2026-10-01T00:00:00Z".into()),
    );
    assert!(index.prepare_historical_replay("synthetic-replay".into()));
    assert_eq!(
        index.files[&local_index_key(&path)].last_snapshot_fingerprint,
        before.last_snapshot_fingerprint
    );
    assert_eq!(index.file_snapshot_fingerprints, incidence);
    assert!(
        index.accepted_snapshot_fingerprints.is_empty(),
        "history is not fresh replay ACK authority"
    );
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    let ((mut index, mut result), rows) = capture(|| {
        no_open(&path, || {
            normal(&root, ScanIndex::load(&saved).unwrap(), &[])
        })
    });
    assert_no_red(&result, &rows);
    assert!(result.census_complete, "custody-only terminal census");
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    assert_eq!(
        index.snapshot_activity_at, activity,
        "existing finalizer prunes orphan activity"
    );
    let manifest = index
        .manifest_for_window(
            SnapshotSource::Codex,
            "2000-01-01T00:00:00Z",
            "2100-01-01T00:00:00Z",
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(manifest).unwrap(),
        serde_json::to_value(prior_manifest).unwrap()
    );
    assert_eq!(index.file_snapshot_fingerprints, incidence);
    assert_eq!(
        index.files[&local_index_key(&path)].last_upload_body_witness,
        before.last_upload_body_witness
    );
    assert!(index.accepted_snapshot_fingerprints.is_empty());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unsafe_subset_overlay_preserves_real_entries_in_both_rollback_cases() {
    let root = crate::test_scratch::private_dir("custody-subset");
    let path = member(&root, "sessions", OWNER, false);
    for committed in [false, true] {
        let previous = if committed {
            accepted(&root, &path)
        } else {
            ScanIndex::default()
        };
        let mut working = previous.clone();
        let key = local_index_key(&path);
        working
            .files
            .entry(key.clone())
            .or_default()
            .source_file_fingerprint = "current-source".into();
        working
            .files
            .get_mut(&key)
            .unwrap()
            .last_snapshot_fingerprint = Some("unsettled-current".into());
        working
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from(["unsettled-current".into()]));
        latch(&mut working, &path);
        let next = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            next.files[&key].codex_compressed_hold,
            Some(CodexZstCause::ParentLedgerUnbound)
        );
        assert_eq!(
            next.files[&key].source_file_fingerprint,
            if committed {
                "accepted-source"
            } else {
                "current-source"
            }
        );
        assert!(!next
            .accepted_snapshot_fingerprints
            .contains("unsettled-current"));
        let mut older = serde_json::to_value(&next).unwrap();
        older["files"][&key]
            .as_object_mut()
            .unwrap()
            .remove("codex_compressed_hold");
        let saved = root.join(format!("rollback-{committed}.json"));
        fs::write(&saved, serde_json::to_vec(&older).unwrap()).unwrap();
        assert_eq!(
            ScanIndex::load(&saved).unwrap().files[&key].codex_compressed_hold,
            None
        );
        if committed {
            assert_eq!(
                next.file_snapshot_fingerprints,
                previous.file_snapshot_fingerprints
            );
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn parent_role_opens_and_retained_ledger_validation_refuse_before_content_io() {
    let root = crate::test_scratch::private_dir("custody-grandchild");
    let child = member(&root, "sessions", OWNER, false);
    member(&root, "sessions", PARENT, true);
    let mut index = accepted(&root, &child);
    index.codex_parent_ownership_refs.insert(OWNER.into());
    index.codex_parent_ownership_ledgers.insert(
        OWNER.into(),
        CodexParentOwnershipLedger {
            scan_complete: true,
            signatures: vec!["retained-signature".into()],
            opened_object_identity: "retained-object".into(),
            ..Default::default()
        },
    );
    latch(&mut index, &child);
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    let index = ScanIndex::load(&saved).unwrap();
    let paths = BTreeSet::from([local_index_key(&child)]);
    let roots = [root.clone()];
    let census = CodexParentCensus {
        scan_roots: &roots,
        paths: &paths,
        files: Some(&index.files),
        available: true,
    };
    assert!(index.codex_parent_ownership_ledgers[OWNER].scan_complete);
    assert!(no_open(&child, || validate_codex_parent_ownership_ledgers(
        &index, census
    ))
    .0
    .is_empty());
    let found = CodexCensusMatch::One(paths.first().unwrap());
    assert_eq!(
        codex_parent_candidate_match(census, found).unwrap_err(),
        CodexParentUnresolvable::NoLedger
    );
    assert!(
        codex_parent_open_match_retained(census, found, &sampled_scan::SharedCache::default())
            .is_err()
    );
    assert!(codex_parent_locate(census, OWNER).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn unknown_field_values_hold_but_older_writer_field_loss_is_accepted() {
    let root = crate::test_scratch::private_dir("custody-field");
    let path = member(&root, "sessions", OWNER, false);
    let mut index = accepted(&root, &path);
    latch(&mut index, &path);
    let key = local_index_key(&path);
    for bad in [json!("future-cause"), json!({"bad":"shape"}), json!(17)] {
        let mut value = serde_json::to_value(&index).unwrap();
        value["files"][&key]["codex_compressed_hold"] = bad;
        let decoded: ScanIndex = serde_json::from_value(value).unwrap();
        assert_eq!(
            decoded.files[&key].codex_compressed_hold,
            Some(CodexZstCause::OwnerUnproven)
        );
    }
    let mut value = serde_json::to_value(&index).unwrap();
    value["files"][&key]
        .as_object_mut()
        .unwrap()
        .remove("codex_compressed_hold");
    let saved = root.join("index.json");
    fs::write(&saved, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::remove_file(&path).unwrap();
    let recovered = ScanIndex::load(&saved).unwrap();
    assert_eq!(recovered.files[&key].codex_compressed_hold, None);
    assert_eq!(
        recovered.files[&key].last_snapshot_fingerprint,
        index.files[&key].last_snapshot_fingerprint
    );
    if crate::heap_layout_bound::layout_supported() {
        assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 488);
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_blocked_plain_entry_is_not_recovered_as_compressed_custody() {
    let root = crate::test_scratch::private_dir("custody-ordinary-control");
    let path = member(&root, "sessions", OWNER, false);
    let mut index = accepted(&root, &path);
    index.extend_codex_blocked_attribution(&local_index_key(&path), BTreeSet::from([OWNER.into()]));
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    assert!(
        ScanIndex::load(&saved).unwrap().files[&local_index_key(&path)]
            .codex_compressed_hold
            .is_none()
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn custody_preserves_parser_identity_and_never_selects_migration_or_parse() {
    let root = crate::test_scratch::private_dir("custody-identity");
    let path = member(&root, "sessions", OWNER, false);
    let key = local_index_key(&path);
    for (identity, reconcile, expected) in [
        (
            Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
            false,
            CandidateDecision::Skip,
        ),
        (None, false, CandidateDecision::Migrate),
        (
            Some("older-parser"),
            true,
            CandidateDecision::ReconcileLegacy,
        ),
    ] {
        let mut index = accepted(&root, &path);
        index.files.get_mut(&key).unwrap().scan_identity_version = identity.map(str::to_owned);
        let fp = index.files[&key].last_snapshot_fingerprint.clone().unwrap();
        index.snapshot_activity_at.insert(fp, None);
        let mut candidate = codex_zst_refusal_tests::candidate(&path);
        candidate.source_file_fingerprint = "accepted-source".into();
        candidate.legacy_source_file_fingerprint = "accepted-source".into();
        candidate.legacy_config_reconciliation_required = reconcile;
        assert_eq!(index.candidate_decision(&candidate), expected);
        let identity_bytes = serde_json::to_vec(&index.files[&key].scan_identity_version).unwrap();
        let digest = index.healthy_custody_digest_for_test(std::iter::once(key.as_str()));
        latch(&mut index, &path);
        assert_eq!(
            serde_json::to_vec(&index.files[&key].scan_identity_version).unwrap(),
            identity_bytes
        );
        assert_eq!(
            index.healthy_custody_digest_for_test(std::iter::once(key.as_str())),
            digest
        );
        assert_eq!(
            index.candidate_decision(&candidate),
            CandidateDecision::Skip
        );
        candidate.source_file_fingerprint = "changed-object".into();
        assert_eq!(
            index.candidate_decision(&candidate),
            CandidateDecision::Skip
        );
        let saved = root.join("index.json");
        index.save(&saved).unwrap();
        let loaded = ScanIndex::load(&saved).unwrap();
        assert_eq!(
            serde_json::to_vec(&loaded.files[&key].scan_identity_version).unwrap(),
            identity_bytes
        );
        assert_eq!(
            loaded.candidate_decision(&candidate),
            CandidateDecision::Skip
        );
    }
    fs::remove_dir_all(root).unwrap();
}

/// The CI driver supplies an output directory, then feeds these actual writer
/// bytes to the production loaders compiled from both pinned old source trees.
#[test]
fn write_codex_zst_downgrade_fixture() {
    let root = crate::test_scratch::private_dir("custody-downgrade-writer");
    let plain = member(&root, "sessions", OWNER, false);
    let archive = member(&root, "sessions", PARENT, true);
    let mut index = accepted(&root, &plain);
    seed_archive(&mut index, &archive, PARENT);
    for path in [&plain, &archive] {
        index
            .files
            .get_mut(&local_index_key(path))
            .unwrap()
            .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        latch(&mut index, path);
    }
    let out = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("out"));
    fs::create_dir_all(&out).unwrap();
    index.save(&out.join("branch.json")).unwrap();
    let mut control = serde_json::to_value(&index).unwrap();
    for entry in control["files"].as_object_mut().unwrap().values_mut() {
        let entry = entry.as_object_mut().unwrap();
        assert!(entry.remove("codex_compressed_hold").is_some());
        entry.remove("archive");
    }
    fs::write(
        out.join("as-today.json"),
        serde_json::to_vec(&control).unwrap(),
    )
    .unwrap();
    assert_eq!(
        ScanIndex::load(&out.join("branch.json"))
            .unwrap()
            .files
            .len(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn verify_codex_zst_downgrade_roundtrip() {
    // The driver executes this after both real old-code saves. Without the
    // driver the ordinary unit suite still exercises the retained-field arm.
    let Some(root) = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR").map(PathBuf::from) else {
        let root = crate::test_scratch::private_dir("custody-retained-field");
        let path = member(&root, "sessions", OWNER, false);
        let mut index = accepted(&root, &path);
        latch(&mut index, &path);
        let saved = root.join("index.json");
        index.save(&saved).unwrap();
        assert_eq!(
            ScanIndex::load(&saved).unwrap().files[&local_index_key(&path)].codex_compressed_hold,
            Some(CodexZstCause::ParentLedgerUnbound)
        );
        fs::remove_dir_all(root).unwrap();
        return;
    };
    for label in ["stable", "r1"] {
        let (index, origin) =
            ScanIndex::load_inner(&root.join(format!("{label}.json")), None).unwrap();
        assert!(matches!(origin, LoadOrigin::Loaded(_)));
        assert_eq!(index.files.len(), 2);
        assert!(!index.file_snapshot_fingerprints.is_empty());
        for entry in index.files.values() {
            assert!(
                entry.codex_compressed_hold.is_none(),
                "accepted old-writer field loss"
            );
            assert_eq!(
                entry.scan_identity_version.as_deref(),
                Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
            );
        }
    }
}

#[test]
fn foundation_unknown_owner_coverage_defers_present_or_absent_held_siblings() {
    for absent in [false, true] {
        let root = crate::test_scratch::private_dir("custody-foundation-sibling");
        let held = member(&root, "sessions", OWNER, false);
        let mut index = accepted(&root, &held);
        latch(&mut index, &held);
        let smaller = held.with_file_name(format!("rollout-2026-10-01T11-00-00-{OWNER}.jsonl"));
        let bytes = codex_file_join::tests::member(OWNER, "shorter", 1, 1)
            .iter()
            .map(|v| v.to_string() + "\n")
            .collect::<String>();
        fs::write(&smaller, bytes).unwrap();
        assert!(smaller.exists());
        if absent {
            fs::remove_file(&held).unwrap();
        }
        let ((index, scan), rows) = capture(|| normal(&root, index, &[]));
        assert_no_red(&scan, &rows);
        assert!(index.files[&local_index_key(&held)]
            .last_upload_body_witness
            .is_some());
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn malformed_large_hold_streams_to_generic_custody() {
    let root = crate::test_scratch::private_dir("custody-large-field");
    let path = member(&root, "sessions", OWNER, false);
    let mut raw = serde_json::to_value(accepted(&root, &path)).unwrap();
    let key = local_index_key(&path);
    raw["files"][&key]["codex_compressed_hold"] = json!(vec![0; 100_000]);
    let bytes = serde_json::to_vec(&raw).unwrap();
    let saved = root.join("index.json");
    fs::write(&saved, bytes).unwrap();
    let loaded = ScanIndex::load(&saved).unwrap();
    assert_eq!(
        loaded.files[&key].codex_compressed_hold,
        Some(CodexZstCause::OwnerUnproven)
    );
    raw["files"][&key]["codex_compressed_hold"] = json!("x".repeat(100_000));
    fs::write(&saved, serde_json::to_vec(&raw).unwrap()).unwrap();
    assert_eq!(
        ScanIndex::load(&saved).unwrap().files[&key].codex_compressed_hold,
        Some(CodexZstCause::OwnerUnproven)
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn custody_lexical_mask_precedes_reader_allocation_and_keeps_entry_evidence() {
    let root = crate::test_scratch::private_dir("custody-lexical-bound");
    let path = member(&root, "sessions", OWNER, false);
    let key = local_index_key(&path);
    let original = accepted(&root, &path);
    let witness = original.files[&key].last_upload_body_witness.clone();
    let incidence = original.file_snapshot_fingerprints.clone();
    let names = [
        "size_bytes",
        "modified_unix_seconds",
        "modified_unix_nanos",
        "source_file_fingerprint",
        "last_snapshot_fingerprint",
        "last_upload_body_witness",
        "effective_upload_body_witness_revision",
        "scan_identity_version",
        "codex_joined_member_set",
        "codex_captured_joined_member_set",
        "codex_protected_owner",
        "codex_applied_tier_receipt",
        "codex_applied_tier_receipt_required",
        "codex_captured_tier_receipt",
        "codex_captured_tier_receipt_required",
        "codex_captured_uncommitted",
        "codex_counting_v2",
        "codex_counting_owner",
        "opened_changed_nanos",
        "archive",
        "opened_birth_nanos",
        "codex_compressed_hold",
    ];
    for positional in [false, true] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["files"][&key]["codex_compressed_hold"] = json!("CUSTODY_PAYLOAD");
        if positional {
            let mut fields = json!([
                0, 0, null, "", null, null, 0, null, null, null, null, null, false, null, false,
                false, false, null, 0, null, 0, null
            ]);
            for (at, name) in names.iter().enumerate() {
                if let Some(v) = value["files"][&key].get(*name) {
                    fields[at] = v.clone();
                }
            }
            value["files"][&key] = fields;
        }
        let template = serde_json::to_string(&value).unwrap();
        let payload = "x".repeat(16 * 1024 * 1024);
        for malformed in [
            format!("\"{payload}\""),
            format!("[\"{payload}\"]"),
            format!("{{\"{payload}\":0}}"),
        ] {
            let saved = root.join("large.json");
            fs::write(&saved, template.replace("\"CUSTODY_PAYLOAD\"", &malformed)).unwrap();
            let (result, allocations) =
                crate::retry_allocation_probe::measure(|| ScanIndex::load(&saved));
            let loaded = result.unwrap();
            assert_eq!(
                loaded.files[&key].codex_compressed_hold,
                Some(CodexZstCause::OwnerUnproven)
            );
            assert_eq!(loaded.files[&key].last_upload_body_witness, witness);
            assert_eq!(loaded.file_snapshot_fingerprints, incidence);
            assert!(allocations.requested_peak < 256 * 1024, "{allocations:?}");
            assert!(allocations.usable_peak < 512 * 1024, "{allocations:?}");
        }
    }
    fs::remove_dir_all(root).unwrap();
}
