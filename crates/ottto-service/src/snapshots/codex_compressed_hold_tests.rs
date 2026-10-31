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
pub(super) fn seed_archive(index: &mut ScanIndex, path: &Path, owner: &str) {
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
    for _ in 0..10000 {
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

/// [behaviour] Publication validation skips a newly held file before sampling.
#[test]
fn publication_validation_skips_a_newly_held_file_before_sampling() {
    let root = crate::test_scratch::private_dir("custody-publication-validation");
    let held = member(&root, "sessions", OWNER, false);
    let healthy = member(&root, "sessions", PARENT, false);
    let sessions = root.join("sessions");
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let paths = BTreeSet::from([local_index_key(&held), local_index_key(&healthy)]);
    let mut index = ScanIndex::default();
    let mut inv = codex_file_join::HeaderInventory::new(&[sessions], &paths, Some(&dirs));
    while inv.step_with_archive(&CodexTitleMetadata::default(), &mut index, None)
        != codex_file_join::HeaderStep::Complete
    {}
    assert_eq!(inv.headers.len(), 2);
    let home = inv
        .headers
        .iter()
        .find(|h| h.owner == PARENT)
        .unwrap()
        .home
        .clone();
    latch(&mut index, &held);
    inv.refresh_custody(&index);
    assert!(inv.member_held(&held));
    assert!(!inv.member_held(&healthy));
    assert!(!inv.complete_for(Some(&OWNER.to_owned())));
    assert!(inv.complete_for(Some(&PARENT.to_owned())));
    let old_len = fs::metadata(&held).unwrap().len();
    fs::write(&held, b"invalid replacement after custody\n").unwrap();
    assert_ne!(old_len, fs::metadata(&held).unwrap().len());
    no_open(&held, || inv.validate_membership(PARENT, &home).unwrap());
    fs::remove_dir_all(root).unwrap();
}

/// [money] Watcher removal, save, restart and recreation keep unprotected accepted evidence.
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

/// [money] Replay keeps historical coverage without new ACK credit.
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

/// [format] An unsafe committable-subset overlay keeps the real entries in both rollback cases.
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

/// [behaviour] Parent-role opens and retained-ledger validation refuse before content I/O.
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

/// [format] Unknown persisted hold values hold; field loss from an older writer is accepted.
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
        assert_eq!(std::mem::size_of::<ScanIndexEntry>(), 568);
    }
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] An ordinary blocked plain entry is not recovered as compressed custody.
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

/// [money] Read bound: custody keeps parser identity and never selects a migration or parse.
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
        // Each row saves a fresh index; the save CAS (#894) refuses to
        // overwrite another index's file.
        fs::remove_file(saved).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

/// The CI driver supplies an output directory, then feeds these actual writer
/// bytes to the production loaders compiled from both pinned old source trees.
/// [format] Writes the branch bytes the pinned old loaders read
/// (scripts/test_codex_zst_downgrade.py).
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
    index
        .files
        .get_mut(&local_index_key(&archive))
        .unwrap()
        .codex_compressed_hold = Some(CodexZstCause::FamilyUnproven);
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
    // Activated singleton: deliberately no old-reader protection, tier/join
    // receipt or unverified marker. The historical runtime must census/save it.
    let activation_root = out.join("activation");
    let singleton = member(&activation_root, "sessions", OWNER, true);
    let mut activation = accepted(&activation_root, &singleton);
    seed_archive(&mut activation, &singleton, OWNER);
    let entry = activation
        .files
        .get_mut(&local_index_key(&singleton))
        .unwrap();
    assert!(entry.codex_protected_owner.is_none());
    assert!(entry.codex_counting_owner.is_none());
    assert!(entry.codex_applied_tier_receipt.is_none());
    assert!(entry.codex_joined_member_set.is_none());
    let archive = entry.archive.as_mut().unwrap();
    let mut raw = serde_json::to_value(&**archive).unwrap();
    raw["header_bound_reached"] = json!(true);
    **archive = serde_json::from_value(raw).unwrap();
    archive.owner = Some(OWNER.into());
    archive.decode_attempts = 1;
    archive.disposition = ArchiveDisposition::Acquired;
    activation.save(&out.join("activation.json")).unwrap();
    fs::write(out.join("activation-key.txt"), local_index_key(&singleton)).unwrap();
    fs::remove_dir_all(root).unwrap();
}

/// [format] Re-upgrade loads the old loaders' saves without reset; the hold field loss is accepted.
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

/// [behaviour] Unknown-owner coverage defers present or absent held siblings.
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

/// [format] A malformed large persisted hold streams to generic custody.
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

/// [behaviour] The custody lexical mask runs before reader allocation and keeps entry evidence.
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
        "upload_context_receipt",
        "codex_compressed_hold",
    ];
    for positional in [false, true] {
        let mut value = serde_json::to_value(&original).unwrap();
        value["files"][&key]["codex_compressed_hold"] = json!("CUSTODY_PAYLOAD");
        if positional {
            let mut fields = json!([
                0, 0, null, "", null, null, 0, null, null, null, null, null, false, null, false,
                false, false, null, 0, null, 0, null, null
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
    while inventory.step_with_archive(&CodexTitleMetadata::default(), index, None)
        != codex_file_join::HeaderStep::Complete
    {}
    assert!(inventory.complete);
    assert!(inventory.refused.is_empty());
    inventory
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
    scan.identified_candidates.retain(|candidate| {
        !scan
            .index
            .files
            .get(&local_index_key(&candidate.path))
            .is_some_and(|entry| entry.codex_compressed_hold.is_some())
    });
    for candidate in &mut scan.identified_candidates {
        candidate.scan_root = root.to_owned();
        candidate.size_bytes = fs::metadata(&candidate.path).map_or(0, |s| s.len());
    }
    let traversal = scan.index.traversal.as_mut().unwrap();
    traversal.scan_roots = vec![root.to_owned()];
    traversal.codex_rollout_paths = paths.iter().map(|p| local_index_key(p)).collect();
    // Production discovery observes every candidate before identification;
    // without it census reconciliation prunes in-range plain entries.
    traversal.observed_index_keys = paths.iter().map(|p| local_index_key(p)).collect();
    traversal.pending_directories.clear();
    scan.codex_parent_identities.census_valid = true;
    scan.census_unix_seconds = None;
    scan
}

/// [behaviour] Shared history is paged with inline current-owner flags and a bound-plus-one probe.
#[test]
fn shared_history_is_paged_with_inline_current_owner_flags_and_bound_plus_one() {
    let root = crate::test_scratch::private_dir("custody-bounded-history");
    let plain = member(&root, "sessions", PARENT, false);
    let mut index = ScanIndex::default();
    for n in 0..2049 {
        let path = root.join(format!("absent-{n}"));
        index.hold_compressed(
            &path,
            BTreeSet::from([format!("old-{n}")]),
            CodexZstCause::ParentLedgerUnbound,
        );
    }
    let mut inv = inventory(&root, std::slice::from_ref(&plain), &mut index);
    let mut steps = 0;
    while !inv.prepare_custody(&index) {
        steps += 1;
    }
    assert_eq!(steps, 2049);
    assert_eq!(inv.headers.len(), 1);
    assert!(inv.headers[0].custody_cause.is_none());
    assert_eq!(inv.custody_peak, codex_compressed_holds::OWNER_LOOKUP_SLACK);
    let sample = inv.headers[0].clone();
    inv.headers
        .resize(codex_file_join::MAX_HEADER_FILES + 1, sample);
    inv.mark_custody_owner(PARENT, CodexZstCause::ParentLedgerUnbound);
    assert!(inv.custody_refused);
    assert!(inv.headers.iter().all(|h| h.custody_cause.is_some()));
    while !inv.hold_custodied_siblings(&mut index) {}
    assert_eq!(
        index.files.len(),
        2050,
        "one unique durable file obligation despite refusal"
    );
    assert!(index.files[&local_index_key(&plain)]
        .codex_compressed_hold
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [money] Present custody without a header keeps the legacy tombstone through two censuses and
/// restart.
#[test]
fn present_custody_no_header_keeps_legacy_tombstone_through_two_censuses_and_restart() {
    use codex_counting_version::{AckEvidence, CountingTombstone};
    let root = crate::test_scratch::private_dir("custody-present-tombstone");
    let held = member(&root, "sessions", OWNER, false);
    let plain = member(&root, "sessions", PARENT, false);
    let owner = codex_protected_owner(OWNER);
    let mut index = ScanIndex::default();
    index.codex_counting_tombstones.insert(
        owner.clone(),
        CountingTombstone {
            evidence: AckEvidence::LegacyAcked,
            retired_in: "prior-generation".into(),
            created_unix_ms: None,
        },
    );
    index.hold_compressed(
        &held,
        BTreeSet::from([OWNER.into()]),
        CodexZstCause::ParentLedgerUnbound,
    );
    let saved = root.join("index.json");
    for pass in 0..2 {
        let paths = [held.clone(), plain.clone()];
        let inv = no_open(&held, || inventory(&root, &paths, &mut index));
        assert!(held.exists());
        assert!(
            inv.complete,
            "held no-header exit preserves unrelated coverage"
        );
        assert!(index.files[&local_index_key(&held)]
            .codex_compressed_hold
            .is_some());
        assert!(!inv.headers.iter().any(|h| h.candidate.path == held));
        assert_eq!(inv.headers.len(), 1);
        assert_eq!(inv.headers[0].owner, PARENT);
        let mut scan = staged(&root, index, std::slice::from_ref(&plain));
        scan.index
            .traversal
            .as_mut()
            .unwrap()
            .codex_rollout_paths
            .insert(local_index_key(&held));
        scan.index.known_configured_scan_roots = BTreeSet::from([local_index_key(&root)]);
        scan.codex_join_inventory = Some(inv);
        let ((mut next, result), _) = capture(|| no_open(&held, || run(scan)));
        assert_eq!(result.unreadable_path_count, 0);
        assert!(result.census_complete, "clean census {pass}: {result:?}");
        assert_eq!(
            next.codex_counting_tombstones[&owner].evidence,
            AckEvidence::LegacyAcked
        );
        assert!(next.files[&local_index_key(&held)]
            .codex_compressed_hold
            .is_some());
        next.save(&saved).unwrap();
        index = ScanIndex::load(&saved).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Scratch overflow serves unheld plain work in one page and discloses pending custody.
#[test]
fn scratch_overflow_serves_unheld_plain_in_one_page_and_discloses_pending_custody() {
    let root = crate::test_scratch::private_dir("custody-overflow-service");
    let base = member(&root, "sessions", OWNER, false);
    let unrelated = member(&root, "sessions", PARENT, false);
    let mut paths = vec![base.clone(), unrelated];
    for n in 1..5000 {
        let path = base.with_file_name(format!(
            "rollout-2026-10-01T{:02}-{:02}-{:02}-{OWNER}.jsonl",
            n / 3600,
            n / 60 % 60,
            n % 60
        ));
        fs::hard_link(&base, &path).unwrap();
        paths.push(path);
    }
    let old = root.join("retained-custody.jsonl");
    let mut index = ScanIndex::default();
    index.hold_compressed(
        &old,
        BTreeSet::from([OWNER.into()]),
        CodexZstCause::ParentLedgerUnbound,
    );
    let inv = inventory(&root, &paths, &mut index);
    assert_eq!(inv.headers.len(), 5001);
    let mut scan = staged(&root, index, &paths);
    scan.codex_join_inventory = Some(inv);
    let ((mut index, result), rows) = capture(|| run(scan));
    assert_eq!(result.snapshots.len(), 1, "plain served in N=1 source page");
    assert_eq!(result.snapshots[0].source_session_id, PARENT);
    assert!(result.snapshots[0].input_tokens > 0);
    assert_eq!(result.unreadable_path_count, 0);
    assert!(
        result.census_complete,
        "all known plain obligations are durable"
    );
    for path in &paths {
        if path != &paths[1] {
            assert!(index.files[&local_index_key(path)]
                .codex_compressed_hold
                .is_some());
        }
    }
    assert!(index.files[&local_index_key(&old)]
        .codex_compressed_hold
        .is_some());
    assert!(rows.iter().any(
        |r| r["counts"]["codex_zst_held"]["CompressedAdmissionRefused"]
            .as_u64()
            .is_some()
    ));
    assert!(rows
        .iter()
        .any(|r| r["stage"] == "durable_tail_alarm"
            && r["counts"]["custody_overflow"]["events"] == 1));
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    let reloaded = ScanIndex::load(&saved).unwrap();
    for path in &paths {
        if path != &paths[1] {
            assert!(reloaded.files[&local_index_key(path)]
                .codex_compressed_hold
                .is_some());
        }
    }
    assert!(reloaded.files[&local_index_key(&old)]
        .codex_compressed_hold
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Unattributed custody keeps plain progress; the archive waits across restart.
#[test]
fn unattributed_custody_keeps_plain_progress_and_archive_waits_across_restart() {
    let root = crate::test_scratch::private_dir("custody-unknown-scope");
    let held = member(&root, "sessions", OWNER, false);
    let plain = member(&root, "sessions", PARENT, false);
    let archive = member(&root, "sessions", OWNER, true);
    let mut index = accepted(&root, &held);
    latch(&mut index, &held);
    index.codex_state_only_blocked_by_file.clear();
    seed_archive(&mut index, &archive, OWNER);
    let before = index.files[&local_index_key(&held)].clone();
    let incidence = index.file_snapshot_fingerprints[&local_index_key(&held)].clone();
    let decodes = codex_zst_refusal_tests::activity().0;
    let paths = [held.clone(), plain.clone(), archive.clone()];
    let mut inv = no_open(&held, || inventory(&root, &paths, &mut index));
    while !inv.prepare_custody(&index) {}
    assert!(inv.custody_unknown);
    assert!(!inv.member_held(&plain));
    assert!(inv.member_held(&archive));
    assert!(inv.complete_for(Some(&PARENT.to_owned())));
    let mut scan = staged(&root, index, &[plain.clone(), archive.clone()]);
    scan.index
        .traversal
        .as_mut()
        .unwrap()
        .codex_rollout_paths
        .insert(local_index_key(&held));
    scan.codex_join_inventory = Some(inv);
    let (mut index, first) = no_open(&held, || run(scan));
    assert_eq!(first.snapshots.len(), 1);
    assert_eq!(first.snapshots[0].source_session_id, PARENT);
    assert!(first.snapshots[0].input_tokens > 0);
    assert_eq!(first.unreadable_path_count, 0);
    assert!(!first.census_complete, "archive remains pending");
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .any(|p| p.path == archive));
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    let mut tokens = first.snapshots[0].input_tokens;
    for pass in 0..5 {
        index = ScanIndex::load(&saved).unwrap();
        assert!(index
            .codex_state_only_blocked_by_file
            .get(&local_index_key(&held))
            .map_or(true, |owners| owners.is_empty()));
        let mut file = fs::OpenOptions::new().append(true).open(&plain).unwrap();
        for row in
            codex_file_join::tests::member(PARENT, &format!("new-{pass}"), 100, (pass + 2) * 100)
                .into_iter()
                .skip(1)
        {
            writeln!(file, "{row}").unwrap();
        }
        drop(file);
        let (mut next, result) =
            no_open(&held, || normal(&root, index, std::slice::from_ref(&plain)));
        assert_eq!(result.unreadable_path_count, 0);
        assert_eq!(
            result.snapshots.len(),
            1,
            "ordinary plain served pass {pass}"
        );
        assert_eq!(result.snapshots[0].source_session_id, PARENT);
        assert!(result.snapshots[0].input_tokens > tokens);
        tokens = result.snapshots[0].input_tokens;
        let retained = &next.files[&local_index_key(&held)];
        assert_eq!(retained.codex_compressed_hold, before.codex_compressed_hold);
        assert_eq!(
            retained.last_snapshot_fingerprint,
            before.last_snapshot_fingerprint
        );
        assert_eq!(
            retained.last_upload_body_witness,
            before.last_upload_body_witness
        );
        assert_eq!(
            next.file_snapshot_fingerprints[&local_index_key(&held)],
            incidence
        );
        assert!(next.files[&local_index_key(&plain)]
            .codex_compressed_hold
            .is_none());
        assert!(next.files[&local_index_key(&archive)]
            .last_snapshot_fingerprint
            .is_none());
        assert_eq!(codex_zst_refusal_tests::activity().0, decodes);
        next.save(&saved).unwrap();
    }
    let index = ScanIndex::load(&saved).unwrap();
    let (_, quiet) = no_open(&held, || normal(&root, index, &[]));
    assert!(
        quiet.snapshots.is_empty(),
        "unchanged ordinary plain remains quiet"
    );
    assert_eq!(quiet.unreadable_path_count, 0);
    assert_eq!(codex_zst_refusal_tests::activity().0, decodes);
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Paged custody keeps the complete OsStr path lookup order.
#[test]
fn paged_custody_preserves_complete_osstr_path_lookup_order() {
    let root = crate::test_scratch::private_dir("custody-path-order");
    let path = member(&root, "sessions", OWNER, false);
    let mut index = ScanIndex::default();
    let mut inv = inventory(&root, std::slice::from_ref(&path), &mut index);
    let sample = inv.headers[0].clone();
    inv.headers = vec![sample.clone(), sample.clone(), sample];
    for (header, leaf) in inv
        .headers
        .iter_mut()
        .zip(["a.jsonl", "a/b.jsonl", "b.jsonl"])
    {
        header.candidate.path = root.join(leaf);
        header.owner = leaf.into();
    }
    while !inv.prepare_custody(&index) {}
    for header in &inv.headers {
        assert_eq!(
            inv.owner_for_path(&header.candidate.path),
            Some(header.owner.as_str())
        );
    }
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Unattributed hold lookup pages unheld retained entries too.
#[test]
fn unattributed_hold_lookup_pages_unheld_retained_entries_too() {
    let root = crate::test_scratch::private_dir("custody-all-files-pager");
    let plain = member(&root, "sessions", PARENT, false);
    let mut index = ScanIndex::default();
    for n in 0..2049 {
        index.files.insert(
            local_index_key(&root.join(format!("old-{n:05}"))),
            ScanIndexEntry::default(),
        );
    }
    let last = local_index_key(&root.join("z-unattributed"));
    index.files.insert(
        last.clone(),
        ScanIndexEntry {
            codex_compressed_hold: Some(CodexZstCause::ParentLedgerUnbound),
            ..Default::default()
        },
    );
    let mut inv = inventory(&root, std::slice::from_ref(&plain), &mut index);
    for key in index.files.keys() {
        assert!(!inv.prepare_custody(&index));
        assert_eq!(inv.custody_after.as_ref(), Some(key));
        assert_eq!(inv.custody_unknown, key == &last);
    }
    assert!(inv.prepare_custody(&index));
    assert!(
        !inv.member_held(&plain),
        "unknown cannot claim plain custody"
    );
    assert!(inv.member_held(&plain.with_extension("jsonl.zst")));
    assert!(inv.complete_for(Some(&PARENT.to_owned())));
    assert_eq!(inv.custody_peak, codex_compressed_holds::OWNER_LOOKUP_SLACK);
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Publication validation never reopens a newly custodied sibling.
#[test]
fn publication_validation_never_reopens_newly_custodied_sibling() {
    let root = crate::test_scratch::private_dir("custody-publication-validation");
    let held = member(&root, "sessions", OWNER, false);
    let healthy = member(&root, "sessions", PARENT, false);
    let mut index = ScanIndex::default();
    let mut inv = inventory(&root, &[held.clone(), healthy.clone()], &mut index);
    assert_eq!(inv.headers.len(), 2, "both headers existed before custody");
    let home = inv
        .headers
        .iter()
        .find(|h| h.owner == PARENT)
        .unwrap()
        .home
        .clone();
    index.hold_compressed(
        &root.join("retained-parent"),
        BTreeSet::from([OWNER.into()]),
        CodexZstCause::ParentLedgerUnbound,
    );
    while !inv.prepare_custody(&index) {}
    while !inv.hold_custodied_siblings(&mut index) {}
    assert!(inv.member_held(&held));
    assert!(!inv.member_held(&healthy));
    let old_len = fs::metadata(&held).unwrap().len();
    fs::write(&held, b"invalid replacement after custody\n").unwrap();
    assert_ne!(old_len, fs::metadata(&held).unwrap().len());
    no_open(&held, || inv.validate_membership(PARENT, &home).unwrap());
    assert!(index.files[&local_index_key(&held)]
        .codex_compressed_hold
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [money] A legacy owner barrier, file-attributed or path-scoped, holds the smaller sibling
/// quietly and keeps its body witness; unrelated plain money publishes.
#[test]
fn legacy_owner_barrier_keeps_smaller_sibling_quiet_and_unrelated_plain_publishes() {
    for (attributed, absent) in [(true, false), (true, true), (false, false), (false, true)] {
        let root = crate::test_scratch::private_dir("custody-selective-legacy-owner");
        let held = member(&root, "sessions", OWNER, false);
        let unrelated = member(&root, "sessions", PARENT, false);
        let mut index = accepted(&root, &held);
        assert!(index.files[&local_index_key(&held)]
            .codex_protected_owner
            .is_none());
        assert!(index.files[&local_index_key(&held)]
            .codex_joined_member_set
            .is_none());
        latch(&mut index, &held);
        if attributed {
            assert!(
                index.codex_state_only_blocked_by_file[&local_index_key(&held)].contains(OWNER)
            );
        } else {
            // Path-scoped legacy owner: no file attribution remains.
            index.codex_state_only_blocked_by_file.clear();
        }
        let smaller = held.with_file_name(format!("rollout-2026-10-01T11-00-00-{OWNER}.jsonl"));
        fs::write(
            &smaller,
            codex_file_join::tests::member(OWNER, "shorter", 1, 1)
                .iter()
                .map(|v| v.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let witness = index.files[&local_index_key(&held)]
            .last_upload_body_witness
            .clone();
        assert!(witness.is_some());
        if absent {
            fs::remove_file(&held).unwrap();
        }
        let (index, result) = no_open(&held, || normal(&root, index, &[]));
        assert_eq!(result.unreadable_path_count, 0);
        assert!(!result.snapshots.is_empty());
        assert!(result
            .snapshots
            .iter()
            .all(|s| s.source_session_id == PARENT && s.input_tokens > 0));
        assert!(index.files[&local_index_key(&unrelated)]
            .last_snapshot_fingerprint
            .is_some());
        assert_eq!(
            index.files[&local_index_key(&held)].last_upload_body_witness,
            witness
        );
        assert_eq!(
            index.files[&local_index_key(&smaller)].codex_compressed_hold,
            Some(CodexZstCause::ParentLedgerUnbound)
        );
        fs::remove_dir_all(root).unwrap();
    }
}

/// [money] An opaque filename uses the retained counting binding as negative scope; unrelated money
/// publishes.
#[test]
fn unattributed_opaque_filename_uses_retained_counting_binding_as_negative_scope() {
    for absent in [false, true] {
        let root = crate::test_scratch::private_dir("custody-counting-owner-scope");
        let original = member(&root, "sessions", OWNER, false);
        let held = original.with_file_name("a.jsonl");
        fs::rename(original, &held).unwrap();
        let (mut index, mut accepted) =
            codex_file_join::tests::scan(&root, ScanIndex::default(), 10);
        assert_eq!(accepted.snapshots.len(), 1);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut accepted, &mut index);
        index.accepted_snapshot_fingerprints.extend(
            accepted
                .snapshots
                .iter()
                .map(|snapshot| snapshot.snapshot_fingerprint.clone()),
        );
        let key = local_index_key(&held);
        assert_eq!(
            index.files[&key].codex_counting_owner.as_deref(),
            Some(codex_protected_owner(OWNER).as_str())
        );
        assert!(index.files[&key].codex_protected_owner.is_none());
        assert!(codex_session_id_candidates_from_path(&held).is_empty());
        let witness = index.files[&key].last_upload_body_witness.clone();
        assert!(witness.is_some());
        latch(&mut index, &held);
        index.codex_state_only_blocked_by_file.clear();
        assert!(index.codex_state_only_blocked_session_ids.is_empty());
        let smaller = held.with_file_name("b.jsonl");
        fs::write(
            &smaller,
            codex_file_join::tests::member(OWNER, "shorter", 1, 1)
                .iter()
                .map(|v| v.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let unrelated = member(&root, "sessions", PARENT, false);
        if absent {
            fs::remove_file(&held).unwrap();
        }
        let saved = root.join("index.json");
        for pass in 0..2 {
            index.traversal = None;
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::Codex,
                &[root.join("sessions")],
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
            scan.state_census_complete = true;
            scan.sidecar_census_complete = true;
            for id in [OWNER, "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa"] {
                scan.codex_title_metadata.state_threads.insert(
                    id.to_owned(),
                    CodexStateThread {
                        tokens_used: 1000,
                        updated_at: Some("2026-10-06T00:00:00Z".into()),
                        ..Default::default()
                    },
                );
            }
            let (mut next, result) = no_open(&held, || run(scan));
            assert_eq!(result.unreadable_path_count, 0);
            assert!(result
                .snapshots
                .iter()
                .all(|s| s.source_session_id != OWNER));
            assert!(result
                .snapshots
                .iter()
                .any(|s| s.source_session_id == "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa"));
            if pass == 0 {
                assert!(result
                    .snapshots
                    .iter()
                    .any(|s| s.source_session_id == PARENT));
                fs::remove_file(&smaller).unwrap();
            }
            assert!(next.files[&local_index_key(&unrelated)]
                .last_snapshot_fingerprint
                .is_some());
            assert_eq!(next.files[&key].last_upload_body_witness, witness);
            assert_eq!(
                next.files[&local_index_key(&smaller)].codex_compressed_hold,
                Some(CodexZstCause::ParentLedgerUnbound)
            );
            next.save(&saved).unwrap();
            index = ScanIndex::load(&saved).unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// [behaviour] A stale header never mints custody after rewrite or replacement, even on refusal.
#[test]
fn stale_header_never_mints_custody_after_rewrite_or_replacement_even_on_refusal() {
    for refused in [false, true] {
        for change in 0..3 {
            let root = crate::test_scratch::private_dir("custody-current-header");
            let old = member(&root, "sessions", OWNER, false);
            let next = old.with_file_name("b.jsonl");
            let bytes = fs::read_to_string(&old).unwrap();
            fs::write(&next, &bytes).unwrap();
            let mut index = accepted(&root, &old);
            let witness = index.files[&local_index_key(&old)]
                .last_upload_body_witness
                .clone();
            index.hold_compressed(
                &old,
                BTreeSet::from([OWNER.into()]),
                CodexZstCause::ParentLedgerUnbound,
            );
            let mut inv = inventory(&root, std::slice::from_ref(&next), &mut index);
            while !inv.prepare_custody(&index) {}
            assert_eq!(
                inv.headers[0].custody_cause,
                Some(CodexZstCause::ParentLedgerUnbound)
            );
            // Exercise BOTH normal and refused/unknown per-file assignment.
            inv.custody_refused = refused;
            let replacement = bytes.replace(OWNER, PARENT);
            if change == 2 {
                let temp = next.with_extension("replacement");
                fs::write(&temp, &replacement).unwrap();
                fs::rename(temp, &next).unwrap();
            } else {
                fs::write(
                    &next,
                    if change == 0 {
                        replacement.clone()
                    } else {
                        replacement.clone() + "\n"
                    },
                )
                .unwrap();
                fs::OpenOptions::new()
                    .write(true)
                    .open(&next)
                    .unwrap()
                    .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(2))
                    .unwrap();
            }
            assert!(!inv.headers[0].custody_current());
            assert!(!inv.hold_custodied_siblings(&mut index));
            assert!(!index
                .files
                .get(&local_index_key(&next))
                .is_some_and(|e| e.codex_compressed_hold.is_some()));
            let mut done = false;
            for step in 0..100 {
                if inv.step_with_archive(&CodexTitleMetadata::default(), &mut index, None)
                    != codex_file_join::HeaderStep::Complete
                {
                    continue;
                }
                if !inv.prepare_custody(&index) {
                    continue;
                }
                if inv.hold_custodied_siblings(&mut index) {
                    done = true;
                    break;
                }
                assert_ne!(step, 99, "bounded retry must make progress");
            }
            assert!(done, "retry completed within100 steps");
            assert_eq!(inv.headers.len(), 1);
            assert_eq!(inv.headers[0].owner, PARENT);
            assert!(!inv.member_held(&next));
            let mut scan = staged(&root, index, std::slice::from_ref(&next));
            scan.codex_join_inventory = Some(inv);
            let (next_index, result) = no_open(&old, || run(scan));
            assert_eq!(result.unreadable_path_count, 0);
            assert!(result
                .snapshots
                .iter()
                .any(|s| s.source_session_id == PARENT && s.input_tokens > 0));
            assert!(next_index.files[&local_index_key(&old)]
                .codex_compressed_hold
                .is_some());
            assert_eq!(
                next_index.files[&local_index_key(&old)].last_upload_body_witness,
                witness
            );
            assert!(next_index.files[&local_index_key(&next)]
                .codex_compressed_hold
                .is_none());
            fs::remove_dir_all(root).unwrap();
        }
    }
}

/// [money] State-only exclusion refusal keeps the prior fingerprint, activity and manifest.
#[test]
fn state_only_exclusion_refusal_keeps_prior_fingerprint_activity_and_manifest() {
    fn with_state(root: &Path, index: ScanIndex, present: bool) -> (ScanIndex, SourceScanResult) {
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[root.join("sessions")],
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
        scan.state_census_complete = true;
        scan.sidecar_census_complete = true;
        if present {
            scan.codex_title_metadata.state_threads.insert(
                PARENT.into(),
                CodexStateThread {
                    tokens_used: 1000,
                    updated_at: Some("2026-10-06T00:00:00Z".into()),
                    ..Default::default()
                },
            );
        }
        run(scan)
    }
    let root = crate::test_scratch::private_dir("custody-state-refusal-keeps");
    let held = member(&root, "sessions", OWNER, false);
    let (mut index, mut seed) = with_state(&root, ScanIndex::default(), true);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut seed, &mut index);
    assert!(index
        .codex_state_only_snapshot_fingerprints
        .contains_key(PARENT));
    let fingerprints = index.codex_state_only_snapshot_fingerprints.clone();
    let activity = index.snapshot_activity_at.clone();
    let before = serde_json::to_value(
        index
            .manifest_for_window(
                SnapshotSource::Codex,
                "2000-01-01T00:00:00Z",
                "2100-01-01T00:00:00Z",
            )
            .unwrap(),
    )
    .unwrap();
    let owners = (0..5000)
        .map(|n| format!("{n:08x}-1111-4111-8111-222222222222"))
        .chain(std::iter::once(OWNER.into()))
        .collect();
    index.hold_compressed(&held, owners, CodexZstCause::ParentLedgerUnbound);
    assert!(index.files[&local_index_key(&held)]
        .codex_counting_owner
        .is_some());
    for _ in 0..2 {
        index.traversal = None;
        let saved = root.join("reload.json");
        index.save(&saved).unwrap();
        index = ScanIndex::load(&saved).unwrap();
        let ((mut next, mut result), rows) =
            capture(|| no_open(&held, || with_state(&root, index, true)));
        assert!(
            !result.state_census_complete,
            "refusal must reach finalizer"
        );
        assert_eq!(result.unreadable_path_count, 0);
        assert!(rows.iter().any(|r| r["stage"] == "durable_tail_alarm"
            && r["counts"]["custody_overflow"]["events"] == 1));
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut next);
        assert_eq!(next.codex_state_only_snapshot_fingerprints, fingerprints);
        assert_eq!(next.snapshot_activity_at, activity);
        assert_eq!(
            serde_json::to_value(
                next.manifest_for_window(
                    SnapshotSource::Codex,
                    "2000-01-01T00:00:00Z",
                    "2100-01-01T00:00:00Z"
                )
                .unwrap()
            )
            .unwrap(),
            before
        );
        index = next;
    }
    // Funding recovers; the unrelated gone state thread must now retire.
    index
        .codex_state_only_blocked_by_file
        .insert(local_index_key(&held), BTreeSet::from([OWNER.to_owned()]));
    index.codex_state_only_blocked_session_ids = BTreeSet::from([OWNER.to_owned()]);
    index.traversal = None;
    let (mut recovered, mut result) = no_open(&held, || with_state(&root, index, false));
    assert!(
        result.state_census_complete,
        "funded exclusion recovers completeness"
    );
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut recovered);
    assert!(!recovered
        .codex_state_only_snapshot_fingerprints
        .contains_key(PARENT));
    assert!(fingerprints
        .values()
        .all(|fp| !recovered.snapshot_activity_at.contains_key(fp)));
    assert!(recovered.files[&local_index_key(&held)]
        .codex_compressed_hold
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] A parser-bound fork latches custody; a spawn edge alone does not.
#[test]
fn parser_bound_fork_latches_but_spawn_edge_alone_does_not() {
    for fork in [false, true] {
        let root = crate::test_scratch::private_dir("custody-fork-only");
        let child = member(&root, "sessions", OWNER, false);
        let parent = member(&root, "sessions", PARENT, true);
        if fork {
            let mut rows = codex_file_join::tests::member(OWNER, "response", 100, 100);
            rows[0]["payload"]["forked_from_id"] = json!(PARENT);
            fs::write(
                &child,
                rows.iter()
                    .map(|v| v.to_string() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
        let mut index = ScanIndex::default();
        seed_archive(&mut index, &parent, PARENT);
        let paths = [child.clone(), parent.clone()];
        let inv = inventory(&root, &paths, &mut index);
        let mut scan = staged(&root, index, std::slice::from_ref(&child));
        scan.index
            .traversal
            .as_mut()
            .unwrap()
            .codex_rollout_paths
            .insert(local_index_key(&parent));
        scan.codex_join_inventory = Some(inv);
        scan.codex_title_metadata
            .spawn_parents
            .insert(OWNER.into(), PARENT.into());
        let ((index, result), rows) = capture(|| run(scan));
        assert_eq!(result.scanned_file_count, 1);
        if fork {
            assert_no_red(&result, &rows);
            assert_eq!(
                index.files[&local_index_key(&child)].codex_compressed_hold,
                Some(CodexZstCause::ParentLedgerUnbound)
            );
        } else {
            assert_eq!(result.snapshots.len(), 1);
            assert!(result.snapshots[0].input_tokens > 0);
            assert!(index.files[&local_index_key(&child)]
                .codex_compressed_hold
                .is_none());
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// [behaviour] A side parse of a fork finishes its guard without main custody.
#[test]
fn side_parse_of_fork_finishes_its_guard_without_main_custody() {
    let root = crate::test_scratch::private_dir("custody-side-exit");
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
    let inv = inventory(&root, &[child.clone(), parent.clone()], &mut index);
    let mut scan = staged(&root, index, std::slice::from_ref(&child));
    scan.index
        .traversal
        .as_mut()
        .unwrap()
        .codex_rollout_paths
        .insert(local_index_key(&parent));
    scan.codex_join_inventory = Some(inv);
    let mut reached = false;
    for _ in 0..100 {
        scan = match scan.step(None) {
            OwnedSourceScanStep::Pending(next) => next,
            _ => panic!("must reach staged parser"),
        };
        if scan.active_file.is_some() {
            reached = true;
            break;
        }
    }
    assert!(reached);
    let stat = fs::metadata(&child).unwrap();
    let ((index, result), rows) = capture(|| {
        scan.active_file.as_mut().unwrap().side_origin = Some(SideOrigin {
            guard: crate::local_resource_diagnostics::codex_side_lifecycle::SideReadGuard::start(1),
            dev_ino: (stat.dev(), stat.ino()),
        });
        run(scan)
    });
    assert!(index
        .files
        .get(&local_index_key(&child))
        .map_or(true, |e| e.codex_compressed_hold.is_none()));
    assert!(result.snapshots.is_empty());
    let ends = rows
        .iter()
        .filter(|r| r["stage"] == "side_read_end")
        .collect::<Vec<_>>();
    assert_eq!(
        ends.len(),
        1,
        "production side finish must end exactly once"
    );
    assert_ne!(ends[0]["counts"]["abandoned"], true);
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] A custodied owner sibling is not red and does not become a header witness.
#[test]
fn custodied_owner_sibling_is_non_red_without_becoming_a_header_witness() {
    let root = crate::test_scratch::private_dir("custody-sibling");
    let a = member(&root, "sessions", OWNER, false);
    let b = member(&root, "copy/sessions", OWNER, false);
    let mut index = ScanIndex::default();
    latch(&mut index, &a);
    let inv = inventory(&root, &[a.clone(), b.clone()], &mut index);
    assert_eq!(inv.headers.len(), 1, "custody grants no header authority");
    let mut scan = staged(&root, index, &[a.clone(), b.clone()]);
    scan.codex_join_inventory = Some(inv);
    let ((index, result), rows) = capture(|| run(scan));
    assert_no_red(&result, &rows);
    assert_eq!(
        index.files[&local_index_key(&b)].codex_compressed_hold,
        Some(CodexZstCause::ParentLedgerUnbound)
    );
    fs::remove_dir_all(root).unwrap();
}

/// [money] A missing held path still blocks a new same-owner member.
#[test]
fn missing_held_path_still_blocks_new_same_owner_member() {
    let root = crate::test_scratch::private_dir("custody-absent-owner");
    let a = member(&root, "sessions", OWNER, false);
    let mut index = accepted(&root, &a);
    latch(&mut index, &a);
    fs::remove_file(&a).unwrap();
    let b = member(&root, "copy/sessions", OWNER, false);
    let inv = inventory(&root, std::slice::from_ref(&b), &mut index);
    let mut scan = staged(&root, index, std::slice::from_ref(&b));
    scan.codex_join_inventory = Some(inv);
    let ((index, result), rows) = capture(|| run(scan));
    assert_no_red(&result, &rows);
    assert!(index.files[&local_index_key(&b)]
        .codex_compressed_hold
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Proven local fork boundaries publish without parent custody.
#[test]
fn proven_local_fork_boundaries_publish_without_parent_custody() {
    for ordinal in [false, true] {
        let root = crate::test_scratch::private_dir("custody-local-boundary");
        let child = member(&root, "sessions", OWNER, false);
        let parent = member(&root, "sessions", PARENT, true);
        let mut rows = codex_file_join::tests::member(OWNER, "local", 100, 100);
        rows[0]["payload"]["forked_from_id"] = json!(PARENT);
        if ordinal {
            rows[0]["payload"]["subagent_history_start_ordinal"] = json!(1);
            for (n, row) in rows.iter_mut().enumerate() {
                row["ordinal"] = json!(n);
            }
        } else {
            rows[0]["payload"]["history_base"] = json!({"cursor":"external"});
        }
        fs::write(
            &child,
            rows.iter()
                .map(|v| v.to_string() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        let mut index = ScanIndex::default();
        seed_archive(&mut index, &parent, PARENT);
        let inv = inventory(&root, &[child.clone(), parent.clone()], &mut index);
        let mut scan = staged(&root, index, std::slice::from_ref(&child));
        scan.index
            .traversal
            .as_mut()
            .unwrap()
            .codex_rollout_paths
            .insert(local_index_key(&parent));
        scan.codex_join_inventory = Some(inv);
        let (index, result) = run(scan);
        assert_eq!(result.snapshots.len(), 1);
        assert!(result.snapshots[0].input_tokens > 0);
        assert!(index.files[&local_index_key(&child)]
            .codex_compressed_hold
            .is_none());
        fs::remove_dir_all(root).unwrap();
    }
}

fn home_inventory(
    roots: &[PathBuf],
    paths: &[PathBuf],
    index: &mut ScanIndex,
) -> codex_file_join::HeaderInventory {
    let mut dirs = codex_file_join::DirectoryCensus::new();
    for root in roots {
        dirs.observe(root, &fs::metadata(root).unwrap());
    }
    let mut inv = codex_file_join::HeaderInventory::new(
        roots,
        &paths.iter().map(|p| local_index_key(p)).collect(),
        Some(&dirs),
    );
    while inv.step_with_archive(&CodexTitleMetadata::default(), index, None)
        != codex_file_join::HeaderStep::Complete
    {}
    assert!(inv.complete);
    assert!(inv.refused.is_empty());
    inv
}

fn prepared(inv: &mut codex_file_join::HeaderInventory, index: &mut ScanIndex) -> usize {
    let mut steps = 0;
    while !inv.prepare_custody(index) {
        steps += 1;
        assert!(steps <= index.files.len() + 2);
    }
    while !inv.hold_custodied_siblings(index) {}
    steps
}

/// [behaviour] A two-archive family across distinct homes holds every archive.
#[test]
fn distinct_home_two_archive_family_holds_every_archive() {
    let root = crate::test_scratch::private_dir("family-two-archives");
    let a = member(&root, "left/sessions", OWNER, true);
    let b = member(&root, "right/sessions", OWNER, true);
    let roots = [root.join("left/sessions"), root.join("right/sessions")];
    let mut index = ScanIndex::default();
    seed_archive(&mut index, &a, OWNER);
    seed_archive(&mut index, &b, OWNER);
    let inv = home_inventory(&roots, &[a.clone(), b.clone()], &mut index);
    assert_eq!(
        inv.headers
            .iter()
            .map(|h| h.home.clone())
            .collect::<BTreeSet<_>>()
            .len(),
        2
    );
    let mut scan = staged(&root, index, &[a.clone(), b.clone()]);
    scan.codex_join_inventory = Some(inv);
    assert!(!scan.codex_join_prepared);
    let ((mut index, result), rows) = capture(|| no_open(&a, || run(scan)));
    assert_no_red(&result, &rows);
    for path in [&a, &b] {
        assert_eq!(
            index.files[&local_index_key(path)].codex_compressed_hold,
            Some(CodexZstCause::FamilyUnproven)
        );
    }
    assert_eq!(
        rows.iter()
            .map(|r| {
                r["counts"]["codex_zst_held"]["CompressedFamilyUnproven"]
                    .as_u64()
                    .unwrap_or(0)
            })
            .sum::<u64>(),
        2,
        "Pending pages may drain separate batches; the two mints count once each"
    );
    let saved = root.join("index.json");
    index.save(&saved).unwrap();
    fs::remove_file(&b).unwrap();
    let ((mut index, result), rows) = capture(|| {
        normal(
            &root.join("right"),
            ScanIndex::load(&saved).unwrap(),
            std::slice::from_ref(&b),
        )
    });
    assert_no_red(&result, &rows);
    assert_eq!(
        index.files[&local_index_key(&b)].codex_compressed_hold,
        Some(CodexZstCause::FamilyUnproven)
    );
    index.save(&saved).unwrap();
    fs::remove_dir_all(root).unwrap();
}

/// [money] Mixed-family plain money matches the plain reader; only the archive hold is sticky.
#[test]
fn mixed_family_plain_money_matches_plain_reader_and_only_archive_is_sticky() {
    for distinct in [false, true] {
        let root = crate::test_scratch::private_dir("family-plain-money");
        let plain = member(&root, "left/sessions", OWNER, false);
        let (_, control) = run(staged(
            &root,
            ScanIndex::default(),
            std::slice::from_ref(&plain),
        ));
        assert_eq!(control.snapshots.len(), 1);
        assert!(control.snapshots[0].input_tokens > 0);
        let expected = serde_json::to_vec(&control.snapshots[0]).unwrap();
        let dir = if distinct {
            "right/sessions"
        } else {
            "left/sessions"
        };
        let old = member(&root, dir, OWNER, true);
        let archive = old.with_file_name(format!("rollout-2026-10-01T10-00-00-{OWNER}.jsonl.zst"));
        fs::rename(old, &archive).unwrap();
        let roots = if distinct {
            vec![root.join("left/sessions"), root.join("right/sessions")]
        } else {
            vec![root.join("left/sessions")]
        };
        let paths = [plain.clone(), archive.clone()];
        let mut index = ScanIndex::default();
        seed_archive(&mut index, &archive, OWNER);
        let decodes = codex_zst_refusal_tests::activity().0;
        for pass in 0..3 {
            let inv = if pass == 0 {
                home_inventory(&roots, &paths, &mut index)
            } else {
                no_open(&archive, || home_inventory(&roots, &paths, &mut index))
            };
            let mut scan = staged(&root, index, &paths);
            scan.codex_join_inventory = Some(inv);
            let ((mut next, result), rows) = capture(|| no_open(&archive, || run(scan)));
            assert_eq!(result.unreadable_path_count, 0);
            assert_eq!(result.snapshots.len(), 1);
            assert_eq!(serde_json::to_vec(&result.snapshots[0]).unwrap(), expected);
            assert_eq!(
                codex_zst_refusal_tests::activity().0,
                decodes,
                "zero archive decodes"
            );
            assert!(next.files[&local_index_key(&plain)]
                .codex_compressed_hold
                .is_none());
            assert_eq!(
                next.files[&local_index_key(&archive)].codex_compressed_hold,
                Some(CodexZstCause::FamilyUnproven)
            );
            let archive_entry = &next.files[&local_index_key(&archive)];
            assert!(archive_entry.last_snapshot_fingerprint.is_none());
            if pass > 0 {
                assert!(!rows.iter().any(|r| r["stage"] == "codex_zst_held"));
            }
            let saved = root.join("index.json");
            next.save(&saved).unwrap();
            index = ScanIndex::load(&saved).unwrap();
            // Re-offer the unchanged plain body through its ordinary reader;
            // custody on its archive sibling must not change emitted bytes.
            index.files.remove(&local_index_key(&plain));
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// [money] Validated plain/archive twins count once and the plain body is unchanged.
#[test]
fn validated_plain_archive_twins_count_once_and_plain_body_is_unchanged() {
    let root = crate::test_scratch::private_dir("family-twins");
    let plain = member(&root, "left/sessions", OWNER, false);
    let archive = member(&root, "right/sessions", OWNER, true);
    let roots = [root.join("left/sessions"), root.join("right/sessions")];
    let (_, cold) = codex_file_join::tests::scan(&root.join("left"), ScanIndex::default(), 10);
    assert_eq!(cold.snapshots.len(), 1);
    let mut index = ScanIndex::default();
    seed_archive(&mut index, &archive, OWNER);
    let mut inv = home_inventory(&roots, &[plain.clone(), archive.clone()], &mut index);
    while !inv.prepare_custody(&index) {}
    assert!(!inv.plain_twin(&plain));
    assert!(inv.plain_twin(&archive));
    let decodes = codex_zst_refusal_tests::activity().0;
    let mut scan = staged(&root, index, &[plain.clone(), archive.clone()]);
    scan.codex_join_inventory = Some(inv);
    let ((index, result), rows) = capture(|| run(scan));
    assert_eq!(result.unreadable_path_count, 0);
    assert_eq!(result.ownership_incomplete_file_count, 0);
    assert_eq!(result.census_residue_index_key_count, 0);
    assert_eq!(result.census_residue_archived_rollout_count, 0);
    assert_eq!(result.census_residue_blocked_session_count, 0);
    assert_eq!(codex_zst_refusal_tests::activity().0, decodes);
    assert_eq!(result.scanned_file_count, 1);
    assert_eq!(result.snapshots.len(), 1);
    assert_eq!(
        snapshot_upload_body_witness(&result.snapshots[0]),
        snapshot_upload_body_witness(&cold.snapshots[0])
    );
    assert!(index
        .files
        .values()
        .all(|e| e.codex_compressed_hold.is_none()));
    assert!(!rows
        .iter()
        .any(|r| r["stage"] == "codex_zst_input" || r["stage"] == "codex_zst_inventory"));
    fs::remove_dir_all(root).unwrap();
}

/// [behaviour] Plain-only families and a single archive are not held.
#[test]
fn plain_only_family_and_single_archive_controls_are_unheld() {
    let root = crate::test_scratch::private_dir("family-controls");
    let a = member(&root, "left/sessions", OWNER, false);
    let b = member(&root, "right/sessions", OWNER, false);
    let mut index = ScanIndex::default();
    let mut inv = home_inventory(
        &[root.join("left/sessions"), root.join("right/sessions")],
        &[a, b],
        &mut index,
    );
    prepared(&mut inv, &mut index);
    assert!(inv.headers.iter().all(|h| h.custody_cause.is_none()));
    assert!(index.files.is_empty());
    let archive = member(&root, "single/sessions", PARENT, true);
    seed_archive(&mut index, &archive, PARENT);
    let mut inv = home_inventory(
        &[root.join("single/sessions")],
        std::slice::from_ref(&archive),
        &mut index,
    );
    prepared(&mut inv, &mut index);
    assert!(inv.headers.iter().all(|h| h.custody_cause.is_none()));
    assert!(!inv.plain_twin(&archive));
    assert!(index.files[&local_index_key(&archive)]
        .codex_compressed_hold
        .is_none());
    fs::remove_dir_all(root).unwrap();
}

/// [money] A present family archive keeps the legacy tombstone across two censuses.
#[test]
fn present_family_archive_keeps_legacy_tombstone_across_two_censuses() {
    use codex_counting_version::{AckEvidence, CountingTombstone};
    let root = crate::test_scratch::private_dir("family-present-tombstone");
    let archive = member(&root, "sessions", OWNER, true);
    let plain = member(&root, "sessions", PARENT, false);
    let invalid_owner = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
    let invalid = member(&root, "sessions", invalid_owner, true);
    let invalid_hash = codex_protected_owner(invalid_owner);
    let held = codex_protected_owner(OWNER);
    let other = codex_protected_owner("unrelated-absent");
    let mut index = ScanIndex::default();
    for owner in [&held, &invalid_hash, &other] {
        index.codex_counting_tombstones.insert(
            owner.clone(),
            CountingTombstone {
                evidence: AckEvidence::LegacyAcked,
                retired_in: "prior-generation".into(),
                created_unix_ms: None,
            },
        );
    }
    seed_archive(&mut index, &archive, OWNER);
    let mut evidence =
        ArchiveEvidence::begin(&File::open(&invalid).unwrap(), &invalid, None).unwrap();
    evidence.disposition = ArchiveDisposition::Held {
        cause: CodexZstCause::HeaderInvalid,
    };
    assert!(evidence.header_validated.is_none());
    index
        .files
        .entry(local_index_key(&invalid))
        .or_default()
        .archive = Some(Box::new(evidence));
    index.hold_compressed(
        &archive,
        BTreeSet::from([OWNER.into()]),
        CodexZstCause::FamilyUnproven,
    );
    let saved = root.join("index.json");
    for _ in 0..2 {
        let paths = [archive.clone(), plain.clone(), invalid.clone()];
        let inv = no_open(&archive, || inventory(&root, &paths, &mut index));
        assert_eq!(inv.headers.len(), 1);
        assert_eq!(inv.headers[0].owner, PARENT);
        assert!(invalid.exists());
        assert!(inv.complete);
        assert!(inv.held_owners.contains(invalid_owner));
        assert!(index.files[&local_index_key(&invalid)]
            .codex_compressed_hold
            .is_none());
        let mut scan = staged(&root, index, std::slice::from_ref(&plain));
        scan.index
            .traversal
            .as_mut()
            .unwrap()
            .codex_rollout_paths
            .extend([local_index_key(&archive), local_index_key(&invalid)]);
        scan.index.known_configured_scan_roots = BTreeSet::from([local_index_key(&root)]);
        scan.codex_join_inventory = Some(inv);
        let ((mut next, result), _) = capture(|| no_open(&archive, || run(scan)));
        assert_eq!(result.unreadable_path_count, 0);
        assert!(result.census_complete);
        assert_eq!(
            next.codex_counting_tombstones[&held].evidence,
            AckEvidence::LegacyAcked
        );
        assert_eq!(
            next.codex_counting_tombstones[&invalid_hash].evidence,
            AckEvidence::LegacyAcked,
            "header-excluded present owner keeps Legacy evidence"
        );
        assert!(
            next.codex_counting_tombstones.contains_key(&other),
            "opaque held ownership cannot prove an unrelated tombstone absent"
        );
        next.save(&saved).unwrap();
        index = ScanIndex::load(&saved).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

/// [regress] The #878 same-stamp early return for a persisted Held archive
/// dropped its owner from `held_owners` (fixed in a6c394ffa), so custody lost
/// the tombstone's absence scope before classification rebuilt it.
#[test]
fn regress_held_archive_early_return_keeps_owner_in_custody_scope() {
    use codex_counting_version::{AckEvidence, CountingTombstone};
    let root = crate::test_scratch::private_dir("regress-held-owner-scope");
    let plain = member(&root, "sessions", PARENT, false);
    let owner = "bbbbbbbb-cccc-4ddd-8eee-ffffffffffff";
    let held = member(&root, "sessions", owner, true);
    let mut index = ScanIndex::default();
    index.codex_counting_tombstones.insert(
        codex_protected_owner(owner),
        CountingTombstone {
            evidence: AckEvidence::LegacyAcked,
            retired_in: "prior-generation".into(),
            created_unix_ms: None,
        },
    );
    let mut evidence = ArchiveEvidence::begin(&File::open(&held).unwrap(), &held, None).unwrap();
    evidence.disposition = ArchiveDisposition::Held {
        cause: CodexZstCause::HeaderInvalid,
    };
    index
        .files
        .entry(local_index_key(&held))
        .or_default()
        .archive = Some(Box::new(evidence));
    let paths = [plain, held.clone()];
    let mut inv = no_open(&held, || inventory(&root, &paths, &mut index));
    assert!(
        inv.held_owners.contains(owner),
        "held_owners={}",
        inv.held_owners.len()
    );
    while !inv.prepare_custody(&index) {}
    assert!(
        inv.absence_held.contains(&codex_protected_owner(owner)),
        "absence_held={}",
        inv.absence_held.len()
    );
    fs::remove_dir_all(root).unwrap();
}

/// [money] Excluded-archive priority receipts cannot be bypassed by a plain replacement.
#[test]
fn excluded_archive_priority_receipts_cannot_be_bypassed_by_plain_replacement() {
    for twin in [false, true] {
        for captured in [false, true] {
            let root = crate::test_scratch::private_dir("family-protected-replacement");
            let plain = member(&root, "left/sessions", OWNER, false);
            let original = member(&root, "right/sessions", OWNER, true);
            let archive = if twin {
                original
            } else {
                let path = original
                    .with_file_name(format!("rollout-2026-10-01T10-00-00-{OWNER}.jsonl.zst"));
                fs::rename(original, &path).unwrap();
                path
            };
            let mut index = accepted(&root, &archive);
            seed_archive(&mut index, &archive, OWNER);
            let mut replay = codex_file_join::TierReplay::new(None, false, "scope".into());
            for row in codex_file_join::tests::member(OWNER, "response", 100, 100) {
                replay.observe(&row);
            }
            replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
            let receipt = replay.finish().unwrap().unwrap();
            let key = local_index_key(&archive);
            let entry = index.files.get_mut(&key).unwrap();
            entry.codex_protected_owner = Some(codex_protected_owner(OWNER));
            if captured {
                entry.codex_captured_tier_receipt = Some(receipt);
                entry.codex_captured_tier_receipt_required = true;
            } else {
                entry.codex_applied_tier_receipt = Some(receipt);
                entry.codex_applied_tier_receipt_required = true;
            }
            let before = index.files[&key].clone();
            let incidence = index.file_snapshot_fingerprints.clone();
            let decodes = codex_zst_refusal_tests::activity().0;
            let saved = root.join("index.json");
            for _ in 0..2 {
                let paths = [plain.clone(), archive.clone()];
                // An unheld twin may validate its cached stamp, without decoding.
                let inv = home_inventory(
                    &[root.join("left/sessions"), root.join("right/sessions")],
                    &paths,
                    &mut index,
                );
                let mut scan = staged(&root, index, &paths);
                scan.codex_join_inventory = Some(inv);
                // Expired traces are a present, empty, complete map (never None).
                assert!(
                    scan.codex_turn_traces
                        .as_deref()
                        .is_some_and(|t| t.priority_turns.is_empty() && !t.is_incomplete()),
                    "live traces expired"
                );
                let (mut next, result) = no_open(&archive, || run(scan));
                assert!(
                    result.snapshots.is_empty(),
                    "cannot reprice protected money"
                );
                assert!(result.ownership_incomplete_file_count > 0);
                assert!(!result.census_complete);
                assert_eq!(codex_zst_refusal_tests::activity().0, decodes);
                let retained = &next.files[&key];
                assert_eq!(
                    retained.last_snapshot_fingerprint,
                    before.last_snapshot_fingerprint
                );
                assert_eq!(
                    retained.last_upload_body_witness,
                    before.last_upload_body_witness
                );
                assert_eq!(
                    retained.codex_applied_tier_receipt,
                    before.codex_applied_tier_receipt
                );
                assert_eq!(
                    retained.codex_captured_tier_receipt,
                    before.codex_captured_tier_receipt
                );
                assert_eq!(next.file_snapshot_fingerprints, incidence);
                assert!(!next
                    .files
                    .get(&local_index_key(&plain))
                    .is_some_and(|entry| entry.codex_compressed_hold.is_some()));
                next.save(&saved).unwrap();
                index = ScanIndex::load(&saved).unwrap();
            }
            fs::remove_dir_all(root).unwrap();
        }
    }
}

/// [money] A historical family cannot weaken a new member's parent custody.
#[test]
fn historical_family_cannot_weaken_new_member_parent_custody() {
    let root = crate::test_scratch::private_dir("family-parent-precedence");
    let archive = member(&root, "sessions", OWNER, true);
    let mut index = ScanIndex::default();
    seed_archive(&mut index, &archive, OWNER);
    for (name, cause) in [
        ("a-parent", CodexZstCause::ParentLedgerUnbound),
        ("z-family", CodexZstCause::FamilyUnproven),
    ] {
        index.hold_compressed(&root.join(name), BTreeSet::from([OWNER.into()]), cause);
    }
    let mut inv = inventory(&root, std::slice::from_ref(&archive), &mut index);
    while !inv.prepare_custody(&index) {}
    assert_eq!(
        inv.headers[0].custody_cause,
        Some(CodexZstCause::ParentLedgerUnbound)
    );
    inv.hold_custodied_siblings(&mut index);
    assert_eq!(
        index.files[&local_index_key(&archive)].codex_compressed_hold,
        Some(CodexZstCause::ParentLedgerUnbound)
    );
    fs::remove_dir_all(root).unwrap();
}

/// [money] A replaced held path cannot retire its hidden current legacy owner.
#[test]
fn replaced_held_path_cannot_retire_its_hidden_current_legacy_owner() {
    use codex_counting_version::{AckEvidence, CountingTombstone};
    let root = crate::test_scratch::private_dir("family-opaque-replacement-absence");
    let held = member(&root, "sessions", OWNER, false);
    let replacement = member(&root, "replacement/sessions", PARENT, false);
    let healthy = member(
        &root,
        "sessions",
        "cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa",
        false,
    );
    let hidden_owner = codex_protected_owner(PARENT);
    let mut index = accepted(&root, &held);
    latch(&mut index, &held);
    fs::rename(&replacement, &held).unwrap();
    assert!(held.exists());
    assert!(index.codex_state_only_blocked_by_file[&local_index_key(&held)].contains(OWNER));
    index.codex_counting_tombstones.insert(
        hidden_owner.clone(),
        CountingTombstone {
            evidence: AckEvidence::LegacyAcked,
            retired_in: "old-generation".into(),
            created_unix_ms: None,
        },
    );
    let saved = root.join("index.json");
    for pass in 0..2 {
        let paths = [held.clone(), healthy.clone()];
        let inv = no_open(&held, || inventory(&root, &paths, &mut index));
        assert!(inv.complete);
        assert_eq!(inv.headers.len(), 1);
        assert!(inv.headers.iter().all(|h| h.owner != PARENT));
        let mut scan = staged(&root, index, std::slice::from_ref(&healthy));
        scan.index
            .traversal
            .as_mut()
            .unwrap()
            .codex_rollout_paths
            .insert(local_index_key(&held));
        scan.index.known_configured_scan_roots = BTreeSet::from([local_index_key(&root)]);
        scan.codex_join_inventory = Some(inv);
        let (mut next, result) = no_open(&held, || run(scan));
        assert_eq!(result.unreadable_path_count, 0);
        assert!(result.census_complete, "stable census {pass}");
        assert_eq!(
            next.codex_counting_tombstones[&hidden_owner].evidence,
            AckEvidence::LegacyAcked
        );
        assert!(next.files[&local_index_key(&held)]
            .codex_compressed_hold
            .is_some());
        next.save(&saved).unwrap();
        index = ScanIndex::load(&saved).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

/// Historical money survives custody/replay; current archive credit still
/// requires the current attempt's exact body witness, never its old fingerprint.
/// [money] Exact ACK: held archive replay does not settle from a historical fingerprint alone.
#[test]
fn held_archive_replay_does_not_settle_from_historical_fingerprint_alone() {
    for current_body in [false, true] {
        let root = crate::test_scratch::private_dir("custody-current-archive-body");
        let path = member(&root, "sessions", OWNER, true);
        let key = local_index_key(&path);
        let mut index = accepted(&root, &path);
        let before = index.files[&key].clone();
        let fp = before.last_snapshot_fingerprint.as_ref().unwrap().clone();
        let witness = before.last_upload_body_witness.as_ref().unwrap().clone();
        let historical_ack = BTreeMap::from([(fp.clone(), witness.clone())]);
        seed_archive(&mut index, &path, OWNER);
        let seeded_attempts = 1;
        let archive = index.files.get_mut(&key).unwrap().archive.as_mut().unwrap();
        archive.disposition = ArchiveDisposition::Pending {
            attempts: seeded_attempts,
            retry_after: u64::MAX,
        };
        archive.body_witness =
            current_body.then(|| snapshot_file_upload_body_set_hex(BTreeSet::from([&witness])));
        index.hold_compressed(
            &path,
            BTreeSet::from([OWNER.into()]),
            CodexZstCause::FamilyUnproven,
        );
        assert!(index.prepare_historical_replay("held-archive-current-body".into()));
        let saved = root.join("index.json");
        for _ in 0..3 {
            let roots = [root.join("sessions")];
            ensure_bounded_traversal(
                SnapshotSource::Codex,
                &roots,
                &mut index,
                "2026-10-06T23:00:00Z",
                7,
            );
            let traversal = index.traversal.as_mut().unwrap();
            traversal.pending_directories.clear();
            traversal.pending_candidates.push_back(ScanTraversalPath {
                order_modified: None,
                scan_root: roots[0].clone(),
                path: path.clone(),
                census_member: true,
                watcher_hint: false,
            });
            traversal.codex_rollout_paths.insert(key.clone());
            let mut dirs = codex_file_join::DirectoryCensus::new();
            dirs.observe(&roots[0], &fs::metadata(&roots[0]).unwrap());
            traversal.codex_join_directory_census = Some(dirs);
            index.save(&saved).unwrap();
            let ((mut next, result), rows) = capture(|| {
                no_open(&path, || {
                    normal(&root, ScanIndex::load(&saved).unwrap(), &[])
                })
            });
            assert_no_red(&result, &rows);
            if let Some(traversal) = &next.traversal {
                assert!(!traversal.codex_rollout_paths.contains(&key));
                assert!(traversal.pending_candidates.iter().all(|p| p.path != path));
            }
            let gauges = rows
                .iter()
                .filter(|r| r["stage"] == "archive_quiet_pending_unacked")
                .collect::<Vec<_>>();
            assert_eq!(gauges.len(), 1, "one RAM gauge per completed page");
            assert_eq!(
                gauges[0]["counts"]["archive_quiet_pending_unacked_count"], 0,
                "excluded custody is not a quiet opened unacked attempt"
            );
            assert!(!next.files[&key].archive.as_ref().unwrap().reservation_saved);
            // Replay makes NO new decode: attempts stay at the seeded value.
            assert_eq!(
                next.files[&key].archive.as_ref().unwrap().decode_attempts,
                seeded_attempts
            );
            assert!(
                next.accepted_snapshot_fingerprints.contains(&fp),
                "retain historical money"
            );
            assert_eq!(
                next.files[&key].last_snapshot_fingerprint,
                before.last_snapshot_fingerprint
            );
            assert_eq!(
                next.files[&key].last_upload_body_witness,
                before.last_upload_body_witness
            );
            // Exercise the real settlement consumer with every historical ACK
            // present. Only its exact CURRENT body witness may accept the attempt.
            next.settle_archive_outcome(&historical_ack, true, Some(&historical_ack));
            let entry = &next.files[&key];
            assert_eq!(
                entry.codex_compressed_hold,
                Some(CodexZstCause::FamilyUnproven)
            );
            let archive = entry.archive.as_ref().unwrap();
            assert_eq!(
                matches!(archive.disposition, ArchiveDisposition::Acquired),
                current_body
            );
            if !current_body {
                assert!(matches!(
                    archive.disposition,
                    ArchiveDisposition::Pending { .. }
                ));
                assert!(archive.body_witness.is_none());
            }
            index = next;
        }
        fs::remove_dir_all(root).unwrap();
    }
}

/// [behaviour] A prior tombstone with an omitted archive keeps plain progress across clean census
/// and restart.
#[test]
fn prior_tombstone_omitted_archive_clean_census_restart_keeps_plain_progress() {
    use codex_counting_version::{AckEvidence, CountingTombstone};
    let root = crate::test_scratch::private_dir("activation-omitted-tombstone");
    let archive = member(&root, "sessions", OWNER, true);
    let plain = member(&root, "sessions", PARENT, false);
    let owner = codex_protected_owner(OWNER);
    let mut index = ScanIndex::default();
    index.codex_counting_tombstones.insert(
        owner.clone(),
        CountingTombstone {
            evidence: AckEvidence::LegacyAcked,
            retired_in: "prior-generation".into(),
            created_unix_ms: None,
        },
    );
    let saved = root.join("index.json");
    for _ in 0..2 {
        let sessions = root.join("sessions");
        let paths = BTreeSet::from([local_index_key(&archive), local_index_key(&plain)]);
        let mut dirs = codex_file_join::DirectoryCensus::new();
        dirs.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut inv = codex_file_join::HeaderInventory::new(&[sessions], &paths, Some(&dirs));
        while !inv.prepare_feed_custody(&index) {}
        assert!(inv.retain_cached_archives(&index, &paths).is_none());
        assert!(
            inv.first_read_archives.contains(&local_index_key(&archive)),
            "F3 omission is negative absence scope"
        );
        let mut scan = staged(&root, index, std::slice::from_ref(&plain));
        scan.index.traversal.as_mut().unwrap().codex_rollout_paths = paths;
        scan.index.known_configured_scan_roots = BTreeSet::from([local_index_key(&root)]);
        scan.codex_join_inventory = Some(inv);
        let ((mut next, result), rows) = capture(|| no_open(&archive, || run(scan)));
        assert_eq!(result.unreadable_path_count, 0);
        assert!(
            result.census_complete,
            "later clean census cannot certify archive absence"
        );
        assert!(result
            .snapshots
            .iter()
            .all(|body| body.source_session_id == PARENT));
        assert!(next.files[&local_index_key(&plain)]
            .last_snapshot_fingerprint
            .is_some());
        assert_eq!(
            next.codex_counting_tombstones[&owner].evidence,
            AckEvidence::LegacyAcked
        );
        assert!(!rows
            .iter()
            .any(|row| row["stage"] == "codex_zst_input" || row["stage"] == "codex_zst_inventory"));
        next.save(&saved).unwrap();
        index = ScanIndex::load(&saved).unwrap();
    }
    fs::remove_dir_all(root).unwrap();
}

/// [money] Departed-owner custody precedes the #926 F3 header lookup; plain still publishes.
#[test]
fn departed_owner_custody_precedes_f3_header_lookup_and_plain_still_publishes() {
    let root = crate::test_scratch::private_dir("activation-prefilter-custody");
    let archive = member(&root, "sessions", OWNER, true);
    let plain = member(&root, "sessions", PARENT, false);
    let mut index = ScanIndex::default();
    seed_archive(&mut index, &archive, OWNER);
    index.hold_compressed(
        &root.join("departed.jsonl"),
        BTreeSet::from([OWNER.into()]),
        CodexZstCause::ParentLedgerUnbound,
    );
    let sessions = root.join("sessions");
    let mut dirs = codex_file_join::DirectoryCensus::new();
    dirs.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let paths = BTreeSet::from([local_index_key(&archive), local_index_key(&plain)]);
    let mut inv = codex_file_join::HeaderInventory::new(&[sessions], &paths, Some(&dirs));
    let mut steps = 0;
    while !inv.prepare_feed_custody(&index) {
        steps += 1;
    }
    assert_eq!(steps, index.files.len(), "one retained entry per step");
    let (_, rows) = capture(|| inv.retain_cached_archives(&index, &paths));
    assert_eq!(
        rows.iter()
            .map(
                |row| row["counts"]["codex_zst_cached_inventory_metadata_checks"]
                    .as_u64()
                    .unwrap_or(0)
            )
            .sum::<u64>(),
        0,
        "held before cached stamp lookup"
    );
    assert!(inv.feed_member_held(&archive));
    let mut scan = staged(&root, index, &[archive.clone(), plain]);
    scan.codex_join_inventory = Some(inv);
    let ((index, result), _) = capture(|| no_open(&archive, || run(scan)));
    assert_eq!(result.unreadable_path_count, 0);
    assert!(result
        .snapshots
        .iter()
        .all(|body| body.source_session_id == PARENT));
    assert!(index.files[&local_index_key(&archive)]
        .codex_compressed_hold
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [format] A singleton saved by the old census schedules one first read on re-upgrade.
#[test]
fn historical_census_saved_singleton_schedules_a1_on_reupgrade() {
    let Some(root) = std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR").map(PathBuf::from) else {
        return; // The Linux historical-runtime driver supplies the saved census.
    };
    let key = fs::read_to_string(root.join("activation-key.txt")).unwrap();
    for label in ["stable", "r1"] {
        let index = ScanIndex::load(&root.join(format!("{label}-census.json"))).unwrap();
        assert!(!index.files.contains_key(&key));
        assert!(!index.file_snapshot_fingerprints.contains_key(&key));
        let sessions = root.join("activation/sessions");
        let mut scan = OwnedSourceScan::new(
            SnapshotSource::Codex,
            &[sessions],
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
        // A real activated discovery construction, with deterministic permission
        // denial rather than a dependency on the host's current power state.
        scan.index.archive_pass.power = false;
        for _ in 0..100 {
            if scan
                .identified_candidates
                .iter()
                .any(|candidate| local_index_key(&candidate.path) == key)
            {
                break;
            }
            scan = match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => next,
                OwnedSourceScanStep::Complete { .. } => panic!("archive must be scheduled"),
            };
        }
        let candidate = scan
            .identified_candidates
            .iter()
            .find(|candidate| local_index_key(&candidate.path) == key)
            .unwrap();
        assert_eq!(
            scan.index.candidate_decision(candidate),
            CandidateDecision::Parse
        );
        assert!(
            !scan.index.files.contains_key(&key),
            "new object: A1, no fabricated protection"
        );
        assert!(
            !scan.index.archive_pass.power,
            "scheduling alone grants no decode"
        );
    }
}

/// [money] A declined ordinary archive ACK replacement keeps custody and the accepted body.
#[test]
fn declined_ordinary_archive_ack_replacement_keeps_custody_and_accepted_body() {
    let root = crate::test_scratch::private_dir("activation-declined-archive-ack");
    let archive = member(&root, "sessions", OWNER, true);
    let key = local_index_key(&archive);
    let mut previous = accepted(&root, &archive);
    seed_archive(&mut previous, &archive, OWNER);
    previous.hold_compressed(
        &archive,
        BTreeSet::from([OWNER.into()]),
        CodexZstCause::ParentLedgerUnbound,
    );
    let before = previous.files[&key].clone();
    let incidence = previous.file_snapshot_fingerprints.clone();
    let mut working = previous.clone();
    let entry = working.files.get_mut(&key).unwrap();
    entry.source_file_fingerprint = "declined-source".into();
    entry.last_snapshot_fingerprint = Some("declined-entity".into());
    entry.last_upload_body_witness = Some("declined-body".into());
    let evidence = entry.archive.as_mut().unwrap();
    evidence.decode_attempts = 1;
    evidence.disposition = ArchiveDisposition::Pending {
        attempts: 1,
        retry_after: 0,
    };
    evidence.body_witness = Some(snapshot_file_upload_body_set_hex(BTreeSet::from([
        &"declined-body".to_owned(),
    ])));
    working
        .file_snapshot_fingerprints
        .insert(key.clone(), BTreeSet::from(["declined-entity".into()]));
    let submitted = BTreeMap::from([("declined-entity".into(), "declined-body".into())]);
    working.settle_archive_outcome(&BTreeMap::new(), false, Some(&submitted));
    let mut next = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
    assert_eq!(
        next.files[&key].source_file_fingerprint,
        before.source_file_fingerprint
    );
    assert_eq!(
        next.files[&key].last_snapshot_fingerprint,
        before.last_snapshot_fingerprint
    );
    assert_eq!(
        next.files[&key].last_upload_body_witness,
        before.last_upload_body_witness
    );
    assert_eq!(next.file_snapshot_fingerprints, incidence);
    assert!(!next
        .accepted_snapshot_fingerprints
        .contains("declined-entity"));
    assert_eq!(
        next.files[&key].codex_compressed_hold,
        Some(CodexZstCause::ParentLedgerUnbound)
    );
    assert!(matches!(
        next.files[&key].archive.as_ref().unwrap().disposition,
        ArchiveDisposition::Pending { .. }
    ));
    let saved = root.join("index.json");
    next.save(&saved).unwrap();
    let ((next, result), rows) = capture(|| {
        no_open(&archive, || {
            normal(&root, ScanIndex::load(&saved).unwrap(), &[])
        })
    });
    assert_no_red(&result, &rows);
    assert_eq!(next.file_snapshot_fingerprints, incidence);
    assert_eq!(
        next.files[&key].last_upload_body_witness,
        before.last_upload_body_witness
    );
    fs::remove_dir_all(root).unwrap();
}
