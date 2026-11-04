//! Carry-specific transaction cases use the existing native route fixture.
use super::super::tail_route::{carry_tail, pending_carries};
use super::*;
use crate::snapshots::{sampled_audit, ScanResidueWitness};

const MOVED: &str = "/synthetic/tail/file.jsonl.zst";
fn facts() -> InventoryFacts {
    InventoryFacts {
        owner: "session".into(),
        created_unix_ms: Some(123),
        read_bytes: 0,
        stamp: crate::snapshots::sampled_scan::codex_cursor::ContentStamp::from_parts(
            1,
            2,
            3,
            (4, 5),
        ),
    }
}
fn pair(f: &Fixture, index: &mut ScanIndex) {
    carry_tail(
        &f.path,
        MOVED,
        tail::PathCarry {
            from: FILE.into(),
            scan_root: PathBuf::from("/synthetic/tail"),
            head: b"rebound".to_vec(),
            inventory: facts(),
        },
    )
    .unwrap();
    let entry = index.files.remove(FILE).unwrap();
    index.files.insert_shared(MOVED.into(), entry);
    let entities = index.file_snapshot_fingerprints.remove(FILE).unwrap();
    index
        .file_snapshot_fingerprints
        .insert_shared(MOVED.into(), entities);
    let incidence = index.accepted_rebuild_incidence.remove(FILE).unwrap();
    index
        .accepted_rebuild_incidence
        .insert(MOVED.into(), incidence);
    let growth = index.v2_mut().growth_retention.remove(FILE).unwrap();
    index.v2_mut().growth_retention.insert(MOVED.into(), growth);
    index.confirmed_empty_files.remove(FILE);
    index.confirmed_empty_files.insert(MOVED.into());
    index.held_audit_progress.as_mut().unwrap().key = MOVED.into();
    index.scan_residue_witness.as_mut().unwrap().index_keys = BTreeSet::from([MOVED.into()]);
}
fn seed(f: &Fixture) -> ScanIndex {
    f.published();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let mut entry = progress_row();
    entry.last_snapshot_fingerprint = Some("e".repeat(64));
    entry.last_upload_body_witness = Some("f".repeat(64));
    entry.evidence_owed = true;
    index.files.insert(FILE.into(), entry);
    index
        .file_snapshot_fingerprints
        .insert(FILE.into(), BTreeSet::from(["e".repeat(64)]));
    index
        .accepted_rebuild_incidence
        .insert(FILE.into(), BTreeSet::from(["d".repeat(64)]));
    index.confirmed_empty_files.insert(FILE.into());
    index.v2_mut().growth_retention.insert(
        FILE.into(),
        serde_json::from_value(serde_json::json!({
            "predecessor_size": 2, "uncertain_passes": 3, "checked_generation": 5,
            "last_growth_full_unix": crate::snapshots::sampled_scan::now_seconds()
        }))
        .unwrap(),
    );
    index.held_audit_progress = Some(sampled_audit::HeldAuditProgress {
        key: FILE.into(),
        due: 11,
        attempted: true,
    });
    index.scan_residue_witness = Some(ScanResidueWitness {
        index_keys: BTreeSet::from([FILE.into()]),
        ..Default::default()
    });
    stage_tail(
        &f.path,
        FILE,
        staged(b"old", &[(Collection::Responses, 0, &long_value())]),
    )
    .unwrap();
    observe_tail(&f.path, FILE, observation(&[b"unaccepted revision"])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    set_aside_tail(&f.path, FILE, SetAsideCause::Encode).unwrap();
    save_with(&f.path, &mut index).unwrap();
    index
}
fn assert_pair(index: &ScanIndex, moved: bool) {
    let (live, absent) = if moved { (MOVED, FILE) } else { (FILE, MOVED) };
    assert!(index.files.contains_key(live));
    assert!(!index.files.contains_key(absent));
    let entry = &index.files[live];
    assert_eq!(
        entry.last_snapshot_fingerprint.as_deref(),
        Some("e".repeat(64).as_str())
    );
    assert_eq!(
        entry.last_upload_body_witness.as_deref(),
        Some("f".repeat(64).as_str())
    );
    assert!(entry.evidence_owed);
    assert!(index.confirmed_empty_files.contains(live));
    assert!(!index.confirmed_empty_files.contains(absent));
    assert!(index.v2().growth_retention.contains_key(live));
    assert!(!index.v2().growth_retention.contains_key(absent));
    assert_eq!(
        index.v2().growth_retention[live].checked_generation,
        Some(5)
    );
    assert!(index.accepted_rebuild_incidence.contains_key(live));
    assert!(!index.accepted_rebuild_incidence.contains_key(absent));
    assert_eq!(index.held_audit_progress.as_ref().unwrap().key, live);
    assert_eq!(index.held_audit_progress.as_ref().unwrap().due, 11);
    assert_eq!(
        index.scan_residue_witness.as_ref().unwrap().index_keys,
        BTreeSet::from([live.into()])
    );
    assert!(load_head(index, absent, REVISION).unwrap().is_none());
    let (head, pages) = read(index, live).unwrap();
    let head = head.unwrap();
    assert_eq!(head.body, if moved { &b"rebound"[..] } else { &b"old"[..] });
    assert_eq!(head.common.debt.earliest_unacked_change_at, Some(7_000));
    assert_eq!(head.common.next_revision_id, 1);
    assert_eq!(pages[&(Collection::Responses, 0)], long_value());
    assert_eq!(
        revisions(index, live),
        BTreeMap::from([(0, b"unaccepted revision".to_vec())])
    );
    assert!(tail_set_aside(index, live).unwrap().is_some());
    assert!(tail_set_aside(index, absent).unwrap().is_none());
    if moved {
        assert_eq!(head.common.inventory, Some(facts()));
    }
}

/// [regress] Graph rows, alias rows, fragmented pages, revisions and the
/// set-aside marker move together without manufacturing acceptance or debt age.
#[test]
fn paired_carry_moves_every_store_owner_once() {
    let f = Fixture::new();
    let mut index = seed(&f);
    pair(&f, &mut index);
    // The working graph reads its old pages through the pending alias.
    assert_eq!(read(&index, MOVED).unwrap().0.unwrap().body, b"rebound");
    save_with(&f.path, &mut index).unwrap();
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert_pair(&index, true);
    assert!(pending_carries(&index).unwrap().is_empty());
    assert_eq!(frag_rows(&index), 2, "no orphaned predecessor fragments");
    assert!(rows(&index, "file.progress", FILE).is_empty());
    assert!(rows(&index, "file.entities", FILE).is_empty());
}

/// [regress] A refused row after both graph keys and the Tail move rolls the
/// entire pair back; an unrelated file still commits, then RAM must reload.
#[test]
fn paired_row_refusal_restores_predecessor_and_aliases_before_finish() {
    let f = Fixture::new();
    let mut index = seed(&f);
    pair(&f, &mut index);
    stage_tail(
        &f.path,
        MOVED,
        staged(
            b"bad",
            &[(Collection::Responses, i64::MAX as u64 + 1, b"refused")],
        ),
    )
    .unwrap();
    index.files.insert(SIBLING.into(), progress_row());
    index
        .accepted_rebuild_incidence
        .insert(SIBLING.into(), BTreeSet::from(["c".repeat(64)]));
    stage_tail(&f.path, SIBLING, staged(b"sibling", &[])).unwrap();
    let error = save_with(&f.path, &mut index).unwrap_err();
    assert_eq!(error.downcast_ref::<Hold>(), Some(&Hold::ReloadRequired));
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert_pair(&index, false);
    assert!(index.files.contains_key(SIBLING));
    assert_eq!(
        index.accepted_rebuild_incidence.len(),
        2,
        "manifest counts the rows that actually committed"
    );
    assert!(index.accepted_rebuild_incidence.contains_key(SIBLING));
    assert!(read(&index, SIBLING).unwrap().0.is_some());
    assert!(stage_empty(&f.path), "COMMIT published the rollback result");
}

/// [regress] Before-COMMIT failure exposes the old pair. A confirmed COMMIT
/// followed by failed digest promotion exposes the complete new pair.
#[test]
fn paired_carry_commit_outcomes_are_complete_old_or_complete_new() {
    for published in [false, true] {
        let f = Fixture::new();
        let mut index = seed(&f);
        pair(&f, &mut index);
        if published {
            kinds::FAIL_DIGEST_PROMOTION.with(|fail| fail.set(true));
        } else {
            with_session_db(&index, |db| sqlite::fence_commit_writing(db, "generation"));
        }
        assert!(save_with(&f.path, &mut index).is_err());
        drop(BaselineRelease::new(&f.path, &index));
        let index = load_with(&f.path, false).unwrap().unwrap();
        assert_pair(&index, published);
    }
}

/// [regress] A Tail-only exit and a claim-only save cannot publish the Tail or
/// graph half of a move. The normal graph save remains the one publication.
#[test]
fn graph_free_exit_and_claim_save_refuse_a_pending_pair() {
    let f = Fixture::new();
    let mut index = seed(&f);
    pair(&f, &mut index);
    let release = BaselineRelease::new(&f.path, &index);
    assert!(release.commit_tail().is_err());
    assert!(!stage_empty(&f.path));
    assert!(save_with_mode(&f.path, &mut index, true, None).is_err());
    drop(release);
    let index = load_with(&f.path, false).unwrap().unwrap();
    assert_pair(&index, false);
}

/// [regress] Exercise the real compression proof and baseline alignment. A
/// held/partial restoration uses the moved committed entry, not the working
/// entry's newer state, and a fresh plaintext inode never earns carry.
#[test]
fn compression_carries_without_read_and_held_baseline_keeps_its_revision() {
    use crate::snapshots::{
        codex_protected_owner, local_index_key, tail_source, CandidateFile, ScanTraversalCheckpoint,
    };
    let f = Fixture::new();
    f.published();
    let root = f.support.join("codex-home/sessions");
    fs::create_dir_all(&root).unwrap();
    let plain = root.join("rollout-session.jsonl");
    let compressed = root.join("rollout-session.jsonl.zst");
    fs::write(&plain, b"synthetic original body").unwrap();
    let old_metadata = fs::metadata(&plain).unwrap();
    let from = local_index_key(&plain);
    let to = local_index_key(&compressed);
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    let mut entry = progress_row();
    entry.codex_counting_owner = Some(codex_protected_owner("session").into_boxed_str());
    index.files.insert(from.clone(), entry);
    index
        .file_snapshot_fingerprints
        .insert(from.clone(), BTreeSet::from(["e".repeat(64)]));
    index.traversal = Some(serde_json::from_value::<ScanTraversalCheckpoint>(serde_json::json!({
        "context_fingerprint": "fixture", "census_window_end": "2026-01-01T00:00:00Z",
        "scan_roots": [root], "pending_directories": [],
        "pending_candidates": [{"scan_root": root, "path": plain, "census_member": true, "watcher_hint": true}],
        "observed_index_keys": [], "codex_rollout_paths": [from],
        "reconciliation_started": false, "counts": {}, "residue": {}
    })).unwrap());
    let body = tail_source::carry_head_for_test(&f.path, &root, &plain, &old_metadata);
    stage_tail(
        &f.path,
        &from,
        staged(&body, &[(Collection::Responses, 0, b"unchanged page")]),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    let mut baseline = index.clone();
    // Deliberately invalid zstd: a carry must not open a decoder or header.
    fs::write(&compressed, b"not a zstd frame").unwrap();
    let metadata = fs::metadata(&compressed).unwrap();
    let candidate = CandidateFile {
        physical_identity: Some([metadata.dev(), metadata.ino()]),
        scan_root: root.clone(),
        path: compressed.clone(),
        size_bytes: metadata.len(),
        modified_unix_seconds: 0,
        modified_unix_nanos: 0,
        source_file_fingerprint: String::new(),
        legacy_source_file_fingerprint: String::new(),
        legacy_config_reconciliation_required: false,
        opened_object_identity: String::new(),
        fingerprint_changed_nanos: 0,
        fingerprint_birth_nanos: 0,
        withheld_content_stamp: None,
    };
    assert!(
        !index
            .carry_codex_rollout(&f.path, &candidate, None)
            .unwrap(),
        "plain wins"
    );
    let parked_plain = root.join("original-object");
    fs::rename(&plain, &parked_plain).unwrap();
    crate::snapshots::START_IDENTITY_SAMPLE_FOR_TEST.with(|samples| samples.set((0, 0)));
    assert!(index
        .carry_codex_rollout(&f.path, &candidate, None)
        .unwrap());
    assert_eq!(
        crate::snapshots::START_IDENTITY_SAMPLE_FOR_TEST.with(|samples| samples.get()),
        (0, 0)
    );
    assert_eq!(
        index.codex_physical_matches(&to, &metadata).unwrap(),
        Some(true)
    );
    assert_eq!(
        index.files[&to].size_bytes, baseline.files[&from].size_bytes,
        "decoded extent unchanged"
    );
    index.files.get_mut(&to).unwrap().size_bytes = 999;
    baseline.rehome_codex_carry_baseline(&index).unwrap();
    assert!(!baseline.files.contains_key(&from));
    assert_eq!(
        baseline.files[&to].size_bytes, 4,
        "held restoration retains committed progress"
    );
    let pending = &baseline.traversal.as_ref().unwrap().pending_candidates[0];
    assert_eq!(pending.path, compressed);
    assert!(pending.census_member && pending.watcher_hint);
    // Save the aligned partial/held baseline through the same paired operation.
    save_with(&f.path, &mut baseline).unwrap();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    fs::remove_file(&compressed).unwrap();
    fs::write(&plain, b"synthetic original body").unwrap();
    let mut materialized = candidate.clone();
    materialized.path = plain.clone();
    assert!(
        !index
            .carry_codex_rollout(&f.path, &materialized, None)
            .unwrap(),
        "new inode is ordinary Replaced"
    );
    assert!(index.files.contains_key(&to));
    fs::remove_file(&plain).unwrap();
    fs::rename(&parked_plain, &plain).unwrap();
    // The original object still has its exact old certificate. Carry it back
    // without inventing equivalence for the new inode refused above.
    assert!(index
        .carry_codex_rollout(&f.path, &materialized, None)
        .unwrap());
    let original_head = load_head(&index, &from, REVISION).unwrap().unwrap();
    assert!(tail_source::certified_physical_matches(
        &original_head.body,
        &fs::metadata(&plain).unwrap()
    ));
    save_with(&f.path, &mut index).unwrap();
    assert!(!index.files.contains_key(&to));
    assert!(index.files.contains_key(&from));
}

/// [regress] A current header does not prove that a saved reduction applied a
/// later append. Ordinary checkpoint completion then makes equality true even
/// before the next header pass refreshes the older inventory facts.
#[test]
fn refreshed_header_never_certifies_unapplied_growth() {
    use crate::snapshots::{codex_rollout_carry, local_index_key, tail_source};
    let f = Fixture::new();
    f.published();
    let root = f.support.join("header-home/sessions");
    fs::create_dir_all(&root).unwrap();
    let path = root.join("rollout-session.jsonl");
    fs::write(&path, b"prefix").unwrap();
    let key = local_index_key(&path);
    let before = fs::metadata(&path).unwrap();
    let before_stamp =
        crate::snapshots::sampled_scan::codex_cursor::OpenStamp::of(&before).content_stamp();
    let mut index = load_with(&f.path, false).unwrap().unwrap();
    index.files.insert(key.clone(), progress_row());
    stage_tail(
        &f.path,
        &key,
        staged(
            &tail_source::carry_head_for_test(&f.path, &root, &path, &before),
            &[],
        ),
    )
    .unwrap();
    observe_tail(&f.path, &key, observation(&[b"owed"])).unwrap();
    save_with(&f.path, &mut index).unwrap();
    let header_facts = |stamp| InventoryFacts {
        owner: "session".into(),
        created_unix_ms: Some(123),
        stamp,
        read_bytes: 6,
    };
    codex_rollout_carry::observe_codex_inventory(&index, &key, header_facts(before_stamp)).unwrap();
    // A later G7 observation with no inventory must keep the header facts.
    let common = load_head(&index, &key, REVISION).unwrap().unwrap().common;
    observe_tail(
        &f.path,
        &key,
        Observation {
            summary: common.debt,
            ..Default::default()
        },
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(
        load_head(&index, &key, REVISION)
            .unwrap()
            .unwrap()
            .common
            .inventory,
        Some(header_facts(before_stamp))
    );
    fs::write(&path, b"prefix plus append").unwrap();
    let after = fs::metadata(&path).unwrap();
    let after_stamp =
        crate::snapshots::sampled_scan::codex_cursor::OpenStamp::of(&after).content_stamp();
    codex_rollout_carry::observe_codex_inventory(&index, &key, header_facts(after_stamp)).unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(
        index.codex_physical_matches(&key, &after).unwrap(),
        Some(false),
        "header alone grants no applied-byte credit"
    );
    let head = load_head(&index, &key, REVISION).unwrap().unwrap();
    assert_eq!(head.common.inventory.unwrap().stamp, before_stamp);
    assert_eq!(head.common.debt.earliest_unacked_change_at, Some(7_000));
    stage_tail(
        &f.path,
        &key,
        staged(
            &tail_source::carry_head_for_test(&f.path, &root, &path, &after),
            &[],
        ),
    )
    .unwrap();
    save_with(&f.path, &mut index).unwrap();
    assert_eq!(
        index.codex_physical_matches(&key, &after).unwrap(),
        Some(true)
    );
    assert_eq!(
        revisions(&index, &key),
        BTreeMap::from([(0, b"owed".to_vec())])
    );
}
