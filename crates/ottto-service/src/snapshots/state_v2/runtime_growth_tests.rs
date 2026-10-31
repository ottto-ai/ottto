//! Native custody fixtures. Execution belongs to CI; no production save bypass.
use super::*;
use crate::snapshots::{
    candidate_from_traversal_path_with_growth, local_index_key,
    open_and_identify_scan_candidate_at, sampled_audit, sampled_scan, CandidateFile, ScanCensus,
    ScanTraversalPath, SnapshotSource, LOCAL_SCAN_INDEX_IDENTITY_VERSION,
};
use crate::transcript_acquisition::{FullReason, ReadMode};
use std::sync::atomic::{AtomicU64, Ordering};

const NOW: u64 = 100_000;
const INTERVAL: u64 = 6 * 60 * 60;

struct Fixture {
    support: PathBuf,
    path: PathBuf,
    source: PathBuf,
    key: String,
}
impl Fixture {
    fn new() -> Self {
        Self::with_claims(BTreeMap::new())
    }
    fn with_claims(claims: BTreeMap<String, sampled_audit::GrowthRetention>) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let support = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-growth-lineage-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = support.join("snapshots/destinations").join("a".repeat(64));
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("claude_code-test-scan-index.json");
        let source = support.join("session.jsonl");
        fs::write(&source, b"old\nappend\n").unwrap();
        let key = local_index_key(&source);
        let mut index = ScanIndex::default();
        index.files.insert(
            key.clone(),
            serde_json::from_value(serde_json::json!({
                "size_bytes": 4, "modified_unix_seconds": 1,
                "source_file_fingerprint": "a".repeat(64),
                "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
            }))
            .unwrap(),
        );
        index.v2_mut().growth_retention = claims;
        index
            .v2_mut()
            .growth_retention
            .insert(key.clone(), debt(None));
        let identity = Identity {
            format: FORMAT,
            db_id: "synthetic-growth-lineage".into(),
            binding: binding(&path).unwrap(),
            fence_generation: 1,
        };
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&path, ".v2.sqlite.import")).unwrap();
        db.path_extractor(kinds::private_paths);
        db.reference_extractor(kinds::references);
        db.control("identity", &identity).unwrap();
        db.control("generation", &0_u64).unwrap();
        let mut cx = KindCx::default();
        cx.binding = Some(identity.binding.clone());
        let mut tx = db.begin(TxnMode::Write).unwrap();
        kinds::populate(&index, &mut tx, &mut cx).unwrap();
        assert_eq!(tx.commit(0, 1), DurableCommitOutcome::Committed(1));
        db.finish_import().unwrap();
        super::super::ack::ProgressRecovery::seal_import(identity.clone(), 1, &path, None).unwrap();
        fence::publish(&path, &identity, &mut false).unwrap();
        Self {
            support,
            path,
            source,
            key,
        }
    }
    fn load(&self) -> ScanIndex {
        ScanIndex::load(&self.path).unwrap()
    }
    fn candidate(&self, index: &ScanIndex) -> CandidateFile {
        let mut census = ScanCensus::default();
        let pending = ScanTraversalPath {
            scan_root: self.support.clone(),
            path: self.source.clone(),
            census_member: true,
            watcher_hint: false,
        };
        let candidate = candidate_from_traversal_path_with_growth(
            SnapshotSource::ClaudeCode,
            pending,
            &mut census,
            None,
            30,
            &index.files,
            Some(&index.v2().growth_retention),
        )
        .unwrap();
        open_and_identify_scan_candidate_at(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            None,
            30,
            &index.files,
            Some(&index.v2().growth_retention),
            sampled_scan::now_seconds(),
        )
        .unwrap()
        .0
    }
    /// Simulate a confirmed claim-only transaction independently of SAVE's
    /// still-gated production planner, then exercise the real receipt hook.
    fn commit_claim(&self, index: &mut ScanIndex, confirmed: bool) {
        index
            .v2_mut()
            .growth_retention
            .insert(self.key.clone(), debt(Some(NOW)));
        let runtime = index.v2().persistence_v2.as_ref().unwrap().clone();
        let mut guard = runtime.session.lock().unwrap();
        let session = guard.as_mut().unwrap();
        let mut tx = session.db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            key: &RowKey::record("file.growth_retention", self.key.as_bytes(), 1).unwrap(),
            fixed: &Fixed::None,
            value_version: 1,
            value: &PackedDebt(&index.v2().growth_retention[&self.key]),
        })
        .unwrap();
        let next = index.generation + 1;
        assert_eq!(
            tx.commit(index.generation, next),
            DurableCommitOutcome::Committed(next)
        );
        index.generation = next;
        if confirmed {
            session.stamp = session.db.stamp().unwrap();
        } else {
            session.reload = true;
        }
        drop(guard);
        with_state(&self.path, |state| {
            state.cached = Some(index.clone());
            Ok(())
        })
        .unwrap();
        let _lock = crate::snapshots::CheckpointLock::acquire(&self.path).unwrap();
        assert_eq!(
            sampled_audit::publish_growth_claim_receipt(index, &self.path).is_ok(),
            confirmed
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        super::super::money_test_support::erase_published(&self.path);
        let _ = fs::remove_dir_all(&self.support);
    }
}
fn debt(last: Option<u64>) -> sampled_audit::GrowthRetention {
    serde_json::from_value(serde_json::json!({
        "predecessor_size": 4, "last_growth_full_unix": last,
    }))
    .unwrap()
}
struct PackedDebt<'a>(&'a sampled_audit::GrowthRetention);
impl Value for PackedDebt<'_> {
    fn write(&self, out: &mut dyn Write) -> Result<()> {
        let mut encoder = codec::Encoder::new(out);
        serde_json::to_writer(&mut encoder, self.0)?;
        encoder.finish()?;
        Ok(())
    }
}
fn admitted(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    reason: FullReason,
    now: u64,
) -> bool {
    sampled_audit::growth_read_admitted_at(index, candidate, ReadMode::Full(reason), now)
}

/// [money] confirmed claim survives native reopen and clock rollback.
#[test]
fn confirmed_claim_survives_native_reopen_and_clock_rollback() {
    let f = Fixture::new();
    let mut committed = f.load();
    let original = committed.clone();
    let fence_before = fs::read(&f.path).unwrap();
    f.commit_claim(&mut committed, true);
    assert_eq!(
        sampled_audit::own_growth_claim_generation(&original, &f.path),
        Some(2)
    );
    assert_eq!(
        fs::read(&f.path).unwrap(),
        fence_before,
        "the root is constant"
    );
    invalidate_locked(&f.path).unwrap();
    let mut reopened = f.load();
    let candidate = f.candidate(&reopened);
    assert_eq!(
        serde_json::to_value(&reopened.v2().growth_retention[&f.key]).unwrap()
            ["last_growth_full_unix"],
        NOW
    );
    for now in [NOW - 1, NOW, NOW + INTERVAL - 1] {
        assert!(!admitted(
            &mut reopened,
            &candidate,
            FullReason::StateMissing,
            now
        ));
    }
    assert!(admitted(
        &mut reopened,
        &candidate,
        FullReason::Replaced,
        NOW + 1
    ));
}

/// [money] independent load cannot borrow claim generation even without working debt.
#[test]
fn independent_load_cannot_borrow_claim_generation_even_without_working_debt() {
    let f = Fixture::new();
    let mut owner = f.load();
    let mut stale = f.load();
    let candidate = f.candidate(&stale);
    f.commit_claim(&mut owner, true);
    assert_eq!(
        sampled_audit::own_growth_claim_generation(&stale, &f.path),
        None
    );
    assert!(crate::snapshots::state_v2_side_effect_guard(&f.path, &stale)().is_err());
    stale.v2_mut().growth_retention.clear();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        for reason in [FullReason::StateMissing, FullReason::Replaced] {
            assert!(!admitted(&mut stale, &candidate, reason, NOW + INTERVAL));
        }
    });
    assert!(rows
        .iter()
        .any(|row| row["counts"]["latest"]["growth_claim_refused"] == "lineage"));
}

/// [money] reopened owner and other path cannot reuse foreign claim context.
#[test]
fn reopened_owner_and_other_path_cannot_reuse_foreign_claim_context() {
    let f = Fixture::new();
    let mut old = f.load();
    f.commit_claim(&mut old, true);
    let context = old.v2().growth_claim_context.clone();
    invalidate_locked(&f.path).unwrap();
    let mut reopened = f.load();
    let candidate = f.candidate(&reopened);
    reopened.v2_mut().growth_claim_context = context.clone();
    assert!(!admitted(
        &mut reopened,
        &candidate,
        FullReason::Replaced,
        NOW + INTERVAL
    ));
    let other = Fixture::new();
    let mut foreign = other.load();
    foreign.v2_mut().growth_claim_context = context;
    let candidate = other.candidate(&foreign);
    assert!(!admitted(
        &mut foreign,
        &candidate,
        FullReason::StateMissing,
        NOW + INTERVAL
    ));
}

/// [money] unconfirmed commit cannot publish receipt or admit full.
#[test]
fn unconfirmed_commit_cannot_publish_receipt_or_admit_full() {
    let f = Fixture::new();
    let mut index = f.load();
    let mut original = index.clone();
    let candidate = f.candidate(&original);
    f.commit_claim(&mut index, false);
    assert_eq!(
        sampled_audit::own_growth_claim_generation(&original, &f.path),
        None
    );
    assert!(!admitted(
        &mut original,
        &candidate,
        FullReason::Replaced,
        NOW + INTERVAL
    ));
}

/// [money] same generation db replacement cannot borrow constant fence.
#[test]
fn same_generation_db_replacement_cannot_borrow_constant_fence() {
    let f = Fixture::new();
    let mut owner = f.load();
    let mut original = owner.clone();
    let candidate = f.candidate(&original);
    f.commit_claim(&mut owner, true);
    let db = fence::sibling(&f.path, ".v2.sqlite");
    let replacement = f.support.join("replacement.sqlite");
    fs::copy(&db, &replacement).unwrap();
    fs::rename(&replacement, &db).unwrap();
    assert_eq!(
        sampled_audit::own_growth_claim_generation(&original, &f.path),
        None
    );
    assert!(!admitted(
        &mut original,
        &candidate,
        FullReason::Replaced,
        NOW + INTERVAL
    ));
}

/// [money] real claim save authenticates old clone and ordinary save ends its authority.
#[test]
fn real_claim_save_authenticates_old_clone_and_ordinary_save_ends_its_authority() {
    let f = Fixture::new();
    let mut claim = f.load();
    let mut old = claim.clone();
    let context = claim.v2().growth_claim_context.clone().unwrap();
    claim
        .v2_mut()
        .growth_retention
        .insert(f.key.clone(), debt(Some(NOW)));
    claim.save_growth_claim(&f.path).unwrap();
    assert!(Arc::ptr_eq(
        claim.v2().growth_claim_context.as_ref().unwrap(),
        &context
    ));
    {
        let _lock = crate::snapshots::CheckpointLock::acquire(&f.path).unwrap();
        sampled_audit::publish_growth_claim_receipt(&claim, &f.path).unwrap();
    }
    assert_eq!(
        sampled_audit::own_growth_claim_generation(&old, &f.path),
        Some(claim.generation)
    );
    let guard = crate::snapshots::state_v2_side_effect_guard(&f.path, &old);
    guard().unwrap();
    let receipt = super::super::ack::ProgressRecovery::for_index(&old, &f.path).unwrap();
    assert!(receipt.is_some());
    old.upload_context_fingerprint = Some("synthetic-next-context".into());
    old.save(&f.path).unwrap();
    assert!(
        guard().is_err(),
        "an ordinary save ends this claim's authority"
    );
    assert!(!Arc::ptr_eq(
        old.v2().growth_claim_context.as_ref().unwrap(),
        &context
    ));
    assert_eq!(
        sampled_audit::own_growth_claim_generation(&claim, &f.path),
        None
    );
    let reopened = f.load();
    assert_eq!(
        reopened.upload_context_fingerprint,
        old.upload_context_fingerprint
    );
    assert_eq!(
        serde_json::to_value(&reopened.v2().growth_retention[&f.key]).unwrap()
            ["last_growth_full_unix"],
        serde_json::json!(NOW)
    );
}

/// [regress] v2 CAS resurrected expired absent-file claims on normal and claim saves.
#[test]
fn saves_reclaim_expired_orphan_claims_after_merging_maxima() {
    let now = crate::snapshots::sampled_scan::now_seconds();
    for route in ["normal", "claim", "subset"] {
        let expired = "/synthetic/expired.jsonl";
        let recent = "/synthetic/recent.jsonl";
        let future = "/synthetic/future.jsonl";
        let f = Fixture::with_claims(BTreeMap::from([
            (expired.into(), debt(Some(now - INTERVAL - 1))),
            (recent.into(), debt(Some(now - 1))),
            (future.into(), debt(Some(now + INTERVAL))),
        ]));
        let previous = f.load();
        let mut working = previous.clone();
        working.v2_mut().growth_retention.remove(expired);
        if route == "subset" {
            working =
                working.committable_subset(&previous, &Default::default(), &Default::default());
        }
        let (_, rows) = crate::local_resource_diagnostics::capture(|| {
            if route == "claim" {
                working.save_growth_claim(&f.path).unwrap();
            } else {
                working.save(&f.path).unwrap();
            }
        });
        assert!(rows
            .iter()
            .any(|row| row["counts"]["growth_claim_reclaimed"] == 1));
        invalidate_locked(&f.path).unwrap();
        let reopened = f.load();
        assert!(
            !reopened.v2().growth_retention.contains_key(expired),
            "{route}"
        );
        for key in [&f.key, recent, future] {
            assert!(
                reopened.v2().growth_retention.contains_key(key),
                "{route}: {key}"
            );
        }
        let mut guard = reopened
            .v2()
            .persistence_v2
            .as_ref()
            .unwrap()
            .session
            .lock()
            .unwrap();
        let db = &mut guard.as_mut().unwrap().db;
        assert!(
            db.read_control::<u64>("erasure_pending")
                .unwrap()
                .unwrap_or(0)
                > 0
        );
    }
}

/// [regress] claim-only saves undid page halving and page-one oversize retries stormed.
#[test]
fn claims_preserve_page_reduction_and_oversize_retries_are_paced() {
    let f = Fixture::new();
    let mut index = f.load();
    assert_eq!(collection_page_limit(&index, 250), 250);
    super::tests::with_session_db(&index, |db| sqlite::set_save_ceiling(db, 0));
    assert!(index.save(&f.path).is_err());
    let mut index = f.load();
    assert_eq!(collection_page_limit(&index, 250), 125);
    index.save_growth_claim(&f.path).unwrap();
    assert_eq!(collection_page_limit(&index, 250), 125);
    assert!(crate::snapshots::state_v2_side_effect_guard(&f.path, &index)().is_err());

    // Simulate successive ceiling reductions reaching a page of one.
    with_state(&f.path, |state| {
        state.page_limit = 1;
        Ok(())
    })
    .unwrap();
    assert!(save_read_admitted(&index, &f.key, NOW).unwrap());
    super::tests::with_session_db(&index, |db| sqlite::set_save_ceiling(db, 0));
    assert!(index.save(&f.path).is_err());
    let mut index = f.load();
    assert!(save_oversize_active(&index).unwrap());
    for now in [NOW - 1, NOW, NOW + INTERVAL - 1] {
        assert!(!save_read_admitted(&index, &f.key, now).unwrap());
    }
    assert!(!save_read_admitted(&index, "/synthetic/other.jsonl", NOW + INTERVAL).unwrap());
    let candidate = f.candidate(&index);
    assert!(save_read_admitted(&index, &f.key, NOW + INTERVAL).unwrap());
    assert!(sampled_audit::growth_read_admitted_at(
        &mut index,
        &candidate,
        ReadMode::Tail,
        NOW + INTERVAL
    ));
    assert_eq!(collection_page_limit(&index, 250), 1);
    assert!(
        save_oversize_active(&index).unwrap(),
        "the claim does not lift the fence"
    );
    // A cursor-only save after a skipped read cannot resolve the held file.
    index.save(&f.path).unwrap();
    invalidate_locked(&f.path).unwrap();
    let mut reopened = f.load();
    assert!(save_oversize_active(&reopened).unwrap());
    assert!(!save_read_admitted(&reopened, &f.key, NOW + INTERVAL + 1).unwrap());
    assert!(!sampled_audit::growth_read_admitted_at(
        &mut reopened,
        &candidate,
        ReadMode::Full(FullReason::StateMissing),
        NOW + INTERVAL + 1
    ));
    assert!(crate::snapshots::state_v2_side_effect_guard(&f.path, &reopened)().is_err());
    // A complete retry may have unACKed bodies: its recovery subset keeps the
    // old file entry, but a successful local save must allow the next upload.
    assert!(save_read_admitted(&reopened, &f.key, NOW + 2 * INTERVAL).unwrap());
    assert!(sampled_audit::growth_read_admitted_at(
        &mut reopened,
        &candidate,
        ReadMode::Tail,
        NOW + 2 * INTERVAL
    ));
    sampled_audit::settle_growth(&mut reopened, &f.key);
    let previous = f.load();
    let entry = reopened.files.get_mut(&f.key).unwrap();
    entry.size_bytes = 999;
    entry.source_file_fingerprint = "b".repeat(64);
    entry.last_snapshot_fingerprint = Some("d".repeat(64));
    let mut subset =
        reopened.committable_subset(&previous, &Default::default(), &Default::default());
    assert_eq!(
        subset.files[&f.key].size_bytes, 4,
        "unACKed progress stays owed"
    );
    subset.save(&f.path).unwrap();
    assert_eq!(
        subset.files[&f.key].size_bytes,
        previous.files[&f.key].size_bytes
    );
    crate::snapshots::state_v2_side_effect_guard(&f.path, &subset)().unwrap();
}

/// [regress] grown and undiscovered keys kept old Exact proof after lossy/failed parses.
#[test]
fn growth_never_suppresses_lossy_records_or_failed_validation() {
    use crate::snapshots::claude_request_census::{
        self, ClaudeRequestBirth, ClaudeRequestCensusParse, ClaudeRequestCensusRecord,
        ClaudeRequestCensusShape,
    };
    for case in [
        "lossy",
        "lossy_at_cap",
        "incomplete",
        "no_record",
        "invalidate",
        "nongrown_in_range",
    ] {
        let f = Fixture::new();
        let mut index = f.load();
        let fingerprint = "a".repeat(64);
        let record = ClaudeRequestCensusRecord::synthetic_for_test(
            &fingerprint,
            1,
            ClaudeRequestCensusShape::Exact,
            vec![7],
        )
        .with_modified_for_test(Some(1))
        .with_birth_for_test(Some(ClaudeRequestBirth {
            unix_seconds: 1,
            device: 1,
            inode: 1,
        }));
        index.claude_request_census.insert_for_test(&f.key, record);
        if case == "lossy_at_cap" {
            let cap =
                crate::snapshots::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64;
            index.claude_request_census.insert_for_test(
                "/synthetic/young.jsonl",
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &fingerprint,
                    1,
                    ClaudeRequestCensusShape::Exact,
                    (100..cap + 99).collect(),
                )
                .with_modified_for_test(Some(u64::MAX)),
            );
        }
        crate::snapshots::ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&f.support),
            &mut index,
            "2026-10-07T12:00:00Z",
            30,
        );
        if case == "nongrown_in_range" {
            index.v2_mut().growth_retention.clear();
        }
        if case == "invalidate" {
            let mut candidate = f.candidate(&index);
            candidate.physical_identity = Some([2, 2]);
            assert!(!claude_request_census::retain_held(&mut index, &candidate));
        } else {
            claude_request_census::record_claude_request_census(
                &mut index,
                ClaudeRequestCensusParse {
                    path: &f.source,
                    index_key: &f.key,
                    source_file_fingerprint: if case == "no_record" {
                        "invalid"
                    } else {
                        &fingerprint
                    },
                    census_window_end: "2026-10-07T12:00:00Z",
                    complete: case != "incomplete",
                    lossy: case != "no_record",
                    source_verified: true,
                    unchanged_source: false,
                    itemless_request_hashes: vec![8, 9],
                    opened_birth: None,
                    modified_unix_seconds: 1,
                },
                &[],
            );
        }
        let record = index.claude_request_census.record_for_test(&f.key).unwrap();
        assert!(!record.request_hashes_for_test().contains(&7), "{case}");
        if matches!(case, "no_record" | "invalidate") {
            assert!(record.is_birth_stub(), "{case}");
        } else if case != "lossy_at_cap" {
            assert_eq!(
                record.shape_for_test(),
                ClaudeRequestCensusShape::Lossy,
                "{case}"
            );
        }
        let holders = index
            .claude_request_census
            .family_transcript_holders(
                &BTreeMap::from([("session", vec![7])]),
                Instant::now() + Duration::from_secs(10),
            )
            .unwrap();
        assert!(
            holders
                .get("session")
                .map_or(true, |family| family.held.is_empty()),
            "{case}"
        );
    }
}

/// [regress] excluded grown stock evicted overlapping #920 proofs at the soft cap.
#[test]
fn excluded_growth_stock_does_not_evict_overlapping_proofs() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusRecord, ClaudeRequestCensusShape, MAX_CLAUDE_REQUEST_CENSUS_HASHES,
    };
    for prechecked in [true, false] {
        let f = Fixture::new();
        let mut index = f.load();
        if !prechecked {
            index.v2_mut().growth_retention.clear();
        }
        let overlap = crate::snapshots::local_index_key(&f.support.join("overlap.jsonl"));
        let copy = crate::snapshots::local_index_key(&f.support.join("copy.jsonl"));
        let nongrown = crate::snapshots::local_index_key(&f.support.join("nongrown.jsonl"));
        let residue = crate::snapshots::local_index_key(&f.support.join("residue.jsonl"));
        for key in [&overlap, &copy, &nongrown, &residue] {
            fs::write(key, b"old\n").unwrap();
        }
        let cap = MAX_CLAUDE_REQUEST_CENSUS_HASHES as u64;
        for (key, age, hashes) in [
            (f.key.clone(), 1, (0..cap / 10).collect()),
            (overlap.clone(), 1, (cap / 10..cap / 5).collect()),
            (
                copy.clone(),
                40 * 86400,
                (cap / 10..cap * 85 / 100).collect(),
            ),
            (nongrown.clone(), 1, vec![cap + 1]),
            (residue.clone(), 1, vec![cap + 2]),
        ] {
            let entry = index.files[&f.key].clone();
            index.files.insert(key.clone(), entry);
            index.claude_request_census.insert_for_test(
                &key,
                ClaudeRequestCensusRecord::synthetic_for_test(
                    &"a".repeat(64),
                    1,
                    ClaudeRequestCensusShape::Exact,
                    hashes,
                )
                .with_modified_for_test(Some(age)),
            );
        }
        crate::snapshots::ensure_bounded_traversal(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&f.support),
            &mut index,
            "2026-10-07T12:00:00Z",
            30,
        );
        let walk = index.traversal.as_mut().unwrap();
        walk.reconciliation_upper_bound = Some("z".into());
        walk.reconciliation_after = None;
        walk.residue.index_keys.insert(residue.clone());
        let (aged, kept, _, overflow) = index.retire_claude_transcript_records_for_test(40 * 86400);
        assert_eq!(
            aged, 2,
            "neither an unchecked range nor untracked residue is growth debt"
        );
        assert_eq!(kept, 1);
        assert_eq!(overflow, 0);
        assert_eq!(
            index
                .claude_request_census
                .get(&overlap)
                .unwrap()
                .retired_for_test(),
            None
        );
        assert_eq!(
            index
                .claude_request_census
                .get(&f.key)
                .unwrap()
                .retired_for_test(),
            None
        );
        sampled_audit::settle_growth(&mut index, &f.key);
        assert_eq!(
            index
                .retire_claude_transcript_records_for_test(40 * 86400)
                .0,
            1
        );
        assert_eq!(
            index.claude_request_census.totals_for_test(),
            index.claude_request_census.recounted_for_test()
        );
    }
}
