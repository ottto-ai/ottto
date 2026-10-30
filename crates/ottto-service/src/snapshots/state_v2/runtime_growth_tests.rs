//! Native custody fixtures. Execution belongs to CI; no production save bypass.
use super::*;
use crate::snapshots::{
    candidate_from_traversal_path_with_growth, local_index_key,
    open_and_identify_scan_candidate_with_growth, sampled_audit, CandidateFile, ScanCensus,
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
        index.growth_retention.insert(key.clone(), debt(None));
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
            Some(&index.growth_retention),
        )
        .unwrap();
        open_and_identify_scan_candidate_with_growth(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            None,
            30,
            &index.files,
            Some(&index.growth_retention),
        )
        .unwrap()
        .0
    }
    /// Simulate a confirmed claim-only transaction independently of SAVE's
    /// still-gated production planner, then exercise the real receipt hook.
    fn commit_claim(&self, index: &mut ScanIndex, confirmed: bool) {
        index
            .growth_retention
            .insert(self.key.clone(), debt(Some(NOW)));
        let runtime = index.persistence_v2.as_ref().unwrap().clone();
        let mut guard = runtime.session.lock().unwrap();
        let session = guard.as_mut().unwrap();
        let mut tx = session.db.begin(TxnMode::Write).unwrap();
        tx.put(RowInput {
            key: &RowKey::record("file.growth_retention", self.key.as_bytes(), 0).unwrap(),
            fixed: &Fixed::None,
            value_version: 1,
            value: &PackedDebt(&index.growth_retention[&self.key]),
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
        invalidate_locked(&self.path).unwrap();
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
        let mut encoder = packed::Encoder::new(out);
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
        serde_json::to_value(&reopened.growth_retention[&f.key]).unwrap()["last_growth_full_unix"],
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
    stale.growth_retention.clear();
    let (_, rows) = crate::local_resource_diagnostics::capture(|| {
        for reason in [FullReason::StateMissing, FullReason::Replaced] {
            assert!(!admitted(&mut stale, &candidate, reason, NOW + INTERVAL));
        }
    });
    assert!(rows
        .iter()
        .any(|row| row["counts"]["latest"]["growth_claim_refused"] == "lineage"));
}

#[test]
fn reopened_owner_and_other_path_cannot_reuse_foreign_claim_context() {
    let f = Fixture::new();
    let mut old = f.load();
    f.commit_claim(&mut old, true);
    let context = old.growth_claim_context.clone();
    invalidate_locked(&f.path).unwrap();
    let mut reopened = f.load();
    let candidate = f.candidate(&reopened);
    reopened.growth_claim_context = context.clone();
    assert!(!admitted(
        &mut reopened,
        &candidate,
        FullReason::Replaced,
        NOW + INTERVAL
    ));
    let other = Fixture::new();
    let mut foreign = other.load();
    foreign.growth_claim_context = context;
    let candidate = other.candidate(&foreign);
    assert!(!admitted(
        &mut foreign,
        &candidate,
        FullReason::StateMissing,
        NOW + INTERVAL
    ));
}

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

#[test]
fn real_claim_save_authenticates_old_clone_and_ordinary_save_ends_its_authority() {
    let f = Fixture::new();
    let mut claim = f.load();
    let mut old = claim.clone();
    let context = claim.growth_claim_context.clone().unwrap();
    claim
        .growth_retention
        .insert(f.key.clone(), debt(Some(NOW)));
    claim.save_growth_claim(&f.path).unwrap();
    assert!(Arc::ptr_eq(
        claim.growth_claim_context.as_ref().unwrap(),
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
    old.upload_context_fingerprint = Some("synthetic-next-context".into());
    old.save(&f.path).unwrap();
    assert!(!Arc::ptr_eq(
        old.growth_claim_context.as_ref().unwrap(),
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
        serde_json::to_value(&reopened.growth_retention[&f.key]).unwrap()["last_growth_full_unix"],
        serde_json::json!(NOW)
    );
}
