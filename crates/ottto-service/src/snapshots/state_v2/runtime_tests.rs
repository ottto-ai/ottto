//! Table-agnostic F5–F7 fixtures. The fake mapper carries only generation;
//! these tests make no condition-b/hydration parity claim.
use super::*;
use std::sync::atomic::{AtomicU64, Ordering};

struct Fixture {
    support: PathBuf,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let support = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "ottto-v2-route-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = support.join("snapshots/destinations").join("b".repeat(64));
        fs::create_dir_all(&parent).unwrap();
        Self {
            path: parent.join("claude_code-test-scan-index.json"),
            support,
        }
    }
    fn identity(&self) -> Identity {
        Identity {
            format: FORMAT,
            db_id: "fixture-db".into(),
            binding: binding(&self.path).unwrap(),
            fence_generation: 0,
        }
    }
    fn imported(&self) {
        let mut db =
            sqlite::Sqlite::create_import(&fence::sibling(&self.path, ".v2.sqlite.import"))
                .unwrap();
        db.control("identity", &self.identity()).unwrap();
        db.control("generation", &0_u64).unwrap();
        db.finish_import().unwrap();
    }
    fn published(&self) {
        self.imported();
        fence::publish(&self.path, &self.identity(), &mut false).unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.support);
    }
}
struct EmptyMapper;
impl Mapper for EmptyMapper {
    fn private_paths(
        _: &RowKey,
        _: &dyn Value,
        _: &mut dyn FnMut(&str) -> Result<()>,
    ) -> Result<()> {
        Ok(())
    }
    fn inventory(&self, _: &Path) -> std::result::Result<(), Pause> {
        Ok(())
    }
    fn preflight(&self, _: &ScanIndex) -> std::result::Result<(), Pause> {
        Ok(())
    }
    fn populate<S: Store>(&self, _: &mut S, _: &ScanIndex) -> Result<()> {
        Ok(())
    }
    fn verify<S: Store>(&self, _: &mut S, _: &ScanIndex) -> Result<()> {
        Ok(())
    }
    fn hydrate<S: Store>(&self, db: &mut S) -> Result<ScanIndex> {
        let mut tx = db.begin(TxnMode::Read)?;
        let h = tx.get(&RowKey::Meta("generation".into()))?.unwrap();
        let mut packed = Vec::new();
        tx.read_value(&h, &mut packed)?;
        let mut json = Vec::new();
        super::super::packed::decode(packed.as_slice(), &mut json)?;
        Ok(ScanIndex {
            generation: serde_json::from_slice(&json)?,
            ..ScanIndex::default()
        })
    }
    fn merge_cas<T: Transaction>(&self, _: &mut T, _: &mut ScanIndex) -> Result<()> {
        Ok(())
    }
    fn delta<T: Transaction>(&self, _: &mut T, _: &ScanIndex) -> Result<()> {
        Ok(())
    }
}
#[test]
fn f5_missing_v1_garbled_fences_never_authenticate_final_db() {
    for root in [
        None,
        Some(b"{\"schema_version\":3}".as_slice()),
        Some(b"bad".as_slice()),
    ] {
        let f = Fixture::new();
        f.published();
        if let Some(bytes) = root {
            fs::write(&f.path, bytes).unwrap();
        } else {
            fs::remove_file(&f.path).unwrap();
        }
        let db = fence::sibling(&f.path, ".v2.sqlite");
        let before = fs::read(&db).unwrap();
        assert_eq!(
            load_with(&f.path, false, &EmptyMapper)
                .unwrap_err()
                .downcast_ref::<Hold>(),
            Some(&Hold::FenceLost)
        );
        assert!(guard_containment_locked(&f.path).is_err());
        assert!(save_with(&f.path, &mut ScanIndex::default(), &EmptyMapper).is_err());
        assert_eq!(fs::read(db).unwrap(), before);
        assert!(!fence::sibling(&f.path, ".v2.sqlite.import").exists());
    }
}
#[test]
fn f7_publication_failures_keep_latch_and_artifacts_and_restart_recovers() {
    for point in [
        fence::Boundary::FenceAttempt,
        fence::Boundary::FenceRenamed,
        fence::Boundary::FenceSynced,
        fence::Boundary::DbRenamed,
        fence::Boundary::FinalSynced,
    ] {
        let f = Fixture::new();
        fs::write(&f.path, b"v1-before-publication").unwrap();
        f.imported();
        let mut latch = false;
        fence::fail_at(point);
        assert!(fence::publish(&f.path, &f.identity(), &mut latch).is_err());
        assert!(latch);
        assert!(fence::cleanup_unpublished(&f.path, latch).is_err());
        if point == fence::Boundary::FenceAttempt {
            assert!(fence::reconcile(&f.path, &f.identity().binding, true).is_err());
            assert_eq!(fs::read(&f.path).unwrap(), b"v1-before-publication");
        } else {
            let pair = fence::reconcile(&f.path, &f.identity().binding, false)
                .unwrap()
                .unwrap();
            assert_eq!(pair.0, f.identity());
            assert!(pair.1.exists());
            assert!(load_with(&f.path, false, &EmptyMapper).unwrap().is_some());
            assert!(guard_containment_locked(&f.path).is_err());
        }
    }
}
#[test]
fn f7_off_after_publication_and_ambiguous_commits_cannot_ack_or_fallback() {
    let f = Fixture::new();
    f.published();
    let mut index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    assert!(save_with(&f.path, &mut index, &EmptyMapper).unwrap());
    assert_eq!(index.generation, 1);
    for outcome in [
        DurableCommitOutcome::Published(2),
        DurableCommitOutcome::Ambiguous,
    ] {
        let mut index = index.clone();
        let mut reload = false;
        assert!(apply_outcome(&mut index, &mut reload, outcome).is_err());
        assert!(reload);
    }
    let mut reload = false;
    assert!(apply_outcome(&mut index, &mut reload, DurableCommitOutcome::NotPublished).is_err());
    assert!(!reload);
    assert_eq!(index.generation, 1);
    assert!(load_locked(&f.path, None).is_err()); // unmapped published custody holds
}
#[test]
fn f6_explicit_forget_deletes_all_artifacts_and_invalidates_stale_clones() {
    let f = Fixture::new();
    f.published();
    let index = load_with(&f.path, false, &EmptyMapper).unwrap().unwrap();
    let mut stale = index.clone();
    for suffix in [
        ".v1-readonly",
        ".v2.sqlite.import",
        ".v2.sqlite.import-wal",
        ".v2.sqlite.import-shm",
        ".v2-fence.tmp",
    ] {
        fs::write(fence::sibling(&f.path, suffix), b"forgotten-path-canary").unwrap();
    }
    let shards = fence::sibling(&f.path, ".v1-readonly.shards");
    fs::create_dir(&shards).unwrap();
    fs::write(shards.join("payload"), b"forgotten-path-canary").unwrap();
    crate::snapshots::erase_claude_state_v2_artifacts(&f.support).unwrap();
    for suffix in [
        "",
        ".v2.sqlite",
        ".v2.sqlite-wal",
        ".v2.sqlite-shm",
        ".v2.sqlite.import",
        ".v2.sqlite.import-wal",
        ".v2.sqlite.import-shm",
        ".v1-readonly",
        ".v1-readonly.shards",
        ".v2-fence.tmp",
    ] {
        assert!(!fence::sibling(&f.path, suffix).exists());
    }
    assert!(save_with(&f.path, &mut stale, &EmptyMapper).is_err());
    assert!(load_with(&f.path, false, &EmptyMapper).is_err());
}
#[test]
fn pending_mapper_pause_does_not_touch_v1_and_off_cancels_inventory_slot() {
    let f = Fixture::new();
    let bytes = serde_json::to_vec(&ScanIndex::default()).unwrap();
    fs::write(&f.path, &bytes).unwrap();
    assert!(load_with(&f.path, true, &PendingMapper).unwrap().is_none());
    let mut index = ScanIndex::default();
    import_with(&f.path, &mut index, &PendingMapper).unwrap();
    assert_eq!(fs::read(&f.path).unwrap(), bytes);
    assert_eq!(fs::read_dir(f.path.parent().unwrap()).unwrap().count(), 1);
    let f = Fixture::new();
    fs::write(&f.path, &bytes).unwrap();
    assert!(load_with(&f.path, true, &EmptyMapper).unwrap().is_none());
    assert!(load_with(&f.path, false, &EmptyMapper).unwrap().is_none());
    import_with(&f.path, &mut index, &EmptyMapper).unwrap();
    assert_eq!(fs::read(&f.path).unwrap(), bytes);
}

#[test]
fn state_v2_hold_reporting_accepts_every_repair_cause() {
    use crate::snapshots::scan_index_health::RepairCause;
    for cause in [
        RepairCause::PriorState,
        RepairCause::StorageGeneration,
        RepairCause::StateV2,
    ] {
        crate::local_resource_diagnostics::scan_index_repair_required("claude_code", cause);
    }
}
#[test]
fn absent_parent_containment_guard_never_promotes_a_database() {
    let f = Fixture::new();
    f.imported();
    let mut file = fence::create_private(&f.path).unwrap();
    serde_json::to_writer(&mut file, &fence::Fence::new(&f.identity())).unwrap();
    drop(file);
    assert!(guard_containment_locked(&f.path).is_err());
    assert!(fence::sibling(&f.path, ".v2.sqlite.import").exists());
    assert!(!fence::sibling(&f.path, ".v2.sqlite").exists());
}

#[test]
fn damaged_and_oversized_fence_claims_hold_before_v1_containment() {
    for bytes in [
        b"{\"schema_version\":4,".to_vec(),
        format!(
            "{{\"schema_version\":4,\"padding\":\"{}\"}}",
            "x".repeat(5000)
        )
        .into_bytes(),
    ] {
        let f = Fixture::new();
        fs::write(&f.path, &bytes).unwrap();
        assert!(load_with(&f.path, false, &EmptyMapper).is_err());
        assert!(guard_containment_locked(&f.path).is_err());
        assert_eq!(fs::read(&f.path).unwrap(), bytes);
    }
}
