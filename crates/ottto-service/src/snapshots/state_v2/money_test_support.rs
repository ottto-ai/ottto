//! Test-only bridge from emitted-body fixtures to the composed semantic mapper.
//! Publication is deliberately not simulated: this proves row custody, while
//! the import fixtures separately exercise the production publication route.
use super::super::account_pending_retention::ArchivedWindows;
use super::*;
use std::collections::BTreeMap;
use std::path::Path;

use super::super::scan_index_persistence::Source;

pub(super) fn binding(source: Source) -> super::super::scan_index_persistence::Binding {
    super::super::scan_index_persistence::Binding {
        source,
        namespace_hash: "a".repeat(64),
    }
}

/// Synthetic v1 file name that `scan_index_storage_binding` binds to `source`.
pub(super) fn synthetic_file(source: Source, suffix: &str) -> String {
    let slug = match source {
        Source::Claude => "claude_code",
        Source::Codex => "codex",
        Source::Pi => "pi",
    };
    format!("{slug}-synthetic-scan-index{suffix}")
}

pub(super) fn populate(
    path: &Path,
    index: &ScanIndex,
    presence: BTreeMap<String, bool>,
) -> sqlite::Sqlite {
    let mut db = sqlite::Sqlite::create_import(path).unwrap();
    db.path_extractor(import::Mapper::private_paths);
    db.reference_extractor(import::Mapper::references);
    let identity = Identity {
        format: FORMAT,
        db_id: "synthetic-money-custody".into(),
        binding: binding(Source::Claude),
        fence_generation: index.generation,
    };
    db.control("identity", &identity).unwrap();
    db.control("generation", &index.generation).unwrap();
    let mut cx = KindCx::default();
    cx.binding = Some(binding(Source::Claude));
    cx.presence = presence;
    let mut tx = db.begin(TxnMode::Write).unwrap();
    kinds::populate(index, &mut tx, &mut cx).unwrap();
    assert_eq!(
        tx.commit(index.generation, index.generation + 1),
        DurableCommitOutcome::Committed(index.generation + 1)
    );
    // Journal OFF deliberately invalidates aborted imports. Fault/rollback
    // tests must operate on a completed import reopened in live WAL mode.
    db.finish_import().unwrap();
    let mut db = sqlite::Sqlite::open(path, &identity).unwrap();
    db.path_extractor(import::Mapper::private_paths);
    db.reference_extractor(import::Mapper::references);
    db
}

pub(crate) fn roundtrip(index: &ScanIndex, path: &Path) -> ScanIndex {
    ColdStore::roundtrip(index, path).2
}

/// Condition b's v2 store. Its graphs load as a live pass loads them, on a
/// live session with cold archives and cold usage pending; resident views
/// are read back for comparisons only.
pub(crate) struct ColdStore {
    session: ColdSession,
}
impl ColdStore {
    /// (store, its cold graph, the same graph read back resident).
    pub(crate) fn roundtrip(index: &ScanIndex, path: &Path) -> (Self, ScanIndex, ScanIndex) {
        // Feed v1 bytes through its decoder, rather than smuggling runtime
        // state into the oracle. Leases and in-process flags are not custody.
        let bytes = serde_json::to_vec(index).unwrap();
        let mut expected: ScanIndex = serde_json::from_slice(&bytes).unwrap();
        let mut db = populate(path, &expected, BTreeMap::new());
        let restored = hydrate_resident(&mut db);
        expected.generation += 1;
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&expected).unwrap(),
            "composed money custody changed v1 fields or join keys"
        );
        assert_eq!(
            restored.decode_holds.v2_provenance(),
            expected.decode_holds.v2_provenance()
        );
        expected.generation -= 1;
        let (session, cold) = ColdSession::publish(&expected, &path.with_extension("session"));
        (Self { session }, cold, restored)
    }

    /// Roll every account family inside `page` (scanned from this store's
    /// graph), save it through the production route and reload: (cold graph,
    /// resident view).
    pub(crate) fn roll_save_reload(
        &mut self,
        page: &mut ScanIndex,
        end: &str,
    ) -> (ScanIndex, ScanIndex) {
        roll_account_families(page, end);
        self.session.save_reload(page)
    }
}

/// Custody published through the real fence route and loaded by the runtime
/// as a live pass loads it: cold usage pending's keyed and whole-kind loads
/// read a real session store. Dropping it erases the custody.
pub(crate) struct ColdSession {
    path: std::path::PathBuf,
}
impl ColdSession {
    /// (custody under `dir`, its cold graph).
    pub(crate) fn publish(index: &ScanIndex, dir: &Path) -> (Self, ScanIndex) {
        let path = dir
            .join("snapshots/destinations")
            .join("a".repeat(64))
            .join("claude_code-test-scan-index.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let progress = serde_json::to_vec(&serde_json::json!({
            "schema_version": 3,
            "destination_namespace_hash": "a".repeat(64),
        }))
        .unwrap();
        let cold = publish(index, &path, &progress);
        assert!(cold.v2().persistence_v2.is_some(), "a live session");
        (Self { path }, cold)
    }
    /// Save `page` (descended from this custody's graph) through the
    /// production route and reload it: (cold graph, resident view).
    pub(crate) fn save_reload(&self, page: &mut ScanIndex) -> (ScanIndex, ScanIndex) {
        page.save(&self.path).unwrap();
        let cold = ScanIndex::load(&self.path).unwrap();
        let view = resident(&cold);
        (cold, view)
    }
    /// Whether this pass's claim-only growth save moved the store past
    /// `index`, the working graph a page still saves from.
    pub(crate) fn claimed_ahead(&self, index: &ScanIndex) -> bool {
        super::super::sampled_audit::own_growth_claim_generation(index, &self.path)
            .is_some_and(|generation| generation > index.generation)
    }
}
impl Drop for ColdSession {
    fn drop(&mut self) {
        erase_published(&self.path);
    }
}

/// A session graph with its cold archives and usage pending read back
/// resident, for comparisons.
pub(crate) fn resident(index: &ScanIndex) -> ScanIndex {
    runtime::materialized(index)
}

/// Whether a cold graph holds `root`'s stored value, loaded this pass.
pub(crate) fn usage_loaded(index: &ScanIndex, root: &str) -> bool {
    index
        .claude_usage_family_pending
        .cold()
        .is_some_and(|cold| cold.loaded().contains_key(root))
}

/// Whether `root` is a stored family this cold graph never loaded: a head
/// with no value, whose evidence a page could only have refused.
pub(crate) fn usage_head_only(index: &ScanIndex, root: &str) -> bool {
    index.claude_usage_family_pending.cold().is_some()
        && index.claude_usage_family_pending.family(root).is_err()
}

/// Families of a cold usage-pending graph; None while resident.
pub(crate) fn cold_usage_families(index: &ScanIndex) -> Option<usize> {
    let usage = &index.claude_usage_family_pending;
    usage.cold().map(|_| usage.len())
}

/// Every account family's current window rolls to `end`, as a scan rollover
/// with strict runs would: resident archives apply the endpoint rule, cold
/// ones queue it.
pub(crate) fn roll_account_families(index: &mut ScanIndex, end: &str) {
    for family in index.claude_account_family_pending.values_mut() {
        let mut current = family.current.clone();
        current.census_window_end = end.into();
        let old = std::mem::replace(&mut family.current, current);
        family.archive(old, true);
    }
}

/// Whether some account family's archive loaded cold.
pub(crate) fn has_cold_archive(index: &ScanIndex) -> bool {
    index
        .claude_account_family_pending
        .values()
        .any(|family| matches!(family.previous_windows, ArchivedWindows::Cold(_)))
}

/// Compare each selected page with the graph the full-clone saver received.
/// Keep returned commitments across pages, including a freshly rebuilt subset.
pub(crate) fn assert_selected_saves(initial: &ScanIndex, pages: &[ScanIndex]) {
    let scratch = crate::test_scratch::ScratchDir::canonical("selected-row-saves");
    let mut db = populate(
        &scratch.join("state.v2.sqlite.import"),
        initial,
        BTreeMap::new(),
    );
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let (previous, mut cx) = kinds::hydrate(&mut db, binding(Source::Claude)).unwrap();
    let mut digests = kinds::baseline(&previous, &mut cx).unwrap();
    for page in pages {
        let mut expected = page.clone();
        digests = kinds::save_graph(&mut db, &identity, digests, &mut expected, &mut cx).unwrap();
        let restored = kinds::hydrate(&mut db, binding(Source::Claude)).unwrap().0;
        assert_eq!(
            serde_json::to_vec(&restored).unwrap(),
            serde_json::to_vec(&expected).unwrap()
        );
        assert!(restored.decode_holds.same_as(&expected.decode_holds));
        assert_eq!(
            restored.decode_holds.v2_provenance(),
            expected.decode_holds.v2_provenance()
        );
        assert_eq!(
            restored.v2().growth_retention,
            expected.v2().growth_retention
        );
    }
}

/// Preserve v2-only debt and raw holds through the composed store as well.
pub(in super::super) fn roundtrip_rows(index: &ScanIndex, path: &Path) -> ScanIndex {
    let mut db = populate(path, index, BTreeMap::new());
    hydrate_resident(&mut db)
}

/// The production hydrate with cold archives read back resident, for graph
/// comparisons.
pub(super) fn hydrate_resident(db: &mut sqlite::Sqlite) -> ScanIndex {
    let mut index = import::Mapper.hydrate_context(db).unwrap().0;
    let mut tx = db.begin(TxnMode::Read).unwrap();
    kinds_accounts::materialize(&mut tx, &mut index).unwrap();
    index
}

/// CCR2 of #938's persisted copy-removals fixture plus one prefix-hold debt
/// file, with definite metadata (shared by the format and inventory tests).
pub(super) const CCR2_DEFINITE: &str = "Q0NSMgACAAAAEhWSo6RMxEDjJVe1q0p5xwAAAAAAAAAAAQAAAAhTn1hKY1r1cpjByPzdpVwCAAAAAQAAAAAAAAACAAAAAAAAAJGPX3TzuiqIHEpSPndxZkoBAAAAAAAAAAAAAAA";

/// Install synthetic custody through the publication route.
/// All subsequent loads, saves and receipt replay use the real route.
pub(crate) fn publish(index: &ScanIndex, path: &Path, progress: &[u8]) -> ScanIndex {
    let binding = super::super::scan_index_integration::scan_index_storage_binding(path).unwrap();
    let identity = Identity {
        format: FORMAT,
        db_id: "synthetic-partial-checkpoint".into(),
        binding: binding.clone(),
        fence_generation: index.generation + 1,
    };
    let mut db = sqlite::Sqlite::create_import(&fence::sibling(path, ".v2.sqlite.import")).unwrap();
    db.path_extractor(import::Mapper::private_paths);
    db.reference_extractor(import::Mapper::references);
    db.control("identity", &identity).unwrap();
    db.control("generation", &index.generation).unwrap();
    let mut cx = KindCx::default();
    cx.binding = Some(binding);
    let mut tx = db.begin(TxnMode::Write).unwrap();
    kinds::populate(index, &mut tx, &mut cx).unwrap();
    assert_eq!(
        tx.commit(index.generation, identity.fence_generation),
        DurableCommitOutcome::Committed(identity.fence_generation)
    );
    db.finish_import().unwrap();
    ottto_core::write_owner_only_file_atomic(
        &fence::sibling(path, ".v1-readonly"),
        &serde_json::to_vec(index).unwrap(),
    )
    .unwrap();
    crate::snapshot_sync::with_state_v2_progress_lock(path, |progress_path| {
        match std::fs::read(progress_path) {
            Ok(bytes) => assert_eq!(
                bytes, progress,
                "synthetic custody must seal the actual original bytes"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                ottto_core::write_owner_only_file_atomic(progress_path, progress)?
            }
            Err(error) => return Err(error.into()),
        }
        Ok(())
    })
    .unwrap();
    ack::ProgressRecovery::seal_import(
        identity.clone(),
        identity.fence_generation,
        path,
        Some(progress),
    )
    .unwrap();
    fence::publish(path, &identity, &mut false).unwrap();
    ScanIndex::load(path).unwrap()
}

pub(in super::super) use runtime::{
    delete_usage_row_in_session, erase_published, usage_unknown_count,
};
