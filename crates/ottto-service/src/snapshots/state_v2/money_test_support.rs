//! Test-only bridge from emitted-body fixtures to the composed semantic mapper.
//! Publication is deliberately not simulated: this proves row custody, while
//! the import fixtures separately exercise the production publication route.
use super::*;
use std::collections::BTreeMap;
use std::path::Path;

pub(super) fn binding() -> super::super::scan_index_persistence::Binding {
    super::super::scan_index_persistence::Binding {
        source: super::super::scan_index_persistence::Source::Claude,
        namespace_hash: "a".repeat(64),
    }
}

pub(super) fn populate(
    path: &Path,
    index: &ScanIndex,
    presence: BTreeMap<String, bool>,
) -> sqlite::Sqlite {
    let mut db = sqlite::Sqlite::create_import(path).unwrap();
    db.path_extractor(import::ClaudeMapper::private_paths);
    db.reference_extractor(import::ClaudeMapper::references);
    let identity = Identity {
        format: FORMAT,
        db_id: "synthetic-money-custody".into(),
        binding: binding(),
        fence_generation: index.generation,
    };
    db.control("identity", &identity).unwrap();
    db.control("generation", &index.generation).unwrap();
    let mut cx = KindCx::default();
    cx.binding = Some(binding());
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
    db.path_extractor(import::ClaudeMapper::private_paths);
    db.reference_extractor(import::ClaudeMapper::references);
    db
}

pub(crate) fn roundtrip(index: &ScanIndex, path: &Path) -> ScanIndex {
    // Feed v1 bytes through its decoder, rather than smuggling runtime state
    // into the oracle. Runtime leases and in-process flags are not custody.
    let bytes = serde_json::to_vec(index).unwrap();
    let mut expected: ScanIndex = serde_json::from_slice(&bytes).unwrap();
    let restored = roundtrip_rows(&expected, path);
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
    restored
}

/// Compare each selected page with the graph the full-clone saver received.
/// Keep returned commitments across pages, including a freshly rebuilt subset.
pub(crate) fn assert_selected_saves(initial: &ScanIndex, pages: &[ScanIndex]) {
    let scratch = crate::test_scratch::ScratchDir::canonical("selected-row-saves");
    let mut db = populate(&scratch.join("state.sqlite"), initial, BTreeMap::new());
    let identity = db.read_control::<Identity>("identity").unwrap().unwrap();
    let (previous, mut cx) = kinds::hydrate(&mut db, binding()).unwrap();
    let mut digests = kinds::baseline(&previous, &mut cx).unwrap();
    for page in pages {
        let mut expected = page.clone();
        digests = kinds::save_graph(&mut db, &identity, digests, &mut expected, &mut cx).unwrap();
        let restored = kinds::hydrate(&mut db, binding()).unwrap().0;
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
    import::ClaudeMapper.hydrate_context(&mut db).unwrap().0
}

use import::Mapper;

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
    db.path_extractor(import::ClaudeMapper::private_paths);
    db.reference_extractor(import::ClaudeMapper::references);
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

pub(in super::super) use runtime::erase_published;
