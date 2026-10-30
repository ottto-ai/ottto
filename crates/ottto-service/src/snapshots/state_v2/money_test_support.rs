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

/// Preserve v2-only debt and raw holds through the composed store as well.
pub(super) fn roundtrip_rows(index: &ScanIndex, path: &Path) -> ScanIndex {
    let mut db = populate(path, index, BTreeMap::new());
    import::ClaudeMapper.hydrate(&mut db).unwrap()
}

use import::Mapper;

/// Install synthetic custody without lifting the production conversion/R1 gate.
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
