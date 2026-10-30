//! Test-only bridge from emitted-body fixtures to the composed semantic mapper.
//! Publication is deliberately not simulated: this proves row custody, while
//! the import-peak fixture separately requires the real production route.
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
    let mut db = populate(path, &expected, BTreeMap::new());
    let restored = import::ClaudeMapper.hydrate(&mut db).unwrap();
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

use import::Mapper;
