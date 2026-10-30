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
pub(in super::super) fn roundtrip_rows(index: &ScanIndex, path: &Path) -> ScanIndex {
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

/// Release synthetic native custody before deleting a fixture directory.
pub(in super::super) fn erase_published(path: &Path) {
    let _owner = super::super::CheckpointLock::acquire(path).unwrap();
    runtime::erase_locked(path, None).unwrap();
}

/// Synthetic R1 certificate using the real storage and durable-tail digests.
pub(super) fn checkpoint(
    key: &str,
    entry: &super::super::ScanIndexEntry,
    generation: u64,
    binding: super::super::scan_index_persistence::Binding,
) -> resume::ResumeCheckpoint {
    use crate::durable_tail_store::{entry_digest, key_digest, DurableSource};
    let key_digest = key_digest(DurableSource::ClaudeCode, key);
    let name = key_digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let row = mapper::key("file.progress", key, 1).unwrap();
    let publication = preflight(&RowInput {
        key: &row,
        fixed: &Fixed::None,
        value_version: 1,
        value: &ControlJson(entry),
    })
    .unwrap()
    .digest;
    resume::ResumeCheckpoint {
        record_generation: generation,
        record_name: format!("{name}.{generation}.synthetic.rec"),
        trailer_digest: [1; 32],
        file_generation: generation,
        committed_bytes: entry.size_bytes,
        reduction_version: 1,
        reduction_allowlist: [2; 32],
        reduction_pin: vec![1],
        binding,
        key_digest,
        context: [3; 32],
        scope: [4; 32],
        entry: entry_digest(
            &entry.source_file_fingerprint,
            entry.last_upload_body_witness.as_deref(),
        ),
        publication,
        certificate: resume::Certificate {
            device: 1,
            inode: 1,
            length: entry.size_bytes,
            modified: (
                entry.modified_unix_seconds as i64,
                entry
                    .modified_unix_nanos
                    .unwrap_or(0)
                    .rem_euclid(1_000_000_000) as i64,
            ),
            birth_nanos: entry.opened_birth_nanos,
            sealed_offset: entry.size_bytes,
            sample_len: entry.size_bytes.min(4096) as u32,
            head_sha256: [5; 32],
            boundary_sha256: [6; 32],
            verified_unix_seconds: 1,
            audit_debt_unix_seconds: None,
        },
    }
}
