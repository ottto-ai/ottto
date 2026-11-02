//! Historical transition seeds come only from the checked 53d05a43 archive.
//! M3 retires this pin: these bytes exercise rebuild dispatch, never current
//! encoding disguised as v1. Only the scratch-path key and checksum move.
use super::super::transition_fixture::load_v1_goldens;
use super::*;

pub(crate) fn seed_pinned_v1(
    cache: &SharedCache,
    source: SnapshotSource,
    key: &str,
    pin: &str,
) -> Vec<u8> {
    assert_eq!(pin, "53d05a43");
    let ds = durable_source(source).unwrap();
    let case_id = match source {
        SnapshotSource::ClaudeCode => "claude-three-request",
        SnapshotSource::Codex => "codex-v2-24b",
        SnapshotSource::Pi => unreachable!("no historical Pi record"),
    };
    let golden = load_v1_goldens()
        .unwrap()
        .into_iter()
        .find(|golden| golden.case_id == case_id)
        .unwrap();
    let digest = store::key_digest(ds, key);
    let bytes = golden.relocated_record(digest);
    let mut stores = cache.durable().unwrap();
    let slot = stores.slot(ds).as_mut().unwrap();
    let name = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    std::fs::write(slot.store.dir().join(format!("{name}.rec")), &bytes).unwrap();
    assert_eq!(slot.store.missing_cause(&digest), Some("repin"));
    assert_eq!(slot.store.read(&digest), ReadOutcome::Missing);
    bytes
}
