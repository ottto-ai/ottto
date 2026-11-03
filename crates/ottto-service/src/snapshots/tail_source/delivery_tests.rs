use super::*;
use crate::snapshots::tail_source::load::settlement_tests::{finalize, stored_finish};
use crate::snapshots::tail_source::load::tests::committed;
use crate::snapshots::tail_source::seam::tests::route;

/// [behaviour] A partial/wrong/old ACK cannot clear debt for an entity set.
/// Rebuilding, saving and restarting also grant no acceptance.
#[test]
fn every_rebuilt_incident_entity_needs_an_exact_ack() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    assert!(owed(&route.index, &key));
    route
        .index
        .activate_file_upload_context(SnapshotSource::ClaudeCode, "d".repeat(64));
    let (mut items, bytes) = stored_finish(&route, &path, &key);
    assert_eq!(bytes, 0);
    let mut sibling = items[0].clone();
    sibling.source_session_id = "another-incident-entity".into();
    items.push(sibling);
    let scan = finalize(
        &mut route,
        &key,
        items,
        true,
        Some(CandidateParseReason::DeliveryDebt),
    );
    assert_eq!(scan.snapshots.len(), 2, "unACKed cursor is not a no-op");
    let candidates = route
        .index
        .file_upload_context_ack_candidates(&scan.snapshots);
    assert_eq!(candidates.len(), 1);
    let exact = scan
        .snapshots
        .iter()
        .map(|item| {
            (
                item.snapshot_fingerprint.clone(),
                snapshot_upload_body_witness(item),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut partial = exact.clone();
    partial.pop_first();
    for acks in [
        partial,
        exact
            .keys()
            .map(|key| (key.clone(), "old-body".into()))
            .collect(),
    ] {
        route
            .index
            .accept_file_upload_context_acks(&candidates, &acks);
        route.save(false);
        route.index = ScanIndex::load(&route.path).unwrap();
        assert!(owed(&route.index, &key));
        route
            .index
            .activate_file_upload_context(SnapshotSource::ClaudeCode, "d".repeat(64));
    }
    route
        .index
        .accept_file_upload_context_acks(&candidates, &exact);
    route.save(false);
    route.index = ScanIndex::load(&route.path).unwrap();
    assert!(!owed(&route.index, &key));
}

/// [behaviour] Absence cannot forgive a failed publication's debt. Retirement
/// keeps its metadata-only head and G7 alarm, with no source available to read.
#[test]
fn deleted_source_stays_owed_after_retirement_and_restart() {
    let mut route = route();
    let (path, key) = committed(&mut route, "a.jsonl", 3);
    fs::remove_file(&path).unwrap();
    state_v2::retire_tail(&route.path, [key.clone()]).unwrap();
    route.save(false);
    route.index = ScanIndex::load(&route.path).unwrap();
    assert!(owed(&route.index, &key));
    assert!(route.head(&key).unwrap().metadata_only);
    assert!(!retry_pending(&route.index, &key));
    let (_, diagnostic) = crate::local_resource_diagnostics::capture(|| {
        wake(SnapshotSource::ClaudeCode, &mut route.index);
    });
    assert!(diagnostic.iter().any(|row| {
        row["counts"]["deleted_unaccepted_files"] == 1 && row["counts"]["alarm"] == true
    }));
}

/// [behaviour] Holds are dormant until their event exit; neither a debt wake
/// nor a saved cursor overrides a quarantine, account hold or invalid head.
#[test]
fn held_debt_does_not_rebuild() {
    let mut route = route();
    let (_, key) = committed(&mut route, "a.jsonl", 3);
    assert!(retry_pending(&route.index, &key));
    let fp = "c".repeat(64);
    route
        .index
        .file_snapshot_fingerprints
        .insert(key.to_string(), [fp.clone()].into());
    let mut hold = snapshot_quarantine_record(SnapshotSource::ClaudeCode);
    hold.disposition = SnapshotQuarantineDisposition::UnprovenTerminal;
    route
        .index
        .quarantined_snapshot_fingerprints
        .insert(fp.clone(), hold);
    assert!(!retry_pending(&route.index, &key));
    route.index.quarantined_snapshot_fingerprints.remove(&fp);
    assert!(retry_pending(&route.index, &key));
    state_v2::set_aside_tail(&route.path, &key, state_v2::SetAsideCause::Row).unwrap();
    route.save(false);
    assert!(!retry_pending(&route.index, &key));
}
