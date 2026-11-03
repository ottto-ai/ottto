use super::*;
use crate::snapshots::tail_source::load::settlement_tests::{finalize, stored_finish};
use crate::snapshots::tail_source::load::tests::committed;
use crate::snapshots::tail_source::seam::tests::{route, Route};

/// Whether `key`'s committed head owes delivery.
pub(in crate::snapshots) fn owed(index: &ScanIndex, key: &str) -> bool {
    head(index, key).is_some_and(|(_, head)| head.common.debt.reason_bits & DELIVERY_DEBT != 0)
}

/// A committed file whose publishing save lacked its exact ACK.
fn owed_commit(route: &mut Route) -> (PathBuf, String) {
    let (path, key) = committed(route, "a.jsonl", 3);
    assert!(!owed(&route.index, &key), "a stage alone owes nothing");
    mark(&route.path, &route.index, &key, true);
    route.save(false);
    (path, key)
}

/// [behaviour] A partial/wrong/old ACK cannot clear debt for an entity set.
/// Rebuilding, saving and restarting also grant no acceptance.
#[test]
fn every_rebuilt_incident_entity_needs_an_exact_ack() {
    let mut route = route();
    let (path, key) = owed_commit(&mut route);
    assert!(owed(&route.index, &key));
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
    let old: BTreeMap<_, _> = exact
        .keys()
        .map(|fp| (fp.clone(), "old-body".to_owned()))
        .collect();
    for (acks, owes) in [(partial, true), (old, true), (exact, false)] {
        settle(
            SnapshotSource::ClaudeCode,
            &route.index,
            &scan.snapshots,
            &acks,
            false,
        );
        route.save(false);
        route.index = ScanIndex::load(&route.path).unwrap();
        assert_eq!(owed(&route.index, &key), owes);
    }
}

/// [behaviour] Absence cannot forgive a failed publication's debt. Census
/// retirement keeps its metadata-only head, counted `tail_absent.kept_debt`,
/// with no source available to read.
#[test]
fn deleted_source_stays_owed_after_retirement_and_restart() {
    let mut route = route();
    let (path, key) = owed_commit(&mut route);
    fs::remove_file(&path).unwrap();
    route.index.files.remove(&key);
    let none = BTreeSet::new();
    let census = |route: &mut Route| {
        let ((), rows) = crate::local_resource_diagnostics::capture(|| {
            load::retire_absent(SnapshotSource::ClaudeCode, &route.index, &none, &none)
        });
        route.save(false);
        route.index = ScanIndex::load(&route.path).unwrap();
        rows
    };
    census(&mut route);
    let rows = census(&mut route);
    assert!(owed(&route.index, &key));
    assert!(route.head(&key).unwrap().metadata_only);
    assert!(!retry_pending(&route.index, &key));
    assert!(rows
        .iter()
        .any(|row| row["stage"] == "tail_absent" && row["counts"]["kept_debt"] == 1));
}

/// [behaviour] Holds are dormant until their event exit; neither a debt wake
/// nor a saved cursor overrides a quarantine, account hold or invalid head.
#[test]
fn held_debt_does_not_rebuild() {
    let mut route = route();
    let (_, key) = owed_commit(&mut route);
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
