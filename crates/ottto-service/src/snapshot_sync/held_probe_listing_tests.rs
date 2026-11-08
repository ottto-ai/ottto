// The held-probe re-arm reached through a real listing: a kept generation's
// due re-listing into an empty queue, not a fresh census walk.
use super::*;

/// The synthetic server's activity-hint window, the walk's context.
const HINT_WINDOW_DAYS: u64 = 183;

/// [regress] An unchanged legacy cache-bearing witness gets one parse, then
/// exact covered-probe receipts retire debt without another parse or offer.
/// The re-armed file is found by a kept generation's due re-listing into an
/// empty queue, not by a fresh census walk.
#[test]
#[serial]
#[serial(source_cadences, source_manifests)]
#[serial(client_report)]
fn held_probe_legacy_file_rearms_once() {
    if !supported("held_probe_legacy_file_rearms_once") {
        return;
    }
    let now = current_unix_seconds();
    let mut pipeline = ReofferPipeline::new(
        "held-probe-legacy",
        Answer::Refuse("accepted_log_stale_older_upload"),
        now,
    );
    let (legacy, probe) = seed_legacy_probe_file(&mut pipeline, now);
    let original = legacy.index.files.values().next().unwrap();
    let digest = body_set(&probe);
    assert_ne!(original.last_upload_body_witness.as_ref(), Some(&digest));
    assert!(original.upload_context_receipt.is_none());
    assert!(pipeline
        .server
        .offered()
        .iter()
        .all(|body| body.get("cache_observations").is_none()));
    pipeline.server.offered.lock().unwrap().clear();
    // The completed census retired its walk; keep a finished one, with an
    // empty queue and a due re-listing, as a long-lived generation has.
    let roots =
        crate::snapshot_roots::scan_roots(SnapshotSource::ClaudeCode, &pipeline.fixture.home, &[])
            .unwrap();
    let mut kept = ScanIndex::load(&legacy.index_path).unwrap();
    crate::snapshots::e2_pipeline_scan_fixture::retain_indexed_walk_for_test(
        &mut kept,
        SnapshotSource::ClaudeCode,
        &roots,
        &current_rfc3339(),
        HINT_WINDOW_DAYS,
    );
    crate::snapshots::e2_pipeline_scan_fixture::age_listing_for_test(&mut kept);
    assert!(
        crate::snapshots::e2_pipeline_scan_fixture::pending_keys_for_test(&kept).is_empty(),
        "nothing is queued before the listing"
    );
    let kept_entry = kept.files.values().next().unwrap();
    assert_eq!(
        kept_entry.source_file_fingerprint,
        original.source_file_fingerprint
    );
    assert!(kept_entry.last_snapshot_fingerprint.is_some());
    assert!(kept.confirmed_empty_files.is_empty());
    kept.save(&legacy.index_path).unwrap();
    reset_held_probe_process();
    FINALIZED_PROBE_ITEMS.with(|slot| *slot.borrow_mut() = Some(Vec::new()));
    let (reparsed, parsed, _) = pipeline.measured_cycle(now + 60, true);
    let finalized = FINALIZED_PROBE_ITEMS.with(|slot| slot.borrow_mut().take().unwrap());
    assert_eq!(parsed, 1, "the unchanged legacy file must be parsed once");
    assert_eq!(reparsed.held_probe_rearms, 1);
    assert_eq!(finalized.len(), 1);
    assert!(finalized[0].cache_observations.is_some());
    let entry = reparsed.index.files.values().next().unwrap();
    assert_eq!(
        entry.source_file_fingerprint,
        original.source_file_fingerprint
    );
    assert_eq!(entry.last_upload_body_witness.as_ref(), Some(&digest));
    assert!(
        pipeline.server.offered().is_empty(),
        "rearm offers no bodies"
    );

    let (quiet, parsed, bytes) = pipeline.measured_cycle(now + 120, false);
    assert!(quiet.result.is_ok(), "{:?}", quiet.result);
    assert_eq!((parsed, bytes, quiet.held_probe_rearms), (0, 0, 0));
    let receipt = quiet
        .index
        .files
        .values()
        .next()
        .unwrap()
        .upload_context_receipt
        .as_ref()
        .unwrap();
    assert_eq!(receipt.body_witness, digest);
    crate::snapshots::e2_pipeline_scan_fixture::assert_file_receipt_retires_debt(
        std::slice::from_ref(&probe),
        true,
        |index| {
            let covered = quiet.progress.covered_stale_bodies();
            let candidates = index.file_upload_context_ack_candidates(&[], &covered);
            index.accept_file_upload_context_acks(&candidates, &BTreeMap::new(), &covered);
        },
    );

    // A fresh process has no latch protection: the aligned digest alone
    // must prevent rearming and keep the file quiet.
    reset_held_probe_process();
    let (restarted, parsed, bytes) = pipeline.measured_cycle(now + 180, true);
    assert!(restarted.result.is_ok(), "{:?}", restarted.result);
    assert_eq!((parsed, bytes, restarted.held_probe_rearms), (0, 0, 0));
    assert_eq!(
        restarted
            .index
            .files
            .values()
            .next()
            .unwrap()
            .last_upload_body_witness,
        Some(digest)
    );
    assert!(pipeline.server.offered().is_empty());
}
