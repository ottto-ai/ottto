use super::*;
use serde_json::{json, Value};

fn progress() -> SnapshotUploadProgress {
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    );
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    progress
}
fn body() -> Value {
    json!({"source_session_id":"synthetic-sticky-session", "snapshot_fingerprint":"b".repeat(64),
        "provenance":{"collector":crate::snapshots::claude_request_identity::COLLECTOR},
        "request_evidence":[{"identity_basis":"telemetry_login"}],
        "usage_buckets":[{"bucket_start":"2026-09-01T10:00:00Z","model_usage":[{"model":"claude-synthetic","evidence_ref":0,"account_identifier_hash":"a".repeat(64)}]}]})
}
#[test]
fn acknowledged_bucket_keys_survive_progress_restart_and_older_decoder_drops_only_hint() {
    let mut progress = progress();
    progress.record_body(&"b".repeat(64), &"c".repeat(64));
    progress.record_cache_state(&body(), false).unwrap();
    let bytes = serde_json::to_vec(&progress).unwrap();
    let mut restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
    restored
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    assert_eq!(
        restored.accepted_identity_buckets,
        progress.accepted_identity_buckets
    );
    assert_eq!(
        restored
            .accepted_identity_buckets
            .get("synthetic-sticky-session")
            .unwrap()
            .len(),
        1
    );
    // An older progress decoder ignores the append-only L field. Re-encoding
    // it loses that hint; the new decoder defaults to unknown, preserving ACKs.
    #[derive(Serialize, Deserialize)]
    struct OlderProgress {
        schema_version: u16,
        generation: u64,
        destination_namespace_hash: String,
        accepted_fingerprints: BTreeSet<String>,
        accepted_body_witnesses: BTreeMap<String, String>,
    }
    let older: OlderProgress = serde_json::from_slice(&bytes).unwrap();
    let downgraded = serde_json::to_vec(&older).unwrap();
    assert!(!String::from_utf8_lossy(&downgraded).contains("accepted_identity_buckets"));
    let restored: SnapshotUploadProgress = serde_json::from_slice(&downgraded).unwrap();
    assert!(restored
        .accepted_identity_buckets
        .get("synthetic-sticky-session")
        .is_none());
    assert_eq!(
        restored.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
}
#[test]
fn only_a_stored_body_ack_records_bucket_keys() {
    let mut progress = progress();
    let items = [body()];
    let mut accepted = 0;
    for stored in [false, true] {
        attempt_snapshot_page(
            &items,
            &[0],
            "synthetic-sticky-ack",
            &mut progress,
            &mut accepted,
            &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
            &|_: &Value| "c".repeat(64),
            &|value: &Value| value["source_session_id"].as_str(),
            &mut |_| {
                let entity = crate::snapshot_client::SnapshotEntityRef {
                    source_session_id: "synthetic-sticky-session".into(),
                    snapshot_fingerprint: "b".repeat(64),
                    occurrence_count: 1,
                    body_witness_version: None,
                    body_witness_digest: None,
                    head_etag: None,
                    head_challenge: None,
                    unchanged_basis: (!stored).then(|| "usage_identical".into()),
                    retained_proof_missing: Vec::new(),
                };
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    accepted: u64::from(stored),
                    sessions_reconciled: 0,
                    session_ids: vec![],
                    disabled: false,
                    disabled_reason: None,
                    entity_ack_contract: Some(
                        crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into(),
                    ),
                    accepted_entities: if stored { vec![entity.clone()] } else { vec![] },
                    unchanged_entities: if stored { vec![] } else { vec![entity] },
                    rejected_entities: vec![],
                    conflict_entities: vec![],
                })
            },
            &mut |_| Ok(()),
        )
        .unwrap();
        assert_eq!(
            progress
                .accepted_identity_buckets
                .get("synthetic-sticky-session")
                .is_some(),
            stored
        );
    }
}

#[test]
fn identity_budget_reserves_predecessor_retractions_without_mutating_local_patch() {
    use crate::snapshots::cache_observations::CacheObservations;
    let mut item = crate::snapshots::cache_adapter_tests::cache_fixture_item();
    let observation = item.cache_observations_state.as_ref().unwrap()["observations"][0].clone();
    item.cache_observations = Some(CacheObservations {
        schema_version: 1,
        operations: vec![],
        coverage: "complete".into(),
        omitted_observation_count: Some(0),
    });
    let before = item.cache_observations.clone();
    let mut progress = progress();
    progress.accepted_cache_states.insert(
        cache_session_key(&item.source_session_id),
        json!({"observations":(0..32).map(|n| {
            let mut row = observation.clone();
            row["event_id"] = json!(format!("cache:{n:064x}"));
            row
        }).collect::<Vec<_>>()}),
    );
    let reserved = identity_cache_wire_reserve(&item, &progress);
    assert_eq!(item.cache_observations, before);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false, &BTreeSet::new());
    assert_eq!(
        projected
            .cache_observations
            .as_ref()
            .unwrap()
            .operations
            .len(),
        32,
        "reconciled patch: {:?}",
        projected.cache_observations,
    );
    assert!(reserved > 2_000, "reserved={reserved}");
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        crate::snapshots::claude_request_identity::item_bytes(&item) + reserved,
    );
    // The upload owner attaches a known predecessor even with no cache patch.
    item.cache_observations = None;
    item.cache_observations_state = None;
    item.cache_requests.clear();
    item.cache_base_head_etag = None;
    progress
        .accepted_cache_heads
        .insert(cache_session_key(&item.source_session_id), "a".repeat(64));
    let reserved = identity_cache_wire_reserve(&item, &progress);
    assert!(reserved > 64);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false, &BTreeSet::new());
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        crate::snapshots::claude_request_identity::item_bytes(&item) + reserved,
    );
}

/// [regress] a maximum valid identity ledger stays bounded and admits a small
/// v2 upload; unchanged retained sessions must not be charged twice.
#[test]
fn maximum_accepted_ledger_progress_json_and_actual_load_peak_are_bounded() {
    let mut progress = progress();
    progress.accepted_identity_buckets =
        crate::snapshots::claude_request_identity::AcceptedBuckets::maximum_for_test();
    let bytes = serde_json::to_vec(&progress).unwrap();
    // Worst accepted-ledger caps in the real progress envelope; other ACK owners empty.
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ottto-identity-load-{}-{stamp}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let path = root.join("progress.json");
    std::fs::write(&path, &bytes).unwrap();
    let (restored, allocation) = crate::retry_allocation_probe::measure_caller_thread(|| {
        SnapshotUploadProgress::load(
            &path,
            &"a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap()
    });
    assert!(!restored.accepted_identity_buckets.is_empty());
    let json_bytes = bytes.len();
    let load_peak = allocation.requested_peak_with_overlap;
    eprintln!("E2_ACCEPTED_PROGRESS_JSON_BYTES={json_bytes} E2_ACCEPTED_PROGRESS_LOAD_PEAK_BYTES={load_peak}");
    assert!(json_bytes <= 7_900_000, "json={json_bytes}");
    assert!(load_peak <= 13_500_000, "peak={load_peak}");
    let recovery = crate::snapshots::ProgressRecovery::synthetic(
        &root.join("index.json"),
        &progress.destination_namespace_hash,
        0,
    );
    recovery
        .admit_progress_bytes(serde_json::to_vec_pretty(&progress).unwrap().len() as u64)
        .unwrap();
    progress.ack_recovery = Some(Box::new(recovery));
    let before = progress.clone();
    let item = body();
    assert!(!progress
        .admit_ack_custody(
            std::slice::from_ref(&item),
            std::iter::empty(),
            &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
            &|_| "d".repeat(64),
        )
        .unwrap());
    assert_eq!(
        progress, before,
        "admission neither evicts accepted shares nor mutates custody"
    );
    std::fs::remove_dir_all(root).unwrap();
}
// Option (ii): only a stored-body entity ACK whose versioned body witness equals
// the local one admits rows to the proved ledger, and only for a body with a
// public witness version; `retained_proof_missing` is optional and only removes.
fn witnessed_body() -> Value {
    let mut item = body();
    item["context_curve"] = json!({"points": []});
    item
}
fn retained_ack(
    progress: &mut SnapshotUploadProgress,
    items: &[Value],
    legacy: bool,
    stored: bool,
    digest: bool,
    missing: Vec<String>,
) {
    let mut accepted = 0;
    attempt_snapshot_page(
        items,
        &[0],
        "synthetic-retained-ack",
        progress,
        &mut accepted,
        &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
        // The local witness; the ACK below always claims "d" * 64.
        &|value: &Value| {
            value["local_witness"]
                .as_str()
                .map_or_else(|| "d".repeat(64), str::to_owned)
        },
        &|value: &Value| value["source_session_id"].as_str(),
        &mut |_| {
            let entity = crate::snapshot_client::SnapshotEntityRef {
                source_session_id: "synthetic-sticky-session".into(),
                snapshot_fingerprint: items[0]["snapshot_fingerprint"].as_str().unwrap().into(),
                occurrence_count: 1,
                body_witness_version: digest.then_some(3),
                body_witness_digest: digest.then(|| "d".repeat(64)),
                head_etag: None,
                head_challenge: None,
                unchanged_basis: (!stored).then(|| "usage_identical".into()),
                retained_proof_missing: missing.clone(),
            };
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                accepted: 1,
                sessions_reconciled: 0,
                session_ids: vec![],
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: (!legacy)
                    .then(|| crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
                accepted_entities: if stored { vec![entity.clone()] } else { vec![] },
                unchanged_entities: if stored { vec![] } else { vec![entity] },
                rejected_entities: vec![],
                conflict_entities: vec![],
            })
        },
        &mut |_| Ok(()),
    )
    .unwrap();
}
fn retained_rows(progress: &SnapshotUploadProgress) -> Option<(usize, usize)> {
    progress
        .accepted_identity_buckets
        .proved_rows_for_test("synthetic-sticky-session")
}
fn retained_progress() -> SnapshotUploadProgress {
    let mut progress = progress();
    progress
        .accepted_identity_buckets
        .set_retained_enabled(true);
    progress
}
#[test]
fn retained_proof_needs_a_witnessed_stored_body_entity_ack() {
    for (legacy, stored, digest) in [
        (true, true, false),
        (false, false, true),
        (false, true, false),
    ] {
        let mut progress = retained_progress();
        let mut item = witnessed_body();
        item["snapshot_fingerprint"] = json!(format!(
            "{:064x}",
            u8::from(legacy) * 4 + u8::from(stored) * 2 + u8::from(digest)
        ));
        retained_ack(&mut progress, &[item], legacy, stored, digest, vec![]);
        assert_eq!(
            retained_rows(&progress).map_or(0, |rows| rows.0),
            0,
            "legacy={legacy} stored={stored} digest={digest}"
        );
    }
    // Before the server advertises retention, a witnessed ACK proves nothing.
    let mut progress = progress();
    retained_ack(
        &mut progress,
        &[witnessed_body()],
        false,
        true,
        true,
        vec![],
    );
    assert_eq!(retained_rows(&progress), Some((0, 0)));
    // A digest that is not this body's witness proves nothing, and neither
    // does any digest on a body without a public witness version (the ACK
    // validator compares none there).
    let mut progress = retained_progress();
    let mut wrong = witnessed_body();
    wrong["local_witness"] = json!("c".repeat(64));
    retained_ack(&mut progress, &[wrong], false, true, true, vec![]);
    assert_eq!(retained_rows(&progress), Some((0, 0)));
    let mut progress = retained_progress();
    retained_ack(&mut progress, &[body()], false, true, true, vec![]);
    assert_eq!(retained_rows(&progress), Some((0, 0)));
    let mut progress = retained_progress();
    retained_ack(
        &mut progress,
        &[witnessed_body()],
        false,
        true,
        true,
        vec![],
    );
    assert_eq!(retained_rows(&progress), Some((1, 0)));
    // An older server omits the field; a newer one may list a marked bucket.
    let mut marked = witnessed_body();
    marked["snapshot_fingerprint"] = json!("e".repeat(64));
    marked["usage_buckets"][0]["model_usage"][0] =
        json!({"model":"claude-synthetic","identity_retained":true});
    crate::snapshots::claude_request_identity::take_identity_counts();
    retained_ack(
        &mut progress,
        &[marked],
        false,
        true,
        true,
        vec!["2026-09-01T10:00:00Z".into()],
    );
    assert_eq!(retained_rows(&progress), Some((0, 1)));
    let counts =
        serde_json::to_value(crate::snapshots::claude_request_identity::take_identity_counts())
            .unwrap();
    assert_eq!(
        counts["identity_cap"]["retained_proof_missing_received"],
        json!(1)
    );
    let decoded: crate::snapshot_client::SnapshotEntityRef = serde_json::from_value(json!({
        "source_session_id":"s","snapshot_fingerprint":"b".repeat(64)
    }))
    .unwrap();
    assert!(decoded.retained_proof_missing.is_empty());
}
#[test]
fn a_replacement_proof_leaves_the_ledger_durably_before_its_upload() {
    for retained in [true, false] {
        let mut progress = retained_progress();
        retained_ack(
            &mut progress,
            &[witnessed_body()],
            false,
            true,
            true,
            vec![],
        );
        assert_eq!(retained_rows(&progress), Some((1, 0)));
        // ON->OFF: proof left in the ledger is still superseded before the POST.
        progress
            .accepted_identity_buckets
            .set_retained_enabled(retained);
        let mut replacement = witnessed_body();
        replacement["snapshot_fingerprint"] = json!("9".repeat(64));
        replacement["usage_buckets"][0]["model_usage"][0]["account_identifier_hash"] =
            json!("c".repeat(64));
        let saved = std::cell::Cell::new(None);
        let mut accepted = 0;
        let lost = attempt_snapshot_page(
            &[replacement],
            &[0],
            "synthetic-retained-replacement",
            &mut progress,
            &mut accepted,
            &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
            &|_: &Value| "d".repeat(64),
            &|value: &Value| value["source_session_id"].as_str(),
            &mut |_| {
                assert_eq!(saved.get(), Some((0, 0)), "persisted before the POST");
                Err(anyhow!("reply lost"))
            },
            &mut |progress| {
                saved.set(retained_rows(progress));
                Ok(())
            },
        );
        assert!(lost.is_err());
        assert_eq!(retained_rows(&progress), Some((0, 0)));
    }
}
#[test]
fn replay_generation_or_namespace_change_clears_retained_proof() {
    let mut progress = retained_progress();
    retained_ack(
        &mut progress,
        &[witnessed_body()],
        false,
        true,
        true,
        vec![],
    );
    assert_eq!(retained_rows(&progress), Some((1, 0)));
    let path = crate::test_scratch::unique_path("ottto-e2-optii-namespace").join("progress.json");
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    progress.save(&path).unwrap();
    crate::snapshots::claude_request_identity::take_identity_counts();
    let mut other = SnapshotUploadProgress::load(
        &path,
        &"f".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    other
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    assert_eq!(retained_rows(&other), None);
    assert!(progress.prepare_historical_replay("next-generation"));
    assert_eq!(retained_rows(&progress), Some((0, 0)));
    assert!(
        progress
            .accepted_identity_buckets
            .get("synthetic-sticky-session")
            .is_some_and(|known| known.len() == 1),
        "#909 hints are not option (ii) state"
    );
    let counts =
        serde_json::to_value(crate::snapshots::claude_request_identity::take_identity_counts())
            .unwrap();
    assert_eq!(counts["identity_cap"]["retained_set_cleared"], json!(2));
    let _ = std::fs::remove_dir_all(path.parent().unwrap());
}

/// One settled-history group: a segment of the old window and the live body
/// past `through`, each tagged with its own account, as bodies on the wire.
fn history_group() -> [Value; 2] {
    let row = |account: char| json!({"model":"claude-synthetic","evidence_ref":0,"account_identifier_hash":account.to_string().repeat(64)});
    let body = |session: &str, fingerprint: char, start: &str, account: char, extra: Value| {
        let mut body = json!({"source_session_id": session, "snapshot_fingerprint": fingerprint.to_string().repeat(64),
            "provenance":{"collector":crate::snapshots::claude_request_identity::COLLECTOR},
            "request_evidence":[{"identity_basis":"telemetry_login"}],
            "usage_buckets":[{"bucket_start": start, "model_usage":[row(account)]}]});
        body.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        body
    };
    [
        body(
            "synthetic-group#w20260827",
            'd',
            "2026-08-28T10:00:00Z",
            'a',
            json!({"history_segment":{"of":"synthetic-group","window_start":"2026-08-27T00:00:00Z","window_end":"2026-09-03T00:00:00Z"}}),
        ),
        body(
            "synthetic-group",
            'e',
            "2026-09-29T10:00:00Z",
            'b',
            json!({"history_segments":{"through":"2026-09-03T00:00:00Z","count":1}}),
        ),
    ]
}

fn group_page(progress: &mut SnapshotUploadProgress, items: &[Value], conflicted: &[usize]) {
    let mut accepted = 0;
    attempt_snapshot_page(
        items,
        &(0..items.len()).collect::<Vec<_>>(),
        "synthetic-history-group",
        progress,
        &mut accepted,
        &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
        &|_: &Value| "c".repeat(64),
        &|value: &Value| value["source_session_id"].as_str(),
        &mut |_| {
            let entity = |index: usize| crate::snapshot_client::SnapshotEntityRef {
                source_session_id: items[index]["source_session_id"].as_str().unwrap().into(),
                snapshot_fingerprint: items[index]["snapshot_fingerprint"]
                    .as_str()
                    .unwrap()
                    .into(),
                occurrence_count: 1,
                body_witness_version: None,
                body_witness_digest: None,
                head_etag: None,
                head_challenge: None,
                unchanged_basis: None,
                retained_proof_missing: Vec::new(),
            };
            let (conflict, accepted): (Vec<_>, Vec<_>) =
                (0..items.len()).partition(|index| conflicted.contains(index));
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                accepted: accepted.len() as u64,
                sessions_reconciled: 0,
                session_ids: vec![],
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
                accepted_entities: accepted.into_iter().map(entity).collect(),
                unchanged_entities: vec![],
                rejected_entities: vec![],
                conflict_entities: conflict.into_iter().map(entity).collect(),
            })
        },
        &mut |_| Ok(()),
    )
    .unwrap();
}

/// [money] A settled-history group settles whole. With the live
/// ACK lost (conflicted), nothing of the group is recorded or settled, so
/// the moved bucket stays protected by the live entry and the segment is
/// offered again; once the whole group ACKs, the segment records into its own
/// sibling entry before the live body drops the moved bucket.
#[test]
fn history_group_settles_whole_segments_before_live() {
    let mut progress = progress();
    progress
        .accepted_identity_segments
        .bind_test_key(Some([0x42; 32]));
    let [segment, live] = history_group();
    // The unsegmented body was ACKed before: the live entry holds both hours.
    let mut whole = live.clone();
    whole.as_object_mut().unwrap().remove("history_segments");
    whole["usage_buckets"] = json!([segment["usage_buckets"][0], live["usage_buckets"][0]]);
    progress.record_cache_state(&whole, false).unwrap();
    let held = progress
        .accepted_identity_buckets
        .get("synthetic-group")
        .unwrap()
        .len();
    assert_eq!(held, 2);
    let items = [segment, live];
    group_page(&mut progress, &items, &[1]);
    assert!(!progress.accepted_fingerprints.contains(&"d".repeat(64)));
    assert!(progress
        .accepted_identity_segments
        .get("synthetic-group#w20260827")
        .is_none());
    assert_eq!(
        progress
            .accepted_identity_buckets
            .get("synthetic-group")
            .unwrap()
            .len(),
        2
    );
    progress.active_quarantine_retries.clear();
    progress.quarantined_fingerprints.clear();
    group_page(&mut progress, &items, &[]);
    for fingerprint in ['d', 'e'] {
        assert!(progress
            .accepted_fingerprints
            .contains(&fingerprint.to_string().repeat(64)));
    }
    assert_eq!(
        progress
            .accepted_identity_segments
            .get("synthetic-group#w20260827")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        progress
            .accepted_identity_buckets
            .get("synthetic-group")
            .unwrap()
            .len(),
        1
    );
}

/// [format] Segment hints persist in their own sibling field, beside the
/// live map; an older progress decoder ignores the field and keeps ACKs.
#[test]
fn segment_hints_persist_in_a_sibling_field_older_decoders_ignore() {
    let mut progress = progress();
    progress
        .accepted_identity_segments
        .bind_test_key(Some([0x42; 32]));
    let [segment, _] = history_group();
    progress.record_body(&"d".repeat(64), &"c".repeat(64));
    progress.record_cache_state(&segment, false).unwrap();
    assert!(progress
        .accepted_identity_buckets
        .get("synthetic-group#w20260827")
        .is_none());
    let bytes = serde_json::to_vec(&progress).unwrap();
    let saved: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(saved.get("accepted_identity_buckets").is_none());
    assert_eq!(
        saved["accepted_identity_segments"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    let mut restored: SnapshotUploadProgress = serde_json::from_slice(&bytes).unwrap();
    restored
        .accepted_identity_segments
        .bind_test_key(Some([0x42; 32]));
    assert_eq!(
        restored.accepted_identity_segments,
        progress.accepted_identity_segments
    );
    #[derive(Deserialize)]
    struct OlderProgress {
        accepted_body_witnesses: BTreeMap<String, String>,
    }
    let older: OlderProgress = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        older.accepted_body_witnesses,
        progress.accepted_body_witnesses
    );
}

/// [off=main][regress] Each pass binds the attribution key on both ledgers;
/// the partial checkpoint re-reads progress from disk (no key) and must adopt
/// that runtime state for both before comparing, even with the sibling empty
/// and the capability off.
#[test]
fn partial_checkpoint_adopts_both_ledgers_runtime_state() {
    let scratch = crate::test_scratch::ScratchDir::new("segments-partial-checkpoint");
    let mut progress = SnapshotUploadProgress::new(
        "a".repeat(64),
        crate::snapshots::snapshot_quarantine_witness_for_context(
            SnapshotSource::ClaudeCode,
            &"d".repeat(64),
        ),
    );
    for ledger in [
        &mut progress.accepted_identity_buckets,
        &mut progress.accepted_identity_segments,
    ] {
        ledger.bind_test_key(Some([0x42; 32]));
    }
    let progress_path = scratch.join("progress.json");
    let index_path = scratch.join("index.json");
    progress.save(&progress_path).unwrap();
    let index = ScanIndex::default();
    checkpoint_partial_snapshot_index(
        &index,
        &index,
        &progress,
        &[],
        None,
        &BTreeSet::new(),
        &index_path,
        &progress_path,
        || Ok(()),
    )
    .unwrap();
}
