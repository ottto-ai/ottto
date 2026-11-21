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
    progress.record_cache_state(&body()).unwrap();
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
                    cache_observations_state: None,
                };
                Ok(crate::snapshot_client::SnapshotBatchResponse {
                    conflict_rescans: Default::default(),
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
        full_replacement: false,
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
    let reserved = identity_cache_wire_reserve(&item, &progress, false);
    assert_eq!(item.cache_observations, before);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false);
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
    let reserved = identity_cache_wire_reserve(&item, &progress, false);
    assert!(reserved > 64);
    let mut projected = item.clone();
    prepare_snapshot_cache_for_upload(&mut projected, &progress, true, false);
    assert_eq!(
        crate::snapshots::claude_request_identity::item_bytes(&projected),
        crate::snapshots::claude_request_identity::item_bytes(&item) + reserved,
    );
}

/// [regress] one maximal session's hints stay bounded in JSON and load peak:
/// the per-row bound (sessions are uncapped; each is one identity row).
#[test]
fn maximal_session_progress_json_and_actual_load_peak_are_bounded() {
    let mut progress = progress();
    progress.accepted_identity_buckets =
        crate::snapshots::claude_request_identity::AcceptedBuckets::maximal_session_for_test();
    let bytes = serde_json::to_vec(&progress).unwrap();
    // Worst per-session caps in the real progress envelope; other ACK owners empty.
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
    // 16 such sessions measured 7,822,016 JSON bytes and a 13,331,628-byte
    // peak; one session's peak adds the one-session Value tree to its bytes.
    assert!(json_bytes <= 500_000, "json={json_bytes}");
    assert!(load_peak <= 5_000_000, "peak={load_peak}");
    std::fs::remove_dir_all(root).unwrap();
}
/// A body with a public witness version.
fn witnessed_body() -> Value {
    let mut item = body();
    item["session_account_evidence"] = json!({"provider": "anthropic"});
    item
}
/// `cache_state_ack:v1`: a stored ref whose digest is not this body's local
/// witness carries the echoed cache state that ACK validation matched to that
/// digest; the ledger then holds the echo.
#[test]
fn stored_state_follows_a_validated_cache_state_echo() {
    let patch = crate::snapshots::cache_adapter_tests::cache_fixture_item()
        .cache_observations
        .unwrap();
    let state = crate::snapshots::cache_state_from_patch(None, &patch).unwrap();
    let mut item = witnessed_body();
    item["cache_observations"] = serde_json::to_value(&patch).unwrap();
    let entity = |echo: Option<&Value>| crate::snapshot_client::SnapshotEntityRef {
        source_session_id: "synthetic-sticky-session".into(),
        snapshot_fingerprint: "b".repeat(64),
        occurrence_count: 1,
        body_witness_version: Some(15),
        body_witness_digest: Some("e".repeat(64)),
        head_etag: None,
        head_challenge: None,
        unchanged_basis: None,
        cache_observations_state: echo.cloned(),
    };
    let local_witness = "d".repeat(64);
    let mut echoed = progress();
    echoed
        .record_stored_state(&item, Some((&entity(Some(&state)), local_witness.as_str())))
        .unwrap();
    assert_eq!(
        echoed.accepted_cache_states[&cache_session_key("synthetic-sticky-session")],
        state
    );
}

// Hints for more sessions than the former ledger held. The earliest session is
// ACKed first, then `siblings` more; after a restart only the store holds its
// state, which every consumer and scope change must still reach. The hints
// are a published route's progress rows, one per session.
const EARLIEST: &str = "synthetic-sticky-session";
const KEY: [u8; 32] = [0x42; 32];
/// A published Claude route. Dropping it erases the custody, then its
/// directory.
struct Route {
    session: crate::snapshots::StateV2ColdSession,
    index: ScanIndex,
    _dir: crate::test_scratch::ScratchDir,
}
impl Route {
    fn new() -> Self {
        let dir = crate::test_scratch::ScratchDir::canonical("identity-session-rows");
        let (session, index) = crate::snapshots::StateV2ColdSession::publish(
            crate::snapshots::scan_index_persistence::Source::Claude,
            &ScanIndex::default(),
            &dir,
        );
        Self {
            session,
            index,
            _dir: dir,
        }
    }
    fn progress_path(&self) -> PathBuf {
        snapshot_upload_progress_path(self.session.path())
    }
    /// The next cycle's progress: the route's rows, keyed under `key`, and
    /// its first page step (which applies a key change to the stored scope).
    fn load(&self, key: Option<[u8; 32]>) -> SnapshotUploadProgress {
        let mut progress = SnapshotUploadProgress::load_for_index(
            &self.index,
            self.session.path(),
            &self.progress_path(),
            &"a".repeat(64),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        assert!(progress.rows.is_some(), "routed progress rows");
        progress.accepted_identity_buckets.bind_test_key(key);
        progress.load_identity(std::iter::empty()).unwrap();
        progress
    }
}
/// A page naming `sessions`: their stored hints are point-loaded.
fn loaded<'p>(
    progress: &'p mut SnapshotUploadProgress,
    sessions: &[&str],
) -> &'p SnapshotUploadProgress {
    progress.load_identity(sessions.iter().copied()).unwrap();
    progress
}
/// A stored-body entity ACK of `item` whose digest echoes the local witness.
fn stored_ack(progress: &mut SnapshotUploadProgress, item: &Value) {
    let mut accepted = 0;
    attempt_snapshot_page(
        std::slice::from_ref(item),
        &[0],
        "synthetic-session-cap",
        progress,
        &mut accepted,
        &|value: &Value| value["snapshot_fingerprint"].as_str().unwrap(),
        &|_: &Value| "d".repeat(64),
        &|value: &Value| value["source_session_id"].as_str(),
        &mut |_| {
            let entity = crate::snapshot_client::SnapshotEntityRef {
                source_session_id: item["source_session_id"].as_str().unwrap().into(),
                snapshot_fingerprint: item["snapshot_fingerprint"].as_str().unwrap().into(),
                occurrence_count: 1,
                body_witness_version: Some(3),
                body_witness_digest: Some("d".repeat(64)),
                head_etag: None,
                head_challenge: None,
                unchanged_basis: None,
                cache_observations_state: None,
            };
            Ok(crate::snapshot_client::SnapshotBatchResponse {
                conflict_rescans: Default::default(),
                accepted: 1,
                sessions_reconciled: 0,
                session_ids: vec![],
                disabled: false,
                disabled_reason: None,
                entity_ack_contract: Some(crate::snapshots::SNAPSHOT_ENTITY_ACK_CONTRACT.into()),
                accepted_entities: vec![entity],
                unchanged_entities: vec![],
                rejected_entities: vec![],
                conflict_entities: vec![],
            })
        },
        &mut |_| Ok(()),
    )
    .unwrap();
}
/// Save the route's rows, load and re-key under `key`, as the next process
/// does.
fn restarted(
    progress: &mut SnapshotUploadProgress,
    key: Option<[u8; 32]>,
    route: &Route,
) -> SnapshotUploadProgress {
    progress.save(&route.progress_path()).unwrap();
    route.load(key)
}
/// The earliest session's bucket starts and frozen share set.
fn frozen(progress: &SnapshotUploadProgress) -> Option<Value> {
    progress
        .accepted_identity_buckets
        .get(EARLIEST)
        .map(|state| {
            let state = serde_json::to_value(state).unwrap();
            json!([state["starts"], state["shares"]])
        })
}
/// The earliest session's frozen shares, then `siblings` tagged sessions,
/// then a restart at `path`. Returns the earliest state as ACKed.
fn seeded(siblings: usize, route: &Route) -> (SnapshotUploadProgress, Value) {
    let mut progress = route.load(Some(KEY));
    stored_ack(&mut progress, &witnessed_body());
    let before = frozen(&progress).unwrap();
    for n in 0..siblings {
        let mut sibling = body();
        sibling["source_session_id"] = json!(format!("synthetic-sibling-{n}"));
        sibling["snapshot_fingerprint"] = json!(format!("{n:064x}"));
        stored_ack(&mut progress, &sibling);
    }
    (restarted(&mut progress, Some(KEY), route), before)
}
/// [behaviour] An ACK record after a restart sees the store's frozen set: a
/// stripped body keeps the earliest session's frozen shares.
fn identity_cap_ack_record_keeps_store_only_frozen_shares_case(sessions: usize) {
    let route = Route::new();
    let (mut progress, before) = seeded(sessions - 1, &route);
    let mut stripped = body();
    stripped["snapshot_fingerprint"] = json!("8".repeat(64));
    stripped["usage_buckets"][0]["model_usage"][0] = json!({"model":"claude-synthetic"});
    stored_ack(&mut progress, &stripped);
    assert_eq!(
        frozen(loaded(&mut progress, &[EARLIEST])),
        Some(before),
        "{sessions}: frozen set kept"
    );
}
#[test]
fn identity_cap_ack_record_keeps_store_only_frozen_shares_17() {
    identity_cap_ack_record_keeps_store_only_frozen_shares_case(17);
}
/// [behaviour] A replay-generation change reaches a session that is not
/// resident: starts and shares are kept, across a restart.
fn identity_cap_replay_change_keeps_store_only_shares_case(sessions: usize) {
    let route = Route::new();
    let (mut progress, before) = seeded(sessions - 1, &route);
    assert!(progress.prepare_historical_replay("next-generation"));
    let mut progress = restarted(&mut progress, Some(KEY), &route);
    let progress = loaded(&mut progress, &[EARLIEST]);
    assert_eq!(frozen(progress), Some(before), "{sessions}: shares kept");
}
#[test]
fn identity_cap_replay_change_keeps_store_only_shares_17() {
    identity_cap_replay_change_keeps_store_only_shares_case(17);
}
/// [behaviour] Key changes A→None→A and A→B→A reject every older row, even
/// for sessions that were not resident.
#[test]
fn identity_cap_key_change_rejects_store_only_rows() {
    for path in [[None, Some(KEY)], [Some([0x43; 32]), Some(KEY)]] {
        let route = Route::new();
        let (mut progress, _) = seeded(16, &route);
        for key in path {
            progress = restarted(&mut progress, key, &route);
        }
        let progress = loaded(&mut progress, &[EARLIEST, "synthetic-sibling-15"]);
        assert_eq!(frozen(progress), None, "{path:?}");
        assert!(progress
            .accepted_identity_buckets
            .get("synthetic-sibling-15")
            .is_none());
    }
}
/// [money] An ACK after a restart that omits a frozen row of a present bucket
/// keeps that row's older frozen shares.
#[test]
fn frozen_shares_survive_an_ack_omitting_their_row_after_restart() {
    let tagged = |model: &str| json!({"model":model,"evidence_ref":0,"account_identifier_hash":"a".repeat(64)});
    let route = Route::new();
    let mut progress = route.load(Some(KEY));
    let mut both = body();
    both["usage_buckets"][0]["model_usage"] =
        json!([tagged("claude-synthetic"), tagged("claude-other")]);
    stored_ack(&mut progress, &both);
    let before = frozen(&progress).unwrap();
    assert_eq!(before[1].as_array().unwrap().len(), 2, "two frozen rows");
    let mut progress = restarted(&mut progress, Some(KEY), &route);
    let mut omitting = body();
    omitting["snapshot_fingerprint"] = json!("7".repeat(64));
    omitting["usage_buckets"][0]["model_usage"] = json!([tagged("claude-other")]);
    stored_ack(&mut progress, &omitting);
    assert_eq!(frozen(loaded(&mut progress, &[EARLIEST])), Some(before));
}
/// The identity rows of `sessions` as stored: (written at P, hint).
fn stored_rows(
    progress: &SnapshotUploadProgress,
    sessions: &[String],
) -> BTreeMap<String, (u64, Value)> {
    let hints = &progress.accepted_identity_buckets;
    let names = (sessions.iter())
        .map(|session| hints.row_name(session).unwrap())
        .collect::<BTreeSet<_>>();
    let rows = progress.rows.as_ref().unwrap();
    let points = rows
        .read_points::<crate::snapshots::ProgressPoint<Value>>(&names, |_, _| true)
        .unwrap();
    (points.into_iter())
        .map(|(name, point)| (name, (point.progress_generation, point.accepted)))
        .collect()
}
fn sibling_body(n: usize, hour: u8) -> Value {
    let mut sibling = body();
    sibling["source_session_id"] = json!(format!("synthetic-sibling-{n}"));
    sibling["snapshot_fingerprint"] = json!(format!("{n:063x}{hour:x}"));
    sibling["usage_buckets"][0]["bucket_start"] = json!(format!("2026-09-01T{hour:02}:00:00Z"));
    sibling
}
/// [format] A legacy 16-session JSON ledger becomes one identity row per
/// session in the single import transaction, with their scope, the marker
/// and P = 1; a later page rewrites only the session it changed. (An older
/// writer refuses the capability-6 store: the progress rows carry job.)
#[test]
fn identity_rows_import_splits_a_legacy_ledger_in_one_transaction() {
    let mut legacy = progress();
    stored_ack(&mut legacy, &witnessed_body());
    let mut sessions = vec![EARLIEST.to_owned()];
    for n in 0..15 {
        stored_ack(&mut legacy, &sibling_body(n, 10));
        sessions.push(format!("synthetic-sibling-{n}"));
    }
    let mut json = serde_json::to_value(&legacy).unwrap();
    let hints = json["accepted_identity_buckets"].as_object_mut().unwrap();
    assert_eq!(hints.len(), 16);
    for (n, hint) in hints.values_mut().enumerate() {
        hint["last_ack"] = json!(n + 1);
    }
    let bytes = serde_json::to_vec(&json).unwrap();
    let dir = crate::test_scratch::ScratchDir::canonical("identity-import-split");
    let (session, index) = crate::snapshots::StateV2ColdSession::publish_with_progress(
        crate::snapshots::scan_index_persistence::Source::Claude,
        &ScanIndex::default(),
        &dir,
        &bytes,
    );
    let path = snapshot_upload_progress_path(session.path());
    let mut progress = SnapshotUploadProgress::load_for_index(
        &index,
        session.path(),
        &path,
        &"a".repeat(64),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    assert_eq!(progress.generation, 1, "the import commits P 0 -> 1");
    assert!(
        progress.accepted_identity_buckets.is_empty(),
        "no resident hint"
    );
    assert_eq!(
        progress.accepted_identity_scope.key_epoch,
        legacy.accepted_identity_buckets.epoch(),
        "the scope commits with the rows"
    );
    let read = with_state_v2_progress_owner(session.path(), None, |owner, _| {
        crate::snapshots::read_progress_rows(session.path(), owner)
    })
    .unwrap();
    assert!(read.marker.is_some(), "the marker commits with the rows");
    let ledger = read.ledger.unwrap();
    assert!(ledger.get("accepted_identity_buckets").is_none());
    assert!(ledger.get("accepted_identity_scope").is_some());
    progress.accepted_identity_buckets.bind_test_key(Some(KEY));
    let imported = stored_rows(&progress, &sessions);
    assert_eq!(imported.len(), 16, "one row per session");
    for name in &sessions {
        let (generation, hint) =
            &imported[&legacy.accepted_identity_buckets.row_name(name).unwrap()];
        assert_eq!(*generation, 1, "stamped with the imported P");
        assert_eq!(
            hint,
            &serde_json::to_value(legacy.accepted_identity_buckets.get(name).unwrap()).unwrap()
        );
        assert!(hint.get("last_ack").is_none(), "the LRU stamp is dropped");
    }
    // One session changes; the other 15 rows keep the import's bytes.
    stored_ack(&mut progress, &sibling_body(0, 11));
    progress.save(&path).unwrap();
    let after = stored_rows(&progress, &sessions);
    let changed = legacy
        .accepted_identity_buckets
        .row_name("synthetic-sibling-0")
        .unwrap();
    for (name, row) in &after {
        if *name == changed {
            assert_eq!(row.0, 2, "the changed session is rewritten");
            assert_ne!(row.1, imported[name].1);
        } else {
            assert_eq!(row, &imported[name], "an untouched row is never rewritten");
        }
    }
}
/// [behaviour] A page commit and the pass end with no resident hint leave
/// every identity row as it was.
#[test]
fn identity_rows_survive_pages_and_pass_end_with_no_resident_hint() {
    let route = Route::new();
    let (mut progress, _) = seeded(1, &route);
    let sessions = [EARLIEST.to_owned(), "synthetic-sibling-0".to_owned()];
    let before = stored_rows(&progress, &sessions);
    assert_eq!(before.len(), 2);
    assert!(progress.accepted_identity_buckets.is_empty());
    progress
        .accepted_cache_heads
        .insert("e".repeat(64), "f".repeat(64));
    progress.save(&route.progress_path()).unwrap();
    progress.finish_cycle(&route.progress_path()).unwrap();
    let after = restarted(&mut progress, Some(KEY), &route);
    assert!(after.generation > 2, "the page committed");
    assert_eq!(stored_rows(&after, &sessions), before);
}
/// [behaviour] Resident identity state is the page's sessions, not the
/// destination's history: an ACK after a restart holds one session's hints
/// whether 17 or 736 sessions are stored.
#[test]
fn identity_hints_resident_heap_does_not_grow_with_history() {
    use crate::heap_layout_bound::{Counter, HeapLayoutBound};
    let mut heaps = Vec::new();
    for siblings in [16, 735] {
        let route = Route::new();
        let (mut progress, _) = seeded(siblings, &route);
        let mut stripped = body();
        stripped["snapshot_fingerprint"] = json!("8".repeat(64));
        stripped["usage_buckets"][0]["model_usage"][0] = json!({"model":"claude-synthetic"});
        stored_ack(&mut progress, &stripped);
        let mut counter = Counter::new(usize::MAX);
        progress
            .accepted_identity_buckets
            .heap_bound(&mut counter)
            .unwrap();
        heaps.push(counter.bytes);
    }
    assert_eq!(heaps[0], heaps[1], "{heaps:?}");
}
