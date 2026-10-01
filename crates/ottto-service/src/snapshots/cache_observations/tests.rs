use super::*;
fn request(id: &str, read: u64) -> OwnedRequest {
    OwnedRequest {
        slot: RequestSlot {
            request_ref: id.into(),
            occurred_at: "2026-09-30T10:00:00Z".into(),
            model: Some("model".into()),
            prompt_tokens: Some(100_000),
            cache_read_tokens: Some(read),
            ..Default::default()
        },
        ordering: "sequential".into(),
        compaction_before: false,
        configuration_changed: false,
        configuration_witness: None,
        idle_seconds: None,
    }
}
#[test]
fn chain_keeps_adjacent_slots_and_episode_anchor() {
    let requests = vec![
        request("A", 90_000),
        request("B", 0),
        request("C", 0),
        request("D", 0),
        request("E", 90_000),
    ];
    let rows = detect("session", &requests);
    assert_eq!(rows.len(), 3);
    let c = &rows[&event_id("session", "C")];
    assert_eq!(c.previous.as_ref().unwrap().request_ref, "B");
    assert_eq!(c.immediate_next.as_ref().unwrap().request_ref, "D");
    assert_eq!(c.baseline_request_ref.as_deref(), Some("A"));
    assert_eq!(c.episode_anchor_request_ref.as_deref(), Some("B"));
    assert_eq!(
        rows[&event_id("session", "D")]
            .immediate_next
            .as_ref()
            .unwrap()
            .request_ref,
        "E"
    );
}
#[test]
fn restart_update_and_retraction_keep_identity() {
    let before = detect("s", &[request("A", 90_000), request("B", 0)]);
    let after = detect(
        "s",
        &[request("A", 90_000), request("B", 0), request("C", 90_000)],
    );
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>()
    );
    assert_eq!(after[&event_id("s", "B")].status, "complete");
    assert!(matches!(
        &reconcile(&before, &after).operations[0],
        Operation::Upsert { .. }
    ));
    let corrected = detect("s", &[request("A", 90_000), request("B", 90_000)]);
    assert!(
        matches!(&reconcile(&after,&corrected).operations[0],Operation::Retract{event_id} if event_id==&super::event_id("s", "B"))
    );
    let persisted = serde_json::to_string(&after).unwrap();
    let restored: BTreeMap<String, Observation> = serde_json::from_str(&persisted).unwrap();
    assert!(reconcile(&restored, &after).operations.is_empty());
}
#[test]
fn cold_start_model_switch_and_suffix_growth() {
    assert_eq!(
        detect("s", &[request("A", 0)])[&event_id("s", "A")].observation_kind,
        "cold_start"
    );
    let mut switched = request("B", 0);
    switched.slot.model = Some("other".into());
    assert_eq!(
        detect("s", &[request("A", 90_000), switched])[&event_id("s", "B")].observation_kind,
        "expected_rebuild"
    );
    let mut growing = request("B", 90_000);
    growing.slot.prompt_tokens = Some(115_000);
    assert!(detect("s", &[request("A", 90_000), growing]).is_empty());
}
#[test]
fn canonical_codex_retains_presence_and_zero() {
    let raw = serde_json::json!({"type":"token_usage_record","timestamp":"2026-09-30T10:00:00Z","payload":{"response_id":"resp_1","usage":{"input_tokens":100_000,"cached_input_tokens":0,"output_tokens":0}}});
    let slot = codex_slot(&raw, None, None).unwrap();
    assert_eq!(slot.cache_creation_tokens, None);
    assert_eq!(slot.uncached_tokens, None);
    assert_eq!(slot.output_tokens, Some(0));
    let mut explicit = raw;
    explicit["payload"]["usage"]["cache_write_input_tokens"] = serde_json::json!(0);
    assert_eq!(
        codex_slot(&explicit, None, None).unwrap().uncached_tokens,
        Some(100_000)
    );
}
#[test]
fn missing_predecessor_ordering_and_known_boundaries() {
    let mut ambiguous = request("B", 0);
    ambiguous.ordering = "ambiguous".into();
    assert_eq!(
        detect("s", &[request("A", 90_000), ambiguous])[&event_id("s", "B")].observation_kind,
        "ambiguous"
    );
    let mut compacted = request("B", 30_000);
    compacted.compaction_before = true;
    assert_eq!(
        detect("s", &[request("A", 90_000), compacted])[&event_id("s", "B")].observation_kind,
        "expected_rebuild"
    );
}
#[test]
fn expiry_needs_task_idle_and_observed_stable_configuration() {
    let mut warm = request("A", 90_000);
    warm.configuration_witness = Some("stable".into());
    let mut cold = request("B", 0);
    cold.configuration_witness = Some("stable".into());
    cold.idle_seconds = Some(7200);
    assert_eq!(
        detect("s", &[warm.clone(), cold.clone()])[&event_id("s", "B")].explanation_code,
        "likely_expiry"
    );
    cold.configuration_witness = Some("changed".into());
    assert_eq!(
        detect("s", &[warm, cold])[&event_id("s", "B")].explanation_code,
        "configuration_change"
    );
    let mut long_gap = request("B", 0);
    long_gap.slot.occurred_at = "2026-09-30T12:00:00Z".into();
    assert_eq!(
        detect("s", &[request("A", 90_000), long_gap])[&event_id("s", "B")].explanation_code,
        "unclear"
    );
}
#[test]
fn bounded_pathological_loss_chain_measurement() {
    let mut requests = vec![request("warm", 90_000)];
    for index in 0..1000 {
        requests.push(request(&format!("cold_{index}"), 0));
    }
    let bounded_started = std::time::Instant::now();
    let (bounded, omitted) = detect_bounded("s", &requests, MAX_OPERATIONS);
    assert_eq!(bounded.len(), 64);
    assert_eq!(omitted, 936);
    eprintln!(
        "cache detector bounded requests={} rows={} omitted={} elapsed_us={}",
        requests.len(),
        bounded.len(),
        omitted,
        bounded_started.elapsed().as_micros()
    );
    let started = std::time::Instant::now();
    let rows = detect("s", &requests);
    assert_eq!(rows.len(), 1000);
    let patch = reconcile(&BTreeMap::new(), &rows);
    assert!(!patch.validate());
    eprintln!(
        "cache detector pathological requests={} rows={} elapsed_us={} raw_patch_bytes={}",
        requests.len(),
        rows.len(),
        started.elapsed().as_micros(),
        serde_json::to_vec(&patch).unwrap().len()
    );
}
#[test]
fn non_comparable_next_is_unavailable_without_slot() {
    let mut switched = request("C", 90_000);
    switched.slot.model = Some("other".into());
    let rows = detect("s", &[request("A", 90_000), request("B", 0), switched]);
    let b = &rows[&event_id("s", "B")];
    assert_eq!(b.status, "next_unavailable");
    assert!(b.immediate_next.is_none());
    for row in rows.values() {
        assert_eq!(row.status == "complete", row.immediate_next.is_some());
    }
}
