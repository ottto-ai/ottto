//! Codex earliest-prefix uploads and accepted-state budget regressions.
//! No fixture content comes from a provider account.
use super::cache_observations::{Operation, MAX_OPERATIONS};
use super::*;

fn request(name: &str, read: u64, second: i64) -> OwnedRequest {
    let start = OffsetDateTime::parse("2026-09-30T10:00:00Z", &Rfc3339).unwrap();
    OwnedRequest {
        slot: RequestSlot {
            request_ref: name.into(),
            occurred_at: (start + time::Duration::seconds(second))
                .format(&Rfc3339)
                .unwrap(),
            model: Some("m".into()),
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

/// Warm and cold requests alternate, so every cold request is one break.
fn session(prefix: &str, breaks: usize) -> Vec<OwnedRequest> {
    let mut requests = vec![request(&format!("{prefix}warm_0"), 90_000, 0)];
    for index in 0..breaks {
        let second = 2 * index as i64;
        requests.push(request(&format!("{prefix}cold_{index}"), 0, second + 1));
        requests.push(request(
            &format!("{prefix}warm_{}", index + 1),
            90_000,
            second + 2,
        ));
    }
    requests
}

fn colds(range: std::ops::Range<usize>) -> Vec<String> {
    range.map(|index| format!("cold_{index}")).collect()
}

fn upserted(wire: &CacheObservations) -> Vec<String> {
    wire.operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::Upsert { observation } => Some(observation.affected_request_ref.clone()),
            Operation::Retract { .. } => None,
        })
        .collect()
}

fn retracted(wire: &CacheObservations) -> usize {
    wire.operations
        .iter()
        .filter(|operation| matches!(operation, Operation::Retract { .. }))
        .count()
}

/// The upload step for one pass, given the accepted state of the last one.
fn upload(requests: &[OwnedRequest], prior: Option<&Value>) -> (CacheObservations, Value) {
    let mut item = super::tests::sample_session_artifact_item();
    item.cache_observations = codex_cache_wire_for_requests("s", requests);
    prepare_cache_observations(&mut item, prior);
    let wire = item.cache_observations.unwrap();
    assert!(wire.validate());
    assert!(cache_state_within_limits(
        item.cache_observations_state.as_ref().unwrap()
    ));
    (wire, item.cache_observations_state.unwrap())
}

#[test]
fn over_cap_session_uploads_first_breaks_with_exact_omitted_count() {
    for (breaks, omitted) in [(64, None), (65, Some(1)), (10_000, Some(9_936))] {
        let wire = codex_cache_wire_for_requests("s", &session("", breaks)).unwrap();
        assert!(wire.validate(), "{breaks}");
        let mut refs = upserted(&wire);
        if omitted.is_none() {
            // Complete patches preserve the existing event-ID wire order.
            refs.sort_by_key(|name| name["cold_".len()..].parse::<usize>().unwrap());
        }
        assert_eq!(refs, colds(0..breaks.min(MAX_OPERATIONS)), "{breaks}");
        assert_eq!(wire.omitted_observation_count, omitted, "{breaks}");
        let coverage = if omitted.is_some() {
            "partial"
        } else {
            "complete"
        };
        assert_eq!(wire.coverage, coverage, "{breaks}");
        assert_eq!(
            upserted(&wire).len() as u64 + omitted.unwrap_or(0),
            breaks as u64,
            "every break is either uploaded or counted"
        );
    }
}

#[test]
fn over_cap_duplicates_and_out_of_order_times_keep_session_order() {
    let requests = session("", 65);
    let expected = codex_cache_wire_for_requests("s", &requests).unwrap();
    // A replayed request, adjacent or far back, is one request.
    let mut replayed = requests
        .iter()
        .flat_map(|request| [request.clone(), request.clone()])
        .collect::<Vec<_>>();
    replayed.push(requests[1].clone());
    assert_eq!(
        codex_cache_wire_for_requests("s", &replayed).unwrap(),
        expected
    );
    // A replay with different counters stays a lossy parse with no rows.
    let mut conflicting = requests.clone();
    let mut changed = requests[1].clone();
    changed.slot.output_tokens = Some(1);
    conflicting.push(changed);
    let lossy = codex_cache_wire_for_requests("s", &conflicting).unwrap();
    assert!(lossy.operations.is_empty());
    assert_eq!(
        (lossy.coverage.as_str(), lossy.omitted_observation_count),
        ("partial", None)
    );
    // Clock order never reorders the session: the first breaks in the file
    // are kept, and a backwards clock reports no gap.
    let mut reversed = requests;
    let count = reversed.len() as i64;
    for (index, request) in reversed.iter_mut().enumerate() {
        request.slot.occurred_at = request_time(count - index as i64);
    }
    let wire = codex_cache_wire_for_requests("s", &reversed).unwrap();
    assert_eq!(upserted(&wire), colds(0..MAX_OPERATIONS));
    assert_eq!(wire.omitted_observation_count, Some(1));
    assert!(wire.operations.iter().all(|operation| matches!(
        operation,
        Operation::Upsert { observation } if observation.report_gap_seconds.is_none()
    )));
}

fn request_time(second: i64) -> String {
    request("t", 0, second).slot.occurred_at
}

#[test]
fn over_cap_tail_uploads_match_one_full_upload_without_retractions() {
    let full = session("", 200);
    // The daemon before this fix left an empty partial state for big sessions.
    let empty = json!({"schema_version":1,"observations":[],"coverage":"partial","omitted_observation_count":131});
    for start in [None, Some(empty)] {
        let mut prior = start;
        // Each length is one tail pass; 130 ends on a break still awaiting its next request.
        for length in [21, 129, 130, 131, 141, full.len()] {
            let (wire, state) = upload(&full[..length], prior.as_ref());
            assert_eq!(retracted(&wire), 0, "length {length}");
            assert!(wire.operations.len() <= MAX_OPERATIONS);
            prior = Some(state);
        }
        let (wire, fresh) = upload(&full, None);
        assert_eq!(prior.unwrap(), fresh, "tail passes equal one full read");
        assert_eq!(upserted(&wire), colds(0..MAX_OPERATIONS));
        assert_eq!(wire.omitted_observation_count, Some(136));
        assert_eq!(
            fresh["observations"].as_array().unwrap().len(),
            MAX_OPERATIONS
        );
    }
}

#[test]
fn prefix_storage_is_fixed_for_many_requests_with_few_or_many_breaks() {
    for breaks in [0, 2, 100_000] {
        let mut requests = session("", breaks);
        while requests.len() < 100_000 {
            let index = requests.len();
            requests.push(request(
                &format!("warm_extra_{index}"),
                90_000,
                index as i64,
            ));
        }
        let (rows, omitted) = cache_observations::detect_unique_prefix("s", &requests);
        assert_eq!(rows.capacity(), MAX_OPERATIONS);
        assert_eq!(rows.len(), breaks.min(MAX_OPERATIONS));
        assert_eq!(omitted, breaks.saturating_sub(MAX_OPERATIONS) as u64);
        assert_eq!(
            rows.iter()
                .map(|row| row.affected_request_ref.clone())
                .collect::<Vec<_>>(),
            colds(0..breaks.min(MAX_OPERATIONS))
        );
    }
}

#[test]
fn partial_never_retracts_prior_and_extra_prior_ids_make_count_unknown() {
    let (_, prior) = upload(&session("old_", 10), None);
    let (wire, state) = upload(&session("", 65), Some(&prior));
    assert_eq!(retracted(&wire), 0);
    assert_eq!(wire.omitted_observation_count, None);
    assert_eq!(state["observations"].as_array().unwrap().len(), 74);
    for row in prior["observations"].as_array().unwrap() {
        assert!(state["observations"].as_array().unwrap().contains(row));
    }
}

fn large_row(
    mut row: cache_observations::Observation,
    conditions: usize,
) -> cache_observations::Observation {
    // All fields remain schema-valid: <=32 conditions of <=256 characters.
    row.supporting_conditions = vec!["x".repeat(256); conditions];
    row
}

fn rows(wire: &CacheObservations) -> Vec<cache_observations::Observation> {
    wire.operations
        .iter()
        .filter_map(|op| match op {
            Operation::Upsert { observation } => Some(observation.as_ref().clone()),
            _ => None,
        })
        .collect()
}

fn partial(rows: Vec<cache_observations::Observation>) -> CacheObservations {
    CacheObservations {
        schema_version: 1,
        operations: rows
            .into_iter()
            .map(|row| Operation::Upsert {
                observation: Box::new(row),
            })
            .collect(),
        coverage: "partial".into(),
        omitted_observation_count: Some(1),
    }
}

fn encoded(state: &Value) -> usize {
    crate::canonical_json::canonicalize(state).unwrap().len()
}

pub(crate) fn large_prior_and_replacement_fixture() -> (CacheObservations, Value) {
    let desired = rows(&codex_cache_wire_for_requests("s", &session("", 65)).unwrap());
    // Place shrinking replacements last, so trimming first restores their larger
    // accepted versions. Unrelated accepted rows cannot be deleted under S3.
    let mut selected = desired[10..].to_vec();
    selected.extend_from_slice(&desired[..10]);
    let extra = rows(&codex_cache_wire_for_requests("s", &session("old_", 10)).unwrap());
    let candidate = partial(selected);
    // Build the boundary by measured canonical bytes, not guessed row sizes.
    for conditions in 1..=32 {
        let old = desired[..10]
            .iter()
            .chain(extra.iter())
            .cloned()
            .map(|row| large_row(row, conditions))
            .collect();
        let prior = cache_state_from_patch(None, &partial(old));
        let merged = cache_state_from_patch(Some(&prior), &candidate);
        if encoded(&prior) <= cache_observations::MAX_WIRE_BYTES
            && encoded(&merged) > cache_observations::MAX_WIRE_BYTES
        {
            return (candidate, prior);
        }
    }
    panic!("schema-valid near-cap prior fixture must exist");
}

#[test]
fn large_accepted_prior_small_replacements_validate_actual_merge_after_every_trim() {
    let (candidate, prior) = large_prior_and_replacement_fixture();
    assert!(candidate.validate(), "small replacement patch itself fits");
    let merged = cache_state_from_patch(Some(&prior), &candidate);
    assert!(
        !cache_state_within_limits(&merged),
        "but actual cumulative state does not"
    );
    let mut trimmed = candidate.clone();
    trimmed.operations.pop();
    assert!(
        encoded(&cache_state_from_patch(Some(&prior), &trimmed)) > encoded(&merged),
        "discarding a shrinking replacement increases cumulative bytes"
    );
    let mut item = super::tests::sample_session_artifact_item();
    item.cache_observations = Some(candidate);
    prepare_cache_observations(&mut item, Some(&prior));
    let wire = item.cache_observations.unwrap();
    assert!(wire.validate());
    assert_eq!(retracted(&wire), 0);
    assert_eq!(wire.omitted_observation_count, None);
    let state = item.cache_observations_state.unwrap();
    assert!(cache_state_within_limits(&state));
    assert_eq!(state, cache_state_from_patch(Some(&prior), &wire));
    for row in prior["observations"].as_array().unwrap() {
        assert!(state["observations"].as_array().unwrap().contains(row));
    }
}

#[test]
fn dropped_replacement_is_present_and_not_counted_as_omitted() {
    let desired = rows(&codex_cache_wire_for_requests("s", &session("", 65)).unwrap());
    let prior = cache_state_from_patch(None, &partial(desired[..10].to_vec()));
    let mut selected = desired[10..].to_vec();
    selected.extend_from_slice(&desired[..10]);
    let mut candidate = partial(selected);
    for op in &mut candidate.operations {
        if let Operation::Upsert { observation } = op {
            **observation = large_row(observation.as_ref().clone(), 32);
        }
    }
    let mut item = super::tests::sample_session_artifact_item();
    item.cache_observations = Some(candidate);
    prepare_cache_observations(&mut item, Some(&prior));
    let wire = item.cache_observations.unwrap();
    let state = item.cache_observations_state.unwrap();
    assert!(wire.validate() && cache_state_within_limits(&state));
    let present = state["observations"].as_array().unwrap().len();
    assert_eq!(wire.omitted_observation_count, Some(65 - present as u64));
    assert!(wire.operations.len() < MAX_OPERATIONS);
}

#[test]
fn cumulative_row_cap_and_metadata_only_refusal_preserve_accepted_evidence() {
    let mut accepted = rows(&codex_cache_wire_for_requests("s", &session("old_", 64)).unwrap());
    accepted.extend(rows(
        &codex_cache_wire_for_requests("s", &session("other_", 64)).unwrap(),
    ));
    // Use short witnesses so 128 rows fit the byte budget independently.
    for row in &mut accepted {
        row.previous = None;
        row.immediate_next = None;
        row.status = "next_unavailable".into();
    }
    let prior = cache_state_from_patch(None, &partial(accepted));
    assert!(cache_state_within_limits(&prior));
    let (wire, state) = upload(&session("", 65), Some(&prior));
    assert!(wire.operations.is_empty());
    assert_eq!(wire.omitted_observation_count, None);
    assert_eq!(state["observations"], prior["observations"]);

    // An accepted prior exactly at the byte cap can fit partial/0 metadata,
    // while unknown omission (partial/null) needs three more bytes. Refuse the
    // cache member entirely rather than publishing a false exact count.
    let mut exact = cache_state_from_patch(
        None,
        &partial(rows(
            &codex_cache_wire_for_requests("s", &session("old_", 10)).unwrap(),
        )),
    );
    exact["omitted_observation_count"] = json!(0);
    // Fill using schema-valid condition strings within per-field limits.
    let budget = cache_observations::MAX_WIRE_BYTES;
    // This fixture targets refusal, so the prior is a server-sized state rather
    // than a detector output. Spread padding over many schema-valid rows.
    let mut base = rows(&codex_cache_wire_for_requests("s", &session("old_", 64)).unwrap());
    for row in &mut base {
        row.supporting_conditions = vec![String::new(); 32];
    }
    exact["observations"] = serde_json::to_value(base).unwrap();
    // Replace empty conditions with valid strings, and grow to exactly the cap.
    for row in exact["observations"].as_array_mut().unwrap() {
        for condition in row["supporting_conditions"].as_array_mut().unwrap() {
            *condition = json!("x");
        }
    }
    let mut remaining = budget - encoded(&exact);
    for row in exact["observations"].as_array_mut().unwrap() {
        for condition in row["supporting_conditions"].as_array_mut().unwrap() {
            let add = remaining.min(255);
            *condition = json!("x".repeat(1 + add));
            remaining -= add;
        }
    }
    assert_eq!(remaining, 0);
    assert_eq!(encoded(&exact), budget);
    let mut item = super::tests::sample_session_artifact_item();
    item.cache_observations = Some(CacheObservations {
        schema_version: 1,
        operations: vec![],
        coverage: "partial".into(),
        omitted_observation_count: None,
    });
    prepare_cache_observations(&mut item, Some(&exact));
    assert!(item.cache_observations.is_none());
    assert!(item.cache_observations_state.is_none());
}

#[test]
fn claude_overflow_adapter_keeps_its_existing_empty_gate() {
    let wire = cache_wire_for_requests("s", &session("", 65)).unwrap();
    assert!(wire.operations.is_empty());
    assert_eq!(wire.omitted_observation_count, Some(65));
}

#[test]
fn complete_patch_over_operation_budget_falls_back_without_partial_deletions() {
    let (_, prior) = upload(&session("old_", 10), None);
    let (wire, state) = upload(&session("", 60), Some(&prior));
    assert_eq!(wire.coverage, "partial");
    assert_eq!(wire.omitted_observation_count, None);
    assert_eq!(retracted(&wire), 0);
    assert_eq!(state["observations"].as_array().unwrap().len(), 70);
}

#[test]
fn partial_retracted_status_is_not_a_deletion_backdoor() {
    let (mut wire, prior) = upload(&session("", 1), None);
    if let Operation::Upsert { observation } = &mut wire.operations[0] {
        observation.status = "retracted".into();
    }
    wire.coverage = "partial".into();
    let mut item = super::tests::sample_session_artifact_item();
    item.cache_observations = Some(wire);
    prepare_cache_observations(&mut item, Some(&prior));
    assert!(item.cache_observations.unwrap().operations.is_empty());
    assert_eq!(
        item.cache_observations_state.unwrap()["observations"],
        prior["observations"]
    );
}
