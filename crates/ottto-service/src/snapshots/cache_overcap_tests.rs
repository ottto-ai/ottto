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
        // 128 ends at selected row 64 awaiting its next request; 129 completes it.
        // 130 ends on the first omitted break awaiting its next request.
        for length in [21, 127, 128, 129, 130, 131, 141, full.len()] {
            let (wire, state) = upload(&full[..length], prior.as_ref());
            assert_eq!(retracted(&wire), 0, "length {length}");
            assert!(wire.operations.len() <= MAX_OPERATIONS);
            let last_selected = state["observations"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["affected_request_ref"] == "cold_63");
            if length == 127 {
                assert!(last_selected.is_none());
            } else if length >= 128 {
                let last_selected = last_selected.unwrap();
                assert_eq!(
                    last_selected["event_id"],
                    cache_observations::event_id("s", "cold_63")
                );
                if length == 128 {
                    assert_eq!(last_selected["status"], "awaiting_next");
                    assert!(last_selected["immediate_next"].is_null());
                } else {
                    assert_eq!(last_selected["status"], "complete");
                    assert_eq!(last_selected["immediate_next"]["request_ref"], "warm_64");
                }
            }
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
        let prior = cache_state_from_patch(None, &partial(old)).unwrap();
        let merged = cache_state_from_patch(Some(&prior), &candidate).unwrap();
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
    let merged = cache_state_from_patch(Some(&prior), &candidate).unwrap();
    assert!(
        !cache_state_within_limits(&merged),
        "but actual cumulative state does not"
    );
    let mut trimmed = candidate.clone();
    trimmed.operations.pop();
    assert!(
        encoded(&cache_state_from_patch(Some(&prior), &trimmed).unwrap()) > encoded(&merged),
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
    assert_eq!(state, cache_state_from_patch(Some(&prior), &wire).unwrap());
    for row in prior["observations"].as_array().unwrap() {
        assert!(state["observations"].as_array().unwrap().contains(row));
    }
}

#[test]
fn dropped_replacement_is_present_and_not_counted_as_omitted() {
    let desired = rows(&codex_cache_wire_for_requests("s", &session("", 65)).unwrap());
    let prior = cache_state_from_patch(None, &partial(desired[..10].to_vec())).unwrap();
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
    let prior = cache_state_from_patch(None, &partial(accepted)).unwrap();
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
    )
    .unwrap();
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

#[test]
fn malformed_accepted_rows_refuse_complete_and_partial_cache_updates() {
    let candidate = codex_cache_wire_for_requests("s", &session("", 2)).unwrap();
    let valid = cache_state_from_patch(None, &candidate).unwrap();
    let mut malformed = valid.clone();
    // Keep the accepted ID but break a required field. Previously this row was
    // silently dropped, even when its raw size exceeded the cumulative budget.
    malformed["observations"][0]["affected"] = Value::Null;
    let mut oversized = malformed.clone();
    oversized["observations"][0]["supporting_conditions"] =
        json!(["x".repeat(cache_observations::MAX_WIRE_BYTES)]);
    assert!(encoded(&oversized) > cache_observations::MAX_WIRE_BYTES);
    let mut wrong_shape = valid.clone();
    wrong_shape["observations"] = Value::Null;
    for prior in [malformed, oversized, wrong_shape] {
        for coverage in ["complete", "partial"] {
            let mut patch = candidate.clone();
            patch.coverage = coverage.into();
            assert!(cache_state_from_patch(Some(&prior), &patch).is_none());
            let before = prior.clone();
            let mut item = super::tests::sample_session_artifact_item();
            item.cache_observations = Some(patch);
            // A previously projected state must be cleared on refusal too.
            item.cache_observations_state = Some(valid.clone());
            prepare_cache_observations(&mut item, Some(&prior));
            assert!(item.cache_observations.is_none());
            assert!(item.cache_observations_state.is_none());
            assert_eq!(prior, before);
        }
    }
}

#[test]
fn under_cap_byte_trim_keeps_the_session_prefix_even_with_backwards_clocks() {
    let mut requests = session("", 64);
    let count = requests.len() as i64;
    for (index, request) in requests.iter_mut().enumerate() {
        request.slot.occurred_at = request_time(count - index as i64);
    }
    let candidate = codex_cache_wire_for_requests("s", &requests).unwrap();
    assert_eq!(candidate.coverage, "complete");
    // Fitting complete patches retain the preexisting event-ID wire order.
    let mut item = super::tests::sample_session_artifact_item();
    item.cache_observations = Some(candidate.clone());
    prepare_cache_observations(&mut item, None);
    let complete = item.cache_observations.unwrap();
    assert_eq!(complete.coverage, "complete");
    let ids = rows(&complete)
        .into_iter()
        .map(|row| row.event_id)
        .collect::<Vec<_>>();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);

    let mut padded = candidate;
    for op in &mut padded.operations {
        if let Operation::Upsert { observation } = op {
            **observation = large_row(observation.as_ref().clone(), 32);
        }
    }
    assert!(
        !padded.validate(),
        "force a byte-budget fallback below 64 rows"
    );
    item.cache_observations = Some(padded);
    prepare_cache_observations(&mut item, None);
    let wire = item.cache_observations.unwrap();
    assert_eq!(wire.coverage, "partial");
    assert!(wire.validate());
    assert!(!wire.operations.is_empty());
    assert!(wire.operations.len() < MAX_OPERATIONS);
    assert_eq!(upserted(&wire), colds(0..wire.operations.len()));
    assert_eq!(
        wire.omitted_observation_count,
        Some((64 - wire.operations.len()) as u64)
    );
    assert_eq!(retracted(&wire), 0);
    let state = item.cache_observations_state.unwrap();
    assert!(cache_state_within_limits(&state));
    assert_eq!(state, cache_state_from_patch(None, &wire).unwrap());
}
