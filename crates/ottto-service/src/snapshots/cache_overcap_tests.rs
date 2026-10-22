//! A session with more cache breaks than one upload carries uploads its first
//! breaks in session order with an exact omitted count, never none of them.
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
    item.cache_observations = cache_wire_for_requests("s", requests);
    prepare_cache_observations(&mut item, prior);
    let wire = item.cache_observations.unwrap();
    assert!(wire.validate());
    (wire, item.cache_observations_state.unwrap())
}

#[test]
fn over_cap_session_uploads_first_breaks_with_exact_omitted_count() {
    for (breaks, omitted) in [(64, None), (65, Some(1)), (10_000, Some(9_936))] {
        let wire = cache_wire_for_requests("s", &session("", breaks)).unwrap();
        assert!(wire.validate(), "{breaks}");
        let mut refs = upserted(&wire);
        if omitted.is_none() {
            // A complete patch keeps its existing event-id order.
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
    let expected = cache_wire_for_requests("s", &requests).unwrap();
    // A replayed request, adjacent or far back, is one request.
    let mut replayed = requests
        .iter()
        .flat_map(|request| [request.clone(), request.clone()])
        .collect::<Vec<_>>();
    replayed.push(requests[1].clone());
    assert_eq!(cache_wire_for_requests("s", &replayed).unwrap(), expected);
    // A replay with different counters stays a lossy parse with no rows.
    let mut conflicting = requests.clone();
    let mut changed = requests[1].clone();
    changed.slot.output_tokens = Some(1);
    conflicting.push(changed);
    let lossy = cache_wire_for_requests("s", &conflicting).unwrap();
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
    let wire = cache_wire_for_requests("s", &reversed).unwrap();
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
fn stale_prior_rows_are_retracted_and_upserts_trimmed_instead_of_cleared() {
    let (_, stale) = upload(&session("old_", 10), None);
    for (breaks, kept, omitted) in [(65, 54, 11), (60, 54, 6)] {
        // Ten retractions and the session's upserts exceed one upload: every
        // retraction is kept, the last upserts wait, and each one is counted.
        let (wire, state) = upload(&session("", breaks), Some(&stale));
        assert_eq!(retracted(&wire), 10, "{breaks}");
        assert_eq!(upserted(&wire).len(), kept, "{breaks}");
        if breaks > MAX_OPERATIONS {
            assert_eq!(
                upserted(&wire),
                colds(0..kept),
                "first breaks in session order"
            );
        }
        assert_eq!(
            (wire.coverage.as_str(), wire.omitted_observation_count),
            ("partial", Some(omitted))
        );
        assert_eq!(state["observations"].as_array().unwrap().len(), kept);
        // The next pass has nothing stale left and converges on the full upload.
        let (wire, converged) = upload(&session("", breaks), Some(&state));
        assert_eq!(retracted(&wire), 0);
        assert_eq!(converged, upload(&session("", breaks), None).1, "{breaks}");
    }
}
