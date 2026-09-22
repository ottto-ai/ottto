use super::*;

fn candidates(count: u64) -> Vec<ContextCurveCandidatePoint> {
    (1..=count)
        .map(|ordinal| ContextCurveCandidatePoint {
            observed_at: Some(format!("2026-09-22T12:00:{:02}Z", ordinal % 60)),
            effective_input_tokens: ordinal * 100,
            model: Some("synthetic-model".to_string()),
            context_window_tokens: Some(200_000),
        })
        .collect()
}

#[test]
fn construction_is_deterministic_and_valid() {
    let candidates = candidates(6);
    let boundaries = [ContextCurveCandidateBoundary {
        observed_at: Some("2026-09-22T12:00:03Z".to_string()),
        point_count_before: 3,
    }];
    let build = || {
        build_context_curve(
            "synthetic_parser:v1",
            "synthetic_owner:v1",
            "synthetic_model:v1",
            &candidates,
            &boundaries,
            "parser_unsupported",
        )
    };

    let first = build();
    let second = build();
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
    assert_eq!(first.coverage, "complete");
    validate_context_curve(0, &first).unwrap();
}

#[test]
fn validation_rejects_unsafe_revision_evidence() {
    let curve = build_context_curve(
        "unsafe revision",
        "synthetic_owner:v1",
        "synthetic_model:v1",
        &candidates(2),
        &[],
        "parser_unsupported",
    );

    assert!(validate_context_curve(0, &curve)
        .unwrap_err()
        .contains("invalid revision evidence"));
}

#[test]
fn wire_budget_pruning_removes_only_fill_points() {
    let mut curve = build_context_curve(
        "synthetic_parser:v1",
        "synthetic_owner:v1",
        "synthetic_model:v1",
        &candidates(40),
        &[],
        "parser_unsupported",
    );
    let retained_before = curve.retained_point_count;

    assert!(prune_one_context_curve_fill_point(&mut curve));
    assert_eq!(curve.retained_point_count, retained_before - 1);
    assert_eq!(curve.coverage, "sampled");
    validate_context_curve(0, &curve).unwrap();
}
