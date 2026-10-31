use super::*;

/// The complete, boundary-free curve the retired builder emitted for `count`
/// owned requests with rising input tokens.
fn complete_curve(parser_revision: &str, count: u64) -> SnapshotContextCurve {
    let points = (1..=count)
        .map(|ordinal| {
            let mut retention_flags = 0;
            if [1, 2, 5, 10, 20].contains(&ordinal) {
                retention_flags |= CONTEXT_CURVE_RETENTION_ANCHOR;
            }
            if ordinal == count {
                retention_flags |= CONTEXT_CURVE_RETENTION_PEAK;
            }
            if ordinal + 10 > count {
                retention_flags |= CONTEXT_CURVE_RETENTION_TAIL;
            }
            if retention_flags == 0 {
                retention_flags = CONTEXT_CURVE_RETENTION_FILL;
            }
            SnapshotContextCurvePoint {
                owned_request_ordinal: ordinal,
                observed_at: format!("2026-09-22T12:00:{:02}Z", ordinal % 60),
                effective_input_tokens: ordinal * 100,
                model_window_index: 0,
                segment_ordinal: 0,
                retention_flags,
                compaction_before_request_boundary_index: None,
                compaction_after_request_boundary_index: None,
            }
        })
        .collect::<Vec<_>>();
    SnapshotContextCurve {
        contract_version: CONTEXT_CURVE_CONTRACT_VERSION.to_string(),
        parser_revision: parser_revision.to_string(),
        ownership_revision: "synthetic_owner:v1".to_string(),
        sampling_revision: CONTEXT_CURVE_SAMPLING_REVISION.to_string(),
        coverage: "complete".to_string(),
        total_owned_request_count: count,
        retained_point_count: points.len() as u64,
        total_compaction_boundary_count: 0,
        retained_boundary_count: 0,
        points,
        boundaries: Vec::new(),
        model_windows: vec![SnapshotContextCurveModelWindow {
            model_window_index: 0,
            model: "synthetic-model".to_string(),
            context_window_tokens: Some(200_000),
            evidence_kind: "provider_reported_window".to_string(),
            evidence_revision: "synthetic_model:v1".to_string(),
        }],
    }
}

#[test]
fn validation_rejects_unsafe_revision_evidence() {
    let curve = complete_curve("unsafe revision", 2);

    assert!(validate_context_curve(0, &curve)
        .unwrap_err()
        .contains("invalid revision evidence"));
}

#[test]
fn wire_budget_pruning_removes_only_fill_points() {
    let mut curve = complete_curve("synthetic_parser:v1", 40);
    validate_context_curve(0, &curve).unwrap();
    let retained_before = curve.retained_point_count;

    assert!(prune_one_context_curve_fill_point(&mut curve));
    assert_eq!(curve.retained_point_count, retained_before - 1);
    assert_eq!(curve.coverage, "sampled");
    validate_context_curve(0, &curve).unwrap();
}
