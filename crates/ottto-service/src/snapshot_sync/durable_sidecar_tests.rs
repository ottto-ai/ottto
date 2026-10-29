use super::*;

#[test]
fn durable_sidecar_prepared_ordinary_and_paid_reports_equal_cold() {
    crate::claude_local_otel::durable_sidecar_prepared_fixture(|support, expected| {
        // This witness is an input-selection premise only, never proof for a
        // money fold. Assert the E-empty eligibility used by the real loader.
        let mut raw = serde_json::to_value(ScanIndex::default()).unwrap();
        raw["claude_usage_family_witnesses"]["scope"] = serde_json::json!({
            "evidence_fingerprint": "synthetic-loader-premise",
            "member_request_id_fingerprints": {}, "assigned_request_id_fingerprints": {}
        });
        let index: ScanIndex = serde_json::from_value(raw).unwrap();
        assert!(
            crate::snapshots::claude_native_comparison::early_root_is_eligible(&index, "scope")
        );
        let roots = BTreeSet::from(["scope".to_owned()]);
        let mut ordinary = PreparedClaudeLocalEvidence::load(support, &[], &index);
        assert!(ordinary.frozen_roots_are_current(support, &roots));
        let api = ordinary.take_api_for_sessions(support, &roots).unwrap();
        assert_eq!(api.evidence, expected.0.evidence);
        assert!(api.session_report("scope").unwrap().complete);
        assert_eq!(ordinary.take_trace(support, "scope"), expected.1);
        if !crate::heap_layout_bound::layout_supported() {
            eprintln!("UNEXECUTED durable prepared paid parity: unsupported layout");
            return;
        }
        let mut paid =
            crate::source_rotation::PaidReservation::from_remainder(Some(256 * 1024 * 1024), 0, 0)
                .unwrap();
        let mut prepared = PreparedClaudeLocalEvidence::load_paid_eligible(
            support,
            &index,
            ["scope"].into_iter(),
            &mut paid,
            0,
        )
        .expect("paid prepared read");
        assert_eq!(prepared.sessions, roots);
        assert!(prepared.frozen_roots_are_current(support, &roots));
        assert_eq!(
            prepared
                .take_api_for_sessions(support, &roots)
                .unwrap()
                .evidence,
            expected.0.evidence
        );
        assert_eq!(prepared.take_trace(support, "scope"), expected.1);
    });
}
