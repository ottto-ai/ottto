use super::*;

/// [money] A marker cannot turn a new destination's full claim into index loss.
/// Compare native bodies, upload membership and placement across both marker
/// states and the restart that used to be required to clear the false latch.
#[test]
fn first_read_latch_new_destination_full_claim_money_oracle() {
    use crate::snapshots::sampled_scan::transition_fixture::{
        money_oracle::assert_equivalent, scan_money,
    };
    crate::snapshots::with_claude_reemission_stop_restored_for_test(|| {
        let mut routes = Vec::new();
        for (number, marker, restart) in [(0, false, false), (1, true, false), (2, true, true)] {
            crate::snapshots::restart_claude_reemission_stop_for_test();
            let fixture = HistoryFixture::new(&format!("first-read-latch-full-{number}"));
            fixture.install_list(&[]);
            if marker {
                std::fs::write(
                    crate::snapshots::claude_reemission_seen_marker_path(&fixture.support),
                    b"",
                )
                .unwrap();
            }
            crate::backfill::apply_claim_backfill_policy_for_destination(
                &fixture.support,
                Some("full"),
                None,
                "same-user",
                Some("new-destination"),
            )
            .unwrap();
            if restart {
                crate::snapshots::restart_claude_reemission_stop_for_test();
            }
            assert!(
                !claude_destination_history_here(
                    &load_backfill_state(&fixture.support),
                    "new-destination",
                    &test_upload_progress(),
                    &fixture.index_path_for(Some("new-destination")),
                ),
                "a new claim has no completed, attested or quarantined history"
            );
            let outcome = fixture.cycle(
                "2026-08-02T09:00:00Z",
                HistoryCycle {
                    destination: Some("new-destination"),
                    bootstrapped: false,
                    ..HISTORY_CURRENT
                },
            );
            assert_eq!(outcome.uploaded.len(), HISTORY_SESSIONS.len());
            assert_eq!(
                crate::snapshots::claude_reemission_stop_reason_for_test(),
                "none"
            );
            routes.push(scan_money(
                SnapshotSource::ClaudeCode,
                &outcome.index,
                &outcome.scan,
            ));
        }
        for route in &routes[1..] {
            assert_equivalent(&routes[0], route);
        }
    });
}

/// [behaviour] Classification precedence and non-Claude sources cannot arm
/// a new stop; completed destinations, attested ledgers and quarantine still can.
#[test]
fn first_read_latch_destination_evidence_and_unverified_precedence() {
    use crate::snapshots::PriorHistory;
    crate::snapshots::with_claude_reemission_stop_restored_for_test(|| {
        let fixture = HistoryFixture::new("first-read-latch-evidence");
        std::fs::write(
            crate::snapshots::claude_reemission_seen_marker_path(&fixture.support),
            b"",
        )
        .unwrap();
        let mut state = crate::backfill::BackfillState::default();
        let mut progress = test_upload_progress();
        assert!(!claude_destination_history_here(
            &state,
            HISTORY_DESTINATION,
            &progress,
            &fixture.index_path
        ));
        state.prior_history_unverified = true;
        assert_eq!(
            claude_prior_history(
                &state,
                HISTORY_DESTINATION,
                &progress,
                &fixture.index_path,
                &fixture.support
            ),
            PriorHistory::Unverified
        );
        state.prior_history_unverified = false;
        crate::backfill::mark_backfill_complete_for_destination(
            &mut state,
            SnapshotSource::ClaudeCode,
            HISTORY_DESTINATION,
        );
        assert!(claude_destination_history_here(
            &state,
            HISTORY_DESTINATION,
            &progress,
            &fixture.index_path
        ));
        assert!(!claude_destination_history_here(
            &state,
            "other",
            &progress,
            &fixture.index_path
        ));
        progress.accepted_fingerprints.insert("f".repeat(64));
        assert!(claude_destination_history_here(
            &state,
            "other",
            &progress,
            &fixture.index_path
        ));
        for (source, fresh, expected) in [
            (SnapshotSource::Pi, true, "none"),
            (SnapshotSource::Codex, true, "none"),
            (SnapshotSource::ClaudeCode, false, "none"),
            (SnapshotSource::ClaudeCode, true, "index_rebuild_withheld"),
        ] {
            crate::snapshots::restart_claude_reemission_stop_for_test();
            note_claude_index_rebuild_for_destination(
                source,
                fresh,
                &state,
                HISTORY_DESTINATION,
                &progress,
                &fixture.index_path,
                &fixture.support,
            );
            assert_eq!(
                crate::snapshots::claude_reemission_stop_reason_for_test(),
                expected
            );
        }
        crate::snapshots::restart_claude_reemission_stop_for_test();
        fixture.install_list(&[]);
        fixture.baseline();
        fixture.corrupt_index();
        fixture.cycle("2026-08-02T09:00:00Z", HISTORY_CURRENT);
        assert_eq!(
            crate::snapshots::claude_reemission_stop_reason_for_test(),
            "index_rebuild_withheld",
            "quarantine with a marker still latches the rebuild stop"
        );
    });
}
