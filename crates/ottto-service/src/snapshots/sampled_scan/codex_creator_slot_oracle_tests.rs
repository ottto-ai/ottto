// The Codex creator-slot naming row of the shared transition matrix. Included
// inside the money-equivalence pipeline fixture, so
// Corpus/Disk/other_page/other_wire are its native adapters.
use super::*;
use crate::codex_scan_diagnostics::CREATOR_NAMED;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Mode, RouteResult,
};
use serde_json::json;

/// [money] Codex sessions whose rows record no login mode, named from their
/// creator record by its single registered subscription slot, emit after a
/// restart (Codex keeps only its RAM reduction, so a new owner reads Full) and
/// on the warm RAM Tail what a cold Full emits, in totals and placement: each
/// named session's rows carry its matched slot's account, and a session whose
/// creator matches no slot stays untagged on every route. Control: swapped
/// account tags fail the comparator.
#[test]
fn shared_codex_creator_slot_naming_matches_cold_full() {
    if !supported("shared_codex_creator_slot_naming") {
        return;
    }
    const SECOND: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    const UNMATCHED: &str = "3338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let source = SnapshotSource::Codex;
    let _cutover = crate::snapshots::TestCutover::set(0);
    let hash = |kind: &str, session: &str| {
        let prefix = if kind == "account" {
            "user"
        } else {
            "workspace"
        };
        ottto_core::billing_identity_hash("openai", kind, &format!("synthetic-{prefix}-{session}"))
            .unwrap()
    };
    let slots = [ROOT, SECOND].map(|session| {
        (
            hash("account", session),
            hash("workspace", session),
            CREATOR_NAMED,
        )
    });
    let c = corpus("transition-codex-creator-slot");
    let mut disk = Disk::new(&c);
    // The session id in the file name lets each header's creator pair reach
    // the row as account evidence.
    let files = [ROOT, SECOND, UNMATCHED].map(|session| {
        let name = format!("rollout-2026-10-27T07-00-00-{session}.jsonl");
        (c.root.join(name), session)
    });
    let grow = |text: &str| {
        for (path, session) in &files {
            append(path, &text.replace(ROOT, session));
            input_clock(path);
        }
    };
    for (path, session) in &files {
        let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z",
            "payload":{"id":session,"timestamp":"2026-10-27T07:00:00Z",
            "creator_user_id":format!("synthetic-user-{session}"),
            "creator_account_id":format!("synthetic-workspace-{session}")}})
        .to_string()
            + "\n";
        std::fs::write(path, header).unwrap();
    }
    let page = |scanner: &E2ScanFixture, prior: ScanIndex| {
        other_page_with_slots(&c, scanner, source, prior, &slots, |_| {})
    };
    // Every row of each session carries exactly its matched slot's account.
    let assert_tags = |scan: &SourceScanResult, route: &str| {
        assert_eq!(scan.snapshots.len(), files.len(), "{route}");
        for item in &scan.snapshots {
            let expected = (item.source_session_id != UNMATCHED)
                .then(|| hash("account", &item.source_session_id));
            assert!(!item.model_usage.is_empty(), "{route}");
            for row in item.model_usage.iter().chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter()),
            ) {
                assert_eq!(row.account_identifier_hash, expected, "{route}");
                assert_eq!(row.auth_mode, None, "{route}: no login mode is written");
            }
        }
    };
    grow(&codex_rows("turn-a", 10));
    let scanner = disk.owner(source);
    let (mut live, first, modes) = page(&scanner, ScanIndex::default());
    assert_eq!(modes, (3, 0, 0));
    assert_tags(&first, "first Full");
    live.record_accepted_snapshot_fingerprints(
        &first
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect(),
    );
    let prior = disk.commit(&scanner.cache, source, &mut live);
    grow(&codex_rows("turn-b", 20));
    let (cold_index, cold_scan, cold_modes) = page(&E2ScanFixture::default(), prior.clone());
    assert_eq!(cold_modes, (3, 0, 0));
    let owner = disk.owner(source);
    let (restart_index, restart_scan, restart_modes) = page(&owner, prior.clone());
    assert_eq!(
        restart_modes,
        (3, 0, 0),
        "a restarted Codex owner reads Full"
    );
    disk.begin(&scanner, source);
    let (ram_index, ram_scan, ram_modes) = page(&scanner, prior.clone());
    assert_eq!(ram_modes, (0, 3, 0));
    for (scan, route) in [
        (&cold_scan, "cold Full"),
        (&restart_scan, "restarted Full"),
        (&ram_scan, "RAM Tail"),
    ] {
        assert_tags(scan, route);
    }
    let route = |mode, index: &ScanIndex, scan: &SourceScanResult| {
        let mut route = RouteResult::emitted(
            mode,
            source,
            vec![other_wire(source, scan)],
            &scan.snapshots,
        );
        route.codex_evidence = fixture::codex_evidence(index, scan);
        route
    };
    let cold = route(Mode::ColdFull, &cold_index, &cold_scan);
    let restart = route(Mode::Restart, &restart_index, &restart_scan);
    money_oracle::assert_equivalent(&cold, &restart);
    money_oracle::assert_equivalent(&cold, &route(Mode::Ram, &ram_index, &ram_scan));
    let mut wrong = restart.clone();
    for (session, other) in [(ROOT, SECOND), (SECOND, ROOT)] {
        for row in wrong.snapshots.get_mut(session).unwrap()["model_usage"]
            .as_array_mut()
            .unwrap()
        {
            row["account_identifier_hash"] = json!(hash("account", other));
        }
    }
    assert!(std::panic::catch_unwind(|| {
        money_oracle::assert_placement_equivalent(&cold, &wrong)
    })
    .is_err());
}
