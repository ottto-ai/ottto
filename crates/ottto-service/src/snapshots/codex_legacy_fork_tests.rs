// The Codex legacy user-fork row of the shared transition matrix. Included
// inside the money-equivalence pipeline fixture, so
// Corpus/Disk/other_page/other_wire are its native adapters.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    self as fixture, money_oracle, Mode, RouteResult,
};
use serde_json::json;

/// [regress] A legacy user fork (an ordinary user header naming
/// `forked_from_id`, no history base or ordinal) whose parent is absent counts
/// best effort: every usage line it holds, its copied parent prefix plus its
/// own suffix, is local. The copied usage may count twice with the parent's own
/// file; that residual is disclosed. Nothing waits on, reads or restarts for the
/// parent. A cold Full, a restarted owner over an older owner's quiet commit,
/// and the warm RAM Tail emit the same totals and placement; the ACK lands; a
/// quiet restart reads no byte and re-emits nothing. Control: two sessions on
/// two named accounts; swapped account tags fail the comparator.
#[test]
fn legacy_user_fork_without_parent_counts_best_effort() {
    if !supported("legacy_user_fork_without_parent") {
        return;
    }
    const SECOND: &str = "2338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    const CHILD: &str = "4338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    // Never written: the fork's parent is absent.
    const PARENT: &str = "5338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    let source = SnapshotSource::Codex;
    // 2026-10-25T00:00:00Z: the two named sessions start after it (V2), the
    // legacy fork before it (Legacy counting).
    let _cutover = crate::snapshots::TestCutover::set(1_792_886_400_000);
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
            crate::codex_scan_diagnostics::CREATOR_NAMED,
        )
    });
    let c = corpus("transition-codex-legacy-fork");
    let mut disk = Disk::new(&c);
    let named = [ROOT, SECOND].map(|session| {
        let name = format!("rollout-2026-10-27T07-00-00-{session}.jsonl");
        (c.root.join(name), session)
    });
    let child = c
        .root
        .join(format!("rollout-2026-10-20T07-00-00-{CHILD}.jsonl"));
    let lines = |values: &[serde_json::Value]| {
        values
            .iter()
            .map(|value| value.to_string() + "\n")
            .collect::<String>()
    };
    let usage = |at: &str, total: u64, last: u64| {
        let tokens = |input: u64| {
            json!({"input_tokens":input,"cached_input_tokens":0,"output_tokens":0,
                "reasoning_output_tokens":0,"total_tokens":input})
        };
        json!({"timestamp":at,"type":"event_msg","payload":{"type":"token_count","info":{
            "model":"gpt-5.2","total_token_usage":tokens(total),
            "last_token_usage":tokens(last)}}})
    };
    let turn = |at: &str, id: &str| {
        json!({"timestamp":at,"type":"turn_context",
            "payload":{"turn_id":id,"model":"gpt-5.2"}})
    };
    let grow = |turn_rows: &str, child_rows: &str| {
        for (path, session) in &named {
            append(path, &turn_rows.replace(ROOT, session));
            input_clock(path);
        }
        append(&child, child_rows);
        input_clock(&child);
    };
    for (path, session) in &named {
        let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z",
            "payload":{"id":session,"timestamp":"2026-10-27T07:00:00Z",
            "creator_user_id":format!("synthetic-user-{session}"),
            "creator_account_id":format!("synthetic-workspace-{session}")}})
        .to_string()
            + "\n";
        std::fs::write(path, header).unwrap();
    }
    // The copied parent prefix (100) precedes the fork's own suffix (15).
    std::fs::write(
        &child,
        lines(&[
            json!({"type":"session_meta","timestamp":"2026-10-20T07:00:00Z",
                "payload":{"id":CHILD,"timestamp":"2026-10-20T07:00:00Z",
                "forked_from_id":PARENT,"thread_source":"user"}}),
            turn("2026-10-19T07:00:01Z", "parent-turn"),
            usage("2026-10-19T07:00:02Z", 100, 100),
            turn("2026-10-20T07:00:01Z", "child-local"),
            usage("2026-10-20T07:00:02Z", 115, 15),
        ]),
    )
    .unwrap();
    let page = |scanner: &E2ScanFixture, prior: ScanIndex| {
        other_page_with_slots(&c, scanner, source, prior, &slots, |_| {})
    };
    let child_totals = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .find(|item| item.source_session_id == CHILD)
            .map(|item| (item.input_tokens, item.output_tokens, item.request_count))
    };
    // Every row of each named session carries exactly its slot's account; the
    // fork names no creator, so its rows stay untagged on every route.
    let assert_page = |scan: &SourceScanResult, route: &str| {
        assert_eq!(scan.snapshots.len(), 3, "{route}: the fork is not held");
        assert_eq!(scan.ownership_incomplete_file_count, 0, "{route}");
        for item in &scan.snapshots {
            let expected =
                (item.source_session_id != CHILD).then(|| hash("account", &item.source_session_id));
            assert!(!item.model_usage.is_empty(), "{route}");
            for row in item.model_usage.iter().chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter()),
            ) {
                assert_eq!(row.account_identifier_hash, expected, "{route}");
            }
        }
    };
    let accept = |index: &mut ScanIndex, scan: &SourceScanResult| {
        index.record_accepted_snapshot_fingerprints(
            &scan
                .snapshots
                .iter()
                .map(|s| s.snapshot_fingerprint.clone())
                .collect(),
        );
    };
    let acked = |index: &ScanIndex, scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .all(|s| index.accepted_snapshot_fingerprint_recorded(&s.snapshot_fingerprint))
    };
    grow(&codex_rows("turn-a", 10), "");
    let scanner = disk.owner(source);
    let (mut live, first, modes) = page(&scanner, ScanIndex::default());
    assert_eq!(modes, (3, 0, 0));
    assert_page(&first, "first Full");
    assert_eq!(child_totals(&first), Some((115, 0, 2)), "copied + suffix");
    accept(&mut live, &first);
    let prior = disk.commit(&scanner.cache, source, &mut live);
    assert!(acked(&prior, &first), "the first page's ACK is saved");
    // The older owner's quiet pass: nothing read, nothing re-emitted (no
    // smaller body), committed again.
    disk.begin(&scanner, source);
    let (mut quiet, quiet_scan, quiet_modes) = page(&scanner, prior.clone());
    assert_eq!(quiet_modes.0 + quiet_modes.1, 0, "the fork is not re-read");
    assert!(quiet_scan.snapshots.is_empty(), "no re-emission");
    let committed = disk.commit(&scanner.cache, source, &mut quiet);
    assert!(committed.generation > prior.generation);
    assert!(acked(&committed, &first), "the quiet commit keeps the ACK");
    grow(
        &codex_rows("turn-b", 20),
        &lines(&[
            turn("2026-10-20T07:10:01Z", "child-later"),
            usage("2026-10-20T07:10:02Z", 140, 25),
        ]),
    );
    let (cold_index, cold_scan, cold_modes) = page(&E2ScanFixture::default(), committed.clone());
    assert_eq!(cold_modes, (3, 0, 0));
    // A restarted (or upgraded) owner over the older owner's commit.
    let owner = disk.owner(source);
    let (restart_index, restart_scan, restart_modes) = page(&owner, committed.clone());
    assert_eq!(
        restart_modes,
        (3, 0, 0),
        "a restarted Codex owner reads Full"
    );
    disk.begin(&scanner, source);
    let (mut ram_index, ram_scan, ram_modes) = page(&scanner, committed.clone());
    assert_eq!(ram_modes, (0, 3, 0), "the fork Tails like any file");
    for (scan, route) in [
        (&cold_scan, "cold Full"),
        (&restart_scan, "restarted Full"),
        (&ram_scan, "RAM Tail"),
    ] {
        assert_page(scan, route);
        assert_eq!(child_totals(scan), Some((140, 0, 3)), "{route}");
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
    let ram = route(Mode::Ram, &ram_index, &ram_scan);
    money_oracle::assert_equivalent(&cold, &restart);
    money_oracle::assert_equivalent(&cold, &ram);
    money_oracle::assert_no_smaller_reemit(CHILD, &cold, &ram, &cold, false);
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
    // The RAM page's ACK lands; a restart over it is quiet: no byte read,
    // no file opened, no body emitted.
    accept(&mut ram_index, &ram_scan);
    let settled = disk.commit(&scanner.cache, source, &mut ram_index);
    assert!(acked(&settled, &ram_scan), "the grown page's ACK is saved");
    let restarted = disk.owner(source);
    let opens = crate::snapshots::all_transcript_opens_for_test();
    let ((_, quiet_restart, quiet_modes), consumed) =
        fixture::observe_consumed(|| page(&restarted, settled));
    assert!(quiet_restart.snapshots.is_empty(), "no re-emission");
    let measured = (crate::snapshots::all_transcript_opens_for_test() == opens).then_some(0);
    let mut quiet = RouteResult::emitted(Mode::Restart, source, Vec::new(), &[]);
    quiet.modes = quiet_modes;
    quiet.io = fixture::IoBytes {
        consumed,
        cheap_checks: measured,
        anchor_reads: measured,
        other_reads: measured,
        ..Default::default()
    };
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
}
