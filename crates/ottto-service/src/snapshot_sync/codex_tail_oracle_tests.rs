//! Scan-level Codex Tail row on a real state database route: a restarted
//! owner's quiet pass over committed Codex heads consumes no transcript byte
//! and emits no body. The per-file money rows (cold Full == Tail restart ==
//! upgrade, totals and placement) are `tail_source::seam::transition_tests`.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture as fixture;
use crate::snapshots::scan_index_persistence::Source;
use crate::snapshots::StateV2ColdSession;

const SOURCE: SnapshotSource = SnapshotSource::Codex;
const A: &str = "019e5a00-0000-7000-8000-00000000000a";
const B: &str = "019e5a00-0000-7000-8000-00000000000b";

fn rollout(c: &Corpus, id: &str, account: &str, turns: u64) {
    let mut body = json!({"timestamp": "2026-10-27T07:00:00Z", "type": "session_meta",
        "payload": {"id": id, "timestamp": "2026-10-27T06:59:00Z",
        "creator_user_id": format!("synthetic-user-{account}"),
        "creator_account_id": format!("synthetic-workspace-{account}")}})
    .to_string()
        + "\n";
    for n in 1..=turns {
        body += &(json!({"timestamp": "2026-10-27T07:30:00Z", "type": "event_msg",
            "payload": {"type": "token_count", "info": {"model": "gpt-5.2",
            "total_token_usage": {"input_tokens": n * 100, "cached_input_tokens": n * 50,
                "output_tokens": n * 10},
            "last_token_usage": {"input_tokens": 100, "cached_input_tokens": 50,
                "output_tokens": 10}}}})
        .to_string()
            + "\n");
    }
    std::fs::write(
        c.root
            .join(format!("rollout-2026-10-27T07-00-00-{id}.jsonl")),
        body,
    )
    .unwrap();
}

/// One sampled Codex page through the scan, policy and finalization.
fn page(
    c: &Corpus,
    scanner: &E2ScanFixture,
    prior: ScanIndex,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let (mut index, mut scan, modes) = scanner.scan_other(
        SOURCE,
        std::slice::from_ref(&c.root),
        &c.support,
        prior,
        true,
    );
    index.bind_session_accounts(SOURCE, "e2-synthetic-machine", &mut scan.snapshots, &[]);
    apply_upload_policy(SOURCE, &mut scan.snapshots, SnapshotUploadPolicy::default());
    finalize_scan_after_policy(SOURCE, &mut scan, &mut index);
    scan.finish_codex_capture_boundary(&mut index);
    (index, scan, modes)
}

/// [money] A restarted owner's quiet pass over committed Codex heads on their
/// route reads no Full, consumes no transcript byte and emits no body.
#[test]
fn a_quiet_codex_restart_on_its_route_reads_zero_bytes() {
    let _cutover = crate::snapshots::TestCutover::set(0);
    let mut c = Corpus::new("codex-tail-quiet-restart");
    c.base = c.base.canonicalize().unwrap();
    c.root = c.base.join("projects");
    c.support = c.base.join("support");
    rollout(&c, A, "a", 3);
    rollout(&c, B, "b", 2);
    let (session, index) =
        StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &c.base.join("state"));
    let warm = E2ScanFixture::default();
    let (mut index, scan, modes) = page(&c, &warm, index);
    assert_eq!(modes.0, 2, "the first pass reads both files Full");
    assert_eq!(scan.snapshots.len(), 2);
    let accepted = scan
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    index.record_accepted_snapshot_fingerprints(&accepted);
    let prior = session.save_reload(&mut index);

    let restart = E2ScanFixture::default();
    let ((_, scan, modes), consumed) = fixture::observe_consumed(|| page(&c, &restart, prior));
    // The quiet-restart equivalent of the Claude route's row (`s2_oracle_tests`):
    // a restart may open a file to check its identity (the anchor read the
    // opened-object witness is), but reads no Full, consumes no transcript
    // byte and emits no body.
    assert_eq!(modes.0, 0, "quiet restart read Full");
    assert_eq!(consumed, 0, "quiet restart: no transcript consumption");
    assert!(
        scan.snapshots.is_empty(),
        "quiet restart emitted a new body"
    );
}
