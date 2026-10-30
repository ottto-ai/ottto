// E2 (T4): the authority disposition of request-owned bodies. A family whose
// exclusive reported body was proven before E2 must reach upload with its
// request-owned body; account and E2 withheld holds still apply.
use super::*;

const CHILD_AGENT: &str = "a4d1585d310070d0f";

struct Proven {
    parent: String,
    api: crate::claude_local_otel::ClaudeLocalOtelLoadReport,
    trace: crate::claude_local_otel::ClaudeTraceOwnershipLoadReport,
    index: ScanIndex,
}

/// The family proven by today's reported fold (gate off), as on a Mac
/// before the switch-on.
fn proven_family() -> Proven {
    let (root, parent, mut items) = claude_account_family_fixture();
    let mut api_rows = (1..=4)
        .map(|n| complete_api_row(&parent, &format!("req_{n}"), n, 10, 10, 0))
        .collect::<Vec<_>>();
    api_rows.push(complete_api_row(&parent, "req_5", 5, 10, 1, 0));
    let mut trace_rows = (1..=4)
        .map(|n| complete_trace_row(&parent, &format!("req_{n}"), ""))
        .collect::<Vec<_>>();
    trace_rows.push(complete_trace_row(&parent, "req_5", CHILD_AGENT));
    let api = crate::claude_local_otel::ClaudeLocalOtelLoadReport {
        evidence: BTreeMap::from([(parent.clone(), api_rows)]),
        health: Default::default(),
    };
    let trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport {
        evidence: BTreeMap::from([(parent.clone(), trace_rows)]),
        ..Default::default()
    };
    let mut index = ScanIndex::default();
    index.files.insert(
        local_index_key(&root.join(format!("{parent}.jsonl"))),
        manifest_index_entry(None),
    );
    index.files.insert(
        local_index_key(
            &root
                .join(&parent)
                .join("subagents")
                .join(format!("agent-{CHILD_AGENT}.jsonl")),
        ),
        manifest_index_entry(None),
    );
    apply_claude_reported_usage_with_index(
        &mut items,
        &api,
        &trace,
        &mut index,
        true,
        "2026-08-02T07:10:00Z",
    );
    assert!(index.claude_usage_family_witnesses.contains_key(&parent));
    Proven {
        parent,
        api,
        trace,
        index,
    }
}

fn child_page(
    proven: &mut Proven,
    healthy: bool,
) -> (Vec<SnapshotItem>, ClaudeUsageAuthorityDisposition) {
    let (_, _, mut reparsed) = claude_account_family_fixture();
    let mut child = vec![reparsed.remove(1)];
    let mut trace = proven.trace.clone();
    if !healthy {
        trace.malformed_lines = 1;
    }
    let disposition = apply_claude_reported_usage_with_index(
        &mut child,
        &proven.api,
        &trace,
        &mut proven.index,
        false,
        "2026-08-02T07:11:00Z",
    );
    (child, disposition)
}

#[test]
fn e2_body_of_previously_proven_family_is_not_a_demotion() {
    for healthy in [true, false] {
        // Today (gate off): an unreconstructable revision is a demotion and
        // is held; a healthy one rebuilds the exclusive body.
        let mut proven = proven_family();
        let (child, disposition) =
            claude_request_money::e2::with_disabled(|| child_page(&mut proven, healthy));
        assert_eq!(
            disposition.quarantined_entity_count(),
            usize::from(!healthy),
            "gate off keeps today's disposition (healthy={healthy})"
        );
        assert_eq!(
            child[0].usage_accounting_contract.is_some(),
            healthy,
            "gate off rebuilds the exclusive body only from healthy reports"
        );

        // Gate on: the same revision is a request-owned body. The old
        // reported rebuild is skipped for it, and it is not a demotion: it
        // reaches upload selection whatever the reports' health.
        let mut proven = proven_family();
        claude_request_money::e2::with_enabled(|| {
            let (mut child, disposition) = child_page(&mut proven, healthy);
            assert!(
                child[0].claude_money.is_some(),
                "the E2 fold rides on the item"
            );
            assert_eq!(
                child[0].usage_accounting_contract, None,
                "the literal is installed later by e2::finish_page"
            );
            assert_eq!(
                disposition.quarantined_entity_count(),
                0,
                "healthy={healthy}"
            );
            assert!(
                proven
                    .index
                    .claude_usage_family_witnesses
                    .contains_key(&proven.parent),
                "the proven witness is kept for the fence"
            );
            let session = child[0].source_session_id.clone();
            let mut uploadable = child.clone();
            disposition.retain_uploadable(&mut uploadable);
            assert_eq!(uploadable.len(), 1, "it reaches upload (healthy={healthy})");

            // An account deferral still holds it.
            let mut deferred = disposition.clone();
            deferred.defer_sessions(BTreeSet::from([session.clone()]));
            let mut uploadable = child.clone();
            deferred.retain_uploadable(&mut uploadable);
            assert!(uploadable.is_empty(), "account hold survives");

            // An E2 withheld entity (held twin, uncertified, unread
            // telemetry) is held, not dropped: its body stays on the page,
            // never uploads, and blocks progress so the file is read again.
            let mut withheld = disposition;
            withheld.hold_request_owned(BTreeSet::from([session]));
            let fingerprint = child[0].snapshot_fingerprint.clone();
            assert!(withheld
                .quarantined_fingerprints(&child)
                .contains(&fingerprint));
            assert!(
                withheld
                    .progress_blocking_held_fingerprints(&child, &proven.index, true)
                    .contains(&fingerprint),
                "delayed, never settled without its body"
            );
            assert!(withheld.account_deferred_fingerprints(&child).is_empty());
            withheld.retain_uploadable(&mut child);
            assert!(child.is_empty());
        });
    }
}

#[test]
fn terminal_off_on_e2_body_of_previously_proven_family_is_not_a_demotion() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    let _completion_paths = crate::snapshots::ClaudeCompletionPathsForTest::enable();
    for healthy in [true, false] {
        // Today (gate off): an unreconstructable revision is a demotion and
        // is held; a healthy one rebuilds the exclusive body.
        let mut proven = proven_family();
        let (child, disposition) =
            claude_request_money::e2::with_disabled(|| child_page(&mut proven, healthy));
        assert_eq!(
            disposition.quarantined_entity_count(),
            usize::from(!healthy),
            "gate off keeps today's disposition (healthy={healthy})"
        );
        assert_eq!(
            child[0].usage_accounting_contract.is_some(),
            healthy,
            "gate off rebuilds the exclusive body only from healthy reports"
        );

        // Gate on: the same revision is a request-owned body. The old
        // reported rebuild is skipped for it, and it is not a demotion: it
        // reaches upload selection whatever the reports' health.
        let mut proven = proven_family();
        claude_request_money::e2::with_enabled(|| {
            let (mut child, disposition) = child_page(&mut proven, healthy);
            assert!(
                child[0].claude_money.is_some(),
                "the E2 fold rides on the item"
            );
            assert_eq!(
                child[0].usage_accounting_contract, None,
                "the literal is installed later by e2::finish_page"
            );
            assert_eq!(
                disposition.quarantined_entity_count(),
                0,
                "healthy={healthy}"
            );
            assert!(
                proven
                    .index
                    .claude_usage_family_witnesses
                    .contains_key(&proven.parent),
                "the proven witness is kept for the fence"
            );
            let session = child[0].source_session_id.clone();
            let mut uploadable = child.clone();
            disposition.retain_uploadable(&mut uploadable);
            assert_eq!(uploadable.len(), 1, "it reaches upload (healthy={healthy})");

            // An account deferral still holds it.
            let mut deferred = disposition.clone();
            deferred.defer_sessions(BTreeSet::from([session.clone()]));
            let mut uploadable = child.clone();
            deferred.retain_uploadable(&mut uploadable);
            assert!(uploadable.is_empty(), "account hold survives");

            // An E2 withheld entity (held twin, uncertified, unread
            // telemetry) is held, not dropped: its body stays on the page,
            // never uploads, and blocks progress so the file is read again.
            let mut withheld = disposition;
            withheld.hold_request_owned(BTreeSet::from([session]));
            let fingerprint = child[0].snapshot_fingerprint.clone();
            assert!(withheld
                .quarantined_fingerprints(&child)
                .contains(&fingerprint));
            assert!(
                withheld
                    .progress_blocking_held_fingerprints(&child, &proven.index, true)
                    .contains(&fingerprint),
                "delayed, never settled without its body"
            );
            assert!(withheld.account_deferred_fingerprints(&child).is_empty());
            withheld.retain_uploadable(&mut child);
            assert!(child.is_empty());
        });
    }
}

#[test]
fn money_cache_creation_normalizer_has_one_reading_for_every_caller() {
    use crate::snapshots::claude_request_money::{claude_cache_creation, CacheCreation::*};
    for (total, five_m, one_h, expected) in [
        (0, 0, 0, Unattributed(0)),
        (100, 0, 0, Unattributed(100)),
        (
            0,
            5,
            6,
            Split {
                five_m: 5,
                one_h: 6,
            },
        ),
        (
            11,
            5,
            6,
            Split {
                five_m: 5,
                one_h: 6,
            },
        ),
        (12, 5, 6, Contradictory),
        (0, u64::MAX, 1, Contradictory),
    ] {
        assert_eq!(
            claude_cache_creation(total, five_m, one_h),
            expected,
            "{total} {five_m} {one_h}"
        );
    }
    // The transcript reading: a stated split wins even when the flat total
    // disagrees; a flat-only write is the default (5m) TTL.
    for (usage, expected) in [
        (
            serde_json::json!({"cache_creation_input_tokens": 9}),
            (9, 0),
        ),
        (
            serde_json::json!({"cache_creation_input_tokens": 9,
                "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0}}),
            (9, 0),
        ),
        (
            serde_json::json!({"cache_creation_input_tokens": 12,
                "cache_creation": {"ephemeral_5m_input_tokens": 5, "ephemeral_1h_input_tokens": 6}}),
            (5, 6),
        ),
        (
            serde_json::json!({"cacheCreation": {"ephemeral5mInputTokens": 2, "ephemeral1hInputTokens": 3}}),
            (2, 3),
        ),
        (serde_json::json!({}), (0, 0)),
    ] {
        assert_eq!(
            claude_code_cache_creation_split(&usage),
            expected,
            "{usage}"
        );
    }
    // The API row reading: a contradiction cannot authorize usage.
    let row = |total, five_m, one_h| crate::claude_local_otel::ClaudeLocalOtelEvidence {
        cache_creation_tokens: total,
        cache_creation_5m_tokens: five_m,
        cache_creation_1h_tokens: one_h,
        ..Default::default()
    };
    assert_eq!(claude_api_cache_creation(&row(7, 0, 0)), Some((0, 0, 7)));
    assert_eq!(claude_api_cache_creation(&row(0, 3, 4)), Some((3, 4, 0)));
    assert_eq!(claude_api_cache_creation(&row(7, 3, 4)), Some((3, 4, 0)));
    assert_eq!(claude_api_cache_creation(&row(8, 3, 4)), None);
}

#[test]
fn terminal_off_on_money_cache_creation_normalizer_has_one_reading_for_every_caller() {
    let _terminal_off = crate::snapshots::ClaudeTerminalOffForTest::enabled();

    use crate::snapshots::claude_request_money::{claude_cache_creation, CacheCreation::*};
    for (total, five_m, one_h, expected) in [
        (0, 0, 0, Unattributed(0)),
        (100, 0, 0, Unattributed(100)),
        (
            0,
            5,
            6,
            Split {
                five_m: 5,
                one_h: 6,
            },
        ),
        (
            11,
            5,
            6,
            Split {
                five_m: 5,
                one_h: 6,
            },
        ),
        (12, 5, 6, Contradictory),
        (0, u64::MAX, 1, Contradictory),
    ] {
        assert_eq!(
            claude_cache_creation(total, five_m, one_h),
            expected,
            "{total} {five_m} {one_h}"
        );
    }
    // The transcript reading: a stated split wins even when the flat total
    // disagrees; a flat-only write is the default (5m) TTL.
    for (usage, expected) in [
        (
            serde_json::json!({"cache_creation_input_tokens": 9}),
            (9, 0),
        ),
        (
            serde_json::json!({"cache_creation_input_tokens": 9,
                "cache_creation": {"ephemeral_5m_input_tokens": 0, "ephemeral_1h_input_tokens": 0}}),
            (9, 0),
        ),
        (
            serde_json::json!({"cache_creation_input_tokens": 12,
                "cache_creation": {"ephemeral_5m_input_tokens": 5, "ephemeral_1h_input_tokens": 6}}),
            (5, 6),
        ),
        (
            serde_json::json!({"cacheCreation": {"ephemeral5mInputTokens": 2, "ephemeral1hInputTokens": 3}}),
            (2, 3),
        ),
        (serde_json::json!({}), (0, 0)),
    ] {
        assert_eq!(
            claude_code_cache_creation_split(&usage),
            expected,
            "{usage}"
        );
    }
    // The API row reading: a contradiction cannot authorize usage.
    let row = |total, five_m, one_h| crate::claude_local_otel::ClaudeLocalOtelEvidence {
        cache_creation_tokens: total,
        cache_creation_5m_tokens: five_m,
        cache_creation_1h_tokens: one_h,
        ..Default::default()
    };
    assert_eq!(claude_api_cache_creation(&row(7, 0, 0)), Some((0, 0, 7)));
    assert_eq!(claude_api_cache_creation(&row(0, 3, 4)), Some((3, 4, 0)));
    assert_eq!(claude_api_cache_creation(&row(7, 3, 4)), Some((3, 4, 0)));
    assert_eq!(claude_api_cache_creation(&row(8, 3, 4)), None);
}
