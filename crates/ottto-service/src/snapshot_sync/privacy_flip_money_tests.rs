// A Tail under a flipped setting or capability after a parse under the old one
// equals a Full under the new one, on the real E2 pipeline with two accounts
// placed, a side call and an evidence gap.
use super::money_equivalence_tests::{claude_change, claude_corpus, input_clock};
use super::state_v2_money_tests::{otel_rows, routed, second_account, tagged_api};
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;

/// Every input of the delivery context: the five settings, the cache
/// capability and the copy-unproven capability.
#[derive(Clone, Copy)]
struct Mode {
    policy: SnapshotUploadPolicy,
    cache: bool,
    copy: bool,
}

fn page_under(c: &Corpus, scanner: &E2ScanFixture, mut index: ScanIndex, mode: Mode) -> Page {
    let namespace = mode
        .policy
        .session_attribution_enabled
        .then_some("synthetic-key");
    let base = cycle_upload_context(mode.policy, namespace, mode.cache);
    index.activate_upload_context(copy_unproven_upload_context(
        resumed_prefix_upload_context(base.clone(), true),
        mode.copy,
    ));
    // As the prepare: finish writes copy rows under the active capability.
    index.copy_unproven_enabled = mode.copy;
    index.set_copy_prefix_base_upload_context(Some(base));
    index.activate_effective_upload_body_witness_revision(3);
    index.adopt_effective_upload_body_witness_revision_monotonically();
    index.load_claude_reemission_exclusions(&c.support);
    let committed = index.clone();
    let (index, scan, modes) = scanner.scan(
        std::slice::from_ref(&c.root),
        &c.support,
        index,
        100,
        true,
        &c.births,
        &[],
    );
    Page {
        cache: scanner.cache.clone(),
        committed,
        index,
        scan,
        modes,
        disposition: Default::default(),
        released: Default::default(),
        unhealthy: Default::default(),
        stats: Default::default(),
        delivered: None,
    }
}
/// A sibling session whose telemetry names no account: an evidence gap,
/// grown with the root.
fn evidence_gap(c: &mut Corpus, grown: bool) {
    let mut text = line(COPY, "gap-1", AT, 6);
    let mut rows = vec![api_for(COPY, "gap-1", 6, 60)];
    if grown {
        text += &line(COPY, "gap-2", AT, 7);
        rows.push(api_for(COPY, "gap-2", 7, 70));
    }
    let path = c.root(COPY, &text);
    c.evidence_for(COPY, &rows, &[]);
    input_clock(&path);
}
/// A telemetry-only request the root owns through its trace, on account b.
fn side_call(c: &Corpus) {
    let mut effort: Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence> =
        otel_rows(c, "claude-code-effort");
    let mut traces: Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence> =
        otel_rows(c, "claude-code-trace-ownership");
    effort.push(tagged_api("r-side", 5, Some(&"b".repeat(64))));
    traces.push(trace("r-side", ""));
    c.evidence(&effort, &traces);
}
fn settle(c: &Corpus, page: &mut Page, policy: SnapshotUploadPolicy) {
    page.enrich(c);
    crate::snapshots::apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut page.scan.snapshots,
        policy,
    );
    page.finish();
}

/// [money] T1 on the real pipeline, for every setting and capability bit in
/// both directions.
#[cfg(unix)]
#[test]
fn flipped_policy_tail_places_money_like_a_full() {
    if !crate::heap_layout_bound::layout_supported() {
        println!("PRIVACY_FLIP_MONEY UNEXECUTED: native retained layout unavailable");
        return;
    }
    let bits: [fn(&mut Mode) -> &mut bool; 7] = [
        |m| &mut m.policy.session_titles_enabled,
        |m| &mut m.policy.workspace_labels_enabled,
        |m| &mut m.policy.session_artifacts_enabled,
        |m| &mut m.policy.session_attribution_enabled,
        |m| &mut m.policy.session_attribution_labels_enabled,
        |m| &mut m.cache,
        |m| &mut m.copy,
    ];
    with_e2(|| {
        for (bit, field) in bits.into_iter().enumerate() {
            for start in [false, true] {
                let before = Mode {
                    policy: SnapshotUploadPolicy {
                        session_titles_enabled: start,
                        workspace_labels_enabled: start,
                        session_artifacts_enabled: start,
                        session_attribution_enabled: start,
                        session_attribution_labels_enabled: start,
                    },
                    cache: start,
                    copy: start,
                };
                let mut after = before;
                *field(&mut after) = !start;

                let (mut c, path) = claude_corpus("progressive_response");
                evidence_gap(&mut c, false);
                let scanner = E2ScanFixture::with_identity_capture(true);
                let mut warm = page_under(&c, &scanner, ScanIndex::default(), before);
                settle(&c, &mut warm, before.policy);
                claude_change(&c, &path, "progressive_response");
                second_account(&c, &path);
                side_call(&c);
                evidence_gap(&mut c, true);
                input_clock(&path);

                let mut tail = page_under(&c, &scanner, warm.index.clone(), after);
                settle(&c, &mut tail, after.policy);
                assert_eq!(tail.modes, (0, 2, 0), "bit {bit} from {start}");

                let fresh = E2ScanFixture::with_identity_capture(true);
                let mut cold = page_under(&c, &fresh, ScanIndex::default(), after);
                settle(&c, &mut cold, after.policy);
                assert_eq!(cold.modes.0, 2, "bit {bit} from {start}: control is a Full");
                let root = cold
                    .scan
                    .snapshots
                    .iter()
                    .find(|item| item.source_session_id == ROOT)
                    .unwrap();
                assert_eq!(
                    root.request_count, 4,
                    "positive control: three transcript requests and the side call"
                );
                assert!(
                    cold.scan
                        .snapshots
                        .iter()
                        .flat_map(|item| &item.usage_buckets)
                        .flat_map(|bucket| &bucket.model_usage)
                        .any(|row| row.account_identifier_hash.is_none()
                            && row.evidence_ref.is_none()
                            && row.identity_parts.is_none()),
                    "positive control: an evidence gap"
                );

                let accounts = tail
                    .scan
                    .snapshots
                    .iter()
                    .flat_map(|item| {
                        item.model_usage
                            .iter()
                            .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
                    })
                    .flat_map(|row| {
                        row.account_identifier_hash.iter().chain(
                            row.identity_parts
                                .iter()
                                .flatten()
                                .filter_map(|part| part.account_identifier_hash.as_ref()),
                        )
                    })
                    .collect::<BTreeSet<_>>();
                assert!(accounts.len() >= 2, "positive control: two accounts placed");
                let mut tampered = routed(&tail);
                let (cold, tail) = (routed(&cold), routed(&tail));
                assert_equivalent(&cold, &tail);
                let body = tampered.snapshots.values_mut().next().unwrap();
                body["input_tokens"] = json!(u32::MAX);
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        assert_equivalent(&cold, &tampered)
                    }))
                    .is_err(),
                    "positive control: the oracle sees a token difference"
                );
            }
        }
    });
}
