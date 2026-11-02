// A Tail under a flipped policy after a parse under the old one equals a Full
// under the new one, on the real E2 pipeline with two accounts placed.
use super::money_equivalence_tests::{claude_change, claude_corpus, input_clock};
use super::state_v2_money_tests::{routed, second_account};
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::money_oracle::assert_equivalent;

fn page_under(
    c: &Corpus,
    scanner: &E2ScanFixture,
    mut index: ScanIndex,
    policy: SnapshotUploadPolicy,
) -> Page {
    let namespace = policy
        .session_attribution_enabled
        .then_some("synthetic-key");
    index.set_upload_context_closure(std::sync::Arc::new(cycle_context_closure(
        namespace, None, false, true, false,
    )));
    index.activate_cycle_contexts(
        resumed_prefix_upload_context(cycle_upload_context(policy, namespace, false), true),
        cycle_acquisition_context(false, true, false),
    );
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
fn settle(c: &Corpus, page: &mut Page, policy: SnapshotUploadPolicy) {
    page.enrich(c);
    crate::snapshots::apply_upload_policy(
        SnapshotSource::ClaudeCode,
        &mut page.scan.snapshots,
        policy,
    );
    page.finish();
}

/// [money] T1 on the real pipeline, for every policy bit in both directions.
#[cfg(unix)]
#[test]
fn flipped_policy_tail_places_money_like_a_full() {
    if !crate::heap_layout_bound::layout_supported() {
        println!("PRIVACY_FLIP_MONEY UNEXECUTED: native retained layout unavailable");
        return;
    }
    let bits: [fn(&mut SnapshotUploadPolicy) -> &mut bool; 5] = [
        |p| &mut p.session_titles_enabled,
        |p| &mut p.workspace_labels_enabled,
        |p| &mut p.session_artifacts_enabled,
        |p| &mut p.session_attribution_enabled,
        |p| &mut p.session_attribution_labels_enabled,
    ];
    with_e2(|| {
        for (bit, field) in bits.into_iter().enumerate() {
            for start in [false, true] {
                let before = SnapshotUploadPolicy {
                    session_titles_enabled: start,
                    workspace_labels_enabled: start,
                    session_artifacts_enabled: start,
                    session_attribution_enabled: start,
                    session_attribution_labels_enabled: start,
                };
                let mut after = before;
                *field(&mut after) = !start;

                let (c, path) = claude_corpus("progressive_response");
                let scanner = E2ScanFixture::with_identity_capture(true);
                let mut warm = page_under(&c, &scanner, ScanIndex::default(), before);
                settle(&c, &mut warm, before);
                claude_change(&c, &path, "progressive_response");
                second_account(&c, &path);
                input_clock(&path);

                let mut tail = page_under(&c, &scanner, warm.index.clone(), after);
                settle(&c, &mut tail, after);
                assert_eq!(tail.modes, (0, 1, 0), "bit {bit} from {start}");

                let fresh = E2ScanFixture::with_identity_capture(true);
                let mut cold = page_under(&c, &fresh, ScanIndex::default(), after);
                settle(&c, &mut cold, after);
                assert_eq!(cold.modes.0, 1, "bit {bit} from {start}: control is a Full");

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
