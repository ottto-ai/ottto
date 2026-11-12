//! Stored copy removals under partial census evidence.
use super::*;

/// [behaviour] Listed ids still prove fresh removals in identity-incomplete records.
#[test]
fn e2_pipeline_incomplete_holder_hits_prove_but_absences_are_flagged() {
    use crate::snapshots::claude_request_census::ClaudeRequestCensusShape::IdentityIncomplete;
    for unverified in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-lossy-positive");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let old = ScanIndex::default();
            let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
            let mut prior = settle(&c, &old, original, &mut e2_progress());
            e2::pipeline_test_observer::census_with_ids(
                &mut prior,
                &file(ROOT),
                &["a"],
                IdentityIncomplete,
                unverified,
            );
            c.write_at(
                &file(COPY),
                &resumed(COPY, &[A, B, C]),
                "2026-08-02T07:03:00Z",
            );
            e2::take_diag();
            let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
            let copy = body(&page, COPY).unwrap();
            assert_eq!(
                (copy.request_count, copy.removed_request_count),
                (2, Some(1))
            );
            assert_eq!(
                copy_diag(&["copy_prefix_unproven", "copy_removal_stored"]),
                [1, 1]
            );
        });
    }
}

/// [regress] Partial id lists cannot disprove saved removals, even when verified.
#[test]
fn e2_pipeline_partial_absence_never_invalidates_a_stored_removal() {
    use crate::snapshots::claude_request_census::ClaudeRequestCensusShape::{
        IdentityIncomplete, Lossy,
    };
    use crate::snapshots::sampled_scan::transition_fixture::money_oracle;
    for (shape, unverified, ids) in [
        (Lossy, false, &["b"][..]),
        (IdentityIncomplete, false, &["b"][..]),
        (IdentityIncomplete, true, &["b"][..]),
        (IdentityIncomplete, false, &["a", "b"][..]),
        (IdentityIncomplete, true, &["a", "b"][..]),
    ] {
        with_e2(|| {
            let mut c = Corpus::new("e2-pipeline-partial-stored");
            let mut prior = demo_family(&mut c, &mut e2_progress());
            let removals = canonical(&prior.claude_copy_removals);
            e2::pipeline_test_observer::retire_census(&mut prior, &file(COPY));
            append(
                &c.root.join(file(THIRD)),
                &line_by(THIRD, "e", "2026-08-02T07:06:20Z", 10, RESUME_WRITER),
            );
            // A complete census with the same saved removals is the cold control.
            let cold = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            for restart in [false, true] {
                let index = if restart {
                    c.reload(&mut prior)
                } else {
                    prior.clone()
                };
                let mut page = c.raw(&E2ScanFixture::default(), index, 100, !restart, &[]);
                // Acquisition may refresh the holder. Replace its census at the
                // decision boundary so every route sees the partial record.
                e2::pipeline_test_observer::census_with_ids(
                    &mut page.index,
                    &file(ROOT),
                    ids,
                    shape,
                    unverified,
                );
                e2::take_diag();
                page.enrich(&c);
                let page = deliver_page(page);
                let third = body(&page, THIRD).unwrap();
                assert_eq!(
                    (third.request_count, third.removed_request_count),
                    (2, Some(3))
                );
                assert_eq!(canonical(third), canonical(body(&cold, THIRD).unwrap()));
                assert_eq!(canonical(&page.index.claude_copy_removals), removals);
                assert_eq!(
                    copy_diag(&["copy_prefix_unproven", "copy_prefix_hold_expired"]),
                    [0, 0]
                );
                money_oracle::assert_equivalent(&sent_money(&cold), &sent_money(&page));
            }
        });
    }
}
