// Included inside the money-equivalence fixture. One copy route through the
// production scan, settlement and reload: an accepted copy an earlier build
// decided keeps its decision (forward-only), and a listed holder never
// reverses a saved removal.
use super::*;

/// How the copy's settled prefix removal reached the growth page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Earlier {
    /// Settled before the cutoff by an earlier build: COPY-marked, accepted,
    /// nothing saved, and its origin no longer proves it.
    Grandfathered,
    /// Removed by request ids and saved: the holder proves it again.
    Saved,
    /// As `Grandfathered`, but every turn is after the cutoff.
    AfterCutoff,
}

/// ROOT (a, b) settles; COPY copies a, b and adds c, removes the prefix
/// and settles; then COPY grows by d. Returns the grown page's COPY
/// (requests, removed) and its (families corrected, unproven) counters.
fn grown_copy(arm: Earlier) -> ((u64, u64), Vec<u64>) {
    let day = if arm == Earlier::AfterCutoff {
        "2026-11-05"
    } else {
        "2026-08-02"
    };
    let at = |clock: &str| format!("{day}T{clock}Z");
    let (a, b, c_at, d_at) = (
        at("07:00:10"),
        at("07:00:20"),
        at("07:03:10"),
        at("07:06:10"),
    );
    let mut c = corpus(&format!("copy_route_earlier_{arm:?}"));
    let holder = c.root(
        ROOT,
        &resumed(
            ROOT,
            &[("a", a.as_str(), OLD_WRITER), ("b", b.as_str(), OLD_WRITER)],
        ),
    );
    input_clock(&holder);
    let old = ScanIndex::default();
    let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
    let mut progress = e2_progress();
    let prior = settle(&c, &old, original, &mut progress);
    let path = c.write_at(
        &file(COPY),
        &resumed(
            COPY,
            &[
                ("a", a.as_str(), OLD_WRITER),
                ("b", b.as_str(), OLD_WRITER),
                ("c", c_at.as_str(), RESUME_WRITER),
            ],
        ),
        &at("07:03:00"),
    );
    input_clock(&path);
    if arm != Earlier::AfterCutoff {
        // Loaded telemetry, so a corrected family counts.
        c.evidence_for(
            COPY,
            &[
                api_for(COPY, "a", 10, 100),
                api_for(COPY, "b", 10, 200),
                api_for(COPY, "c", 10, 300),
                api_for(COPY, "d", 10, 400),
            ],
            &[],
        );
    }
    let first = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
    let copy = body(&first, COPY).expect("the resume publishes");
    assert_eq!(
        (copy.request_count, copy.removed_request_count),
        (1, Some(2)),
        "{arm:?}: the accepted holder proves the prefix"
    );
    let mut prior = settle(&c, &prior, first, &mut progress);
    if arm != Earlier::Saved {
        // What an earlier build left: the settled COPY body and its marks,
        // no saved removal; the origin is listed, so it proves nothing new.
        prior.claude_copy_removals = Default::default();
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&c.support, &[ROOT]);
    }
    append(&path, &line_by(COPY, "d", &d_at, 10, RESUME_WRITER));
    input_clock(&path);
    e2::take_diag();
    let grown = ready(&c, &E2ScanFixture::default(), prior, 100, false);
    let copy = body(&grown, COPY).expect("the grown resume publishes");
    (
        (copy.request_count, copy.removed_request_count.unwrap_or(0)),
        copy_diag(&["copy_prefix_families_corrected", "copy_prefix_unproven"]),
    )
}

/// [money] Forward-only: an accepted copy settled before the cutoff keeps
/// its removed prefix as it grows, with no holder to prove it and without
/// counting as a newly corrected family; the same copy proven by a saved
/// removal is a corrected family; after the cutoff the request-id proof
/// alone decides, so the unproven prefix counts, flagged.
#[test]
fn accepted_pre_cutoff_copy_keeps_its_decision_through_growth() {
    with_e2(|| {
        for (arm, tuple, counters) in [
            (Earlier::Grandfathered, (2, 2), [0, 0]),
            (Earlier::Saved, (2, 2), [1, 0]),
            (Earlier::AfterCutoff, (4, 0), [0, 2]),
        ] {
            let (got, diag) = grown_copy(arm);
            assert_eq!(got, tuple, "{arm:?}");
            assert_eq!(diag, counters, "{arm:?}");
        }
    });
}

/// ROOT (a, b) settles; COPY (a, b, c) removes the prefix and settles;
/// `listed` puts ROOT's family on the re-emission list; COPY grows by d.
/// Returns the grown COPY body (without its source-file fingerprint) and
/// whether an unchanged page after its settlement sends COPY again.
fn grown_beside_holder(listed: bool) -> (serde_json::Value, bool) {
    let mut c = corpus("copy_route_listed_holder");
    let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
    input_clock(&holder);
    let old = ScanIndex::default();
    let original = ready(&c, &E2ScanFixture::default(), old.clone(), 100, false);
    let mut progress = e2_progress();
    let prior = settle(&c, &old, original, &mut progress);
    let path = c.write_at(
        &file(COPY),
        &resumed(COPY, &[A, B, C]),
        "2026-08-02T07:03:00Z",
    );
    input_clock(&path);
    let first = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
    assert_eq!(
        body(&first, COPY).map(|copy| copy.removed_request_count),
        Some(Some(2))
    );
    let prior = settle(&c, &prior, first, &mut progress);
    if listed {
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&c.support, &[ROOT]);
    }
    append(&path, &line_by(COPY, D.0, D.1, 10, D.2));
    input_clock(&path);
    let grown = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
    let copy = body(&grown, COPY).expect("the grown resume publishes");
    assert_eq!(
        (copy.request_count, copy.removed_request_count),
        (2, Some(2)),
        "listed {listed}: the saved removal stands"
    );
    let bytes = without_file_fingerprint(copy);
    let prior = settle(&c, &prior, grown, &mut progress);
    let quiet = ready(&c, &E2ScanFixture::default(), prior, 100, false);
    (bytes, body(&quiet, COPY).is_some())
}

/// [money] A saved removal whose holder family is then listed for
/// re-emission stays removed: the grown copy's body is byte-identical to
/// the unlisted one (no larger or smaller re-emit), and the next unchanged
/// page sends nothing for it.
#[test]
fn listed_holder_keeps_saved_removal_with_identical_body() {
    with_e2(|| {
        let (unlisted, unlisted_resent) = grown_beside_holder(false);
        let (listed, listed_resent) = grown_beside_holder(true);
        assert_eq!(listed, unlisted, "the listed holder changes no byte");
        assert!(!unlisted_resent && !listed_resent, "quiet after settlement");
    });
}
