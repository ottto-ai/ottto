//! Copied files use accepted origins, across sessions and folders.
use super::*;
use crate::snapshots::claude_money_birth_store::location_key;
use crate::snapshots::e2_pipeline_scan_fixture::{
    accepted_file_for_test, origin_accepted_for_test, own_install_for_test,
    upload_context_proof_is_current_for_test,
};
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle, observe_consumed, Mode, RouteResult,
};

const BORN: &str = "2026-08-02T07:03:00Z";

fn warm(c: &Corpus) -> ScanIndex {
    let old = ScanIndex::default();
    let original = ready(c, &E2ScanFixture::default(), old.clone(), 100, false);
    settle(c, &old, original, &mut e2_progress())
}
fn owe(index: &mut ScanIndex) {
    index.activate_effective_upload_body_witness_revision(3);
    for key in index.files.keys().cloned().collect::<Vec<_>>() {
        index.re_owe_effective_upload_body_witness_revision(&key, 2);
    }
}
fn captured(page: &Page, mode: Mode) -> RouteResult {
    let mut progress = e2_progress();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let (status, wire, _) = upload(&page.scan.snapshots, &mut progress, ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let mut result =
        RouteResult::emitted(mode, SnapshotSource::ClaudeCode, wire, &page.scan.snapshots);
    result.modes = page.modes;
    result.accepted_identity_buckets = Some(
        serde_json::to_value(
            page.scan
                .snapshots
                .iter()
                .map(|item| {
                    (
                        &item.source_session_id,
                        progress
                            .accepted_identity_buckets
                            .get(&item.source_session_id),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        )
        .unwrap(),
    );
    result
}

/// [money] Copies count once. Filename-only copies still drop; content-only
/// pages wait for their main. Appending an own turn counts immediately.
#[test]
fn copied_content_and_path_twins_count_once() {
    for content in [true, false] {
        with_e2(|| {
            let mut c = Corpus::new("copied-session-twins");
            c.root(ROOT, &resumed(ROOT, &[A, B]));
            let mut prior = warm(&c);
            let relative = if content {
                file(COPY)
            } else {
                format!("other/{ROOT}.jsonl")
            };
            let copy = c.write_at(&relative, &resumed(ROOT, &[A, B]), BORN);
            let copy_key = copy.to_string_lossy().into_owned();
            owe(&mut prior);
            let mut page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            assert_eq!(
                body(&page, ROOT).unwrap().request_count,
                2,
                "copied history counted twice"
            );
            assert_eq!(body(&page, ROOT).unwrap().removed_request_count, Some(2));
            prior = settle(&c, &prior, page, &mut e2_progress());
            for _ in 0..4 {
                owe(&mut prior);
                // Isolate the selected twin after native acquisition to prove
                // page composition independently from the read closure.
                page = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
                let fingerprint = page.index.files[&copy_key].source_file_fingerprint.clone();
                page.scan.snapshots.retain(|item| {
                    item.source_file_fingerprint.as_deref() == Some(fingerprint.as_str())
                });
                page.enrich(&c);
                if content {
                    assert!(body(&page, ROOT).is_some(), "content-held items stay owed");
                    assert_eq!(
                        page.disposition
                            .request_owned_hold_reasons
                            .get("absent_content_twin"),
                        Some(&1)
                    );
                } else {
                    assert!(
                        page.scan.snapshots.is_empty(),
                        "filename copies still drop without a hold"
                    );
                }
                assert_eq!(
                    page.disposition.quarantined_entity_count(),
                    usize::from(content)
                );
                assert!(!page
                    .index
                    .claude_copy_removals
                    .pending(location_key(&copy_key)));
                assert_eq!(
                    page.index
                        .claude_copy_removals
                        .get(location_key(&copy_key))
                        .iter()
                        .map(|(_, ids)| ids.len())
                        .sum::<usize>(),
                    2
                );
                // Persist the decision without finalizing files whose
                // snapshots this composition arm deliberately filtered out.
                prior = c.reload(&mut page.index);
            }
            append(&copy, &resumed(ROOT, &[C]));
            owe(&mut prior);
            let mut grown = c.raw(&E2ScanFixture::default(), prior, 100, false, &[copy]);
            grown.enrich(&c);
            assert_eq!(body(&grown, ROOT).unwrap().request_count, 3);
            assert_eq!(body(&grown, ROOT).unwrap().removed_request_count, Some(2));
        });
    }
}

/// [money] The in-folder unaccepted twin leads to the accepted original in
/// another folder. Three decisions and a restart never restore its prefix.
#[test]
fn resumed_file_uses_the_in_folder_holders_session() {
    with_e2(|| {
        let mut c = Corpus::new("resume-holder-session");
        c.write_at(
            &format!("original/{ROOT}.jsonl"),
            &resumed(ROOT, &[A, B]),
            "2026-08-02T07:00:00Z",
        );
        let mut prior = warm(&c);
        c.write_at(
            &format!("resume/{ROOT}.jsonl"),
            &resumed(ROOT, &[A, B]),
            "2026-08-02T07:02:00Z",
        );
        let first = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        prior = settle(&c, &prior, first, &mut e2_progress());
        let copy = c.write_at(
            &format!("resume/{COPY}.jsonl"),
            &resumed(COPY, &[A, B, C]),
            BORN,
        );
        for _ in 0..4 {
            owe(&mut prior);
            let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            let item = body(&page, COPY).unwrap();
            assert_eq!(
                (item.request_count, item.removed_request_count),
                (1, Some(2))
            );
            assert!(!page
                .index
                .claude_copy_removals
                .pending(location_key(&copy.to_string_lossy())));
            prior = settle(&c, &prior, page, &mut e2_progress());
        }
    });
}

/// [money] Distinct same-session turns count. A stored removal on an accepted
/// intermediate copy cannot prove another copy after the origin disappears.
#[test]
fn distinct_same_session_file_counts_and_copies_never_prove_copies() {
    with_e2(|| {
        let mut c = Corpus::new("distinct-session-file");
        let origin = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut prior = warm(&c);
        c.write_at(&file(COPY), &resumed(ROOT, &[C]), BORN);
        owe(&mut prior);
        let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        assert_eq!(body(&page, ROOT).unwrap().request_count, 3);
        prior = settle(&c, &prior, page, &mut e2_progress());
        // The accepted origin itself stores A as a removal: it is no longer
        // an origin for A, even though its positive census still contains A.
        let origin_key = origin.to_string_lossy().into_owned();
        prior.claude_copy_removals.store(
            location_key(&origin_key),
            BTreeMap::from([(
                location_key("absent-original"),
                BTreeSet::from([crate::snapshots::claude_request_census::claude_request_hash("a")]),
            )]),
        );
        origin_accepted_for_test(&mut prior, &origin_key);
        // Model the accepted original and the intermediate body's new counted
        // contribution explicitly; the receipt alone carries neither hash set.
        crate::snapshots::e2_pipeline_scan_fixture::accepted_origin_hashes_for_test(
            &mut prior,
            "absent-original",
            "absent-original",
            &[crate::snapshots::claude_request_census::claude_request_hash("a")],
        );
        crate::snapshots::e2_pipeline_scan_fixture::accepted_origin_hashes_for_test(
            &mut prior,
            &origin_key,
            ROOT,
            &[crate::snapshots::claude_request_census::claude_request_hash("b")],
        );
        c.write_at(&file(THIRD), &resumed(THIRD, &[A, D]), BORN);
        owe(&mut prior);
        let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        assert_eq!(body(&page, THIRD).unwrap().request_count, 2);
        assert_eq!(body(&page, THIRD).unwrap().removed_request_count, Some(0));
    });
}

/// [money] A page that reads only the original also reads the copied file it
/// proves, after the copy carried the session: the session keeps the copy's
/// own turn (row one), and an all-copy file adds nothing (row two).
#[test]
fn holder_only_page_brings_its_content_twin() {
    // The copy sorts first: wherever both are read it is read first and
    // carries the session, and its own pull brings the original.
    const FIRST: &str = "0338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    for own in [true, false] {
        with_e2(|| {
            let mut c = Corpus::new("holder-brings-content-twin");
            let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
            let mut prior = warm(&c);
            let twin = c.write_at(&file(FIRST), &resumed(ROOT, &[A, B]), BORN);
            owe(&mut prior);
            let both = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            assert_eq!(body(&both, ROOT).unwrap().request_count, 2);
            prior = settle(&c, &prior, both, &mut e2_progress());
            if own {
                // Copy-seeded: only the copy changed; it carries the session.
                append(&twin, &resumed(ROOT, &[C]));
                let copy = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
                assert_eq!(body(&copy, ROOT).unwrap().request_count, 3);
                prior = settle(&c, &prior, copy, &mut e2_progress());
            }
            // Only the original changes.
            append(&holder, &resumed(ROOT, &[D]));
            let expected = 3 + u64::from(own);
            let scanner = E2ScanFixture::default();
            let mut again = own_install_for_test(&prior, &c.base);
            let seeded = ready(&c, &scanner, prior.clone(), 100, false);
            assert_eq!(
                body(&seeded, ROOT).unwrap().request_count,
                expected,
                "the copy's own turn stays counted"
            );
            // Reference: the owed copy is read first and its pull brings the
            // original, the composition of a copy-seeded page.
            again.activate_effective_upload_body_witness_revision(3);
            assert!(again.re_owe_effective_upload_body_witness_revision(&twin.to_string_lossy(), 2));
            let reference = ready(&c, &E2ScanFixture::default(), again, 100, false);
            assert_eq!(body(&reference, ROOT).unwrap().request_count, expected);
            money_oracle::assert_equivalent(&sent_money(&reference), &sent_money(&seeded));
            if own {
                assert!(
                    scanner.paths().contains(&twin),
                    "the original brings its copy"
                );
            }
        });
    }
}

// Finalize and settle real ACKs, observing each whole-session replacement.
fn accept_monotone_page(
    c: &Corpus,
    committed: &ScanIndex,
    mut page: Page,
    accepted: &mut BTreeMap<String, u64>,
) -> ScanIndex {
    let holds = page.finish();
    accept_finished_monotone_page(c, committed, page, accepted, holds)
}

// Keep the classification from the one finish, before it removes held bodies.
fn accept_finished_monotone_page(
    c: &Corpus,
    committed: &ScanIndex,
    page: Page,
    accepted: &mut BTreeMap<String, u64>,
    holds: LocalHoldSettlement,
) -> ScanIndex {
    let sent = page.scan.snapshots.clone();
    let mut progress = e2_progress();
    let (status, _, _) = upload(&sent, &mut progress, |items| {
        let response = ack(items);
        for item in items {
            let count = accepted.entry(item.source_session_id.clone()).or_default();
            assert!(
                item.request_count >= *count,
                "an ACK must not shrink a session"
            );
            *count = item.request_count;
        }
        response
    });
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let mut settled = settle_completed_upload(page.index, committed, &progress, &holds);
    settle_index_after_upload(&mut settled.index, committed, &progress);
    accept_upload_context_acks_for_test(
        &mut settled.index,
        &sent,
        &progress.fresh_context_body_acks,
    );
    c.reload(&mut settled.index)
}

/// [money] An old ACK cannot own a newly observed request when its holder
/// disappears before that request reaches the receiver; real coverage survives.
#[test]
// The permanent refusal records Poisoned in the shared client_report counters.
#[serial(client_report)]
fn old_ack_does_not_own_new_request_after_holder_loss() {
    use crate::snapshots::claude_request_census::claude_request_hash;
    use crate::snapshots::e2_pipeline_scan_fixture::owe_claimed_growth;

    // Separate hours make the receiver's literal bucket counts an independent
    // per-request oracle, without consulting the saved copy-removal decisions.
    type Receiver = BTreeMap<String, BTreeMap<String, u64>>;
    fn record(receiver: &mut Receiver, item: &SnapshotItem) {
        let hours = item
            .usage_buckets
            .iter()
            .map(|bucket| {
                (
                    bucket.bucket_start[..13].to_owned(),
                    bucket.model_usage.iter().map(|row| row.request_count).sum(),
                )
            })
            .collect::<BTreeMap<String, u64>>();
        assert_eq!(hours.values().sum::<u64>(), item.request_count);
        receiver.insert(item.source_session_id.clone(), hours);
    }
    fn accept(
        c: &Corpus,
        committed: &ScanIndex,
        mut page: Page,
        accepted: &mut BTreeMap<String, u64>,
        receiver: &mut Receiver,
    ) -> ScanIndex {
        let holds = page.finish();
        let sent = page.scan.snapshots.clone();
        let index = accept_finished_monotone_page(c, committed, page, accepted, holds);
        for item in &sent {
            record(receiver, item);
        }
        index
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Arm {
        Refused,
        ContentHeld,
        Accepted,
    }
    let mut missing = Vec::new();
    for arm in [
        Arm::Refused,     // Expected red on main: the old ACK does not cover b.
        Arm::ContentHeld, // Expected red on main: the held append never delivers b.
        Arm::Accepted,    // Expected green on main: the new ACK really covers b.
    ] {
        if arm == Arm::ContentHeld && !crate::heap_layout_bound::layout_supported() {
            continue;
        }
        with_e2(|| {
            let mut c = Corpus::new("old-ack-new-request-holder-loss");
            let holder = c.root(ROOT, &resumed(ROOT, &[A]));
            let holder_key = holder.to_string_lossy().into_owned();
            let mut accepted = BTreeMap::new();
            let mut receiver = Receiver::new();
            let mut prior = ScanIndex::default();
            let mut initial = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
            initial.enrich(&c);
            prior = accept(&c, &prior, initial, &mut accepted, &mut receiver);
            assert_eq!(accepted[ROOT], 1);
            let old_receipt = prior.files[&holder_key]
                .upload_context_receipt
                .clone()
                .expect("A's original body earned a real receipt");

            let twin = (arm == Arm::ContentHeld).then(|| {
                let twin = c.write_at(
                    &file(THIRD),
                    &resumed(ROOT, &[A, ("d", "2026-08-02T10:00:10Z", RESUME_WRITER)]),
                    BORN,
                );
                // Register T through a real parse, without uploading this page.
                // Only A={a} has ever been accepted. T's census knows d, not b.
                let mut known = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
                let key = twin.to_string_lossy();
                let census = known
                    .index
                    .claude_request_census_for_test()
                    .get(&key)
                    .unwrap();
                assert!(census.is_twin());
                assert!(census.request_hashes().contains(&claude_request_hash("d")));
                assert!(!census.request_hashes().contains(&claude_request_hash("b")));
                prior = c.reload(&mut known.index);
                // A duplicate response grows T's bytes without adding a request.
                // Its next acquisition is claimed and paced until after deletion.
                append(
                    &twin,
                    &resumed(ROOT, &[("d", "2026-08-02T10:00:10Z", RESUME_WRITER)]),
                );
                prior = owe_claimed_growth(&prior, &c.base, &twin, true);
                twin
            });

            let b = ("b", "2026-08-02T08:00:20Z", OLD_WRITER);
            let own = ("c", "2026-08-02T09:03:10Z", RESUME_WRITER);
            append(&holder, &resumed(ROOT, &[b]));
            if arm == Arm::Accepted {
                // Prove delivery of b before B even exists in the control.
                let mut delivered =
                    c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
                delivered.enrich(&c);
                prior = accept(&c, &prior, delivered, &mut accepted, &mut receiver);
                assert_eq!(accepted[ROOT], 2);
            }
            let copy = c.write_at(
                &file(COPY),
                &resumed(COPY, &[b, own]),
                "2026-08-02T09:03:00Z",
            );
            owe(&mut prior);
            let scanner = E2ScanFixture::default();
            let mut page = c.raw(&scanner, prior.clone(), 100, twin.is_some(), &[]);
            assert!(scanner.paths().contains(&holder) && scanner.paths().contains(&copy));
            if let Some(twin) = &twin {
                assert!(
                    !scanner.paths().contains(twin),
                    "T's growth stays unacquired"
                );
            }
            let census = page
                .index
                .claude_request_census_for_test()
                .get(&holder_key)
                .unwrap();
            assert!(census.current_for(&page.index.files[&holder_key].source_file_fingerprint));
            assert!(census.request_hashes().contains(&claude_request_hash("b")));
            if arm != Arm::Accepted {
                assert_eq!(
                    page.index.files[&holder_key]
                        .upload_context_receipt
                        .as_ref(),
                    Some(&old_receipt)
                );
            }
            page.enrich(&c);
            assert!(body(&page, COPY).is_some(), "B is independently eligible");

            if arm == Arm::Refused {
                assert_eq!(body(&page, ROOT).unwrap().request_count, 2);
                let holds = page.finish();
                let sent = page.scan.snapshots.clone();
                let mut progress = e2_progress();
                let (status, _, _) = upload(&sent, &mut progress, |items| {
                    let mut response = ack(items)?;
                    for item in items {
                        if item.source_session_id == ROOT {
                            response.accepted_entities.retain(|entity| {
                                entity.snapshot_fingerprint != item.snapshot_fingerprint
                            });
                            response.accepted -= 1;
                            response.sessions_reconciled -= 1;
                            response.rejected_entities.push(
                                crate::snapshot_client::SnapshotEntityRejection {
                                    source_session_id: ROOT.into(),
                                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                                    reason: "hour_bucket_count_above_cap".into(),
                                    detail: "synthetic permanent non-coverage refusal".into(),
                                    permanent: true,
                                    occurrence_count: 1,
                                },
                            );
                        } else {
                            let count = accepted.entry(item.source_session_id.clone()).or_default();
                            assert!(
                                item.request_count >= *count,
                                "an ACK must not shrink a session"
                            );
                            *count = item.request_count;
                            record(&mut receiver, item);
                        }
                    }
                    Ok(response)
                });
                assert_eq!(
                    status.unwrap(),
                    ResumableUploadResult::Rejected { count: 1 }
                );
                let rejected = body(&page, ROOT).unwrap();
                let refusal = &progress.quarantined_fingerprints[&rejected.snapshot_fingerprint];
                assert_eq!(
                    refusal.disposition,
                    SnapshotQuarantineDisposition::UnprovenTerminal
                );
                assert_eq!(
                    progress.permanent_rejections[&rejected.snapshot_fingerprint].reason,
                    crate::upload_receipts::RejectedUsageReason::HourBucketCountAboveCap
                );
                assert_eq!(
                    accepted[ROOT], 1,
                    "the refused append never enters the ledger"
                );
                let mut settled = settle_checkpointed_upload(
                    page.index,
                    &prior,
                    &progress,
                    &holds,
                    true,
                    UnsettledUploadCause::DeferredConflict,
                );
                settle_index_after_upload(&mut settled.index, &prior, &progress);
                accept_upload_context_acks_for_test(
                    &mut settled.index,
                    &sent,
                    &progress.fresh_context_body_acks,
                );
                prior = c.reload(&mut settled.index);
            } else {
                if arm == Arm::ContentHeld {
                    assert_eq!(
                        page.disposition
                            .request_owned_hold_reasons
                            .get("absent_content_twin"),
                        Some(&1)
                    );
                }
                prior = accept(&c, &prior, page, &mut accepted, &mut receiver);
                assert_eq!(accepted[ROOT], if arm == Arm::Accepted { 2 } else { 1 });
            }
            if arm != Arm::Accepted {
                assert_eq!(
                    prior.files[&holder_key].upload_context_receipt.as_ref(),
                    Some(&old_receipt)
                );
            }
            assert!(accepted.contains_key(COPY), "B's actual body was ACKed");
            std::fs::remove_file(&holder).unwrap();
            if let Some(twin) = &twin {
                std::fs::remove_file(twin).unwrap();
            }
            for _ in 0..3 {
                owe(&mut prior);
                let mut page = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
                page.enrich(&c);
                prior = accept(&c, &prior, page, &mut accepted, &mut receiver);
            }
            assert!(
                !prior.files.contains_key(&holder_key),
                "positive absence retired A"
            );
            if arm == Arm::Accepted {
                assert_eq!(accepted[COPY], 1, "B keeps only c after proved ownership");
            }
            for (request, hour) in [
                ("a", "2026-08-02T07"),
                ("b", "2026-08-02T08"),
                ("c", "2026-08-02T09"),
            ] {
                let count = [ROOT, COPY]
                    .iter()
                    .map(|session| {
                        receiver
                            .get(*session)
                            .and_then(|hours| hours.get(hour))
                            .copied()
                            .unwrap_or(0)
                    })
                    .sum::<u64>();
                if count != 1 {
                    missing.push((arm, request, count, accepted.clone()));
                }
            }
        });
    }
    // Collect failures so both negative arms and the positive control run.
    assert!(
        missing.is_empty(),
        "each request must be accepted exactly once: {missing:?}"
    );
}

/// [money] Native and Tail pages preserve the complete union, even when the
/// earliest holder is unrelated. Withholding variants share the same ACK oracle.
#[test]
fn unrelated_main_and_growing_twin_pull_complete_session() {
    fn ordered_money(page: &Page) -> RouteResult {
        let mut ordered = twin(page);
        ordered
            .scan
            .snapshots
            .sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
        sent_money(&ordered)
    }
    for sampled in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("unrelated-main-pulls-twin");
            let unrelated = c.write_at(
                &format!("earlier/{THIRD}.jsonl"),
                &resumed(THIRD, &[A]),
                "2026-08-02T06:59:00Z",
            );
            let main = c.root(ROOT, &resumed(ROOT, &[A, B]));
            let mut accepted = BTreeMap::new();
            let mut prior = ScanIndex::default();
            let mut initial = c.raw(&E2ScanFixture::default(), prior.clone(), 100, sampled, &[]);
            initial.enrich(&c);
            prior = accept_monotone_page(&c, &prior, initial, &mut accepted);
            let twin = c.write_at(&file(COPY), &resumed(ROOT, &[A, B, C]), BORN);
            owe(&mut prior);
            let both = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, sampled);
            assert_eq!(body(&both, ROOT).unwrap().request_count, 3);
            prior = accept_monotone_page(&c, &prior, both, &mut accepted);
            let (main_key, twin_key) = (
                main.to_string_lossy().into_owned(),
                twin.to_string_lossy().into_owned(),
            );
            assert_eq!(
                e2::copied_file_holders_for_test(&prior, std::iter::once(twin_key.as_str()))
                    [&twin_key],
                unrelated.to_string_lossy(),
                "the earliest accepted holder is in another session and folder"
            );
            append(&main, &resumed(ROOT, &[D]));
            let scanner = E2ScanFixture::default();
            let mut all = own_install_for_test(&prior, &c.base);
            let mut complete = c.raw(&scanner, prior.clone(), 100, sampled, &[]);
            assert!(
                scanner.paths().contains(&twin),
                "main-only selection pulls T"
            );
            let folded = complete
                .scan
                .snapshots
                .iter()
                .find(|item| {
                    item.claude_money
                        .as_deref()
                        .and_then(e2::FileFold::location_key)
                        == Some(location_key(&twin_key))
                })
                .unwrap();
            assert_eq!(
                folded.source_session_id, ROOT,
                "content session survives Tail"
            );
            assert_eq!(
                folded.claude_usage_request_ids,
                BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()])
            );
            complete.enrich(&c);
            assert_eq!(body(&complete, ROOT).unwrap().request_count, 4);
            // Q's selected recovery offers both sessions, as does the all-owed oracle.
            owe(&mut all);
            let full = ready(&c, &E2ScanFixture::default(), all, 100, sampled);
            assert_eq!(body(&full, ROOT).unwrap().request_count, 4);
            let reference = ordered_money(&full);
            prior = accept_monotone_page(&c, &prior, complete, &mut accepted);
            assert_eq!(accepted[ROOT], 4);

            for cause in [
                "strip-T",
                "non-Exact",
                "bound hold",
                "Q-pull",
                "twin growth",
                "deletion release",
            ] {
                if cause == "twin growth" {
                    // Only T grows: M keeps its settled stamp and revision.
                    append(
                        &twin,
                        &resumed(ROOT, &[("e", "2026-08-02T07:07:10Z", RESUME_WRITER)]),
                    );
                    let mut full_index = own_install_for_test(&prior, &c.base);
                    // Rebuild S's complete membership; Q stays accepted on both
                    // routes and is pulled only as unchanged counting evidence.
                    full_index.activate_effective_upload_body_witness_revision(3);
                    for key in [&main_key, &twin_key] {
                        assert!(full_index.re_owe_effective_upload_body_witness_revision(key, 2));
                    }
                    let mut full = c.raw(&E2ScanFixture::default(), full_index, 100, sampled, &[]);
                    full.enrich(&c);
                    assert_eq!(body(&full, ROOT).unwrap().request_count, 5);
                    let reference = ordered_money(&full);
                    let scanner = E2ScanFixture::default();
                    let mut grown = c.raw(
                        &scanner,
                        prior.clone(),
                        100,
                        sampled,
                        std::slice::from_ref(&twin),
                    );
                    assert!(scanner.paths().contains(&twin) && scanner.paths().contains(&main));
                    grown.enrich(&c);
                    assert_eq!(body(&grown, ROOT).unwrap().request_count, 5);
                    assert!(!grown
                        .disposition
                        .request_owned_hold_reasons
                        .contains_key("absent_content_twin"));
                    let actual = ordered_money(&grown);
                    for route in [&reference, &actual] {
                        assert_eq!(
                            route
                                .snapshots
                                .keys()
                                .map(String::as_str)
                                .collect::<Vec<_>>(),
                            vec![ROOT],
                            "growth routes emit the complete growing session"
                        );
                    }
                    money_oracle::assert_equivalent(&reference, &actual);
                    let holds = grown.finish();
                    assert!(!holds.progress_blocking);
                    prior = accept_finished_monotone_page(&c, &prior, grown, &mut accepted, holds);
                    assert_eq!(accepted[ROOT], 5, "T's new turn reaches the receiver");
                    continue;
                }
                if cause == "deletion release" {
                    std::fs::remove_file(&twin).unwrap();
                }
                let q_pull = cause == "Q-pull";
                let mut selected = prior.clone();
                let seed = if q_pull { &unrelated } else { &main };
                assert!(selected
                    .re_owe_effective_upload_body_witness_revision(&seed.to_string_lossy(), 2));
                let hints = if q_pull {
                    std::slice::from_ref(seed)
                } else {
                    &[]
                };
                let scanner = E2ScanFixture::default();
                let mut page = c.raw(&scanner, selected, 100, sampled, hints);
                if cause == "deletion release" {
                    page.enrich(&c);
                    assert_eq!(body(&page, ROOT).unwrap().request_count, 3);
                    assert!(!page
                        .disposition
                        .request_owned_hold_reasons
                        .contains_key("absent_content_twin"));
                    continue;
                }
                assert!(scanner.paths().contains(&twin));
                assert!(page.scan.snapshots.iter().any(|item| {
                    item.claude_money
                        .as_deref()
                        .and_then(e2::FileFold::location_key)
                        == Some(location_key(&twin_key))
                }));
                if q_pull {
                    assert!(scanner.paths().contains(&unrelated));
                    assert!(
                        scanner.paths().contains(&main),
                        "Q pulls T, T pulls unchanged M"
                    );
                }
                let missing = if q_pull { &main_key } else { &twin_key };
                page.scan.snapshots.retain(|item| {
                    item.claude_money
                        .as_deref()
                        .and_then(e2::FileFold::location_key)
                        != Some(location_key(missing))
                        && (q_pull || item.source_session_id == ROOT)
                });
                match cause {
                    "bound hold" => {
                        crate::snapshots::e2_pipeline_scan_fixture::hold_file_decode_for_test(
                            &mut page.index,
                            &twin_key,
                        )
                    }
                    "non-Exact" => {
                        let mut record = serde_json::to_value(
                            page.index
                                .claude_request_census_for_test()
                                .get(&twin_key)
                                .unwrap(),
                        )
                        .unwrap();
                        record["s"] = json!("lossy");
                        page.index
                            .claude_request_census_mut_for_test()
                            .insert_for_test(&twin_key, serde_json::from_value(record).unwrap());
                        // No missing ids: only the non-Exact shape requires the hold.
                        page.scan
                            .snapshots
                            .iter_mut()
                            .find(|item| item.source_session_id == ROOT)
                            .unwrap()
                            .claude_usage_request_ids
                            .insert("c".into());
                    }
                    _ => {}
                }
                let removals = page.index.claude_copy_removals.clone();
                page.enrich(&c);
                assert_eq!(
                    page.disposition
                        .request_owned_hold_reasons
                        .get("absent_content_twin"),
                    Some(&1)
                );
                assert_withheld(&page, ROOT, "incomplete content-twin page");
                if q_pull {
                    assert_eq!(page.disposition.quarantined_entity_count(), 1);
                }
                let holds = page.finish();
                assert!(holds.progress_blocking);
                assert!(body(&page, ROOT).is_none(), "partial bodies never upload");
                if !q_pull {
                    assert_eq!(
                        page.index.claude_copy_removals, removals,
                        "holding creates no removal debt or COPY mark"
                    );
                    assert_eq!(
                        page.index.files[&main_key].effective_upload_body_witness_revision,
                        2
                    );
                }
                if q_pull {
                    prior = accept_finished_monotone_page(&c, &prior, page, &mut accepted, holds);
                } else {
                    // The synthetic bound/lossy seam must not be persisted.
                    assert_eq!(
                        upload(&page.scan.snapshots, &mut e2_progress(), |items| {
                            let response = ack(items);
                            for item in items {
                                accepted.insert(item.source_session_id.clone(), item.request_count);
                            }
                            assert_eq!(
                                accepted[ROOT], 4,
                                "an ACK never replaces four requests with three"
                            );
                            response
                        })
                        .0
                        .unwrap(),
                        ResumableUploadResult::Completed
                    );
                }
                assert_eq!(accepted[ROOT], 4, "partial pages never replace M+T");
                let mut recover = prior.clone();
                assert!(recover
                    .re_owe_effective_upload_body_witness_revision(&seed.to_string_lossy(), 2));
                let scanner = E2ScanFixture::default();
                let mut recovered = c.raw(&scanner, recover, 100, sampled, hints);
                if q_pull {
                    assert!(scanner.paths().contains(&unrelated));
                    assert!(scanner.paths().contains(&twin) && scanner.paths().contains(&main));
                }
                recovered.enrich(&c);
                assert_eq!(body(&recovered, ROOT).unwrap().request_count, 4);
                assert!(!recovered
                    .disposition
                    .request_owned_hold_reasons
                    .contains_key("absent_content_twin"));
                if q_pull {
                    money_oracle::assert_equivalent(&reference, &ordered_money(&recovered));
                }
                let holds = recovered.finish();
                assert!(!holds.progress_blocking);
                prior = accept_finished_monotone_page(&c, &prior, recovered, &mut accepted, holds);
                assert_eq!(accepted[ROOT], 4);
            }
        });
    }
}

/// [money] A main deferred before acquisition cannot let its pulled content
/// twin replace the session. Growth pacing, then audit-cap pacing, both hold
/// until a later complete page matches the native Full union after restart.
/// ROOT's exact heads per phase: 20/2, then 30/3, no body while held, then
/// exactly one 70/7 body.
#[test]
fn deferred_main_with_read_content_twin_holds_until_complete() {
    use crate::snapshots::e2_pipeline_scan_fixture::{
        indexed_size, owe_claimed_growth, pace_cap_for_test,
    };
    // A page's ROOT bodies: wire input tokens and requests.
    fn heads(page: &Page) -> Vec<(u64, u64)> {
        (page.scan.snapshots.iter())
            .filter(|item| item.source_session_id == ROOT)
            .map(|item| (item.input_tokens, item.request_count))
            .collect()
    }
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for restart in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("deferred-main-content-twin");
            let main = c.root(ROOT, &resumed(ROOT, &[A, B]));
            let owner = E2ScanFixture::default();
            let mut accepted = BTreeMap::new();
            let mut prior = ScanIndex::default();
            let mut original = c.raw(&owner, prior.clone(), 100, true, &[]);
            original.enrich(&c);
            let holds = original.finish();
            assert_eq!(heads(&original), [(20, 2)], "M(A, B)");
            prior = accept_finished_monotone_page(&c, &prior, original, &mut accepted, holds);
            let twin = c.write_at(&file(COPY), &resumed(ROOT, &[A, B, C]), BORN);
            owe(&mut prior);
            let mut both = c.raw(&owner, prior.clone(), 100, true, &[]);
            both.enrich(&c);
            let holds = both.finish();
            assert_eq!(heads(&both), [(30, 3)], "M+T(A, B, C)");
            prior = accept_finished_monotone_page(&c, &prior, both, &mut accepted, holds);
            assert_eq!(accepted[ROOT], 3);
            let main_key = main.to_string_lossy().into_owned();
            let twin_key = twin.to_string_lossy().into_owned();
            let size = indexed_size(&prior, &main);
            append(
                &main,
                &resumed(
                    ROOT,
                    &[
                        D,
                        ("e", "2026-08-02T07:07:10Z", RESUME_WRITER),
                        ("f", "2026-08-02T07:08:10Z", RESUME_WRITER),
                        ("g", "2026-08-02T07:09:10Z", RESUME_WRITER),
                    ],
                ),
            );
            let mut full_index = prior.clone();
            owe(&mut full_index);
            let mut full = c.raw(&E2ScanFixture::default(), full_index, 100, false, &[]);
            full.enrich(&c);
            let expected = body(&full, ROOT).unwrap();
            assert_eq!(
                (
                    expected.input_tokens,
                    expected.request_count,
                    expected.removed_request_count
                ),
                (70, 7, Some(2))
            );
            let mut reference = sent_money(&full);
            reference.mode = Mode::ColdFull;

            let mut scanner = if restart {
                E2ScanFixture::default()
            } else {
                owner
            };
            // These are the same no-capacity controls as the forced-member
            // fixture. Only M is paced: the content twin still reads natively.
            for paced in [true, false] {
                let mut selected = owe_claimed_growth(&prior, &c.base, &main, paced);
                owe(&mut selected);
                // Preserve accepted-body ownership; remove delivery receipts
                // so this held attempt must prove it cannot earn a new one.
                for key in [&main_key, &twin_key] {
                    selected.files.get_mut(key).unwrap().upload_context_receipt = None;
                }
                if restart {
                    selected = c.reload(&mut selected);
                }
                if !paced {
                    scanner.set_audit_slots(0);
                    pace_cap_for_test(&scanner, &main);
                }
                let mut held = c.raw(
                    &scanner,
                    selected.clone(),
                    100,
                    true,
                    std::slice::from_ref(&main),
                );
                assert!(
                    !scanner.paths().contains(&main),
                    "M is deferred before acquisition"
                );
                assert!(
                    scanner.paths().contains(&twin),
                    "M pulled T before its deferral"
                );
                assert_eq!(indexed_size(&held.index, &main), size);
                assert!(
                    held.scan.snapshots.iter().any(|item| {
                        item.claude_money
                            .as_deref()
                            .and_then(e2::FileFold::location_key)
                            == Some(location_key(&twin_key))
                    }),
                    "the held page has a real T fold"
                );
                held.enrich(&c);
                assert_eq!(
                    held.disposition
                        .request_owned_hold_reasons
                        .get("absent_content_twin"),
                    Some(&1)
                );
                let holds = held.finish();
                assert!(holds.progress_blocking);
                assert!(heads(&held).is_empty(), "T alone cannot publish S");
                prior = accept_finished_monotone_page(&c, &selected, held, &mut accepted, holds);
                assert_eq!(
                    accepted[ROOT], 3,
                    "held pages never change the receiver ledger"
                );
                for key in [&main_key, &twin_key] {
                    assert!(
                        prior.files[key].upload_context_receipt.is_none(),
                        "held files earn no receipt"
                    );
                }
            }
            // The durable growth claim is now due. A fresh page has capacity
            // and must acquire M+T together, without filtering any fold.
            scanner.set_audit_slots(1);
            let mut recovered = c.raw(
                &scanner,
                prior.clone(),
                100,
                true,
                std::slice::from_ref(&main),
            );
            assert!(scanner.paths().contains(&main) && scanner.paths().contains(&twin));
            recovered.enrich(&c);
            assert!(!recovered
                .disposition
                .request_owned_hold_reasons
                .contains_key("absent_content_twin"));
            let expected = body(&recovered, ROOT).unwrap();
            assert_eq!(
                (
                    expected.input_tokens,
                    expected.request_count,
                    expected.removed_request_count
                ),
                (70, 7, Some(2))
            );
            assert_eq!(
                expected.source_file_fingerprint.as_ref(),
                Some(&recovered.index.files[&main_key].source_file_fingerprint),
                "M carries the complete union; T has no separate wire item"
            );
            money_oracle::assert_equivalent(&reference, &sent_money(&recovered));
            let holds = recovered.finish();
            assert!(!holds.progress_blocking);
            assert_eq!(heads(&recovered), [(70, 7)], "exactly one ROOT body");
            prior = accept_finished_monotone_page(&c, &prior, recovered, &mut accepted, holds);
            assert_eq!(accepted[ROOT], 7);
            // Reload drops the runtime context; observe the durable proofs
            // under the same destination that received this page's exact ACKs.
            prior.activate_upload_context("e2-synthetic-destination".into());
            assert!(upload_context_receipt_earned_for_test(&prior, &main));
            // T folded into M: its own revision gets a local suppression
            // proof, never an ACK receipt for M's body. It must owe no read.
            let entry = &prior.files[&twin_key];
            let proof = entry.upload_context_receipt.as_ref().unwrap();
            assert!(prior.confirmed_empty_files.contains(&twin_key));
            assert!(!prior.file_snapshot_fingerprints.contains_key(&twin_key));
            assert!(entry.last_snapshot_fingerprint.is_none());
            assert!(entry.last_upload_body_witness.is_none());
            assert!(proof.body_witness.is_empty());
            assert!(!entry.source_file_fingerprint.is_empty());
            assert_eq!(proof.source_witness, entry.source_file_fingerprint);
            assert!(upload_context_proof_is_current_for_test(&prior, &twin));
            assert!(!upload_context_receipt_earned_for_test(&prior, &twin));
            assert!(!upload_context_owed_for_test(&prior, &twin));
        });
    }
}

/// [money] A holder withheld for its absent content twin cannot remove a
/// later copy's prefix or repeatedly re-arm that unchanged copy after ACK.
#[test]
fn held_content_twin_holder_proves_no_copy_until_released() {
    use crate::snapshots::e2_pipeline_scan_fixture::{indexed_size, owe_claimed_growth};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        // Read T alone first: its content census knows ROOT's distinct X/Y.
        let mut c = Corpus::new("held-content-twin-holder");
        let twin = c.write_at(
            &file(THIRD),
            &resumed(ROOT, &[B, C]),
            "2026-08-02T07:02:00Z",
        );
        let scanner = E2ScanFixture::default();
        let mut accepted = BTreeMap::new();
        let mut prior = ScanIndex::default();
        let mut initial = c.raw(&scanner, prior.clone(), 100, true, &[]);
        assert_eq!(scanner.paths(), vec![twin.clone()]);
        initial.enrich(&c);
        assert_eq!(body(&initial, ROOT).unwrap().request_count, 2);
        prior = accept_monotone_page(&c, &prior, initial, &mut accepted);
        let twin_key = twin.to_string_lossy().into_owned();
        assert!(prior
            .claude_request_census_for_test()
            .get(&twin_key)
            .unwrap()
            .is_twin());
        let size = indexed_size(&prior, &twin);

        // H and C arrive while T's grown, usage-free suffix is growth-paced.
        append(&twin, &"\n".repeat(8192));
        let main = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let copy = c.write_at(&file(COPY), &resumed(COPY, &[A, D]), BORN);
        let main_key = main.to_string_lossy().into_owned();
        let copy_key = copy.to_string_lossy().into_owned();
        owe(&mut prior);
        let selected = owe_claimed_growth(&prior, &c.base, &twin, true);
        let mut held = c.raw(&scanner, selected.clone(), 100, true, &[]);
        assert!(scanner.paths().contains(&main) && scanner.paths().contains(&copy));
        assert!(!scanner.paths().contains(&twin));
        assert_eq!(indexed_size(&held.index, &twin), size);
        held.enrich(&c);
        assert_eq!(
            held.disposition
                .request_owned_hold_reasons
                .get("absent_content_twin"),
            Some(&1)
        );
        assert_withheld(&held, ROOT, "H cannot replace ROOT without T's Y");
        let counted_copy = body(&held, COPY).unwrap();
        assert_eq!(
            counted_copy.request_count, 2,
            "C still counts A and its own D"
        );
        assert_eq!(counted_copy.removed_request_count.unwrap_or(0), 0);
        prior = accept_monotone_page(&c, &selected, held, &mut accepted);
        // H never committed a body, so it may have no index entry at all.
        assert!(prior
            .files
            .get(&main_key)
            .is_none_or(|entry| entry.upload_context_receipt.is_none()));
        assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
        assert_eq!((accepted[ROOT], accepted[COPY]), (2, 2));
        let before_release = accepted.clone();

        // Real ACKs and unchanged passes leave A counted once in C, without a retry.
        for _ in 0..3 {
            let mut unchanged = c.raw(&scanner, prior.clone(), 100, true, &[]);
            assert!(!scanner.paths().contains(&twin), "T remains unacquired");
            assert!(
                !scanner.paths().contains(&copy),
                "C must not loop on H's hold"
            );
            assert_eq!(indexed_size(&unchanged.index, &twin), size);
            unchanged.enrich(&c);
            assert!(!unchanged
                .index
                .claude_copy_removals
                .pending(location_key(&copy_key)));
            prior = accept_monotone_page(&c, &prior, unchanged, &mut accepted);
            assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
            assert_eq!(accepted, before_release);
            assert_eq!(accepted.values().sum::<u64>(), 4, "only C counts A");
        }

        // Release T: the complete ROOT union takes A and C replaces its prefix.
        let released = owe_claimed_growth(&prior, &c.base, &twin, false);
        // The native reference is a cold read of every file with no prior
        // state: no store to share the released growth claim, and no accepted
        // body left unread. (An owed copy of the held state leaves unchanged C
        // owing adoption only, so C would be missing from it.)
        let full = ready(
            &c,
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            false,
        );
        assert_eq!(body(&full, ROOT).unwrap().request_count, 3);
        assert_eq!(body(&full, COPY).unwrap().request_count, 1);
        let reference = sent_money(&full);
        let mut acquired_twin = false;
        let mut saw_root = false;
        let mut saw_copy = false;
        let mut stable = false;
        // Releasing the pace only makes T's growth read due; owe the files
        // once so the first released page reads T, as the reference does.
        prior = released;
        owe(&mut prior);
        for _ in 0..6 {
            let hints = if acquired_twin {
                &[][..]
            } else {
                std::slice::from_ref(&twin)
            };
            let mut page = c.raw(&scanner, prior.clone(), 100, true, hints);
            acquired_twin |= scanner.paths().contains(&twin);
            let quiet = !scanner.paths().contains(&main) && !scanner.paths().contains(&copy);
            page.enrich(&c);
            // A is counted exactly once: until ROOT with A is sent (here or
            // on an earlier page), C keeps counting A; from then on C removes
            // it.
            let held = page
                .disposition
                .quarantined_fingerprints(&page.scan.snapshots);
            let root_sent =
                body(&page, ROOT).filter(|root| !held.contains(&root.snapshot_fingerprint));
            if let Some(root) = root_sent {
                assert_eq!(root.request_count, 3, "ROOT counts A/X/Y");
                saw_root = true;
            }
            if let Some(copy_body) =
                body(&page, COPY).filter(|copy| !held.contains(&copy.snapshot_fingerprint))
            {
                if saw_root {
                    assert_eq!(copy_body.request_count, 1, "C counts only its own D");
                    assert_eq!(copy_body.removed_request_count, Some(1), "C removes A");
                    saw_copy = true;
                } else {
                    assert_eq!(copy_body.request_count, 2, "C keeps A until ROOT is sent");
                }
            }
            // A transfer shrinks C: ACK exact replacements, then update the receiver ledger.
            let mut replacements = BTreeMap::new();
            prior = accept_monotone_page(&c, &prior, page, &mut replacements);
            accepted.extend(replacements);
            if quiet && saw_root && saw_copy {
                stable = true;
                break;
            }
        }
        assert!(acquired_twin, "the released page must acquire T");
        assert!(stable, "released ownership must settle without a read loop");
        assert_eq!((accepted[ROOT], accepted[COPY]), (3, 1));
        assert_eq!(
            accepted.values().sum::<u64>(),
            4,
            "A is counted exactly once"
        );
        assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
        assert_eq!(
            prior
                .claude_copy_removals
                .get(location_key(&copy_key))
                .iter()
                .flat_map(|(_, ids)| ids.iter().copied())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([crate::snapshots::claude_request_census::claude_request_hash("a")])
        );

        // An explicitly owed sampled page matches the native complete-money oracle.
        let mut verify = prior.clone();
        owe(&mut verify);
        let mut complete = c.raw(&scanner, verify, 100, true, &[]);
        complete.enrich(&c);
        money_oracle::assert_equivalent(&reference, &sent_money(&complete));
        prior = accept_monotone_page(&c, &prior, complete, &mut accepted);

        // The owed page re-reads every file, so T stops carrying ROOT's ACK
        // at its save; that carrier loss marks H once. One recovery pass
        // re-reads H (never C) and changes no accepted body.
        let after_release = accepted.clone();
        assert!(e2::carrier_group_owned_for_test(&prior, &main_key));
        assert!(prior.claude_copy_removals.pending(location_key(&main_key)));
        assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
        let mut recovery = c.raw(&scanner, prior.clone(), 100, true, &[]);
        assert!(!scanner.paths().contains(&copy));
        recovery.enrich(&c);
        prior = accept_monotone_page(&c, &prior, recovery, &mut accepted);
        assert_eq!(accepted, after_release);
        assert!(!prior.claude_copy_removals.pending(location_key(&main_key)));
        assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));

        // Two more unchanged passes read neither H nor C after the transfer settles.
        for _ in 0..2 {
            let mut unchanged = c.raw(&scanner, prior.clone(), 100, true, &[]);
            assert!(!scanner.paths().contains(&main) && !scanner.paths().contains(&copy));
            unchanged.enrich(&c);
            prior = accept_monotone_page(&c, &prior, unchanged, &mut accepted);
            assert_eq!(accepted, after_release);
            assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
        }
    });
}

/// [money] A content twin acquired in another evidence chunk cannot hold
/// its overlapping holder or re-arm an ACKed copy on unchanged saves. H and
/// T run in the two planned chunks; the ACKed heads are ROOT 10/1, COPY
/// 20/2 and THIRD 10/1.
#[test]
fn content_twin_in_another_chunk_counts_and_settles() {
    fn removed(index: &ScanIndex, key: &str) -> BTreeSet<u64> {
        index
            .claude_copy_removals
            .get(location_key(key))
            .iter()
            .flat_map(|(_, ids)| ids.iter().copied())
            .collect()
    }
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        const TWIN: &str = "5338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let mut c = Corpus::new("content-twin-another-chunk");
        let main = c.write_at(
            &format!("p/{ROOT}.jsonl"),
            &resumed(ROOT, &[A]),
            "2026-08-02T07:00:00Z",
        );
        let copy = c.write_at(&format!("p/{COPY}.jsonl"), &resumed(COPY, &[A, B, D]), BORN);
        let other = c.write_at(
            &format!("q/{THIRD}.jsonl"),
            &resumed(THIRD, &[B]),
            "2026-08-02T07:00:00Z",
        );
        // A real in-folder ROOT path twin gives Q the Rule B route to H:
        // T's A is a copy too, so only ROOT counts A across all three sessions.
        let bridge = c.write_at(
            &format!("q/{ROOT}.jsonl"),
            &resumed(ROOT, &[A]),
            "2026-08-02T07:01:00Z",
        );
        let content_twin = c.write_at(&format!("q/{TWIN}.jsonl"), &resumed(THIRD, &[A, B]), BORN);
        // Nonempty trace sidecars make ROOT and THIRD separate next-fit
        // chunks, without adding API usage or another ownership source.
        c.evidence_for(ROOT, &[], &[trace("a", "")]);
        c.evidence_for(THIRD, &[], &[trace_for(THIRD, "b", "")]);
        let main_key = main.to_string_lossy().into_owned();
        let copy_key = copy.to_string_lossy().into_owned();
        let twin_key = content_twin.to_string_lossy().into_owned();
        let a = crate::snapshots::claude_request_census::claude_request_hash("a");
        let b = crate::snapshots::claude_request_census::claude_request_hash("b");
        let scanner = E2ScanFixture::default();
        let mut prior = ScanIndex::default();
        let mut first = c.raw(&scanner, prior.clone(), 100, true, &[]);
        for path in [&main, &copy, &other, &bridge, &content_twin] {
            assert!(
                scanner.paths().contains(path),
                "the first page acquires every file"
            );
        }
        let census = first.index.claude_request_census_for_test();
        let twin_census = census.get(&twin_key).unwrap();
        assert!(twin_census.is_twin());
        assert_eq!(
            twin_census
                .request_hashes()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([a, b])
        );
        let families = e2::page_families(&first.scan.snapshots);
        for (session, key) in [(ROOT, &main_key), (THIRD, &twin_key)] {
            assert!(families[session].iter().any(|&slot| {
                first.scan.snapshots[slot]
                    .claude_money
                    .as_deref()
                    .and_then(e2::FileFold::location_key)
                    == Some(location_key(key))
            }));
        }
        assert!(prior.files.is_empty(), "H has no previously committed body");

        // Enrich the same acquisition page through the existing one-chunk
        // reference seam, preserving the packed arm's process-local state.
        let reference = unobserved(|| {
            evidence_chunk_tests::isolated(|| {
                let mut reference = twin(&first);
                crate::snapshot_sync::ONE_EVIDENCE_CHUNK.with(|one| {
                    let was = one.replace(true);
                    let before = crate::snapshot_sync::evidence_chunks_for_test();
                    reference.enrich(&c);
                    one.set(was);
                    // Reference arms are not counted (snapshot_sync.rs, one_evidence_chunk).
                    assert_eq!(crate::snapshot_sync::evidence_chunks_for_test() - before, 0);
                });
                reference
            })
        });
        // ROOT and THIRD's nonzero sidecars force different evidence chunks.
        let placed = evidence_chunk_tests::enrich_planned(
            &mut first,
            &c,
            &[ROOT, COPY, THIRD],
            &[ROOT, THIRD],
            2,
        );
        assert_ne!(
            placed[&location_key(&main_key)],
            placed[&location_key(&twin_key)],
            "H and T run in different chunks"
        );
        assert_eq!(
            first
                .disposition
                .request_owned_hold_reasons
                .get("absent_content_twin")
                .copied()
                .unwrap_or(0),
            0,
            "T is present on this page even outside H's chunk"
        );
        let root = body(&first, ROOT).unwrap();
        assert!(crate::snapshots::claude_request_money::is_request_owned_literal(root));
        assert!(!first
            .disposition
            .quarantined_fingerprints(&first.scan.snapshots)
            .contains(&root.snapshot_fingerprint));
        assert_eq!(removed(&first.index, &copy_key), BTreeSet::from([a]));
        assert_eq!(removed(&first.index, &twin_key), BTreeSet::from([a, b]));
        assert!(first
            .index
            .claude_copy_removals
            .get(location_key(&copy_key))
            .iter()
            .any(|(holder, ids)| *holder == location_key(&main_key) && ids.contains(&a)));
        money_oracle::assert_equivalent(&sent_money(&reference), &sent_money(&first));

        let holds = first.finish();
        let heads = (first.scan.snapshots.iter())
            .map(|item| {
                let head = (item.input_tokens, item.request_count);
                (item.source_session_id.as_str(), head)
            })
            .collect::<BTreeMap<_, _>>();
        assert_eq!(first.scan.snapshots.len(), 3, "one body per session");
        // H counts A, C counts B and D, S counts B.
        assert_eq!(
            heads,
            BTreeMap::from([(ROOT, (10, 1)), (COPY, (20, 2)), (THIRD, (10, 1))])
        );
        assert_eq!(
            (heads.values()).fold((0u64, 0u64), |(input, requests), (i, r)| {
                (input + i, requests + r)
            }),
            (40, 4),
            "A once, B in P and Q, D once"
        );
        let mut accepted = BTreeMap::new();
        prior = accept_finished_monotone_page(&c, &prior, first, &mut accepted, holds);
        assert_eq!((accepted[ROOT], accepted[COPY], accepted[THIRD]), (1, 2, 1));
        // Reload drops the runtime context; observe H's receipt under the
        // destination that received this page's exact ACKs.
        let mut context = prior.clone();
        context.activate_upload_context("e2-synthetic-destination".into());
        assert!(
            upload_context_receipt_earned_for_test(&context, &main),
            "H's counted body earned its ACK receipt"
        );
        assert_eq!(removed(&prior, &copy_key), BTreeSet::from([a]));
        assert_eq!(removed(&prior, &twin_key), BTreeSet::from([a, b]));
        assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
        let accepted_first = accepted.clone();
        for _ in 0..3 {
            let mut unchanged = c.raw(&scanner, prior.clone(), 100, true, &[]);
            assert!(
                !scanner.paths().contains(&copy),
                "C must stay settled after ACK"
            );
            unchanged.enrich(&c);
            assert!(!unchanged
                .index
                .claude_copy_removals
                .pending(location_key(&copy_key)));
            assert_eq!(removed(&unchanged.index, &copy_key), BTreeSet::from([a]));
            prior = accept_monotone_page(&c, &prior, unchanged, &mut accepted);
            assert!(!prior.claude_copy_removals.pending(location_key(&copy_key)));
            assert_eq!(removed(&prior, &copy_key), BTreeSet::from([a]));
            assert_eq!(
                accepted, accepted_first,
                "unchanged saves preserve accepted money"
            );
        }
    });
}

/// [money] An unchanged original read for local work while its owed history
/// is held emits nothing and does not bring its copy, so the session never
/// goes out at the copy's composition alone. Its history stays owed.
#[test]
fn held_history_original_does_not_bring_its_copy() {
    const FIRST: &str = "0338a80a-f36e-4cbc-a5bb-50fc66430ba5";
    with_e2(|| {
        let mut c = Corpus::new("held-history-original");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut prior = warm(&c);
        let twin = c.write_at(&file(FIRST), &resumed(ROOT, &[A, B]), BORN);
        owe(&mut prior);
        let both = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        prior = settle(&c, &prior, both, &mut e2_progress());
        append(&twin, &resumed(ROOT, &[C]));
        let copy = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        assert_eq!(body(&copy, ROOT).unwrap().request_count, 3);
        prior = settle(&c, &prior, copy, &mut e2_progress());
        // The original owes history that an unreadable list holds, and a
        // pending prefix wait selects it for local work: parsed, not emitted.
        let key = holder.to_string_lossy().into_owned();
        prior.activate_effective_upload_body_witness_revision(3);
        assert!(prior.re_owe_effective_upload_body_witness_revision(&key, 2));
        prior.claude_copy_removals.mark(location_key(&key));
        std::fs::write(
            c.support
                .join("snapshots/claude_code-reemission-exclusions.txt"),
            "not a digest\n",
        )
        .unwrap();
        let scanner = E2ScanFixture::default();
        let mut page = c.raw(&scanner, prior, 100, false, &[]);
        page.enrich(&c);
        assert!(body(&page, ROOT).is_none(), "no copy-only session emission");
        page.finish();
        assert_eq!(
            page.index.files[&key].effective_upload_body_witness_revision, 2,
            "the held history stays owed"
        );
        let paths = scanner.paths();
        assert!(
            paths.contains(&holder),
            "the original is read for local work"
        );
        assert!(
            !paths.contains(&twin),
            "the held original does not bring its copy"
        );
    });
}

/// [money] All acquisition routes conserve the corrected totals and placement
/// with two accounts, a switch, a side call, an evidence gap and tagged rows.
#[test]
fn copied_file_routes_preserve_money_and_placement() {
    with_e2(|| {
        let mut c = Corpus::new("copied-session-placement");
        c.root(ROOT, &resumed(ROOT, &[A, B, C]));
        let prior = warm(&c);
        c.write_at(
            &file(COPY),
            &resumed(ROOT, &[A, B, C, D]),
            "2026-08-02T07:05:00Z",
        );
        let mut rows = vec![
            api_login(ROOT, "a", 10, '1', Some('7')),
            api_login(ROOT, "b", 10, '2', Some('8')),
            api_login(ROOT, "side", 4, '2', Some('8')),
        ];
        for row in &mut rows {
            row.observed_at = C.1.into();
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
        }
        let traces = rows
            .iter()
            .map(|row| trace_for(ROOT, &row.request_id, ""))
            .collect::<Vec<_>>();
        c.evidence(&rows, &traces);
        let mut routes = Vec::new();
        for (mode, sampled) in [
            (Mode::ColdFull, false),
            (Mode::Ram, true),
            (Mode::Restart, true),
        ] {
            let mut index = prior.clone();
            if mode == Mode::Restart {
                index = c.reload(&mut index);
            }
            owe(&mut index);
            let mut page = ready(
                &c,
                &E2ScanFixture::capturing_identity(),
                index,
                100,
                sampled,
            );
            page.finish();
            let route = captured(&page, mode);
            assert!(
                super::money_equivalence_tests::copy_prefix_route_tests::accounts(&route) >= 2,
                "placement control needs two tagged accounts, identity parts included"
            );
            assert_eq!(
                body(&page, ROOT).unwrap().request_count,
                5,
                "four own turns and one side call"
            );
            routes.push(route);
        }
        for route in &routes[1..] {
            money_oracle::assert_equivalent(&routes[0], route);
        }
    });
}

/// Split exact totals across synthetic native responses without fixture data.
fn responses(session: &str, from: usize, count: usize, tokens: u64, at: &str) -> String {
    (0..count)
        .map(|n| {
            let mut value: serde_json::Value = serde_json::from_str(&line_by(
                session,
                &format!("r-{}", from + n),
                at,
                tokens / count as u64 + u64::from((n as u64) < tokens % count as u64),
                OLD_WRITER,
            ))
            .unwrap();
            // A meaningful token decrease for the receiver's million-token floor.
            value["message"]["usage"]["cache_read_input_tokens"] = json!(50_000);
            value.to_string() + "\n"
        })
        .collect()
}

/// Receiver model: strict activity fence, head CAS and the literal decrease
/// rule. A large decrease passes only when the new removal delta explains it.
fn receiver_accepts(head: &SnapshotItem, candidate: &SnapshotItem, etag: &str) -> bool {
    let activity = |item: &SnapshotItem| {
        item.usage_buckets
            .iter()
            .flat_map(|bucket| {
                [
                    bucket.first_activity_at.as_deref(),
                    bucket.last_activity_at.as_deref(),
                ]
            })
            .chain([
                item.source_started_at.as_deref(),
                item.source_ended_at.as_deref(),
                item.source_last_activity_at.as_deref(),
            ])
            .flatten()
            .map(nanos)
            .max()
    };
    if activity(candidate) < activity(head)
        || candidate.cache_base_head_etag.as_deref() != Some(etag)
    {
        return false;
    }
    let total = |item: &SnapshotItem| {
        item.input_tokens
            + item.output_tokens
            + item.cache_read_tokens
            + item.cache_creation_5m_tokens
            + item.cache_creation_1h_tokens
            + item.reasoning_output_tokens
            + item.unattributed_total_tokens
    };
    let removed = |item: &SnapshotItem| {
        item.removed_usage.as_ref().map_or(0, |u| {
            u.input_tokens
                + u.output_tokens
                + u.cache_read_tokens
                + u.cache_creation_5m_tokens
                + u.cache_creation_1h_tokens
                + u.reasoning_output_tokens
                + u.unattributed_total_tokens
        })
    };
    let lost_requests = head.request_count.saturating_sub(candidate.request_count);
    let lost_tokens = total(head).saturating_sub(total(candidate));
    let explained = lost_requests
        <= candidate
            .removed_request_count
            .unwrap_or(0)
            .saturating_sub(head.removed_request_count.unwrap_or(0))
        && lost_tokens
            <= removed(candidate).saturating_sub(removed(head)) + (total(head) / 100).max(10_000);
    let below_floor = head.request_count < 10 || lost_tokens < 1_000_000;
    let large = lost_requests * 2 >= head.request_count || lost_tokens * 2 >= total(head);
    below_floor || !large || explained
}

/// [money] An over-counted accepted head is corrected once by version three,
/// with removed units explaining the decrease. The version and decisions
/// survive restart, and an unchanged next page produces no upload.
#[test]
fn copied_file_version_three_converges_once() {
    for shape in 0..3 {
        with_e2(|| {
            let mut c = Corpus::new("copied-session-upgrade");
            let (requests, copied, tokens, copied_tokens) = match shape {
                0 => (5_173, 1_011, 3_491_764, 712_616),
                1 => (495, 459, 320_000, 299_574),
                _ => (38, 38, 19_744, 19_744),
            };
            let prefix = responses(ROOT, 0, copied, copied_tokens, A.1);
            let original_text = prefix.clone()
                + &responses(ROOT, copied, requests - copied, tokens - copied_tokens, B.1);
            c.root(ROOT, &original_text);
            // Before the first origin ACK there is no accepted ownership.
            let mut initial = c.raw(
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                false,
                &[],
            );
            initial.enrich(&c);
            initial.finish();
            let mut prior = initial.index;
            let session = if shape == 2 { COPY } else { ROOT };
            let relative = if shape == 1 {
                format!("other/{ROOT}.jsonl")
            } else {
                file(COPY)
            };
            let text = if shape == 2 {
                responses(COPY, 0, copied, copied_tokens, A.1)
                    + &responses(COPY, copied, 4, 3_501, C.1)
            } else {
                prefix
            };
            c.write_at(&relative, &text, BORN);
            // Rebuild the old over-counted body with an unavailable local
            // holder, rather than manufacturing an expired acceptance wait.
            let holder_key = c.root.join(file(ROOT)).to_string_lossy().into_owned();
            let held_source = prior.files[&holder_key].source_file_fingerprint.clone();
            prior.exclude_effective_upload_body_witness_revision_for_source_files(&BTreeSet::from(
                [held_source.clone()],
            ));
            owe(&mut prior);
            let mut old = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
            // Model an earlier body whose holder's census could not prove ids.
            // Rebuild the current census on the later correction read.
            let holder_census = old
                .index
                .claude_request_census_for_test()
                .get(&holder_key)
                .unwrap()
                .clone();
            // The path-twin arm has two files with this basename.
            old.index
                .claude_request_census_mut_for_test()
                .remove(&holder_key);
            old.enrich(&c);
            old = deliver_page(old);
            old.index
                .claude_request_census_mut_for_test()
                .insert(holder_key.clone(), holder_census);
            old.index
                .effective_upload_body_witness_revision_exclusions_for_test()
                .remove(&held_source);
            let head = body(&old, session).unwrap().clone();
            let expected = if shape == 2 { 4 } else { requests as u64 };
            let expected_tokens = if shape == 2 { 3_501 } else { tokens };
            assert_eq!(head.request_count, expected + copied as u64);
            let mut prior = settle(&c, &prior, old, &mut e2_progress());
            prior.claude_money_birth_store.set_money_rule_version(2);
            e2::take_diag();
            e2::apply_money_rules(&mut prior);
            assert_eq!(prior.claude_money_birth_store.money_rule_version(), 5);
            assert_eq!(copy_diag(&["money_rule_v3_reowed"]), [2]);
            prior = c.reload(&mut prior);
            e2::apply_money_rules(&mut prior);
            assert_eq!(
                copy_diag(&["money_rule_v3_reowed"]),
                [0],
                "no second re-owe after restart"
            );
            let mut corrected = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
            corrected.enrich(&c);
            corrected.finish();
            let item = body(&corrected, session).unwrap();
            assert_eq!(
                (item.request_count, item.output_tokens),
                (expected, expected_tokens)
            );
            assert_eq!(item.removed_request_count, Some(copied as u64));
            // Receiver prerequisites: equal max activity (strictly older
            // fence), the same accepted head (CAS), and a fully explained
            // request/token decrease. No receiver bypass is needed.
            assert_eq!(item.source_last_activity_at, head.source_last_activity_at);
            assert_eq!(
                head.request_count - item.request_count,
                item.removed_request_count.unwrap()
            );
            assert!(
                item.removed_usage.as_ref().unwrap().output_tokens
                    >= head.output_tokens - item.output_tokens
            );
            let etag = snapshot_upload_body_witness(&head);
            let item = corrected
                .scan
                .snapshots
                .iter_mut()
                .find(|item| item.source_session_id == session)
                .unwrap();
            item.cache_base_head_etag = Some(etag.clone());
            assert!(receiver_accepts(&head, item, &etag));
            assert!(
                !receiver_accepts(&head, item, &"f".repeat(64)),
                "CAS rejects the wrong head"
            );
            if shape == 2 {
                let mut unexplained = item.clone();
                unexplained.removed_request_count = Some(0);
                unexplained.removed_usage = None;
                assert!(
                    !receiver_accepts(&head, &unexplained, &etag),
                    "a large unexplained decrease holds"
                );
            }
            let mut progress = e2_progress();
            let mut corrected_posts = 0;
            let (status, _, _) = upload(&corrected.scan.snapshots, &mut progress, |batch| {
                for item in batch
                    .iter()
                    .filter(|item| item.source_session_id == session)
                {
                    assert!(receiver_accepts(&head, item, &etag));
                    corrected_posts += 1;
                }
                ack(batch)
            });
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            assert_eq!(corrected_posts, 1);
            prior = settle(&c, &prior, corrected, &mut progress);
            let (quiet, consumed) =
                observe_consumed(|| ready(&c, &E2ScanFixture::default(), prior, 100, false));
            assert_eq!(consumed, 0, "quiet restart parses no transcript bytes");
            assert!(
                quiet.scan.snapshots.is_empty(),
                "quiet convergence uploads nothing"
            );
        });
    }
}

mod subagent_twins {
    include!("tests/subagent_copy_twin_tests.rs");
    include!("tests/subagent_copy_twin_replace_tests.rs");
    include!("tests/subagent_twin_tail_route_tests.rs");
}

const CARRIER: &str = "0338a80a-f36e-4cbc-a5bb-50fc66430ba5";

// Real discovery, body finalization, exact ACKs, save and reload. T sorts
// first and carries ROOT; H retains only its local empty suppression proof.
fn settled_content_carrier(sampled: bool) -> (Corpus, ScanIndex, [PathBuf; 3]) {
    let mut c = Corpus::new("settled-content-carrier");
    let t = c.write_at(&file(CARRIER), &resumed(ROOT, &[B, C]), BORN);
    let h = c.root(ROOT, &resumed(ROOT, &[A, B]));
    let copy = c.write_at(&file(COPY), &resumed(COPY, &[A, D]), BORN);
    let prior = ScanIndex::default();
    let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, sampled);
    assert_eq!(body(&page, ROOT).unwrap().request_count, 3);
    assert_eq!(body(&page, COPY).unwrap().request_count, 1);
    let mut index = settle(&c, &prior, page, &mut e2_progress());
    index.activate_upload_context("e2-synthetic-destination".into());
    assert!(upload_context_receipt_earned_for_test(&index, &t));
    assert!(index
        .confirmed_empty_files
        .contains(&h.to_string_lossy().into_owned()));
    assert!(index.files[&h.to_string_lossy().into_owned()]
        .upload_context_receipt
        .as_ref()
        .unwrap()
        .body_witness
        .is_empty());
    if sampled {
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
    }
    (c, index, [h, copy, t])
}

fn carrier_scanner(index: &ScanIndex) -> E2ScanFixture {
    let scanner = E2ScanFixture::default();
    if let Some(route) = crate::snapshots::e2_pipeline_scan_fixture::route_of(index) {
        scanner.on_committed_route(&route);
    }
    scanner
}

fn removed_hashes(index: &ScanIndex, path: &Path) -> BTreeSet<u64> {
    index
        .claude_copy_removals
        .get(location_key(&path.to_string_lossy()))
        .iter()
        .flat_map(|(_, ids)| ids.iter().copied())
        .collect()
}

fn quiet_carrier_pass(c: &Corpus, index: ScanIndex, paths: &[PathBuf; 3]) -> ScanIndex {
    let scanner = carrier_scanner(&index);
    let page = ready(c, &scanner, index.clone(), 100, true);
    assert!(
        paths.iter().all(|path| !scanner.paths().contains(path)),
        "unchanged H/COPY/T are not read"
    );
    let mut sent = twin(&page);
    sent.finish();
    assert!(sent.scan.snapshots.is_empty(), "no unchanged offers");
    let next = settle(c, &index, page, &mut e2_progress());
    assert!(!next
        .claude_copy_removals
        .pending(location_key(&paths[1].to_string_lossy())));
    assert_eq!(
        removed_hashes(&next, &paths[1]),
        BTreeSet::from([crate::snapshots::claude_request_census::claude_request_hash("a")])
    );
    next
}

fn local_only_carrier() -> (Corpus, ScanIndex, [PathBuf; 3]) {
    let (c, mut index, paths) = settled_content_carrier(true);
    index.upload_context_proof.request_contributions.clear();
    index = c.reload(&mut index);
    index.activate_upload_context("e2-synthetic-destination".into());
    assert!(e2::carrier_group_owned_for_test(
        &index,
        &paths[0].to_string_lossy()
    ));
    (c, index, paths)
}

fn forced_carrier_corpus() -> (Corpus, ScanIndex, PathBuf, PathBuf) {
    let (mut c, index, [holder, _, carrier]) = local_only_carrier();
    append(
        &holder,
        &resumed(ROOT, &[("holder-append", D.1, RESUME_WRITER)]),
    );
    c.write_at(
        &file(THIRD),
        &resumed(THIRD, &[B, ("own-branch", D.1, RESUME_WRITER)]),
        C.1,
    );
    c.write_at(&file(LATE), &line(LATE, "independent", AT, 10), BORN);
    (c, index, holder, carrier)
}

fn portable_carrier_bodies(items: &[SnapshotItem], base: &Path) -> BTreeMap<String, Vec<u8>> {
    items
        .iter()
        .map(|item| {
            let text = serde_json::to_string(item)
                .unwrap()
                .replace(&*base.to_string_lossy(), "<corpus>");
            let mut value: serde_json::Value = serde_json::from_str(&text).unwrap();
            let object = value.as_object_mut().unwrap();
            object.remove("source_file_fingerprint");
            object.remove("snapshot_fingerprint");
            (item.source_session_id.clone(), canonical(&value))
        })
        .collect()
}

/// A newer forced carrier holds dependent copies until recovery can emit the same bodies as a healthy run.
#[test]
fn forced_newer_carrier_holds_dependent_copies_until_readable() {
    use crate::snapshots::e2_pipeline_scan_fixture::{
        forced_needs_native_for_test, set_future_tail_fact_for_test, tail_counter_for_test,
    };
    use crate::snapshots::sampled_scan::transition_fixture::with_scan_clock;
    use crate::snapshots::state_v2::tail_head_reduction_for_test;

    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (healthy, index, holder, carrier) = forced_carrier_corpus();
        let scanner = carrier_scanner(&index);
        let mut expected = healthy.raw(&scanner, index, 100, true, &[holder]);
        assert!(scanner.paths().contains(&carrier));
        expected.enrich(&healthy);
        expected.finish();
        let expected_third_requests = body(&expected, THIRD).unwrap().request_count;
        assert!(body(&expected, LATE).is_some());

        let (c, mut index, holder, carrier) = forced_carrier_corpus();
        let key = carrier.to_string_lossy();
        set_future_tail_fact_for_test(&mut index, &key, true);
        assert!(!forced_needs_native_for_test(&index, &carrier));
        assert!(e2::carrier_group_owned_for_test(
            &index,
            &holder.to_string_lossy()
        ));
        let head = tail_head_reduction_for_test(&index, &key);
        let held_count = tail_counter_for_test("tail_held_newer_build", "forced_twin");
        let scanner = carrier_scanner(&index);
        e2::take_diag();
        let mut held = c.raw(
            &scanner,
            index.clone(),
            100,
            true,
            std::slice::from_ref(&holder),
        );
        assert!(scanner.paths().contains(&holder));
        assert!(!scanner.paths().contains(&carrier));
        assert_eq!(
            tail_counter_for_test("tail_held_newer_build", "forced_twin"),
            held_count + 1
        );
        held.enrich(&c);
        assert_withheld(&held, THIRD, "the forced carrier is unknown on this page");
        assert!(e2::take_diag().contains_key("request_owned_held"));
        let mut sent = twin(&held);
        sent.finish();
        assert!(body(&sent, THIRD).is_none() && body(&sent, LATE).is_some());
        for item in &sent.scan.snapshots {
            let oracle = body(&expected, &item.source_session_id).unwrap();
            assert!(item.request_count <= oracle.request_count);
        }
        index = settle(&c, &index, held, &mut e2_progress());
        // The newer reduction and facts stay as written; only the freshness
        // debt the page's ACK drained may change.
        assert_eq!(tail_head_reduction_for_test(&index, &key), head);

        index.activate_upload_context("e2-synthetic-destination".into());
        set_future_tail_fact_for_test(&mut index, &key, false);
        let scanner = carrier_scanner(&index);
        // The held page may have used the holder's six-hour growth Full claim.
        let retry_at = crate::scan_clock::utc_seconds() + 7 * 60 * 60;
        let mut recovered = with_scan_clock(retry_at, || {
            c.raw(&scanner, index.clone(), 100, true, &[holder])
        });
        assert!(scanner.paths().contains(&carrier));
        recovered.enrich(&c);
        let mut retried = twin(&recovered);
        retried.finish();
        assert_eq!(
            retried
                .scan
                .snapshots
                .iter()
                .filter(|item| item.source_session_id == THIRD)
                .count(),
            1
        );
        assert_eq!(
            body(&retried, THIRD).unwrap().request_count,
            expected_third_requests
        );
        let mut actual = portable_carrier_bodies(&sent.scan.snapshots, &c.base);
        for (session, value) in portable_carrier_bodies(&retried.scan.snapshots, &c.base) {
            assert!(
                actual.insert(session, value).is_none(),
                "session was already emitted"
            );
        }
        assert_eq!(
            actual,
            portable_carrier_bodies(&expected.scan.snapshots, &healthy.base)
        );
        // The quiet pass keeps the recovery's clock: time never runs backwards.
        let mut quiet = with_scan_clock(retry_at + 60, || {
            let settled = settle(&c, &index, recovered, &mut e2_progress());
            ready(&c, &carrier_scanner(&settled), settled, 100, true)
        });
        quiet.finish();
        // Control: the same settle and quiet pass on a never-held corpus.
        let (control, control_index, control_holder, _) = forced_carrier_corpus();
        let control_scanner = carrier_scanner(&control_index);
        let mut first = control.raw(
            &control_scanner,
            control_index.clone(),
            100,
            true,
            &[control_holder],
        );
        first.enrich(&control);
        let mut control_quiet = with_scan_clock(retry_at + 60, || {
            let settled = settle(&control, &control_index, first, &mut e2_progress());
            ready(&control, &carrier_scanner(&settled), settled, 100, true)
        });
        control_quiet.finish();
        assert_eq!(
            body(&quiet, THIRD).is_some(),
            body(&control_quiet, THIRD).is_some(),
            "after recovery the quiet pass matches a never-held corpus"
        );
        assert!(body(&quiet, THIRD).is_none());
    });
}

/// A forced carrier with a missing live input still reads Full on the holder's page.
#[test]
fn forced_carrier_with_unavailable_live_input_still_reads_full() {
    use crate::snapshots::e2_pipeline_scan_fixture::{
        tail_counter_for_test, twin_diagnostics, unavailable_tail_live_once_for_test,
    };
    use crate::transcript_acquisition::ReadMode;

    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let run = |unavailable| {
        with_e2(|| {
            let (c, index, holder, carrier) = forced_carrier_corpus();
            let _trace = twin_diagnostics::begin("forced carrier");
            twin_diagnostics::register(&carrier, "carrier");
            let scanner = carrier_scanner(&index);
            let held = tail_counter_for_test("tail_db_loads", "held");
            if unavailable {
                unavailable_tail_live_once_for_test(&carrier);
            }
            let mut page = c.raw(&scanner, index, 100, true, &[holder]);
            assert_eq!(
                tail_counter_for_test("tail_db_loads", "held"),
                held + u64::from(unavailable)
            );
            let reads = scanner.acquisitions.lock().unwrap();
            let acquired = reads.iter().find(|read| read.path == carrier).unwrap();
            assert_eq!(matches!(acquired.mode, ReadMode::Full(_)), unavailable);
            assert_eq!(
                twin_diagnostics::context().contains("Held forced_twin=true native_fallback"),
                unavailable
            );
            drop(reads);
            page.enrich(&c);
            page.finish();
            portable_carrier_bodies(&page.scan.snapshots, &c.base)
        })
    };
    let healthy = run(false);
    assert!(healthy.contains_key(THIRD));
    assert_eq!(run(true), healthy);
}

/// A failed save withholds the copy and recovery offers the same bodies without a request-count increase.
#[test]
fn failed_save_holds_twin_carried_copy_until_baseline_recovers() {
    use crate::snapshots::{e2_pipeline_scan_fixture::route_of, state_v2};
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (mut c, index, _) = local_only_carrier();
        let copy = c.write_at(
            &file(THIRD),
            &resumed(
                THIRD,
                &[A, ("own-branch", "2026-08-02T07:03:20Z", RESUME_WRITER)],
            ),
            BORN,
        );
        c.write_at(&file(LATE), &line(LATE, "independent", AT, 10), BORN);
        let scanner = carrier_scanner(&index);
        let mut held = c.raw(&scanner, index, 100, true, &[]);
        let mut expected = twin(&held);
        expected.enrich(&c);
        expected.finish();
        assert_eq!(body(&expected, THIRD).unwrap().request_count, 1);
        assert!(body(&expected, LATE).is_some());

        let route = route_of(&held.index).unwrap();
        state_v2::fail_next_carrier_save_for_test(&held.index);
        assert!(held.index.clone().save_fixture(&route).is_err());
        held.enrich(&c);
        assert_withheld(&held, THIRD, "carrier baseline missing after failed save");
        held.finish();
        assert!(body(&held, THIRD).is_none());
        assert_eq!(
            canonical(body(&held, LATE).unwrap()),
            canonical(body(&expected, LATE).unwrap())
        );
        for item in &held.scan.snapshots {
            let oracle = body(&expected, &item.source_session_id).unwrap();
            assert!(item.request_count <= oracle.request_count);
        }

        let recovered = ScanIndex::load(&route).unwrap();
        let scanner = carrier_scanner(&recovered);
        let mut retried = ready(&c, &scanner, recovered, 100, true);
        assert!(scanner.paths().contains(&copy));
        retried.finish();
        assert_eq!(
            canonical(&retried.scan.snapshots),
            canonical(&expected.scan.snapshots)
        );
    });
}

/// A one-shot carrier read error during reconcile preserves the saved groups and produces no corrective offers.
#[test]
fn carrier_read_error_preserves_saved_removals_through_reconcile() {
    use crate::snapshots::state_v2::with_carrier_head_error_for_test;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let run = |fault| {
        with_e2(|| {
            let (c, mut index, paths) = local_only_carrier();
            let copy = location_key(&paths[1].to_string_lossy());
            let groups = index.claude_copy_removals.get(copy).to_vec();
            assert!(!groups.is_empty());
            index.claude_copy_removals.mark(copy);
            let scanner = carrier_scanner(&index);
            let page = ready(&c, &scanner, index.clone(), 100, true);
            assert!(scanner.paths().contains(&paths[1]));
            assert!(!scanner.paths().contains(&paths[0]) && !scanner.paths().contains(&paths[2]));
            assert_eq!(body(&page, COPY).unwrap().request_count, 1);
            let mut sent = twin(&page);
            sent.finish();
            let save = || settle(&c, &index, page, &mut e2_progress());
            let mut next = if fault {
                with_carrier_head_error_for_test(&paths[2].to_string_lossy(), save)
            } else {
                save()
            };
            assert_eq!(next.claude_copy_removals.get(copy), groups.as_slice());
            next.activate_upload_context("e2-synthetic-destination".into());
            assert!(e2::carrier_group_owned_for_test(
                &next,
                &paths[0].to_string_lossy()
            ));
            quiet_carrier_pass(&c, next, &paths);
            canonical(&sent.scan.snapshots)
        })
    };
    assert_eq!(run(true), run(false));
}

/// Once an unknown carrier is confirmed absent, correction matches the same removal with healthy reads.
#[test]
fn carrier_absence_after_unknown_runs_held_correction() {
    use crate::snapshots::e2_pipeline_scan_fixture::{
        non_tail_carrier_observation_for_test, route_of,
    };
    use crate::snapshots::state_v2::with_carrier_head_error_for_test;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let run = |fault| {
        with_e2(|| {
            let (c, mut index, [holder, copy, carrier]) = local_only_carrier();
            let copy_location = location_key(&copy.to_string_lossy());
            let holder_key = holder.to_string_lossy();
            let holder_location = location_key(&holder_key);
            let groups = index.claude_copy_removals.get(copy_location).to_vec();
            assert!(!groups.is_empty());
            let route = route_of(&index).unwrap();
            let mut save = || index.save_fixture(&route).unwrap();
            if fault {
                with_carrier_head_error_for_test(&carrier.to_string_lossy(), save);
            } else {
                save();
            }
            assert_eq!(
                e2::carrier_group_owned_for_test(&index, &holder_key),
                !fault
            );
            assert_eq!(
                index.claude_copy_removals.get(copy_location),
                groups.as_slice()
            );
            assert!(!index.claude_copy_removals.pending(holder_location));
            assert!(!index.claude_copy_removals.pending(copy_location));

            non_tail_carrier_observation_for_test(&index, &carrier);
            index.save_fixture(&route).unwrap();
            assert!(!e2::carrier_group_owned_for_test(&index, &holder_key));
            assert!(index.claude_copy_removals.pending(holder_location));
            assert!(index.claude_copy_removals.pending(copy_location));
            let scanner = carrier_scanner(&index);
            let mut correction = ready(&c, &scanner, index, 100, true);
            assert!(scanner.paths().contains(&copy));
            correction.finish();
            canonical(&correction.scan.snapshots)
        })
    };
    assert_eq!(run(true), run(false));
}

/// Two unreadable saves cause one carrier recovery read, while a newer-format head stays held.
#[test]
fn persistent_unreadable_carrier_repairs_after_two_saves() {
    use crate::snapshots::{
        e2_pipeline_scan_fixture::{route_of, tail_counter_for_test},
        state_v2, state_v2_baseline_release,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Head {
        Healthy,
        Unreadable,
        Future,
    }
    let run = |head| {
        with_e2(|| {
            let (mut c, mut index, [holder, _, carrier]) = local_only_carrier();
            let key = carrier.to_string_lossy();
            let holder_key = holder.to_string_lossy();
            let route = route_of(&index).unwrap();
            match head {
                Head::Healthy => {}
                Head::Unreadable => state_v2::seed_unreadable_tail_head_for_test(&index, &key),
                Head::Future => state_v2::seed_future_carrier_head_for_test(&index, &key),
            }
            index = ScanIndex::load(&route).unwrap();
            for save in 1..=2 {
                index.activate_upload_context("e2-synthetic-destination".into());
                assert_eq!(
                    e2::carrier_group_owned_for_test(&index, &holder_key),
                    head == Head::Healthy
                );
                index.save_fixture(&route).unwrap();
                assert_eq!(
                    state_v2::tail_set_aside_attempts_for_test(&index, &key),
                    (head == Head::Unreadable && save == 2).then_some(1)
                );
                drop(state_v2_baseline_release(&route, &index));
                index = ScanIndex::load(&route).unwrap();
            }

            let scanner = carrier_scanner(&index);
            let before = tail_counter_for_test("tail_reconstruct", "unreadable");
            let recovery = ready(&c, &scanner, index.clone(), 100, true);
            assert_eq!(
                scanner
                    .paths()
                    .iter()
                    .filter(|path| *path == &carrier)
                    .count(),
                usize::from(head == Head::Unreadable)
            );
            assert_eq!(
                tail_counter_for_test("tail_reconstruct", "unreadable") - before,
                u64::from(head == Head::Unreadable)
            );
            let mut sent = twin(&recovery);
            sent.finish();
            index = settle(&c, &index, recovery, &mut e2_progress());
            assert!(state_v2::tail_set_aside_attempts_for_test(&index, &key).is_none());
            index.activate_upload_context("e2-synthetic-destination".into());
            assert_eq!(
                e2::carrier_group_owned_for_test(&index, &holder_key),
                head != Head::Future
            );

            c.write_at(
                &file(THIRD),
                &resumed(
                    THIRD,
                    &[A, ("own-branch", "2026-08-02T07:03:20Z", RESUME_WRITER)],
                ),
                BORN,
            );
            let scanner = carrier_scanner(&index);
            let mut final_page = c.raw(&scanner, index, 100, true, &[]);
            final_page.enrich(&c);
            assert!(!scanner.paths().contains(&carrier));
            if head == Head::Future {
                assert_withheld(&final_page, THIRD, "the newer carrier stays held");
            }
            final_page.finish();
            (sent.scan.snapshots, final_page.scan.snapshots)
        })
    };
    let (healthy_recovery, healthy) = run(Head::Healthy);
    let (recovery_offers, recovered) = run(Head::Unreadable);
    let (future_offers, future) = run(Head::Future);
    assert!(healthy_recovery.is_empty());
    assert!(future_offers.is_empty() && future.is_empty());
    assert_eq!(healthy.len(), 1);
    assert_eq!(healthy[0].source_session_id, THIRD);
    assert_eq!(healthy[0].request_count, 1);
    for item in recovery_offers.iter().chain(&recovered) {
        let limit = match item.source_session_id.as_str() {
            ROOT => 3,
            COPY => 1,
            THIRD => healthy[0].request_count,
            _ => panic!("an unexpected session was offered during carrier recovery"),
        };
        assert!(item.request_count <= limit);
    }
    // Separate corpora: the fingerprints name each run's physical file, not money.
    let portable = |items: &[SnapshotItem]| {
        let mut values = serde_json::to_value(items).unwrap();
        for value in values.as_array_mut().unwrap() {
            let object = value.as_object_mut().unwrap();
            object.remove("snapshot_fingerprint");
            object.remove("source_file_fingerprint");
        }
        canonical(&values)
    };
    assert_eq!(portable(&recovered), portable(&healthy));
}

/// A store error on every carrier read for two saves sets nothing aside and resolves once reads work.
#[test]
fn store_wide_carrier_error_never_sets_aside() {
    use crate::snapshots::{
        e2_pipeline_scan_fixture::route_of, state_v2, state_v2_baseline_release,
    };
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (_c, mut index, [holder, _, carrier]) = local_only_carrier();
        let key = carrier.to_string_lossy();
        let holder_key = holder.to_string_lossy();
        let route = route_of(&index).unwrap();
        for _ in 1..=2 {
            index.activate_upload_context("e2-synthetic-destination".into());
            state_v2::with_carrier_store_error_for_test(|| index.save_fixture(&route)).unwrap();
            assert!(state_v2::tail_set_aside_attempts_for_test(&index, &key).is_none());
            drop(state_v2_baseline_release(&route, &index));
            index = ScanIndex::load(&route).unwrap();
        }
        index.activate_upload_context("e2-synthetic-destination".into());
        index.save_fixture(&route).unwrap();
        assert!(state_v2::tail_set_aside_attempts_for_test(&index, &key).is_none());
        assert!(e2::carrier_group_owned_for_test(&index, &holder_key));
    });
}

/// Scan decisions reuse the hydrated carrier even when claim-only work has
/// advanced the store beyond the scan image's generation.
#[test]
fn hydrated_content_carrier_survives_a_lagging_scan_generation() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, mut index, paths) = settled_content_carrier(true);
        index = c.reload(&mut index);
        let holder = paths[0].to_string_lossy();
        assert!(!index.file_upload_context_enabled());
        assert!(!e2::carrier_group_owned_for_test(&index, &holder));
        index.activate_upload_context("e2-synthetic-destination".into());
        assert!(e2::carrier_group_owned_for_test(&index, &holder));
        let mut lagging = index.clone();
        lagging.generation = index.generation.checked_sub(1).unwrap();
        assert!(e2::carrier_group_owned_for_test(&lagging, &holder));
        lagging.activate_upload_context("another-destination".into());
        assert!(!e2::carrier_group_owned_for_test(&lagging, &holder));
        for _ in 0..3 {
            index = quiet_carrier_pass(&c, index, &paths);
        }
    });
}

/// [money] An exact-ACKed content carrier survives reload without another
/// offer, receipt rewrite, acquisition or copy-removal re-decision.
#[test]
fn settled_content_carrier_is_quiet_after_reload_and_legacy_hold_age() {
    use base64::Engine;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for legacy_age in [false, true] {
        with_e2(|| {
            let (c, mut index, paths) = settled_content_carrier(true);
            let receipt = serde_json::to_vec(
                &index.files[&paths[2].to_string_lossy().into_owned()].upload_context_receipt,
            )
            .unwrap();
            if legacy_age {
                // Main's prefix-hold age occupied the same CCR2 slot. Import a
                // real encoded age=2 instead of manufacturing a new debt kind.
                let encoded: String = serde_json::from_value(
                    serde_json::to_value(&index.claude_copy_removals).unwrap(),
                )
                .unwrap();
                let mut bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(encoded)
                    .unwrap();
                let count = u32::from_le_bytes(bytes[5..9].try_into().unwrap()) as usize;
                let mut offset = 9;
                let wanted = location_key(&paths[1].to_string_lossy()).to_bytes();
                let mut changed = false;
                for _ in 0..count {
                    if bytes[offset..offset + 16] == wanted {
                        bytes[offset + 16..offset + 24].copy_from_slice(&2_u64.to_le_bytes());
                        changed = true;
                    }
                    let groups =
                        u32::from_le_bytes(bytes[offset + 24..offset + 28].try_into().unwrap())
                            as usize;
                    offset += 28;
                    for _ in 0..groups {
                        let hashes =
                            u32::from_le_bytes(bytes[offset + 16..offset + 20].try_into().unwrap())
                                as usize;
                        offset += 20 + 8 * hashes;
                    }
                }
                assert!(changed);
                index.claude_copy_removals = serde_json::from_value(json!(
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
                ))
                .unwrap();
                index = c.reload(&mut index);
                let scanner = carrier_scanner(&index);
                let page = ready(&c, &scanner, index.clone(), 100, true);
                assert!(
                    scanner.paths().contains(&paths[1]),
                    "one legacy-age re-decision"
                );
                index = settle(&c, &index, page, &mut e2_progress());
            }
            for _ in 0..3 {
                index = quiet_carrier_pass(&c, index, &paths);
            }
            assert_eq!(
                serde_json::to_vec(
                    &index.files[&paths[2].to_string_lossy().into_owned()].upload_context_receipt
                )
                .unwrap(),
                receipt
            );
            assert!(index
                .confirmed_empty_files
                .contains(&paths[0].to_string_lossy().into_owned()));
        });
    }
}

/// [money] Deleting the carrier re-arms H together with COPY. The next page
/// has neither owe-all nor hints: COPY can rely on H's freshly read A.
#[test]
fn deleted_content_carrier_recovers_main_with_its_dependents() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, mut index, [h, copy, t]) = settled_content_carrier(true);
        // Hydration captures the committed baseline before a new pass installs
        // its runtime-only context. This must retain old carrier eligibility.
        index = c.reload(&mut index);
        assert!(!index.file_upload_context_enabled());
        assert!(!e2::carrier_group_owned_for_test(
            &index,
            &h.to_string_lossy()
        ));
        std::fs::remove_file(&t).unwrap();
        let scanner = carrier_scanner(&index);
        // Ordinary discovery commits positive absence; the save publishes
        // both recovery marks, without borrowing any proof from deleted T.
        let discovery = ready(&c, &scanner, index.clone(), 100, true);
        index = settle(&c, &index, discovery, &mut e2_progress());
        assert!(!index.files.contains_key(&t.to_string_lossy().into_owned()));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&h.to_string_lossy())));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        let mut native = index.clone();
        owe(&mut native);
        let reference = ready(&c, &E2ScanFixture::default(), native, 100, false);
        let page = ready(&c, &scanner, index.clone(), 100, true);
        assert!(scanner.paths().contains(&h) && scanner.paths().contains(&copy));
        assert!(!scanner.paths().contains(&t));
        assert_eq!(
            body(&page, ROOT).unwrap().request_count,
            2,
            "ROOT keeps A and B"
        );
        assert_eq!(
            body(&page, COPY).unwrap().request_count,
            1,
            "COPY keeps only D"
        );
        assert_eq!(body(&page, COPY).unwrap().removed_request_count, Some(1));
        // COPY re-decides to the body it already has accepted: finalize
        // carries its receipt instead of offering it again. ROOT is offered.
        let copy_key = copy.to_string_lossy().into_owned();
        let accepted_copy = index.files[&copy_key].last_upload_body_witness.clone();
        let measured = sent_money(&page);
        assert!(measured.snapshots.contains_key(ROOT));
        assert!(!measured.snapshots.contains_key(COPY));
        index = settle(&c, &index, page, &mut e2_progress());
        assert_eq!(
            index.files[&copy_key].last_upload_body_witness,
            accepted_copy
        );
        // An explicitly owed page of the recovered state matches the native
        // complete-money oracle.
        let mut verify = index.clone();
        owe(&mut verify);
        let complete = ready(&c, &carrier_scanner(&verify), verify, 100, true);
        money_oracle::assert_equivalent(&sent_money(&reference), &sent_money(&complete));
        index = settle(&c, &index, complete, &mut e2_progress());
        for _ in 0..3 {
            let page = ready(&c, &scanner, index.clone(), 100, true);
            assert!(!scanner.paths().contains(&h) && !scanner.paths().contains(&copy));
            let mut sent = twin(&page);
            sent.finish();
            assert!(sent.scan.snapshots.is_empty());
            index = settle(&c, &index, page, &mut e2_progress());
            assert!(!index
                .claude_copy_removals
                .pending(location_key(&copy.to_string_lossy())));
        }
    });
}

/// [regress] A held or refused T, and an ACK under an old context, lose
/// authority. Unchanged saves invalidate H's dependents only once.
#[test]
fn content_carrier_hold_refusal_and_context_change_invalidate_once() {
    use crate::snapshots::e2_pipeline_scan_fixture::hold_claude_account_for_test;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for reason in ["held", "refused", "context"] {
        with_e2(|| {
            let (c, mut index, [h, copy, t]) = settled_content_carrier(true);
            let key = t.to_string_lossy().into_owned();
            match reason {
                "held" => hold_claude_account_for_test(&mut index, &key),
                "refused" => {
                    let fp = index.file_snapshot_fingerprints[&key]
                        .iter()
                        .next()
                        .unwrap()
                        .clone();
                    let mut progress = e2_progress();
                    progress.quarantine_permanent_body(&fp, "refused-body", "synthetic refusal");
                    index
                        .quarantined_snapshot_fingerprints
                        .insert(fp.clone(), progress.quarantined_fingerprints[&fp].clone());
                }
                "context" => index.activate_upload_context("changed-destination".into()),
                _ => unreachable!(),
            }
            assert!(
                !e2::carrier_group_owned_for_test(&index, &h.to_string_lossy()),
                "{reason} must not own H"
            );
            index = c.reload(&mut index);
            assert!(
                index
                    .claude_copy_removals
                    .pending(location_key(&copy.to_string_lossy())),
                "{reason}"
            );
            if reason == "context" {
                // Resolve adoption with a real read and ACK before requiring
                // quiet saves; discarding a mark does not settle context debt.
                let mut owed = index.clone();
                owe(&mut owed);
                let scanner = carrier_scanner(&index);
                let mut page = c.raw(&scanner, owed, 100, true, &[]);
                page.index
                    .activate_upload_context("changed-destination".into());
                page.committed
                    .activate_upload_context("changed-destination".into());
                page.enrich(&c);
                index = settle(&c, &index, deliver_page(page), &mut e2_progress());
                index.activate_upload_context("changed-destination".into());
                assert!(upload_context_receipt_earned_for_test(&index, &t));
            } else {
                index
                    .claude_copy_removals
                    .clear_hold(location_key(&copy.to_string_lossy()));
                index
                    .claude_copy_removals
                    .clear_hold(location_key(&h.to_string_lossy()));
            }
            index = c.reload(&mut index);
            assert!(
                !index
                    .claude_copy_removals
                    .pending(location_key(&copy.to_string_lossy())),
                "{reason} re-marked"
            );
        });
    }
}

/// [regress] Exact acceptance and overlapping hashes in the same folder
/// cannot carry a different session's empty-proof-only filename main.
#[test]
fn different_session_content_carrier_does_not_own_main() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (mut c, mut index, [h, copy, t]) = settled_content_carrier(true);
        c.write_at(&file(CARRIER), &resumed(THIRD, &[B, C]), BORN);
        let mut owed = index.clone();
        owe(&mut owed);
        let scanner = carrier_scanner(&index);
        let mut page = c.raw(&scanner, owed, 100, true, &[]);
        let fingerprint = page.index.files[&t.to_string_lossy().into_owned()]
            .source_file_fingerprint
            .clone();
        page.scan
            .snapshots
            .retain(|item| item.source_file_fingerprint.as_ref() == Some(&fingerprint));
        page.enrich(&c);
        let page = deliver_page(page);
        index = settle(&c, &index, page, &mut e2_progress());
        index.activate_upload_context("e2-synthetic-destination".into());
        assert!(upload_context_receipt_earned_for_test(&index, &t));
        assert!(!e2::carrier_group_owned_for_test(
            &index,
            &h.to_string_lossy()
        ));
        // Exercise lost ROOT in the committed image versus staged THIRD in
        // the effective image; same hash incidence is not a session link.
        assert!(index
            .claude_copy_removals
            .pending(location_key(&h.to_string_lossy())));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
    });
}

/// [regress] This save runs reconcile while v2 owns its session mutex. A
/// scan-time reader inside capture/reconcile would recursively lock it.
#[test]
fn content_carrier_reconcile_under_open_v2_save_does_not_deadlock() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let (send, receive) = std::sync::mpsc::channel();
    let worker = std::thread::spawn(move || {
        with_e2(|| {
            let (c, mut index, _) = settled_content_carrier(true);
            index = c.reload(&mut index);
            send.send(index.generation).unwrap();
        });
    });
    assert!(
        receive
            .recv_timeout(std::time::Duration::from_secs(20))
            .is_ok(),
        "v2 carrier reconcile deadlocked"
    );
    worker.join().unwrap();
}

/// [regress] Its saves retain exact accepted counted rows, grant no new
/// head-backed authority and never relock a v2 session. Every save is native
/// now, so the JSON-era unrouted checks are the only ones this case no longer
/// makes.
#[test]
fn unsampled_content_carrier_keeps_accepted_rows_and_removals() {
    with_e2(|| {
        let (c, mut index, _) = settled_content_carrier(false);
        assert!(!index.upload_context_proof.request_contributions.is_empty());
        let rows = index.upload_context_proof.request_contributions.clone();
        let copy = c.root.join(file(COPY));
        let removals = removed_hashes(&index, &copy);
        for _ in 0..3 {
            let page = ready(&c, &E2ScanFixture::default(), index.clone(), 100, false);
            index = settle(&c, &index, page, &mut e2_progress());
            assert_eq!(index.upload_context_proof.request_contributions, rows);
            assert_eq!(removed_hashes(&index, &copy), removals);
            assert!(
                !index
                    .claude_copy_removals
                    .pending(location_key(&c.root.join(file(COPY)).to_string_lossy())),
                "fresh accepted rows settle ownership without a sampled head"
            );
        }
    });
}

/// [regress] Carrier freshness admits verified Exact/Empty twins only and
/// does not broaden any census predicate used to prove copied requests.
#[test]
fn content_carrier_freshness_rejects_each_unknown_revision() {
    use crate::snapshots::claude_request_census::{
        ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
    };
    let fp = "a".repeat(64);
    let record = Record::synthetic_for_test(&fp, 1, Shape::Exact, vec![1]).with_twin_for_test(true);
    assert!(record.current_twin_for(&fp));
    assert!(!record.current_for(&fp));
    assert!(!record.proves_scan());
    assert!(!record.current_twin_for(&"b".repeat(64)));
    let mut retired = record.clone();
    retired.retire();
    for bad in [
        record.clone().with_unverified_for_test(true),
        record.clone().with_derivation_for_test(0),
        record.clone().with_twin_for_test(false),
        retired,
    ] {
        assert!(!bad.current_twin_for(&fp));
    }
    for (shape, expected) in [
        (Shape::Empty, true),
        (Shape::IdentityIncomplete, false),
        (Shape::Lossy, false),
        (Shape::OverBudget, false),
    ] {
        let record = Record::synthetic_for_test(&fp, 1, shape, vec![]).with_twin_for_test(true);
        assert_eq!(record.current_twin_for(&fp), expected, "{shape:?}");
    }
}

/// [regress] Freshness discovery resolves a real persisted T revision by a
/// Tail-only observation. Saving that observation must retain T's session.
#[test]
fn discovery_debt_only_save_keeps_content_carrier() {
    use crate::snapshots::e2_pipeline_scan_fixture::resolve_carrier_discovery_debt_for_test;
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, mut index, paths) = settled_content_carrier(true);
        let (before, after) = resolve_carrier_discovery_debt_for_test(&mut index, &paths[2]);
        assert!(
            before > 0,
            "a real discovery revision must have been persisted"
        );
        assert_eq!(after, 0, "exact ACK resolves the discovery revision");
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&paths[1].to_string_lossy())));
        index = c.reload(&mut index);
        for _ in 0..3 {
            index = quiet_carrier_pass(&c, index, &paths);
        }
    });
}

/// [regress] Reconcile compares different head images. A staged session
/// reset invalidates ROOT even though T retains identical request hashes.
#[test]
fn content_carrier_committed_and_effective_sessions_are_distinct() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (_c, index, [h, copy, t]) = settled_content_carrier(true);
        let mut next = index.clone();
        let key = t.to_string_lossy().into_owned();
        e2::reconcile_carrier_images_for_test(&index, &mut next, |keys, committed| {
            assert!(keys.contains(&key.as_str()));
            BTreeMap::from([(key.clone(), if committed { ROOT } else { THIRD }.to_owned())])
        });
        assert!(next
            .claude_copy_removals
            .pending(location_key(&h.to_string_lossy())));
        assert!(next
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
    });
}

/// [regress] Re-ACKing T under the new upload context restores authority;
/// an old-context receipt alone never makes H owned.
#[test]
fn content_carrier_requires_exact_ack_under_the_active_context() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, mut index, [h, _, t]) = settled_content_carrier(true);
        index.activate_upload_context("replacement-context".into());
        assert!(!e2::carrier_group_owned_for_test(
            &index,
            &h.to_string_lossy()
        ));
        let mut owed = index.clone();
        owe(&mut owed);
        let scanner = carrier_scanner(&index);
        let mut page = c.raw(&scanner, owed, 100, true, &[]);
        page.index
            .activate_upload_context("replacement-context".into());
        page.committed
            .activate_upload_context("replacement-context".into());
        page.enrich(&c);
        index = settle(&c, &index, deliver_page(page), &mut e2_progress());
        index.activate_upload_context("replacement-context".into());
        assert!(upload_context_receipt_earned_for_test(&index, &t));
        assert!(e2::carrier_group_owned_for_test(
            &index,
            &h.to_string_lossy()
        ));
    });
}

/// [regress] A non-Tail debt observation drops T's reduction, so its still
/// exact receipt no longer supplies a session link for H's saved groups.
#[test]
fn non_tail_debt_observation_invalidates_content_carrier_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, mut index, [h, copy, t]) = settled_content_carrier(true);
        crate::snapshots::e2_pipeline_scan_fixture::non_tail_carrier_observation_for_test(
            &index, &t,
        );
        index = c.reload(&mut index);
        index.activate_upload_context("e2-synthetic-destination".into());
        assert!(!e2::carrier_group_owned_for_test(
            &index,
            &h.to_string_lossy()
        ));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&h.to_string_lossy())));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        index
            .claude_copy_removals
            .clear_hold(location_key(&h.to_string_lossy()));
        index
            .claude_copy_removals
            .clear_hold(location_key(&copy.to_string_lossy()));
        index = c.reload(&mut index);
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
    });
}

/// [regress] A context-free baseline remembers only byte-bound carriers.
/// Even a valid committed receipt grants no effective ownership by itself.
#[test]
fn committed_content_carrier_requires_bound_receipt_after_reload() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, mut index, [h, _, t]) = settled_content_carrier(true);
        index = c.reload(&mut index);
        assert!(!index.file_upload_context_enabled());
        let key = t.to_string_lossy().into_owned();
        for case in [
            "valid",
            "source",
            "body",
            "empty",
            "replay",
            "confirmed-empty",
            "missing",
        ] {
            let mut previous = index.clone();
            let receipt = previous
                .files
                .get_mut(&key)
                .unwrap()
                .upload_context_receipt
                .as_mut()
                .unwrap();
            match case {
                "source" => receipt.source_witness.push('x'),
                "body" => receipt.body_witness.push('x'),
                "empty" => receipt.body_witness.clear(),
                "replay" => receipt.replay_generation += 1,
                "confirmed-empty" => {
                    previous.confirmed_empty_files.insert(key.clone());
                }
                "missing" => previous.files.get_mut(&key).unwrap().upload_context_receipt = None,
                "valid" => {}
                _ => unreachable!(),
            }
            assert!(!e2::carrier_group_owned_for_test(
                &previous,
                &h.to_string_lossy()
            ));
            let mut next = previous.clone();
            next.files.remove(&key);
            let mut eligible = false;
            e2::reconcile_carrier_images_for_test(&previous, &mut next, |keys, committed| {
                if committed {
                    eligible = keys.contains(&key.as_str());
                }
                BTreeMap::new()
            });
            assert_eq!(eligible, case == "valid", "{case}");
        }
    });
}

mod accepted_holder_row_tests {
    include!("tests/accepted_holder_row_tests.rs");
}

mod entity_last_clock_tests {
    include!("tests/entity_last_clock_tests.rs");
}

/// [money] A current carrier keeps the main's Local proof for both a stored
/// copy and a new copy, even when old state has no accepted counted rows.
#[test]
fn carried_main_keeps_local_proof_without_accepted_request_rows() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (mut c, mut index, [h, copy, t]) = settled_content_carrier(true);
        index.upload_context_proof.request_contributions.clear();
        index = c.reload(&mut index);
        index.activate_upload_context("e2-synthetic-destination".into());
        assert!(e2::carrier_group_owned_for_test(
            &index,
            &h.to_string_lossy()
        ));
        index
            .claude_copy_removals
            .mark(location_key(&copy.to_string_lossy()));
        c.write_at(
            &file(THIRD),
            &resumed(
                THIRD,
                &[A, ("own-branch", "2026-08-02T07:03:20Z", RESUME_WRITER)],
            ),
            BORN,
        );
        let scanner = carrier_scanner(&index);
        let page = ready(&c, &scanner, index, 100, true);
        assert!(!scanner.paths().contains(&h) && !scanner.paths().contains(&t));
        for session in [COPY, THIRD] {
            let item = body(&page, session).unwrap();
            assert_eq!(
                (item.request_count, item.removed_request_count),
                (1, Some(1))
            );
        }
    });
}

/// [money] A settled same-session path twin can keep its counted prefix when
/// the holder's acceptance was committed while the copy census was absent.
/// Rule 5 compares that unchanged decision once. Ordinary twin acquisition
/// co-reads its main; a separate off-page fold pins the resumed Rule A limit.
#[test]
fn settled_disclosed_copy_redecides_once_after_holder_acceptance() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    const OLD_RULES: &[(u16, u8)] = &[(1, 0), (2, 0), (3, 0), (4, 0)];
    for resumed_copy in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("settled-counted-copy");
            let turns = if resumed_copy {
                vec![A, B, C]
            } else {
                vec![A, B]
            };
            let copy = c.write_at(&file(COPY), &resumed(ROOT, &turns), BORN);
            let unrelated = c.write_at(
                &format!("unrelated/{}", file(THIRD)),
                &resumed(THIRD, &[("unrelated", A.1, OLD_WRITER)]),
                BORN,
            );
            let scanner = E2ScanFixture::default();
            let empty = ScanIndex::default();
            let mut first = ready(&c, &scanner, empty.clone(), 100, true);
            first.finish();
            let counted = body(&first, ROOT).unwrap().clone();
            assert_eq!(counted.request_count, turns.len() as u64);
            assert_eq!(counted.removed_request_count, Some(0));
            let mut prior = settle(&c, &empty, first, &mut e2_progress());
            let copy_key = copy.to_string_lossy().into_owned();
            let unrelated_key = unrelated.to_string_lossy().into_owned();
            let location = location_key(&copy_key);
            assert_ne!(
                prior.claude_money_birth_store.money_marks(location) & e2::money_mark::DISCLOSED,
                0
            );
            assert_ne!(
                prior
                    .claude_money_birth_store
                    .money_marks(location_key(&unrelated_key))
                    & e2::money_mark::DISCLOSED,
                0
            );
            assert!(removed_hashes(&prior, &copy).is_empty());

            // The copy is already settled while its earlier holder has no
            // accepted body. Temporarily missing census is not an invitation
            // to reread it when the holder is subsequently accepted.
            let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
            let holder_key = holder.to_string_lossy().into_owned();
            assert!(!accepted_file_for_test(&prior, &holder_key));
            let census = prior
                .claude_request_census_for_test()
                .get(&copy_key)
                .unwrap()
                .clone();
            prior.claude_request_census_mut_for_test().remove(&copy_key);
            let holder_page = ready(&c, &scanner, prior.clone(), 100, true);
            assert_eq!(scanner.paths(), vec![holder.clone()]);
            assert_eq!(body(&holder_page, ROOT).unwrap().request_count, 2);
            prior = settle(&c, &prior, holder_page, &mut e2_progress());
            assert!(accepted_file_for_test(&prior, &holder_key));
            prior
                .claude_request_census_mut_for_test()
                .insert(copy_key.clone(), census);
            prior.claude_money_birth_store.set_money_rule_version(4);
            prior = c.reload(&mut prior);
            assert!(!prior.claude_copy_removals.pending(location));
            // The graph is already committed. Avoid the fixture's implicit
            // pre-scan save before Corpus::raw activates its upload context:
            // that would falsely withdraw the copy's carrier proof and re-owe
            // the main, whose read also pulls this overlapping content twin.
            let scanner = carrier_scanner(&prior);

            // Old-red control: no pass means no read and no removal, even
            // though exact accepted request rows now prove the earlier main.
            e2::with_money_rules(OLD_RULES, || e2::apply_money_rules(&mut prior));
            let quiet = ready(&c, &scanner, prior.clone(), 100, true);
            assert!(scanner.paths().is_empty());
            assert!(quiet.scan.snapshots.is_empty());
            assert!(removed_hashes(&quiet.index, &copy).is_empty());
            prior = settle(&c, &prior, quiet, &mut e2_progress());
            // Match the daemon: activate the context before rules and save.
            prior.activate_upload_context("e2-synthetic-destination".into());
            // A hold and a decision that already removed this prefix must
            // not gain a correction obligation from the one-time pass.
            let mut held = prior.clone();
            held.exclude_effective_upload_body_witness_revision_for_source_files(&BTreeSet::from(
                [held.files[&copy_key].source_file_fingerprint.clone()],
            ));
            e2::apply_money_rules(&mut held);
            assert!(!held.claude_copy_removals.pending(location));
            let mut removed = prior.clone();
            removed.claude_copy_removals.store(
                location,
                BTreeMap::from([(
                    location_key(&holder_key),
                    BTreeSet::from(
                        ["a", "b"]
                            .map(crate::snapshots::claude_request_census::claude_request_hash),
                    ),
                )]),
            );
            e2::apply_money_rules(&mut removed);
            assert!(!removed.claude_copy_removals.pending(location));

            // Exact accepted request rows also suffice without a locally
            // counted holder body; a receipt alone is not the hash proof.
            let mut accepted_only = prior.clone();
            accepted_only
                .file_snapshot_fingerprints
                .get_mut(&holder_key)
                .unwrap()
                .clear();
            e2::apply_money_rules(&mut accepted_only);
            assert!(accepted_only.claude_copy_removals.pending(location));
            let revisions = prior
                .files
                .iter()
                .map(|(k, v)| (k.clone(), v.effective_upload_body_witness_revision))
                .collect::<BTreeMap<_, _>>();
            e2::apply_money_rules(&mut prior);
            assert_eq!(prior.claude_money_birth_store.money_rule_version(), 5);
            for (key, entry) in &prior.files {
                assert_eq!(entry.effective_upload_body_witness_revision, revisions[key]);
                assert_eq!(
                    prior.claude_copy_removals.pending(location_key(key)),
                    key == &copy_key
                );
            }
            // Publish the version and its one-read mark together, then load
            // that committed state as the next ordinary page does.
            prior = c.reload(&mut prior);
            assert_eq!(prior.claude_money_birth_store.money_rule_version(), 5);
            assert!(prior.claude_copy_removals.pending(location));
            assert!(!prior
                .claude_copy_removals
                .pending(location_key(&holder_key)));
            let mut corrected = c.raw(&scanner, prior.clone(), 100, true, &[]);
            // Ordinary acquisition of a content twin pulls overlapping mains.
            // Only the copy is marked; this isolated pair costs at most two
            // reads, including its same-session main through that existing pull.
            assert_eq!(
                scanner.paths(),
                vec![copy.clone(), holder.clone()],
                "the marked copy plus its pulled main"
            );
            assert!(
                scanner.acquisitions.lock().unwrap().iter().all(|read| {
                    !matches!(read.mode, crate::transcript_acquisition::ReadMode::Full(_))
                }),
                "a correction keeps the ordinary validated Tail mode"
            );
            // Pin the existing off-page Rule A decision independently of
            // acquisition: the real correction page above includes the main.
            // This reference page is never finalized, saved or ACKed.
            let mut off_page = twin(&corrected);
            off_page.scan.snapshots.retain(|item| {
                item.claude_money
                    .as_deref()
                    .and_then(e2::FileFold::location_key)
                    == Some(location)
            });
            unobserved(|| evidence_chunk_tests::isolated(|| off_page.enrich(&c)));
            assert!(!off_page.index.claude_copy_removals.pending(location));
            if resumed_copy {
                // Rule A needs its holder on the page for a resumed copy; this
                // twin-only page is held for its absent filename main
                // (content_twin_holds), so the copy keeps its 3 requests and
                // is not emitted (no removal count).
                let item = body(&off_page, ROOT).unwrap();
                assert_eq!(
                    (item.request_count, item.removed_request_count),
                    (3, None),
                    "Rule A needs its holder on the page for a resumed copy"
                );
                assert_eq!(
                    off_page
                        .disposition
                        .request_owned_hold_reasons
                        .get("absent_content_twin"),
                    Some(&1)
                );
                assert!(removed_hashes(&off_page.index, &copy).is_empty());
            } else {
                // As in copied_content_and_path_twins_count_once, a page
                // containing only a content twin waits for its filename main.
                // The stored removal stands, but the held item stays owed
                // instead of reaching the all-copy suppression branch.
                assert!(
                    body(&off_page, ROOT).is_some(),
                    "the content-held copy stays owed"
                );
                assert_eq!(
                    off_page
                        .disposition
                        .request_owned_hold_reasons
                        .get("absent_content_twin"),
                    Some(&1)
                );
                assert_eq!(off_page.disposition.quarantined_entity_count(), 1);
                assert_eq!(removed_hashes(&off_page.index, &copy).len(), 2);
            }
            corrected.enrich(&c);
            corrected.finish();
            assert!(!corrected.index.claude_copy_removals.pending(location));
            assert_eq!(removed_hashes(&corrected.index, &copy).len(), 2);
            prior = settle(&c, &prior, corrected, &mut e2_progress());
            // A second load needs no intervening inactive-context save.
            let route = crate::snapshots::e2_pipeline_scan_fixture::route_of(&prior).unwrap();
            prior = ScanIndex::load(&route).unwrap();
            e2::apply_money_rules(&mut prior);
            e2::with_money_rules(OLD_RULES, || e2::apply_money_rules(&mut prior));
            assert_eq!(prior.claude_money_birth_store.money_rule_version(), 5);
            assert!(prior
                .files
                .keys()
                .all(|key| !prior.claude_copy_removals.pending(location_key(key))));
            let quiet = ready(&c, &scanner, prior, 100, true);
            assert!(
                scanner.paths().is_empty(),
                "the rule never rearms on reload"
            );
            assert!(quiet.scan.snapshots.is_empty());
        });
    }
}
