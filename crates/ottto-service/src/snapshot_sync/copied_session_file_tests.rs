//! Copied files use accepted origins, across sessions and folders.
use super::*;
use crate::snapshots::claude_money_birth_store::location_key;
use crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test;
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
            let seeded = ready(&c, &scanner, prior.clone(), 100, false);
            assert_eq!(
                body(&seeded, ROOT).unwrap().request_count,
                expected,
                "the copy's own turn stays counted"
            );
            // Reference: the owed copy is read first and its pull brings the
            // original, the composition of a copy-seeded page.
            let mut again = prior.clone();
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

/// [money] The earliest copy holder is not the complete session: every main
/// reselection keeps the union, and incomplete pages never replace that union.
#[test]
fn content_session_closure_ignores_earliest_holder() {
    for sampled in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("content-session-closure");
            let holder = c.write_at(
                &format!("earlier/{THIRD}.jsonl"),
                &resumed(THIRD, &[A]),
                "2026-08-02T06:59:00Z",
            );
            let main = c.root(ROOT, &resumed(ROOT, &[A, B]));
            let mut prior = warm(&c);
            let twin = c.write_at(&file(COPY), &resumed(ROOT, &[A, B, C]), BORN);
            owe(&mut prior);
            let both = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, sampled);
            assert_eq!(body(&both, ROOT).unwrap().request_count, 3);
            prior = settle(&c, &prior, both, &mut e2_progress());
            let (main_key, twin_key) = (
                main.to_string_lossy().into_owned(),
                twin.to_string_lossy().into_owned(),
            );
            assert_eq!(
                e2::copied_file_holders_for_test(&prior, std::iter::once(twin_key.as_str()))
                    [&twin_key],
                holder.to_string_lossy(),
                "the twin's earliest accepted holder is in another session and folder"
            );
            append(&main, &resumed(ROOT, &[D]));
            let scanner = E2ScanFixture::default();
            let mut complete = c.raw(&scanner, prior.clone(), 100, sampled, &[]);
            assert!(
                scanner.paths().contains(&twin),
                "main-only selection pulls the twin"
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
                "content session survives the Tail route"
            );
            assert_eq!(
                folded.claude_usage_request_ids,
                BTreeSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned(),])
            );
            complete.enrich(&c);
            assert_eq!(body(&complete, ROOT).unwrap().request_count, 4);
            // Observe the receiver's whole-session replacement after every ACK.
            let mut accepted = BTreeMap::new();
            let mut acknowledge = |page: &mut Page| {
                page.finish();
                let (status, _, _) = upload(&page.scan.snapshots, &mut e2_progress(), |items| {
                    let response = ack(items);
                    for item in items {
                        accepted.insert(item.source_session_id.clone(), item.request_count);
                    }
                    assert_eq!(
                        accepted[ROOT], 4,
                        "an ACK never replaces four requests with three"
                    );
                    response
                });
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            };
            acknowledge(&mut complete);
            prior = settle(&c, &prior, complete, &mut e2_progress());
            for cause in ["absent", "lossy", "bound"] {
                let mut selected = prior.clone();
                assert!(selected.re_owe_effective_upload_body_witness_revision(&main_key, 2));
                let mut page = c.raw(&E2ScanFixture::default(), selected, 100, sampled, &[]);
                assert!(page.scan.snapshots.iter().any(|item| {
                    item.claude_money
                        .as_deref()
                        .and_then(e2::FileFold::location_key)
                        == Some(location_key(&twin_key))
                }));
                page.scan.snapshots.retain(|item| {
                    item.claude_money
                        .as_deref()
                        .and_then(e2::FileFold::location_key)
                        != Some(location_key(&twin_key))
                        && item.source_session_id == ROOT
                });
                if cause == "bound" {
                    // Install the bound failure at the same post-pull seam
                    // as the missing fold, without committing a corrupt row.
                    crate::snapshots::e2_pipeline_scan_fixture::hold_file_decode_for_test(
                        &mut page.index,
                        &twin_key,
                    );
                }
                if cause == "lossy" {
                    // No extra ids: only the non-Exact shape requires the hold.
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
                    let item = page
                        .scan
                        .snapshots
                        .iter_mut()
                        .find(|item| item.source_session_id == ROOT)
                        .unwrap();
                    item.claude_usage_request_ids.insert("c".into());
                }
                let removals = page.index.claude_copy_removals.clone();
                page.enrich(&c);
                assert_eq!(
                    page.disposition
                        .request_owned_hold_reasons
                        .get("absent_content_twin"),
                    Some(&1)
                );
                assert!(
                    body(&page, ROOT).is_some(),
                    "held items remain until withholding"
                );
                let holds = page.finish();
                assert!(holds.progress_blocking);
                assert!(body(&page, ROOT).is_none(), "partial bodies never upload");
                assert_eq!(
                    page.index.claude_copy_removals, removals,
                    "holding creates no removal debt or COPY mark"
                );
                assert_eq!(
                    page.index.files[&main_key].effective_upload_body_witness_revision,
                    2
                );
                acknowledge(&mut page);
                let mut recover = prior.clone();
                assert!(recover.re_owe_effective_upload_body_witness_revision(&main_key, 2));
                let mut recovered = c.raw(&E2ScanFixture::default(), recover, 100, sampled, &[]);
                recovered.enrich(&c);
                assert_eq!(body(&recovered, ROOT).unwrap().request_count, 4);
                acknowledge(&mut recovered);
                prior = settle(&c, &prior, recovered, &mut e2_progress());
            }
            // Positive deletion releases the dependency, matching path twins.
            std::fs::remove_file(&twin).unwrap();
            let mut selected = prior.clone();
            assert!(selected.re_owe_effective_upload_body_witness_revision(&main_key, 2));
            let mut deleted = c.raw(&E2ScanFixture::default(), selected, 100, sampled, &[]);
            deleted.enrich(&c);
            assert_eq!(body(&deleted, ROOT).unwrap().request_count, 3);
            assert!(!deleted
                .disposition
                .request_owned_hold_reasons
                .contains_key("absent_content_twin"));
        });
    }
}

/// [money] A twin pulls its unchanged main, including when an unrelated main
/// first pulls the twin. Incomplete pages hold; every ACK preserves the union.
#[test]
fn unrelated_main_and_growing_twin_pull_complete_session() {
    // Use production finalization, upload, ACK settlement and index reload;
    // observe the receiver ledger inside every ACK callback.
    fn accept(
        c: &Corpus,
        committed: &ScanIndex,
        mut page: Page,
        accepted: &mut BTreeMap<String, u64>,
    ) -> ScanIndex {
        page.finish();
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
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut page.index,
            &mut page.scan,
            &page.disposition,
        );
        let mut settled = settle_completed_upload(page.index, committed, &progress, &holds);
        settle_index_after_upload(&mut settled.index, committed, &progress);
        accept_upload_context_acks_for_test(
            &mut settled.index,
            &sent,
            &progress.fresh_context_body_acks,
        );
        c.reload(&mut settled.index)
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
            prior = accept(&c, &prior, initial, &mut accepted);
            let twin = c.write_at(&file(COPY), &resumed(ROOT, &[A, B, C]), BORN);
            append(&main, &resumed(ROOT, &[D]));
            owe(&mut prior);
            let mut complete = c.raw(&E2ScanFixture::default(), prior.clone(), 100, sampled, &[]);
            complete.enrich(&c);
            assert_eq!(body(&complete, ROOT).unwrap().request_count, 4);
            let reference = sent_money(&complete);
            prior = accept(&c, &prior, complete, &mut accepted);
            assert_eq!(accepted[ROOT], 4);
            let twin_key = twin.to_string_lossy().into_owned();
            assert_eq!(
                e2::copied_file_holders_for_test(&prior, std::iter::once(twin_key.as_str()))
                    [&twin_key],
                unrelated.to_string_lossy()
            );
            let mut selected = prior.clone();
            assert!(selected
                .re_owe_effective_upload_body_witness_revision(&unrelated.to_string_lossy(), 2));
            let scanner = E2ScanFixture::default();
            let mut partial = c.raw(
                &scanner,
                selected,
                100,
                sampled,
                std::slice::from_ref(&unrelated),
            );
            assert!(scanner.paths().contains(&unrelated));
            assert!(scanner.paths().contains(&twin), "Q pulls T through overlap");
            assert!(scanner.paths().contains(&main), "T pulls unchanged M");
            // Simulate admission preventing M's fold: Q+T still cannot
            // replace S until M and T both reach the same page.
            partial.scan.snapshots.retain(|item| {
                item.claude_money
                    .as_deref()
                    .and_then(e2::FileFold::location_key)
                    != Some(location_key(&main.to_string_lossy()))
            });
            partial.enrich(&c);
            assert_eq!(
                partial
                    .disposition
                    .request_owned_hold_reasons
                    .get("absent_content_twin"),
                Some(&1)
            );
            assert_eq!(partial.disposition.quarantined_entity_count(), 1);
            assert!(partial.finish().progress_blocking);
            assert!(
                body(&partial, ROOT).is_none(),
                "T alone is withheld before upload"
            );
            prior = accept(&c, &prior, partial, &mut accepted);
            assert_eq!(accepted[ROOT], 4, "T alone never replaces M+T");
            assert!(prior
                .re_owe_effective_upload_body_witness_revision(&unrelated.to_string_lossy(), 2));
            let scanner = E2ScanFixture::default();
            let mut recovered = c.raw(
                &scanner,
                prior.clone(),
                100,
                sampled,
                std::slice::from_ref(&unrelated),
            );
            assert!(scanner.paths().contains(&unrelated));
            assert!(scanner.paths().contains(&twin) && scanner.paths().contains(&main));
            recovered.enrich(&c);
            assert_eq!(body(&recovered, ROOT).unwrap().request_count, 4);
            assert!(!recovered
                .disposition
                .request_owned_hold_reasons
                .contains_key("absent_content_twin"));
            money_oracle::assert_equivalent(&reference, &sent_money(&recovered));
            assert!(!recovered.finish().progress_blocking);
            prior = accept(&c, &prior, recovered, &mut accepted);
            assert_eq!(accepted[ROOT], 4);

            // Only T grows. M's stamp and settled revision stay unchanged;
            // ordinary T selection must schedule M without manually owing M.
            append(
                &twin,
                &resumed(ROOT, &[("e", "2026-08-02T07:07:10Z", RESUME_WRITER)]),
            );
            let mut full_index = prior.clone();
            owe(&mut full_index);
            let mut full = c.raw(&E2ScanFixture::default(), full_index, 100, sampled, &[]);
            full.enrich(&c);
            assert_eq!(body(&full, ROOT).unwrap().request_count, 5);
            let reference = sent_money(&full);
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
            money_oracle::assert_equivalent(&reference, &sent_money(&grown));
            assert!(!grown.finish().progress_blocking);
            accept(&c, &prior, grown, &mut accepted);
            assert_eq!(accepted[ROOT], 5, "T's new turn reaches the receiver");
        });
    }
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
            assert_eq!(prior.claude_money_birth_store.money_rule_version(), 4);
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
    include!("subagent_copy_twin_tests.rs");
    include!("subagent_copy_twin_replace_tests.rs");
    include!("subagent_twin_tail_route_tests.rs");
}
