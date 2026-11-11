//! Copied files use accepted origins, across sessions and folders.
use super::*;
use crate::snapshots::claude_money_birth_store::location_key;
use crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};

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
    let (status, wire, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let mut result =
        RouteResult::emitted(mode, SnapshotSource::ClaudeCode, wire, &page.scan.snapshots);
    result.modes = page.modes;
    result
}

/// [money] Both kinds of all-copy file drop permanently, including a page
/// containing only the copy. Appending its own turn counts immediately.
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
                assert!(
                    page.scan.snapshots.is_empty(),
                    "an all-covered twin-only page drops without a hold"
                );
                assert_eq!(page.disposition.quarantined_entity_count(), 0);
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
                prior = settle(&c, &prior, page, &mut e2_progress());
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
                .pending(location_key(&copy.to_string_lossy().into_owned())));
            prior = settle(&c, &prior, page, &mut e2_progress());
        }
    });
}

/// [money] A forced incomplete all-folder walk preserves own turns, advances
/// no completed-decision counter, and keeps revision debt across restart.
#[test]
fn incomplete_all_folder_walk_never_restores_or_ages_copies() {
    with_e2(|| {
        let mut c = Corpus::new("copy-incomplete-census");
        c.write_at(
            &format!("elsewhere/{ROOT}.jsonl"),
            &resumed(ROOT, &[A, B]),
            "2026-08-02T07:00:00Z",
        );
        let mut prior = warm(&c);
        let path = c.write_at(&file(COPY), &resumed(COPY, &[A, B, C]), BORN);
        let key = path.to_string_lossy().into_owned();
        for _ in 0..4 {
            let mut page = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
            crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
                page.enrich(&c);
            });
            let item = body(&page, COPY).unwrap();
            assert_eq!(
                (item.request_count, item.removed_request_count),
                (1, Some(0))
            );
            assert_eq!(
                page.index.claude_copy_removals.hold_age(location_key(&key)),
                0
            );
            prior = settle(&c, &prior, page, &mut e2_progress());
            assert!(prior.files[&key].effective_upload_body_witness_revision < 3);
        }
        let completed = ready(&c, &E2ScanFixture::default(), prior, 100, false);
        let item = body(&completed, COPY).unwrap();
        assert_eq!(
            (item.request_count, item.removed_request_count),
            (1, Some(2))
        );
        assert_eq!(
            completed
                .index
                .claude_copy_removals
                .hold_age(location_key(&key)),
            0
        );
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
            routes.push(captured(&page, mode));
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
            line_by(
                session,
                &format!("r-{}", from + n),
                at,
                tokens / count as u64 + u64::from((n as u64) < tokens % count as u64),
                OLD_WRITER,
            )
        })
        .collect()
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
            let path = c.write_at(&relative, &text, BORN);
            let key = path.to_string_lossy().into_owned();
            // Model the former completed-but-unaccepted holder wait. It
            // expires once, producing the over-counted body this upgrade fixes.
            prior.claude_copy_removals.advance_hold(location_key(&key));
            prior.claude_copy_removals.advance_hold(location_key(&key));
            owe(&mut prior);
            let old = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
            let head = body(&old, session).unwrap().clone();
            let expected = if shape == 2 { 4 } else { requests as u64 };
            let expected_tokens = if shape == 2 { 3_501 } else { tokens };
            assert_eq!(head.request_count, expected + copied as u64);
            let mut prior = settle(&c, &prior, old, &mut e2_progress());
            prior.claude_money_birth_store.set_money_rule_version(2);
            e2::take_diag();
            e2::apply_money_rules(&mut prior);
            assert_eq!(prior.claude_money_birth_store.money_rule_version(), 3);
            assert_eq!(copy_diag(&["money_rule_v3_reowed"]), [2]);
            prior = c.reload(&mut prior);
            e2::apply_money_rules(&mut prior);
            assert_eq!(
                copy_diag(&["money_rule_v3_reowed"]),
                [0],
                "no second re-owe after restart"
            );
            let corrected = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
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
            let mut progress = e2_progress();
            let (status, _, _) = upload(&corrected.scan.snapshots, &mut progress, ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            prior = settle(&c, &prior, corrected, &mut progress);
            let quiet = ready(&c, &E2ScanFixture::default(), prior, 100, false);
            assert!(
                quiet.scan.snapshots.is_empty(),
                "quiet convergence uploads nothing"
            );
        });
    }
}

/// [money] The one-shot selector never stamps an incomplete census walk.
#[test]
fn incomplete_version_three_selector_retries_without_stamping() {
    with_e2(|| {
        let mut c = Corpus::new("copied-session-selector-deadline");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut prior = warm(&c);
        c.write_at(&file(COPY), &resumed(ROOT, &[A, B]), BORN);
        let page = ready(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        prior = settle(&c, &prior, page, &mut e2_progress());
        prior.claude_money_birth_store.set_money_rule_version(2);
        crate::snapshots::claude_request_census::with_walk_deadline_for_test(|| {
            e2::apply_money_rules(&mut prior);
        });
        assert_eq!(prior.claude_money_birth_store.money_rule_version(), 2);
        prior = c.reload(&mut prior);
        e2::apply_money_rules(&mut prior);
        assert_eq!(prior.claude_money_birth_store.money_rule_version(), 3);
    });
}
