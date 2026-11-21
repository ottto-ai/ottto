use super::*;
use crate::snapshots::claude_request_census::claude_request_hash;
use crate::snapshots::e2_pipeline_scan_fixture::{
    accepted_file_for_test, delete_holder_for_test, hold_claude_account_for_test,
    invalidate_holder_for_test, retain_indexed_walk_with_pending_for_test,
    unhold_claude_account_for_test,
};
use crate::snapshots::sampled_scan::transition_fixture::with_scan_clock;
use crate::snapshots::upload_context_receipt::SlotRows;

// Accepted-row assertions, refused-parent and fresh-upgrade controls are
// expected red on main. The deleted Local-only holder control is green there.
fn hashes(index: &ScanIndex, path: &Path) -> BTreeSet<u64> {
    let loc = location_key(&path.to_string_lossy());
    index
        .upload_context_proof
        .request_contributions
        .values()
        .flat_map(|slot| slot.rows.iter())
        .filter(|(holder, _)| *holder == loc)
        .flat_map(|(_, hashes)| hashes.iter().copied())
        .collect()
}
fn has(index: &ScanIndex, path: &Path, id: &str) -> bool {
    hashes(index, path).contains(&claude_request_hash(id))
}
fn parsed(c: &Corpus, index: ScanIndex) -> Page {
    let mut page = c.raw(&E2ScanFixture::default(), index, 100, true, &[]);
    page.enrich(c);
    page
}
fn contributions(items: &[SnapshotItem], progress: &mut SnapshotUploadProgress) {
    progress.request_contributions.extend(
        items
            .iter()
            .filter(|i| {
                crate::snapshots::claude_request_money::request_owned_family_root(i).is_some()
            })
            .map(|i| (i.snapshot_fingerprint.clone(), SlotRows::capture(i))),
    );
}
fn send(
    c: &Corpus,
    before: &ScanIndex,
    mut page: Page,
    refused: Option<&str>,
) -> (ScanIndex, Vec<SnapshotItem>, SnapshotUploadProgress) {
    let holds = page.finish();
    let sent = page.scan.snapshots.clone();
    let mut progress = e2_progress();
    contributions(&sent, &mut progress);
    upload(&sent, &mut progress, |items| {
        let mut response = ack(items)?;
        for item in items
            .iter()
            .filter(|i| Some(i.source_session_id.as_str()) == refused)
        {
            response
                .accepted_entities
                .retain(|e| e.snapshot_fingerprint != item.snapshot_fingerprint);
            response.accepted -= 1;
            response.sessions_reconciled -= 1;
            response
                .rejected_entities
                .push(crate::snapshot_client::SnapshotEntityRejection {
                    source_session_id: item.source_session_id.clone(),
                    snapshot_fingerprint: item.snapshot_fingerprint.clone(),
                    reason: "hour_bucket_count_above_cap".into(),
                    detail: "synthetic body refusal".into(),
                    permanent: true,
                    occurrence_count: 1,
                });
        }
        Ok(response)
    })
    .0
    .unwrap();
    let mut settled = settle_checkpointed_upload(
        page.index,
        before,
        &progress,
        &holds,
        true,
        UnsettledUploadCause::DeferredConflict,
    );
    settle_index_after_upload(&mut settled.index, before, &progress);
    accept_upload_context_acks_for_test(
        &mut settled.index,
        &sent,
        &progress.fresh_context_body_acks,
    );
    settled.index.accept_request_contributions(&progress);
    (c.reload(&mut settled.index), sent, progress)
}
fn seed(c: &Corpus) -> ScanIndex {
    send(
        c,
        &ScanIndex::default(),
        parsed(c, ScanIndex::default()),
        None,
    )
    .0
}
fn stable(c: &Corpus, index: &mut ScanIndex) {
    let before = (
        canonical(&index.upload_context_proof.request_contributions),
        canonical(&index.claude_copy_removals),
    );
    for _ in 0..2 {
        *index = c.reload(index);
        assert_eq!(
            before,
            (
                canonical(&index.upload_context_proof.request_contributions),
                canonical(&index.claude_copy_removals),
            )
        );
    }
}
fn new_copy(c: &mut Corpus, session: &str, id: &str) -> PathBuf {
    c.write_at(
        &file(session),
        &resumed(
            session,
            &[
                (id, "2026-08-02T07:00:20Z", OLD_WRITER),
                ("own", "2026-08-02T09:03:10Z", RESUME_WRITER),
            ],
        ),
        "2026-08-02T09:03:00Z",
    )
}
fn stored_copy(c: &mut Corpus, before: &ScanIndex, id: &str) -> (ScanIndex, PathBuf) {
    let copy = new_copy(c, COPY, id);
    let page = parsed(c, before.clone());
    assert_eq!(body(&page, COPY).unwrap().request_count, 1);
    let index = send(c, before, page, None).0;
    assert!(!index
        .claude_copy_removals
        .get(location_key(&copy.to_string_lossy()))
        .is_empty());
    (index, copy)
}

#[test]
#[serial(client_report)]
fn uncopied_family_duplicates_keep_only_counted_rows_and_stay_quiet() {
    for a_first in [true, false] {
        with_e2(|| {
            let a = uncopied_rows(&[("r1", 10), ("r2", 20), ("r3", 5)]);
            let b = a.clone() + &uncopied_rows(&[("r4", 13)]);
            let (c, paths) = uncopied_pair("accepted-quiet", a_first, &a, &b);
            let mut index = seed(&c);
            assert_eq!(hashes(&index, &paths[0]).len(), if a_first { 3 } else { 0 });
            assert_eq!(hashes(&index, &paths[1]).len(), if a_first { 1 } else { 4 });
            for _ in 0..2 {
                for path in &paths {
                    assert!(!index
                        .claude_copy_removals
                        .pending(location_key(&path.to_string_lossy())));
                }
                let scanner = E2ScanFixture::default();
                let mut repeat = c.raw(&scanner, index.clone(), 100, true, &[]);
                assert!(scanner.paths().is_empty());
                repeat.enrich(&c);
                assert!(repeat.scan.snapshots.is_empty());
                index = c.reload(&mut repeat.index);
            }
        });
    }
}

#[test]
#[serial(client_report)]
fn exact_revision_replaces_the_whole_session_slot() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-revisions");
        let holder = c.root(ROOT, &resumed(ROOT, &[A]));
        let (first, sent, _) = send(
            &c,
            &ScanIndex::default(),
            parsed(&c, ScanIndex::default()),
            None,
        );
        assert!(sent.iter().all(|item| item.claude_money.is_none()));
        assert!(has(&first, &holder, "a"));
        let old_fp = first
            .upload_context_proof
            .request_contributions
            .values()
            .next()
            .unwrap()
            .fingerprint
            .clone();
        std::fs::write(&holder, resumed(ROOT, &[B])).unwrap();
        let second = send(&c, &first, parsed(&c, first.clone()), None).0;
        assert_eq!(second.upload_context_proof.request_contributions.len(), 1);
        assert!(!has(&second, &holder, "a"));
        assert!(has(&second, &holder, "b"));
        assert_ne!(
            second
                .upload_context_proof
                .request_contributions
                .values()
                .next()
                .unwrap()
                .fingerprint,
            old_fp
        );
        append(&holder, &resumed(ROOT, &[D]));
        let (third, _, _) = send(&c, &second, parsed(&c, second.clone()), Some(ROOT));
        assert_eq!(
            third.upload_context_proof.request_contributions,
            second.upload_context_proof.request_contributions
        );
        new_copy(&mut c, COPY, "a");
        let page = parsed(&c, third);
        assert_eq!(body(&page, COPY).unwrap().request_count, 2);
    });
}

#[test]
#[serial(client_report)]
fn refusal_quarantine_and_missing_ack_do_not_replace_rows() {
    for exclusion in ["missing-ack", "quarantine", "wrong-body"] {
        with_e2(|| {
            let mut c = Corpus::new(&format!("accepted-row-{exclusion}"));
            let holder = c.root(ROOT, &resumed(ROOT, &[A]));
            let first = seed(&c);
            append(&holder, &resumed(ROOT, &[B]));
            let mut page = parsed(&c, first.clone());
            page.finish();
            let mut progress = e2_progress();
            contributions(&page.scan.snapshots, &mut progress);
            upload(&page.scan.snapshots, &mut progress, ack).0.unwrap();
            let fp = body(&page, ROOT).unwrap().snapshot_fingerprint.clone();
            match exclusion {
                "missing-ack" => {
                    progress.fresh_context_body_acks.remove(&fp);
                }
                "wrong-body" => {
                    progress
                        .fresh_context_body_acks
                        .insert(fp.clone(), "0".repeat(64));
                }
                "quarantine" => {
                    progress.quarantine_permanent_body(
                        &fp,
                        &snapshot_upload_body_witness(body(&page, ROOT).unwrap()),
                        "synthetic refusal",
                    );
                }
                _ => unreachable!(),
            }
            page.index.accept_request_contributions(&progress);
            assert_eq!(
                page.index.upload_context_proof.request_contributions,
                first.upload_context_proof.request_contributions
            );
        });
    }
}

#[test]
#[serial(client_report)]
fn acknowledged_rows_survive_selected_entry_restoration() {
    for refused in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("accepted-row-checkpoint");
            let holder = c.root(ROOT, &resumed(ROOT, &[A]));
            let before = seed(&c);
            append(&holder, &resumed(ROOT, &[B]));
            c.agent(1, &line(ROOT, "agent", AT, 5));
            let mut page = parsed(&c, before.clone());
            let holds = page.finish();
            let items = page.scan.snapshots.clone();
            assert!(items.len() >= 2);
            let mut progress = e2_progress();
            contributions(&items, &mut progress);
            upload(&items, &mut progress, |batch| {
                let mut response = ack(batch)?;
                let Some(pending) = response
                    .accepted_entities
                    .iter()
                    .position(|e| e.source_session_id != ROOT)
                else {
                    return Ok(response);
                };
                let mut pending = response.accepted_entities.remove(pending);
                response.accepted -= 1;
                response.sessions_reconciled -= 1;
                pending.head_etag = None;
                if refused {
                    response.rejected_entities.push(
                        crate::snapshot_client::SnapshotEntityRejection {
                            source_session_id: pending.source_session_id,
                            snapshot_fingerprint: pending.snapshot_fingerprint,
                            reason: "hour_bucket_count_above_cap".into(),
                            detail: "synthetic sibling refusal".into(),
                            permanent: true,
                            occurrence_count: 1,
                        },
                    );
                } else {
                    response.conflict_entities.push(pending);
                }
                Ok(response)
            })
            .0
            .unwrap();
            let mut index = settle_checkpointed_upload(
                page.index,
                &before,
                &progress,
                &holds,
                true,
                UnsettledUploadCause::DeferredConflict,
            )
            .index;
            // The selected entry can be behind the exact ACK's body.
            index.files.insert(
                holder.to_string_lossy().into_owned(),
                before.files[&holder.to_string_lossy().into_owned()].clone(),
            );
            index.accept_request_contributions(&progress);
            assert!(has(&index, &holder, "b"));
            index = c.reload(&mut index);
            assert!(has(&index, &holder, "b"));
        });
    }
}

#[test]
#[serial(client_report)]
fn stored_accepted_hash_survives_refused_rewrite_and_deletion() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-stored-refusal");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let first = seed(&c);
        let (mut index, copy) = stored_copy(&mut c, &first, "b");
        std::fs::write(&holder, resumed(ROOT, &[A, D])).unwrap();
        index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
        assert!(has(&index, &holder, "b"));
        std::fs::remove_file(&holder).unwrap();
        delete_holder_for_test(&mut index, &holder.to_string_lossy());
        index = c.reload(&mut index);
        assert!(has(&index, &holder, "b"));
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        stable(&c, &mut index);
        owe(&mut index);
        let page = parsed(&c, index);
        assert_eq!(body(&page, COPY).unwrap().request_count, 1);
    });
}

fn summed() -> (Corpus, ScanIndex, PathBuf, PathBuf) {
    let mut c = Corpus::new("accepted-row-summed");
    let main = c.write_at(
        &format!("origin/{ROOT}.jsonl"),
        &resumed(ROOT, &[A]),
        "2026-08-02T07:00:00Z",
    );
    let twin = c.write_at(&file(ROOT), &resumed(ROOT, &[B]), BORN);
    let index = seed(&c);
    assert!(has(&index, &main, "a"));
    assert!(!has(&index, &main, "b"));
    assert!(has(&index, &twin, "b"));
    (c, index, main, twin)
}

/// [regress] Summed path twins emit the later file's last clock whichever
/// file carries the body, with no end below or at it.
#[test]
#[serial(client_report)]
fn summed_contributors_share_the_later_last_clock_in_either_order() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (c, _, main, twin) = summed();
        let clocks = [false, true].map(|main_first| {
            // Unrouted: each arm reads both files fresh, independent of the
            // seeded route and of the other arm.
            let mut page = c.raw(
                &E2ScanFixture::default(),
                ScanIndex::default(),
                100,
                false,
                &[],
            );
            let carrier = if main_first { &main } else { &twin };
            let carrier = page.index.files[carrier.to_string_lossy().as_ref()]
                .source_file_fingerprint
                .clone();
            page.scan
                .snapshots
                .sort_by_key(|item| item.source_file_fingerprint.as_ref() != Some(&carrier));
            page.enrich(&c);
            let item = body(&page, ROOT).unwrap();
            assert_eq!(item.source_file_fingerprint.as_ref(), Some(&carrier));
            assert_eq!(item.request_count, 2);
            (
                item.source_last_activity_at.clone(),
                item.source_ended_at.clone(),
            )
        });
        assert_eq!(clocks[0], clocks[1]);
        assert_eq!(clocks[0], (Some(B.1.to_owned()), None));
    });
}

#[test]
#[serial(client_report)]
fn summed_contributors_keep_only_their_own_counted_hashes() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    for main_first in [false, true] {
        with_e2(|| {
            let (mut c, first, main, twin) = summed();
            let (mut index, copy) = stored_copy(&mut c, &first, "b");
            for path in if main_first {
                [&main, &twin]
            } else {
                [&twin, &main]
            } {
                std::fs::remove_file(path).unwrap();
                delete_holder_for_test(&mut index, &path.to_string_lossy());
                index = c.reload(&mut index);
                assert!(has(&index, &twin, "b"));
                assert!(!index
                    .claude_copy_removals
                    .pending(location_key(&copy.to_string_lossy())));
            }
            new_copy(&mut c, THIRD, "b");
            let page = parsed(&c, index);
            assert_eq!(
                body(&page, THIRD).unwrap().request_count,
                2,
                "new copies cannot discover deleted holders"
            );
        });
    }
}

#[test]
#[serial(client_report)]
fn replacing_a_summed_slot_retracts_deleted_contributor_rows() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (mut c, first, main, twin) = summed();
        let (mut index, copy) = stored_copy(&mut c, &first, "b");
        std::fs::remove_file(&twin).unwrap();
        delete_holder_for_test(&mut index, &twin.to_string_lossy());
        index = c.reload(&mut index);
        assert!(has(&index, &twin, "b"));
        append(&main, &resumed(ROOT, &[D]));
        index = send(&c, &index, parsed(&c, index.clone()), None).0;
        assert!(!has(&index, &twin, "b"));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        let page = parsed(&c, index.clone());
        assert_eq!(body(&page, COPY).unwrap().request_count, 2);
        index = send(&c, &index, page, None).0;
        stable(&c, &mut index);
    });
}

#[test]
#[serial(client_report)]
fn exact_acceptance_corrects_an_earlier_counting_copy_once() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let now = crate::scan_clock::utc_seconds();
        let (c, mut index, holder, copy) = with_scan_clock(now, || {
            let mut c = Corpus::new("accepted-row-correct-once");
            let holder = c.root(ROOT, &resumed(ROOT, &[A]));
            let mut index = seed(&c);
            append(&holder, &resumed(ROOT, &[B]));
            index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
            let copy = new_copy(&mut c, COPY, "b");
            let page = parsed(&c, index.clone());
            assert_eq!(body(&page, COPY).unwrap().request_count, 2);
            index = send(&c, &index, page, None).0;
            // Keep the already-counting copy off the holder's ACK page.
            retain_indexed_walk_with_pending_for_test(
                &mut index,
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&c.root),
                "2026-08-02T08:00:00Z",
                183,
                std::slice::from_ref(&holder),
            );
            (c, index, holder, copy)
        });
        // The next native growth Full is beyond the preceding six-hour claim.
        with_scan_clock(now + 7 * 60 * 60, || {
            // A new exact body, rather than a replayed refusal, supplies b.
            append(&holder, &resumed(ROOT, &[D]));
            let scanner = E2ScanFixture::default();
            let mut accepted = c.raw(&scanner, index.clone(), 1, true, &[]);
            assert_eq!(scanner.paths(), vec![holder.clone()]);
            accepted.enrich(&c);
            assert!(body(&accepted, COPY).is_none());
            index = send(&c, &index, accepted, None).0;
            assert!(has(&index, &holder, "b"));
            assert!(index
                .claude_copy_removals
                .pending(location_key(&copy.to_string_lossy())));
            let scanner = E2ScanFixture::default();
            let mut correction = c.raw(&scanner, index.clone(), 100, true, &[]);
            assert_eq!(
                scanner
                    .paths()
                    .iter()
                    .filter(|p| p.file_name().unwrap() == file(COPY).as_str())
                    .count(),
                1
            );
            correction.enrich(&c);
            assert_eq!(body(&correction, COPY).unwrap().request_count, 1);
            index = send(&c, &index, correction, None).0;
            stable(&c, &mut index);
            for _ in 0..2 {
                let scanner = E2ScanFixture::default();
                let page = c.raw(&scanner, index.clone(), 100, true, &[]);
                assert!(scanner.paths().is_empty());
                assert!(page.scan.snapshots.is_empty());
            }
        });
    });
}

#[test]
#[serial(client_report)]
fn zero_usage_occurrences_never_earn_accepted_hashes() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-zero-usage");
        let zero = json!({"type":"assistant","sessionId":ROOT,"version":OLD_WRITER,
            "timestamp":"2026-08-02T07:00:20Z","requestId":"zero",
            "message":{"id":"msg-zero","model":"claude-haiku-4-5","usage":{"input_tokens":0,"output_tokens":0}}}).to_string() + "\n";
        let holder = c.root(ROOT, &(resumed(ROOT, &[A]) + &zero));
        let mut index = seed(&c);
        assert!(has(&index, &holder, "a"));
        assert!(!has(&index, &holder, "zero"));
        append(&holder, &resumed(ROOT, &[D]));
        index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
        new_copy(&mut c, COPY, "zero");
        assert_eq!(body(&parsed(&c, index), COPY).unwrap().request_count, 2);
    });
}

#[test]
#[serial(client_report)]
fn destination_changes_clear_contribution_only_proof_but_replay_does_not() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-destination");
        c.root(ROOT, &resumed(ROOT, &[A]));
        let first = seed(&c);
        for mode in ["same", "replay", "unbound", "changed", "contribution-only"] {
            let mut index = first.clone();
            let mut proof = serde_json::to_value(&index.upload_context_proof).unwrap();
            if mode == "unbound" {
                proof
                    .as_object_mut()
                    .unwrap()
                    .remove("destination_namespace_hash");
            }
            if mode == "contribution-only" {
                proof.as_object_mut().unwrap().remove("entity_stamps");
            }
            index.upload_context_proof = serde_json::from_value(proof).unwrap();
            if mode == "replay" {
                index.prepare_historical_replay("next-replay".into());
            }
            index.stamp_entity_upload_context_acks(
                if mode == "changed" || mode == "contribution-only" {
                    "other"
                } else {
                    "e2-fixture-destination"
                },
                &BTreeMap::new(),
                &BTreeMap::new(),
            );
            assert_eq!(
                index.upload_context_proof.request_contributions.is_empty(),
                mode == "changed" || mode == "contribution-only",
                "{mode}"
            );
        }
    });
}

#[test]
#[serial(client_report)]
fn fresh_upgrade_refused_holder_counts_until_its_next_exact_ack() {
    with_e2(|| {
        let now = crate::scan_clock::utc_seconds();
        let (c, index, holder) = with_scan_clock(now, || {
            let mut c = Corpus::new("accepted-row-fresh-upgrade");
            let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
            let first = seed(&c);
            let (mut index, copy) = stored_copy(&mut c, &first, "b");
            index.upload_context_proof.request_contributions.clear();
            append(&holder, &resumed(ROOT, &[D]));
            index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
            assert!(index
                .claude_copy_removals
                .pending(location_key(&copy.to_string_lossy())));
            assert_eq!(
                body(&parsed(&c, index.clone()), COPY)
                    .unwrap()
                    .request_count,
                2
            );
            (c, index, holder)
        });
        // The replacement ACK follows the refused body's six-hour growth claim.
        with_scan_clock(now + 7 * 60 * 60, || {
            append(
                &holder,
                &resumed(ROOT, &[("e", "2026-08-02T07:00:40Z", OLD_WRITER)]),
            );
            let (mut index, sent, progress) = send(&c, &index, parsed(&c, index.clone()), None);
            let holder_item = sent
                .iter()
                .find(|item| item.source_session_id == ROOT)
                .expect("the holder's replacement body was sent");
            let witness = snapshot_upload_body_witness(holder_item);
            assert_eq!(
                progress
                    .fresh_context_body_acks
                    .get(&holder_item.snapshot_fingerprint),
                Some(&witness),
                "the holder's replacement body has a fresh exact ACK"
            );
            assert!(has(&index, &holder, "b"));
            stable(&c, &mut index);
        });
    });
}

#[test]
#[serial(client_report)]
fn historical_replay_and_held_copy_saves_preserve_rows() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-replay");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let first = seed(&c);
        let (mut index, copy) = stored_copy(&mut c, &first, "b");
        let rows = index.upload_context_proof.request_contributions.clone();
        index.prepare_historical_replay("replay".into());
        index = c.reload(&mut index);
        assert_eq!(index.upload_context_proof.request_contributions, rows);
        hold_claude_account_for_test(&mut index, &copy.to_string_lossy());
        stable(&c, &mut index);
        assert!(has(&index, &holder, "b"));
        unhold_claude_account_for_test(&mut index, &copy.to_string_lossy());
        append(&holder, &resumed(ROOT, &[D]));
        index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
        assert!(has(&index, &holder, "b"));
    });
}

#[test]
#[serial(client_report)]
fn same_path_replacement_keeps_receiver_rows_until_replacement_ack() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-replacement");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let first = seed(&c);
        let (mut index, copy) = stored_copy(&mut c, &first, "b");
        std::fs::rename(&holder, c.base.join("retired-file")).unwrap();
        std::fs::write(&holder, resumed(ROOT, &[A, D])).unwrap();
        index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
        assert!(has(&index, &holder, "b"));
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        append(
            &holder,
            &resumed(ROOT, &[("e", "2026-08-02T07:00:40Z", OLD_WRITER)]),
        );
        index = send(&c, &index, parsed(&c, index.clone()), None).0;
        assert!(!has(&index, &holder, "b"));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
    });
}

#[test]
#[serial(client_report)]
fn rows_never_supply_delivery_authority_and_rebuild_carries_them() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-rebuild");
        let holder = c.root(ROOT, &resumed(ROOT, &[A]));
        let first = seed(&c);
        let mut index = first.rebuild_identity_for_test();
        assert_eq!(
            index.upload_context_proof.request_contributions,
            first.upload_context_proof.request_contributions
        );
        assert!(index.files.is_empty());
        assert!(!accepted_file_for_test(&index, &holder.to_string_lossy()));
        let mut proof = serde_json::to_value(&index.upload_context_proof).unwrap();
        proof.as_object_mut().unwrap().remove("entity_stamps");
        index.upload_context_proof = serde_json::from_value(proof).unwrap();
        let row = first
            .upload_context_proof
            .request_contributions
            .values()
            .next()
            .unwrap();
        assert!(!index.entity_upload_context_proven(
            "e2-fixture-destination",
            &row.fingerprint,
            &row.body_witness,
            "e2-synthetic-destination"
        ));
        // Save the first bounded rebuild page with the accepted holder absent.
        let fresh = c.write_at(&format!("a/{THIRD}.jsonl"), &resumed(THIRD, &[D]), BORN);
        // Hint every candidate so census reservation cannot select the holder first.
        let scanner = E2ScanFixture::default();
        let mut page = c.raw(&scanner, index, 1, true, &[fresh.clone(), holder.clone()]);
        assert_eq!(scanner.paths(), vec![fresh]);
        page.enrich(&c);
        assert!(!page
            .index
            .files
            .contains_key(&holder.to_string_lossy().into_owned()));
        assert!(!page
            .index
            .deleted_holders
            .contains(&location_key(&holder.to_string_lossy())));
        let mut index = page.index;
        index = c.reload(&mut index);
        assert!(has(&index, &holder, "a"));
    });
}

#[test]
#[serial(client_report)]
fn stale_covered_and_duplicate_slot_acks_cannot_grant_rows() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-ambiguous-ack");
        let holder = c.root(ROOT, &resumed(ROOT, &[A]));
        let first = seed(&c);
        append(&holder, &resumed(ROOT, &[B]));
        let mut page = parsed(&c, first.clone());
        page.finish();
        let items = page.scan.snapshots.clone();
        let mut progress = e2_progress();
        contributions(&items, &mut progress);
        upload(&items, &mut progress, ack).0.unwrap();
        let item = body(&page, ROOT).unwrap();
        progress.permanent_rejections.insert(
            item.snapshot_fingerprint.clone(),
            PermanentSnapshotRejection {
                body_witness: snapshot_upload_body_witness(item),
                reason: crate::upload_receipts::RejectedUsageReason::AcceptedLogStaleOlderUpload,
                reoffer: None,
                exposure: Some(stale_owed::Exposure::new(1)),
                revisions: BTreeMap::new(),
            },
        );
        page.index.accept_request_contributions(&progress);
        assert_eq!(
            page.index.upload_context_proof.request_contributions,
            first.upload_context_proof.request_contributions
        );
        progress.permanent_rejections.clear();
        let (slot, row) = progress
            .request_contributions
            .values()
            .next()
            .unwrap()
            .clone();
        let mut duplicate = row.clone();
        duplicate.fingerprint = "f".repeat(64);
        progress.fresh_context_body_acks.insert(
            duplicate.fingerprint.clone(),
            duplicate.body_witness.clone(),
        );
        progress
            .request_contributions
            .insert(duplicate.fingerprint.clone(), (slot.clone(), duplicate));
        page.index.accept_request_contributions(&progress);
        assert!(!page
            .index
            .upload_context_proof
            .request_contributions
            .contains_key(&slot));
    });
}

#[test]
#[serial(client_report)]
fn temporary_census_loss_never_prunes_accepted_rows() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-census-loss");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut index = seed(&c);
        assert!(index.claude_copy_removals.is_empty());
        invalidate_holder_for_test(&mut index, &holder.to_string_lossy());
        index = c.reload(&mut index);
        assert!(has(&index, &holder, "b"));
        // The unchanged retry restores the census through a real native read.
        let mut retry = parsed(&c, index.clone());
        retry.finish();
        index = c.reload(&mut retry.index);
        assert!(has(&index, &holder, "b"));
        append(&holder, &resumed(ROOT, &[D]));
        index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
        new_copy(&mut c, COPY, "b");
        assert_eq!(body(&parsed(&c, index), COPY).unwrap().request_count, 1);
    });
}

#[test]
#[serial(client_report)]
fn deleted_local_only_holder_loses_stored_hashes_once() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-local-deletion");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        // Commit the native body and its census without any upload ACK.
        let mut page = parsed(&c, ScanIndex::default());
        page.finish();
        let index = c.reload(&mut page.index);
        assert!(index.upload_context_proof.request_contributions.is_empty());
        let (mut index, copy) = stored_copy(&mut c, &index, "b");
        assert!(!has(&index, &holder, "b"));
        std::fs::remove_file(&holder).unwrap();
        delete_holder_for_test(&mut index, &holder.to_string_lossy());
        index = c.reload(&mut index);
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        let page = parsed(&c, index.clone());
        assert_eq!(body(&page, COPY).unwrap().request_count, 2);
        index = send(&c, &index, page, None).0;
        stable(&c, &mut index);
    });
}

#[test]
#[serial(client_report)]
fn refused_retired_parent_proves_only_the_hashes_it_delivered() {
    for accepted_hash in [false, true] {
        with_e2(|| {
            let mut c = Corpus::new("accepted-row-parent");
            let holder = c.root(
                ROOT,
                &resumed(ROOT, if accepted_hash { &[A, B] } else { &[A] }),
            );
            let mut index = seed(&c);
            append(&holder, &resumed(ROOT, &[D]));
            index = send(&c, &index, parsed(&c, index.clone()), Some(ROOT)).0;
            e2::pipeline_test_observer::retire_census(&mut index, &file(ROOT));
            c.write_at(
                &file(COPY),
                &(fork_ref(COPY, ROOT) + &resumed(COPY, &[B])),
                BORN,
            );
            let page = parsed(&c, index);
            assert_eq!(
                body(&page, COPY).unwrap().request_count,
                u64::from(!accepted_hash)
            );
        });
    }
}

#[test]
#[serial(client_report)]
fn held_summed_contributor_keeps_its_stored_copy() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let (mut c, first, _, twin) = summed();
        let (mut index, copy) = stored_copy(&mut c, &first, "b");
        hold_claude_account_for_test(&mut index, &twin.to_string_lossy());
        index = c.reload(&mut index);
        assert!(has(&index, &twin, "b"));
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        stable(&c, &mut index);
    });
}

#[test]
#[serial(client_report)]
fn negative_census_retracts_a_local_only_removal() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-local-negative");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut first = parsed(&c, ScanIndex::default());
        first.finish();
        let first = c.reload(&mut first.index);
        let (mut index, copy) = stored_copy(&mut c, &first, "b");
        assert!(!has(&index, &holder, "b"));
        std::fs::write(&holder, resumed(ROOT, &[A, D])).unwrap();
        index = send(&c, &index, parsed(&c, index.clone()), None).0;
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        assert_eq!(body(&parsed(&c, index), COPY).unwrap().request_count, 2);
    });
}

#[test]
#[serial(client_report)]
fn semantic_noop_rewrite_keeps_rows_until_a_changed_body_is_acknowledged() {
    with_e2(|| {
        let mut c = Corpus::new("accepted-row-noop-rewrite");
        let holder = c.root(ROOT, &line(ROOT, "h", AT, 10));
        let first = seed(&c);
        let copy = c.write_at(&file(COPY), &line(COPY, "h", AT, 10), BORN);
        let page = parsed(&c, first.clone());
        assert_eq!(body(&page, COPY).unwrap().request_count, 0);
        let mut index = send(&c, &first, page, None).0;
        std::fs::write(&holder, line(ROOT, "u", AT, 10)).unwrap();
        let page = parsed(&c, index.clone());
        let (next, sent, _) = send(&c, &index, page, None);
        index = next;
        assert!(sent.iter().all(|item| item.source_session_id != ROOT));
        assert!(has(&index, &holder, "h"));
        assert!(!has(&index, &holder, "u"));
        assert!(!index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        append(&holder, &line(ROOT, "v", "2026-08-02T07:01:00Z", 20));
        index = send(&c, &index, parsed(&c, index.clone()), None).0;
        assert!(!has(&index, &holder, "h"));
        assert!(has(&index, &holder, "u"));
        assert!(index
            .claude_copy_removals
            .pending(location_key(&copy.to_string_lossy())));
        let page = parsed(&c, index.clone());
        let item = body(&page, COPY).unwrap();
        assert_eq!(
            (item.request_count, item.removed_request_count),
            (1, Some(0))
        );
        index = send(&c, &index, page, None).0;
        stable(&c, &mut index);
    });
}
