// A session summed from several on-page files keeps the latest last-activity
// clock of any of them, whichever file carries its body.
use super::*;

/// A holder record after its last request: no usage, only a clock.
const TAIL: &str = "2026-08-02T07:02:30Z";

fn note(session: &str, at: &str) -> String {
    json!({"type":"user","sessionId":session,"timestamp":at,
        "message":{"role":"user","content":"later"}})
    .to_string()
        + "\n"
}

/// The receiver's projected last-seen clock: the end, else the last.
fn last_seen(item: &SnapshotItem) -> Option<&str> {
    item.source_ended_at
        .as_deref()
        .or(item.source_last_activity_at.as_deref())
}

fn lifecycle(item: &SnapshotItem) -> [Option<&str>; 3] {
    [
        item.source_started_at.as_deref(),
        item.source_ended_at.as_deref(),
        item.source_last_activity_at.as_deref(),
    ]
}

/// The emitted money, removal and identity fields, without lifecycle clocks.
fn money(item: &SnapshotItem) -> serde_json::Value {
    json!([
        item.request_count,
        item.input_tokens,
        item.output_tokens,
        item.cache_read_tokens,
        item.cache_creation_5m_tokens,
        item.cache_creation_1h_tokens,
        item.reasoning_output_tokens,
        item.unattributed_total_tokens,
        item.cost,
        item.removed_request_count,
        item.removed_usage,
        item.model_usage,
        item.usage_buckets,
        item.request_evidence,
    ])
}

/// The holder-only head, ACKed and settled, then an all-copy file of the same
/// session. `copy_first` names the copy so that it sorts, and carries, first.
fn head_then_copy(c: &mut Corpus, copy_first: bool) -> (SnapshotItem, ScanIndex, PathBuf) {
    c.root(ROOT, &(resumed(ROOT, &[A, B]) + &note(ROOT, TAIL)));
    let old = ready(
        c,
        &E2ScanFixture::default(),
        ScanIndex::default(),
        100,
        false,
    );
    let head = body(&old, ROOT).unwrap().clone();
    assert_eq!(lifecycle(&head), [Some(A.1), None, Some(TAIL)]);
    let prior = settle(c, &ScanIndex::default(), old, &mut e2_progress());
    let stem = if copy_first { CARRIER } else { COPY };
    let copy = c.write_at(&file(stem), &resumed(ROOT, &[A]), BORN);
    (head, prior, copy)
}

/// [money] [regress] Observed: an all-copy file that sorted first carried the
/// session, and the body's last clock fell to its last request, below the
/// holder's later record and the accepted head. The body keeps the holder's
/// clock and invents no end. Money and clocks match whichever file carries.
#[test]
fn carried_copy_keeps_the_holders_later_last_clock() {
    let mut bodies = Vec::new();
    for copy_first in [true, false] {
        bodies.push(with_e2(|| {
            let mut c = Corpus::new("entity-last-clock");
            let (head, mut prior, copy) = head_then_copy(&mut c, copy_first);
            owe(&mut prior);
            let page = ready(&c, &E2ScanFixture::default(), prior, 100, false);
            let item = body(&page, ROOT).unwrap().clone();
            let copy_witness =
                &page.index.files[copy.to_string_lossy().as_ref()].source_file_fingerprint;
            assert_eq!(
                item.source_file_fingerprint.as_ref() == Some(copy_witness),
                copy_first,
                "the first file carries the session"
            );
            assert_eq!(
                (item.request_count, item.removed_request_count),
                (2, Some(1))
            );
            // The carrier keeps its own start; both files start with A.
            assert_eq!(lifecycle(&item), [Some(A.1), None, Some(TAIL)]);
            assert!(last_seen(&item) >= last_seen(&head));
            item
        }));
    }
    assert_eq!(money(&bodies[0]), money(&bodies[1]));
    assert_eq!(lifecycle(&bodies[0]), lifecycle(&bodies[1]));
}

/// [money] [regress] The copy read without its holder is held, never published
/// without the holder's clock. The next page reads both and offers the
/// correction (the copy's removal, the holder's last clock), which the
/// receiver model accepts over the holder-only head. A transport failure and
/// restart resend the same bytes; a partial ACK settles the root only, and
/// the exactly ACKed root is not offered again.
#[test]
fn lost_holder_correction_keeps_the_head_clock_through_ack_and_restart() {
    with_e2(|| {
        let mut c = Corpus::new("entity-last-clock-recovery");
        let (head, mut prior, copy) = head_then_copy(&mut c, true);
        let copy_key = copy.to_string_lossy().into_owned();
        owe(&mut prior);
        let mut alone = c.raw(&E2ScanFixture::default(), prior.clone(), 100, false, &[]);
        let witness = alone.index.files[&copy_key].source_file_fingerprint.clone();
        alone
            .scan
            .snapshots
            .retain(|item| item.source_file_fingerprint.as_deref() == Some(witness.as_str()));
        alone.enrich(&c);
        assert_withheld(&alone, ROOT, "the copy alone cannot replace the head");
        // Persist the decision without finalizing the filtered-out holder.
        prior = c.reload(&mut alone.index);

        // An independent session joins the page as the sibling to partially ACK.
        c.root(LATE, &line(LATE, "late", AT, 5));
        owe(&mut prior);
        // Cache rows dropped as the production upload seam does: a summed body
        // and its sibling then share one batch class, so one request carries both.
        let mut p = ready_without_cache(&c, &E2ScanFixture::default(), prior.clone(), 100, false);
        let item = body(&p, ROOT).unwrap();
        assert_eq!(
            item.source_file_fingerprint.as_deref(),
            Some(p.index.files[&copy_key].source_file_fingerprint.as_str()),
            "the copy carries"
        );
        assert_eq!(
            (item.request_count, item.removed_request_count),
            (2, Some(1))
        );
        assert_eq!(lifecycle(item), [Some(A.1), None, Some(TAIL)]);
        let etag = snapshot_upload_body_witness(&head);
        let mut candidate = item.clone();
        candidate.cache_base_head_etag = Some(etag.clone());
        assert!(
            receiver_accepts(&head, &candidate, &etag),
            "the correction is not older than the head"
        );
        assert!(body(&p, LATE).is_some());

        p.finish();
        let original = canonical(&p.scan.snapshots);
        let fingerprints = p.receipt();
        let mut progress = e2_progress();
        let (failed, first, order) = upload(&p.scan.snapshots, &mut progress, |_| {
            Err(anyhow!("synthetic connection reset before ACK"))
        });
        assert!(failed.is_err());
        assert_eq!(
            order,
            [[ROOT.to_owned(), LATE.to_owned()]],
            "the session and its sibling travel in one request"
        );
        assert!(progress.accepted_fingerprints.is_empty());
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut p.index,
            &mut p.scan,
            &p.disposition,
        );
        // The checkpoint commits to the page's own fixture route.
        let index_path = crate::snapshots::e2_pipeline_scan_fixture::route_of(&p.index).unwrap();
        let progress_path = snapshot_upload_progress_path(&index_path);
        progress = route_fixture_progress(&p.index, &index_path, &progress_path, progress);
        progress.save(&progress_path).unwrap();
        checkpoint_partial_snapshot_index_with_drains(
            &p.index,
            &prior,
            &progress,
            &p.scan.snapshots,
            Some(&p.scan),
            &holds.held_fingerprints,
            &index_path,
            &progress_path,
            || Ok(()),
            None,
            Some(crate::snapshots::UnsettledUploadCause::UploadError),
            Default::default(),
        )
        .unwrap();
        let restarted = ScanIndex::load(&index_path).unwrap();
        let mut progress = SnapshotUploadProgress::load_for_index(
            &restarted,
            &index_path,
            &progress_path,
            &format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        let mut restart =
            ready_without_cache(&c, &E2ScanFixture::default(), restarted.clone(), 100, false);
        let holds = restart.finish();
        assert_eq!(
            canonical(&restart.scan.snapshots),
            original,
            "the restart rereads both files into the same bytes"
        );
        assert_eq!(restart.receipt(), fingerprints);
        let sent = restart.scan.snapshots.clone();
        let (result, resent, _) = upload(&sent, &mut progress, |batch| {
            let mut response = ack(batch)?;
            let sibling = response
                .accepted_entities
                .iter()
                .position(|e| e.source_session_id != ROOT)
                .unwrap();
            let mut sibling = response.accepted_entities.remove(sibling);
            response.accepted -= 1;
            sibling.head_etag = None;
            response.conflict_entities.push(sibling);
            Ok(response)
        });
        assert_eq!(
            result.unwrap(),
            ResumableUploadResult::Deferred {
                count: 1,
                isolated: 1,
                identity_503: 0
            }
        );
        assert_eq!(first, resent, "the transport retry is byte-exact");
        let root = body(&restart, ROOT).unwrap();
        assert_eq!(lifecycle(root), [Some(A.1), None, Some(TAIL)]);
        assert_eq!(
            progress.accepted_fingerprints,
            BTreeSet::from([root.snapshot_fingerprint.clone()]),
            "a partial ACK never settles its sibling"
        );
        let mut settled = settle_checkpointed_upload(
            restart.index,
            &restarted,
            &progress,
            &holds,
            true,
            UnsettledUploadCause::DeferredConflict,
        );
        settle_index_after_upload(&mut settled.index, &restarted, &progress);
        accept_upload_context_acks_for_test(
            &mut settled.index,
            &sent,
            &progress.fresh_context_body_acks,
        );
        let settled = c.reload(&mut settled.index);
        let mut next = twin(&ready_without_cache(
            &c,
            &E2ScanFixture::default(),
            settled,
            100,
            false,
        ));
        next.finish();
        assert!(
            body(&next, ROOT).is_none(),
            "the exactly ACKed correction is not offered again"
        );
    });
}
