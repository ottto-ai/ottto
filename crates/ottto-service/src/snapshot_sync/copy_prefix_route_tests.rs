// Included inside the money-equivalence fixture for its Disk and page arms.
// Not a cross-build receipt: it prints no MONEY_EQUIVALENCE line.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, Mode, RouteResult};

fn route(mode: Mode, page: &Page) -> RouteResult {
    let (status, wire, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let copy = body(page, COPY).expect("the grown resume publishes");
    assert_eq!(copy.removed_request_count, Some(2), "{mode:?}");
    RouteResult::emitted(mode, SnapshotSource::ClaudeCode, wire, &page.scan.snapshots)
}

/// Deliver a finished page: its exact ACKs earn per-file upload-context
/// receipts, as the service records them after settlement.
fn deliver(page: &mut Page) {
    deliver_into(page, &mut Ledger::new(), false);
}

/// Each session's last exact-ACKed body, as the server keeps it:
/// `(request_count, removed_request_count)`. A refused POST leaves the old one.
type Ledger = BTreeMap<String, (u64, u64)>;

/// How many accepted bodies hold the shared ids A and B: (holder, copy). The
/// holder's body is exactly A and B; the copy's is its own turn C plus the
/// prefix unless it removed or deferred it.
fn shared(ledger: &Ledger) -> (u64, u64) {
    let holder = ledger.get(ROOT).map_or(0, |(count, _)| *count);
    let copy = ledger
        .get(COPY)
        .map_or(0, |(count, _)| count.saturating_sub(1));
    (holder, copy)
}

/// Deliver a page as `deliver` does; every exact-ACKed body replaces its
/// session's ledger entry. `refuse_holder` permanently refuses each holder
/// body of the page instead. Returns the POST count and the refused holder
/// bodies.
fn deliver_into(page: &mut Page, ledger: &mut Ledger, refuse_holder: bool) -> (usize, usize) {
    let mut progress = e2_progress();
    let mut refused = 0;
    let (status, sent, _) = upload(&page.scan.snapshots, &mut progress, |batch| {
        let mut response = ack(batch)?;
        if refuse_holder {
            let (holder, kept): (Vec<_>, Vec<_>) = std::mem::take(&mut response.accepted_entities)
                .into_iter()
                .partition(|entity| entity.source_session_id == ROOT);
            response.accepted_entities = kept;
            response.accepted -= holder.len() as u64;
            response.sessions_reconciled = response.accepted;
            refused += holder.len();
            response.rejected_entities = holder
                .into_iter()
                .map(|entity| crate::snapshot_client::SnapshotEntityRejection {
                    source_session_id: entity.source_session_id,
                    snapshot_fingerprint: entity.snapshot_fingerprint,
                    occurrence_count: entity.occurrence_count,
                    reason: "usage_accounting_authority_downgrade".into(),
                    detail: "synthetic refusal".into(),
                    permanent: true,
                })
                .collect();
        }
        for entity in &response.accepted_entities {
            let item = batch
                .iter()
                .find(|item| item.snapshot_fingerprint == entity.snapshot_fingerprint)
                .expect("an ACK names a sent body");
            ledger.insert(
                item.source_session_id.clone(),
                (item.request_count, item.removed_request_count.unwrap_or(0)),
            );
        }
        Ok(response)
    });
    if refused == 0 {
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    } else {
        assert!(status.is_ok(), "a refusal settles the page: {status:?}");
    }
    // The exact ACKs land as the service records them before it saves; the
    // committed Tail heads continue only from accepted bodies.
    page.index
        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    let acks = std::mem::take(&mut progress.fresh_context_body_acks);
    accept_upload_context_acks_for_test(&mut page.index, &page.scan.snapshots, &acks);
    (sent.len(), refused)
}

/// #1253 at ACK granularity: a copy's prefix removal is decided only on
/// holder acceptance already ACKed on an EARLIER page (`before`, the ledger
/// before this page's POSTs), never on the page's own pending holder POST.
fn assert_removal_follows_acceptance(page: usize, removed: bool, before: &Ledger) {
    if removed {
        assert_eq!(
            shared(before).0,
            2,
            "page {page}: the copy removed its prefix before the holder's body \
             was accepted (ledger {before:?})"
        );
    }
}

/// The warm owner reads Full, is delivered as the service delivers every
/// page, and commits; its saved index is every arm's prior.
fn warm_delivered(c: &Corpus, disk: &Disk) -> (E2ScanFixture, ScanIndex) {
    let scanner = E2ScanFixture::default();
    disk.begin(&scanner, SnapshotSource::ClaudeCode);
    let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
    warm.enrich(c);
    warm.finish();
    deliver(&mut warm);
    let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
    (scanner, prior)
}

fn opened(scanner: &E2ScanFixture, path: &Path) -> bool {
    scanner
        .paths()
        .iter()
        .any(|opened| opened.file_name() == path.file_name())
}

/// [money] Copy-prefix dedupe through every acquisition route: a resumed main
/// file whose uncertified writer copied an earlier session's requests, with
/// own turns after them. RAM Tail, cold Full and a restored owner remove the
/// same copied prefix and emit the same bodies, totals and placement, with a
/// restart between pages. The delivered holder's accepted body is what lets
/// the prefix go.
#[test]
fn resumed_copy_prefix_dedupe_is_route_equivalent() {
    if !supported("resumed_copy_prefix_dedupe") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("resumed_copy_prefix_dedupe");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let mut disk = Disk::new(&c);
        let (scanner, prior) = warm_delivered(&c, &disk);
        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut first = c.raw(&scanner, prior, 100, true, &[]);
        first.enrich(&c);
        first.finish();
        let copy = body(&first, COPY).expect("the resumed file publishes");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (1, Some(2))
        );
        // The page is delivered: its exact ACKs earn per-file upload-context
        // receipts as the service records them, so only the grown copy is
        // read on the next pages; the delivered holder stays proven.
        deliver(&mut first);
        assert!(
            !upload_context_owed_for_test(&first.index, &holder),
            "the delivered holder owes its proof (modes {:?})",
            first.modes
        );
        let prior = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
        let mut priors = [prior.clone(), prior.clone(), prior];
        let mut bodies = Vec::new();
        for (request, at) in [("d", D.1), ("e", "2026-08-02T07:09:10Z")] {
            append(&path, &line_by(COPY, request, at, 10, RESUME_WRITER));
            input_clock(&path);
            for (arm, prior) in ["ram", "cold", "disk"].iter().zip(&priors) {
                // The page activates the same context before it selects.
                let mut prior = prior.clone();
                prior.activate_upload_context("e2-synthetic-destination".into());
                assert!(
                    !upload_context_owed_for_test(&prior, &holder),
                    "page {request}: the {arm} prior owes the holder again"
                );
            }
            let restart = disk.owner(SnapshotSource::ClaudeCode);
            let mut pages = claude_pages(&c, &scanner, &restart, priors, (0, 1, 0));
            finish_claude_pages(&c, &mut pages);
            bodies.push(compare_claude_uploads(&pages));
            let [tail, full, mut disk_page] = pages;
            let cold = route(Mode::ColdFull, &full);
            money_oracle::assert_equivalent(&cold, &route(Mode::Ram, &tail));
            money_oracle::assert_equivalent(&cold, &route(Mode::DiskRestore, &disk_page));
            let next = disk.commit(
                &disk_page.cache,
                SnapshotSource::ClaudeCode,
                &mut disk_page.index,
            );
            // The cold arm reads the same committed prior: its own unACKed
            // lineage, republished on a new route, holds a growth claim bound
            // to the old one (as `restart_between_pages`).
            priors = [next.clone(), next.clone(), next];
        }
        assert_ne!(bodies[0].raw, bodies[1].raw, "the second page adds money");
    });
}

/// [regress] A holder whose page was never delivered owes its upload-context
/// proof, as a production file without a receipt does. Re-read beside a new
/// copy of its prefix, its identical body is offered and exact-ACKed and it
/// earns its receipt. A family re-arm on that page may clear its revision for
/// one forced reparse, so it is read at most once more; the restored revision
/// lets the receipt prove. A copy's prefix goes only once its origin's body is
/// accepted (#1253): page 1 sends the copy with the prefix flagged and the
/// holder; page 2 re-folds the copy from stored state with the prefix removed
/// and sends it as an ordinary update (L02), equal to a cold Full; pages 3-4
/// neither read the holder nor POST anything.
#[test]
fn never_delivered_holder_is_read_at_most_once_more_beside_a_new_copy() {
    // As every owner of this harness: commits persist durable records.
    if !supported("never_delivered_holder_reread_bound") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("never_delivered_holder_reread_bound");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let disk = Disk::new(&c);
        // Committed, never delivered: no receipt.
        let (scanner, mut prior) = warm_claude_undelivered(&c, &disk);
        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        let mut reads = Vec::new();
        let mut posts = Vec::new();
        let mut pages = Vec::new();
        let mut removed_on = None;
        let mut ledger = Ledger::new();
        for page in 1..=4 {
            let base = prior.clone();
            disk.begin(&scanner, SnapshotSource::ClaudeCode);
            let mut p = c.raw(&scanner, prior, 100, true, &[]);
            p.enrich(&c);
            p.finish();
            reads.push(opened(&scanner, &holder));
            let copy = body(&p, COPY).map(|copy| (copy.request_count, copy.removed_request_count));
            pages.push(format!(
                "page {page}: modes {:?}, sessions {:?}, copy {copy:?}",
                p.modes,
                p.scan
                    .snapshots
                    .iter()
                    .map(|item| &item.source_session_id[..4])
                    .collect::<Vec<_>>()
            ));
            if page > 1
                && removed_on.is_none()
                && copy.is_some_and(|(_, removed)| removed == Some(2))
            {
                removed_on = Some(page);
                // The copy's prefix is removed, and the body equals a cold Full
                // of the copy on the same accepted state: a new owner with no
                // entry for the copy reads it whole beside the accepted holder.
                let mut base = base;
                let key = path.to_str().unwrap();
                base.files.remove(key);
                base.file_snapshot_fingerprints.remove(key);
                // Listing is paced: the watcher's hint names the copy.
                let hint = std::slice::from_ref(&path);
                let mut cold = c.raw(&E2ScanFixture::default(), base, 100, true, hint);
                cold.enrich(&c);
                cold.finish();
                money_oracle::assert_equivalent(
                    &route(Mode::ColdFull, &cold),
                    &route(Mode::DiskRestore, &p),
                );
            }
            assert_removal_follows_acceptance(
                page,
                copy.is_some_and(|(_, removed)| removed.unwrap_or(0) > 0),
                &ledger,
            );
            let (sent, _) = deliver_into(&mut p, &mut ledger, false);
            posts.push(sent);
            // After each page's ACKs the shared ids are in exactly one
            // accepted body: never zero, never two.
            let (in_holder, in_copy) = shared(&ledger);
            assert!(
                matches!((in_holder, in_copy), (2, 0) | (0, 2)),
                "page {page}: A and B in holder {in_holder}, copy {in_copy} \
                 (ledger {ledger:?}, {pages:#?})"
            );
            if page == 1 {
                assert!(reads[0], "the owed holder is re-read beside the new copy");
                assert!(
                    upload_context_receipt_earned_for_test(&p.index, &holder),
                    "page 1 earns the holder's receipt"
                );
            }
            let owed = upload_context_owed_for_test(&p.index, &holder);
            prior = disk.commit(&p.cache, SnapshotSource::ClaudeCode, &mut p.index);
            if page >= 2 {
                assert!(!owed, "page {page}: the holder owes its proof again");
            }
        }
        assert!(
            reads[1..].iter().filter(|read| **read).count() <= 1,
            "the holder is read at most once more after it earns its receipt: {reads:?}"
        );
        assert_eq!(
            (&reads[2..], &posts[..], removed_on),
            (&[false, false][..], &[1_usize, 1, 0, 0][..], Some(2)),
            "pages 3-4 never read the holder; only pages 1 and 2 POST, page 2 \
             the copy with its prefix removed (reads {reads:?}, posts {posts:?}, {pages:#?})"
        );
    });
}

/// [regress] #1253 negative: the never-delivered holder's POST is refused on
/// page 1 (its first acceptance) or page 2. A refusal keeps the server's
/// earlier body or none, so the copy removes its prefix only on a page after
/// the holder's body was accepted; the shared ids are never in two accepted
/// bodies and end in exactly one.
#[test]
fn refused_holder_post_never_lets_the_copy_drop_its_prefix() {
    if !supported("refused_holder_copy_prefix") {
        return;
    }
    for refused_on in [1, 2] {
        refused_holder_case(refused_on);
    }
}

fn refused_holder_case(refused_on: usize) {
    with_e2(|| {
        let mut c = corpus(&format!("refused_holder_copy_prefix_{refused_on}"));
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let disk = Disk::new(&c);
        let (scanner, mut prior) = warm_claude_undelivered(&c, &disk);
        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        let mut ledger = Ledger::new();
        let mut refusals = 0;
        let mut pages = Vec::new();
        for page in 1..=6 {
            disk.begin(&scanner, SnapshotSource::ClaudeCode);
            let mut p = c.raw(&scanner, prior, 100, true, &[]);
            p.enrich(&c);
            p.finish();
            let copy = body(&p, COPY).map(|copy| (copy.request_count, copy.removed_request_count));
            pages.push(format!(
                "page {page}: modes {:?}, sessions {:?}, copy {copy:?}",
                p.modes,
                p.scan
                    .snapshots
                    .iter()
                    .map(|item| &item.source_session_id[..4])
                    .collect::<Vec<_>>()
            ));
            assert_removal_follows_acceptance(
                page,
                copy.is_some_and(|(_, removed)| removed.unwrap_or(0) > 0),
                &ledger,
            );
            let (_, refused) = deliver_into(&mut p, &mut ledger, page == refused_on);
            refusals += refused;
            let (in_holder, in_copy) = shared(&ledger);
            assert!(
                in_holder == 0 || in_copy == 0,
                "refused on {refused_on}, page {page}: A and B in two accepted \
                 bodies (ledger {ledger:?}, {pages:#?})"
            );
            prior = disk.commit(&p.cache, SnapshotSource::ClaudeCode, &mut p.index);
        }
        if refused_on == 1 {
            assert_eq!(
                refusals, 1,
                "the holder's first POST is refused: {pages:#?}"
            );
        }
        assert!(
            matches!(shared(&ledger), (2, 0) | (0, 2)),
            "refused on {refused_on} ({refusals} refusals): A and B end in exactly \
             one accepted body (ledger {ledger:?}, {pages:#?})"
        );
    });
}

/// [regress] The server's head already covers the origin (changed there, by an
/// operator admission): its answer settles no body, so the daemon keeps a learned
/// head but no receipt or stamp. That is no acceptance: the copy keeps the prefix.
#[test]
fn server_learned_head_is_not_an_accepted_origin() {
    if !supported("server_learned_head_origin") {
        return;
    }
    with_e2(|| {
        let mut c = corpus("server_learned_head_origin");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let disk = Disk::new(&c);
        let scanner = E2ScanFixture::default();
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
        warm.enrich(&c);
        warm.finish();
        let mut progress = e2_progress();
        let (status, _, _) = upload(&warm.scan.snapshots, &mut progress, |batch| {
            let mut response = ack(batch)?;
            for mut entity in std::mem::take(&mut response.accepted_entities) {
                entity.unchanged_basis = Some("usage_identical".into());
                if entity.head_etag.is_some() {
                    entity.head_etag = Some("3".repeat(64));
                }
                response.unchanged_entities.push(entity);
            }
            Ok(response)
        });
        assert!(status.is_ok());
        assert!(progress.fresh_context_body_acks.is_empty());
        assert!(progress.accepted_body_contexts.is_empty());
        let acks = std::mem::take(&mut progress.fresh_context_body_acks);
        accept_upload_context_acks_for_test(&mut warm.index, &warm.scan.snapshots, &acks);
        assert!(!upload_context_receipt_earned_for_test(
            &warm.index,
            &holder
        ));
        let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);

        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut page = c.raw(&scanner, prior, 100, true, &[]);
        page.enrich(&c);
        page.finish();
        let copy = body(&page, COPY).expect("the copy's own turn publishes");
        assert_eq!(
            copy.request_count, 1,
            "only its own turn, while the prefix waits"
        );
        assert_eq!(copy.removed_request_count.unwrap_or(0), 0);
    });
}
