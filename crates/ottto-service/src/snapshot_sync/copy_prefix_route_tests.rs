// Included inside the money-equivalence fixture for its Disk and page arms.
// Not a cross-build receipt: it prints no MONEY_EQUIVALENCE line.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle, observe_consumed, upgrade_from_legacy_store, Mode, RouteResult,
};

fn route(arm: Settled, mode: Mode, page: &Page) -> RouteResult {
    let (status, wire, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    let copy = body(page, COPY).expect("the grown resume publishes");
    assert_eq!(copy.removed_request_count, Some(2), "{arm:?} {mode:?}");
    let mut result =
        RouteResult::emitted(mode, SnapshotSource::ClaudeCode, wire, &page.scan.snapshots);
    result.modes = page.modes;
    result
}

/// How the copy's settled prefix removal reaches its growth pages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Settled {
    /// The delivered holder proves the prefix again by request ids.
    Holders,
    /// What an earlier build left: the copy settled before the cutoff with
    /// its prefix removed and accepted, and nothing saved. The holder family
    /// is then listed for re-emission, so no holder proves the prefix anew.
    Grandfathered,
    /// The removal is saved, then the holder family is listed: listing
    /// pauses new removals only.
    ListedHolder,
}

impl Settled {
    fn name(self) -> &'static str {
        match self {
            Settled::Holders => "resumed_copy_prefix_dedupe",
            Settled::Grandfathered => "resumed_copy_prefix_dedupe_grandfathered",
            Settled::ListedHolder => "resumed_copy_prefix_dedupe_listed_holder",
        }
    }

    /// The committed index every route of the next page reads.
    fn prior(self, mut prior: ScanIndex) -> ScanIndex {
        if self == Settled::Grandfathered {
            prior.claude_copy_removals = Default::default();
        }
        prior
    }
}

/// One own telemetry row of the copy at its provider time and order.
fn own_row(
    request: &str,
    tokens: u64,
    (login, org): (char, char),
    at: &str,
    sequence: u64,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = api_login(COPY, request, tokens, login, Some(org));
    row.observed_at = at.into();
    row.event_sequence = Some(sequence);
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}

/// The copy's own telemetry, the placement positive control: two accounts,
/// a switch between its own turns c and d, a side call (a request with no
/// transcript line) under the second account, and no row for e (an
/// evidence gap). `grown`: d is written.
fn copy_evidence(c: &Corpus, grown: bool) {
    let mut rows = vec![
        own_row("c", 10, ('1', '7'), C.1, 1),
        own_row("side", 4, ('2', '8'), "2026-08-02T07:03:30Z", 2),
    ];
    if grown {
        rows.push(own_row("d", 10, ('2', '8'), D.1, 3));
    }
    let traces = rows
        .iter()
        .map(|row| trace_for(COPY, &row.request_id, ""))
        .collect::<Vec<_>>();
    c.evidence_for(COPY, &rows, &traces);
}

/// Distinct account hashes anywhere in a route's bodies.
fn accounts(result: &RouteResult) -> usize {
    fn walk(value: &serde_json::Value, out: &mut std::collections::BTreeSet<String>) {
        match value {
            serde_json::Value::Object(fields) => {
                if let Some(account) = fields
                    .get("account_identifier_hash")
                    .and_then(serde_json::Value::as_str)
                {
                    out.insert(account.into());
                }
                for value in fields.values() {
                    walk(value, out);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    walk(value, out);
                }
            }
            _ => {}
        }
    }
    let mut out = std::collections::BTreeSet::new();
    for snapshot in result.snapshots.values() {
        walk(snapshot, &mut out);
    }
    out.len()
}

fn copy_requests(result: &RouteResult) -> u64 {
    result.snapshots[COPY]["request_count"]
        .as_u64()
        .expect("the copy's body counts requests")
}

/// Deliver a finished page: its exact ACKs earn per-file upload-context
/// receipts, as the service records them after settlement.
fn deliver(page: &mut Page) {
    deliver_into(page, &mut Ledger::new());
}

/// Each session's last exact-ACKed body, as the server keeps it:
/// `(request_count, removed_request_count)`.
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
/// session's ledger entry. Returns the POST count.
fn deliver_into(page: &mut Page, ledger: &mut Ledger) -> usize {
    let mut progress = e2_progress();
    let (status, sent, _) = upload(&page.scan.snapshots, &mut progress, |batch| {
        let response = ack(batch)?;
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
    assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    // The exact ACKs land as the service records them before it saves; the
    // committed Tail heads continue only from accepted bodies.
    page.index
        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    let acks = std::mem::take(&mut progress.fresh_context_body_acks);
    accept_upload_context_acks_for_test(&mut page.index, &page.scan.snapshots, &acks);
    sent.len()
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
/// own turns after them, two accounts, a side call and an evidence gap. RAM
/// Tail, cold Full and a restored owner remove the same copied prefix and
/// emit the same bodies, totals and placement, with a restart between pages,
/// as does a new owner of the same committed state upgraded from the store an
/// older release left (pending usage evidence and owed bits on every file);
/// no grown body is smaller than the accepted one, and a restart after the
/// last delivered page parses and sends nothing. The prefix stays removed when
/// the delivered holder proves it, when an earlier build's accepted removal
/// has nothing saved and no holder proves it anew, and when the holder
/// family of a saved removal is listed.
#[test]
fn resumed_copy_prefix_dedupe_is_route_equivalent() {
    for arm in [
        Settled::Holders,
        Settled::Grandfathered,
        Settled::ListedHolder,
    ] {
        if !supported(arm.name()) {
            return;
        }
        with_e2(|| copy_prefix_routes(arm));
    }
}

fn copy_prefix_routes(arm: Settled) {
    let mut c = corpus(arm.name());
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
    copy_evidence(&c, false);
    disk.begin(&scanner, SnapshotSource::ClaudeCode);
    let mut first = c.raw(&scanner, prior, 100, true, &[]);
    first.enrich(&c);
    first.finish();
    let copy = body(&first, COPY).expect("the resumed file publishes");
    assert_eq!(
        (copy.request_count, copy.removed_request_count),
        (2, Some(2)),
        "{arm:?}: own turn c and the side call; the holder proves the prefix"
    );
    let mut accepted = route(arm, Mode::ColdFull, &first);
    // The page is delivered: its exact ACKs earn per-file upload-context
    // receipts as the service records them, so only the grown copy is
    // read on the next pages; the delivered holder stays proven.
    deliver(&mut first);
    assert!(
        !upload_context_owed_for_test(&first.index, &holder),
        "the delivered holder owes its proof (modes {:?})",
        first.modes
    );
    if arm != Settled::Holders {
        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&c.support, &[ROOT]);
    }
    let prior = arm.prior(disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index));
    let mut priors = [prior.clone(), prior.clone(), prior];
    let mut bodies = Vec::new();
    for (request, at) in [("d", D.1), ("e", "2026-08-02T07:09:10Z")] {
        append(&path, &line_by(COPY, request, at, 10, RESUME_WRITER));
        input_clock(&path);
        if request == "d" {
            copy_evidence(&c, true);
        }
        for (owner, prior) in ["ram", "cold", "disk"].iter().zip(&priors) {
            // The page activates the same context before it selects.
            let mut prior = prior.clone();
            prior.activate_upload_context("e2-synthetic-destination".into());
            assert!(
                !upload_context_owed_for_test(&prior, &holder),
                "{arm:?} page {request}: the {owner} prior owes the holder again"
            );
        }
        // The committed prior as an older release's store holds it, loaded
        // by this build.
        let upgraded =
            upgrade_from_legacy_store(&priors[2], &c.base.join("legacy-scan-index.json"));
        let restart = disk.owner(SnapshotSource::ClaudeCode);
        let mut pages = claude_pages(&c, &scanner, &restart, priors, (0, 1, 0));
        finish_claude_pages(&c, &mut pages);
        bodies.push(compare_claude_uploads(&pages));
        let [tail, full, mut disk_page] = pages;
        let cold = route(arm, Mode::ColdFull, &full);
        let mut upgrade = c.raw(&E2ScanFixture::default(), upgraded, 100, true, &[]);
        upgrade.enrich(&c);
        upgrade.finish();
        assert!(
            accounts(&cold) >= 2,
            "{arm:?} page {request}: positive control, two placed accounts"
        );
        assert!(
            body(&full, COPY)
                .unwrap()
                .usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage)
                .any(|row| row.evidence_ref.is_some() || row.identity_parts.is_some()),
            "{arm:?} page {request}: positive control, a tagged row"
        );
        assert!(
            copy_requests(&cold) > copy_requests(&accepted),
            "{arm:?} page {request}: the grown body is no smaller than the accepted one"
        );
        for other in [
            route(arm, Mode::Ram, &tail),
            route(arm, Mode::DiskRestore, &disk_page),
            route(arm, Mode::Restart, &upgrade),
        ] {
            money_oracle::assert_equivalent(&cold, &other);
            money_oracle::assert_no_smaller_reemit(COPY, &accepted, &other, &cold, false);
        }
        // The service delivers each page before it commits. The cold arm
        // reads the same committed prior: its own lineage, republished on a
        // new route, holds a growth claim bound to the old one (as
        // `restart_between_pages`).
        deliver(&mut disk_page);
        let next = arm.prior(disk.commit(
            &disk_page.cache,
            SnapshotSource::ClaudeCode,
            &mut disk_page.index,
        ));
        priors = [next.clone(), next.clone(), next];
        accepted = cold;
    }
    assert_ne!(bodies[0].raw, bodies[1].raw, "the second page adds money");

    // A restart after the last delivered page: nothing changed. The new
    // owner starts a census generation that opens each indexed transcript
    // once to check its identity, then skips it: no Full read, no parser
    // byte, nothing sent, and enrichment opens no transcript.
    // `assert_quiet_restart_zero_bytes` needs a census generation kept
    // across the restart and measured identity bytes; this harness has
    // neither, so it asserts the open count instead.
    let restart = disk.owner(SnapshotSource::ClaudeCode);
    let [_, _, prior] = priors;
    let before = crate::snapshots::all_transcript_opens_for_test();
    let (mut quiet, consumed) = observe_consumed(|| c.raw(&restart, prior, 100, true, &[]));
    let scanned = crate::snapshots::all_transcript_opens_for_test() - before;
    quiet.enrich(&c);
    quiet.finish();
    let enriched = crate::snapshots::all_transcript_opens_for_test() - before - scanned;
    assert_eq!(quiet.modes.0, 0, "{arm:?}: the quiet restart read Full");
    assert_eq!(consumed, 0, "{arm:?}: the quiet restart parsed bytes");
    assert!(
        scanned <= 2,
        "{arm:?}: at most one identity open per indexed transcript, got {scanned}"
    );
    assert_eq!(enriched, 0, "{arm:?}: enrichment opened a transcript");
    assert!(
        quiet.scan.snapshots.is_empty(),
        "{arm:?}: the quiet restart sent a body"
    );
}

/// [regress] A holder whose page was never delivered owes its upload-context
/// proof, as a production file without a receipt does. That proof alone
/// selects no read: the holder is never read, stays owed and never becomes an
/// accepted origin (e2.rs `origin_accepted`). A copy's prefix goes only once
/// its origin's body is accepted (#1253), so the new copy holds its copied
/// prefix for the bounded prefix hold (copy_removals.rs `advance_hold`,
/// `HOLD_PASSES` = 3): page 1 emits only its own turn, page 2 re-parses it
/// from the pending hold (snapshots.rs `claude_copy_removals.pending`) with
/// an identical body and no POST, page 3 expires the hold and emits the
/// restored prefix once (e2.rs `defer_prefix`), and page 4 is quiet. The
/// never-delivered holder's requests are counted once, in the copy.
#[test]
fn never_delivered_holder_is_never_read_and_the_copy_hold_expires_once() {
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
        let mut copy_requests = Vec::new();
        let mut ledger = Ledger::new();
        for page in 1..=4 {
            disk.begin(&scanner, SnapshotSource::ClaudeCode);
            let mut p = c.raw(&scanner, prior, 100, true, &[]);
            p.enrich(&c);
            p.finish();
            reads.push(opened(&scanner, &holder));
            let copy = body(&p, COPY).map(|copy| (copy.request_count, copy.removed_request_count));
            copy_requests.push(copy.map(|(requests, _)| requests));
            assert_removal_follows_acceptance(
                page,
                copy.is_some_and(|(_, removed)| removed.unwrap_or(0) > 0),
                &ledger,
            );
            posts.push(deliver_into(&mut p, &mut ledger));
            assert!(
                upload_context_owed_for_test(&p.index, &holder),
                "page {page}: the holder's proof stays owed, paid by its next read"
            );
            prior = disk.commit(&p.cache, SnapshotSource::ClaudeCode, &mut p.index);
        }
        assert_eq!(reads, [false; 4], "the owed holder is never read");
        assert_eq!(
            (posts.as_slice(), copy_requests.as_slice()),
            (&[1_usize, 0, 1, 0][..], &[Some(1), None, Some(3), None][..]),
            "own turn, held, expired prefix once, quiet"
        );
        assert_eq!(
            shared(&ledger),
            (0, 2),
            "A and B end in exactly one accepted body, the copy's (ledger {ledger:?})"
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
