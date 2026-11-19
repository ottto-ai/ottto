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
    /// The removal is saved, then the holder family is listed: listing
    /// pauses new removals only.
    ListedHolder,
}

impl Settled {
    fn name(self) -> &'static str {
        match self {
            Settled::Holders => "resumed_copy_prefix_dedupe",
            Settled::ListedHolder => "resumed_copy_prefix_dedupe_listed_holder",
        }
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
pub(in crate::snapshot_sync) fn accounts(result: &RouteResult) -> usize {
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

/// A one-slot census page can visit an unchanged member before the marked
/// file. Preserve that budget and settle empty pages until the target is read.
#[track_caller]
fn next_body_page(
    c: &Corpus,
    mut prior: ScanIndex,
    session: &str,
    progress: &mut SnapshotUploadProgress,
) -> Page {
    let scanner = E2ScanFixture::capturing_identity();
    for attempt in 0..4 {
        let mut page = c.raw(&scanner, prior.clone(), 1, false, &[]);
        page.enrich_with(c, Some(&mut progress.accepted_identity_buckets));
        if body(&page, session).is_some() {
            return page;
        }
        // A visited unchanged member can still have a pre-finalize body.
        // Apply the normal no-op suppression before calling it an empty slot.
        page.finish();
        assert!(
            page.scan.snapshots.is_empty(),
            "a deferred census slot sends nothing: target {session}, attempt {attempt}, sent {:?}",
            sent_bodies(&page)
        );
        prior = settle(c, &prior, page, progress);
    }
    panic!("the marked file must be selected after the fixture's census members");
}

/// Failure detail for the oracles: each sent body's session, request count and
/// declared removals.
fn sent_bodies(page: &Page) -> Vec<(&str, u64, Option<u64>)> {
    page.scan
        .snapshots
        .iter()
        .map(|s| {
            (
                s.source_session_id.as_str(),
                s.request_count,
                s.removed_request_count,
            )
        })
        .collect()
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
/// the delivered holder proves it and when the holder family of a saved
/// removal is listed.
#[test]
fn resumed_copy_prefix_dedupe_is_route_equivalent() {
    for arm in [Settled::Holders, Settled::ListedHolder] {
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
    let mut prior = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
    // A deleted session beside the holder is still indexed in the committed
    // prior. Every route's complete read of that directory proves it absent
    // and retires it; no body, total or placement moves.
    let stale_key = holder
        .with_file_name("c0ffee00-0000-4000-8000-0000000057a1.jsonl")
        .to_string_lossy()
        .into_owned();
    // The absence row's positive control: a nonempty accepted baseline,
    // the stale key indexed beside the live holder and copy, with two
    // accounts, a switch, a side call, an evidence gap and a tagged row.
    let live = [&holder, &path].map(|path| path.to_string_lossy().into_owned());
    if arm == Settled::Holders {
        let entry = prior.files.values().next().unwrap().clone();
        prior.files.insert(stale_key.clone(), entry);
        assert!(copy_requests(&accepted) > 0, "a nonempty accepted baseline");
        assert!(live.iter().all(|key| prior.files.contains_key(key)));
    }
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
        // The committed prior as an older release's store holds it, imported
        // by this build; each page's store is its own scratch path.
        let upgraded = upgrade_from_legacy_store(
            &priors[2],
            &c.base.join(format!("legacy-scan-index-{request}.json")),
        );
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
        let next = disk.commit(
            &disk_page.cache,
            SnapshotSource::ClaudeCode,
            &mut disk_page.index,
        );
        priors = [next.clone(), next.clone(), next];
        accepted = cold;
    }
    assert!(
        priors
            .iter()
            .all(|prior| !prior.files.contains_key(&stale_key)),
        "{arm:?}: the deleted session is retired"
    );
    assert!(
        priors
            .iter()
            .all(|prior| live.iter().all(|key| prior.files.contains_key(key))),
        "{arm:?}: the live holder and copy stay indexed"
    );
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

/// Complete a real native account-held page, including its CONTENT memo.
/// Keep the request ids, but rewrite the last response without its model:
/// a Tail append would inherit the preceding model instead.
fn native_account_held_page(
    c: &Corpus,
    scanner: &E2ScanFixture,
    prior: ScanIndex,
    session: &str,
) -> (Page, LocalHoldSettlement) {
    crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&c.support, &[session]);
    let path = c.root.join(file(session));
    let mut rows = std::fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .collect::<Vec<_>>();
    rows.last_mut().unwrap()["message"]
        .as_object_mut()
        .unwrap()
        .remove("model");
    std::fs::write(
        &path,
        rows.iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    input_clock(&path);
    let mut saved = serde_json::to_value(&prior).unwrap();
    let owner = crate::context_footprint::sha256_hex(&[
        "session_owner:v1",
        "e2-synthetic-machine",
        session,
    ]);
    saved["session_account_bindings"][owner] =
        json!({"account_identifier_hash":"a".repeat(64), "workspace_identifier_hash":null});
    let mut bound: ScanIndex = serde_json::from_value(saved).unwrap();
    crate::snapshots::e2_pipeline_scan_fixture::onto_route_for_test(&mut bound, &prior);
    let mut page = c.raw(scanner, bound, 100, true, &[]);
    page.enrich(c);
    assert!(crate::snapshots::e2_pipeline_scan_fixture::explicitly_held(
        &page.disposition,
        session
    ));
    let holds = page.finish();
    assert_eq!(
        page.index.claude_account_deferred_hold_count(),
        1,
        "the unresolved native model must really hold the session"
    );
    assert!(body(&page, session).is_none(), "the held body cannot POST");
    (page, holds)
}

/// [money] A locally held holder supplies no counted body. The copy sends
/// its prefix once and remains quiet across restarts while the hold lasts.
#[test]
fn never_delivered_holder_is_held_and_copy_counts_once() {
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
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let (mut setup, _) = native_account_held_page(&c, &scanner, prior, ROOT);
        assert!(upload_context_owed_for_test(&setup.index, &holder));
        let mut setup_progress = e2_progress();
        upload(&setup.scan.snapshots, &mut setup_progress, |_| {
            panic!("the never-delivered holder must not POST during setup")
        })
        .0
        .unwrap();
        prior = disk.commit(&setup.cache, SnapshotSource::ClaudeCode, &mut setup.index);
        assert_eq!(prior.claude_account_deferred_hold_count(), 1);
        // Reload deliberately forgets the runtime destination. Reapply it,
        // as raw does before a real pass, before asking whether proof is owed.
        prior.activate_upload_context("e2-synthetic-destination".into());
        assert!(upload_context_owed_for_test(&prior, &holder));
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
            (&[1_usize, 0, 0, 0][..], &[Some(3), None, None, None][..]),
            "prefix counted once, then quiet"
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

        crate::snapshots::e2_pipeline_scan_fixture::write_exclusions(&c.support, &[ROOT]);
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
            copy.request_count, 3,
            "the listed holder supplies no local ownership"
        );
        assert_eq!(copy.removed_request_count.unwrap_or(0), 0);
    });
}

/// Drive each entity through the real uploader independently, checking the
/// receiver's latest-body ledger after every ACK, then select and save exactly
/// the index the production completion path keeps.
#[track_caller]
fn acknowledge_ordered(
    c: &Corpus,
    mut page: Page,
    progress: &mut SnapshotUploadProgress,
    ledger: &mut Ledger,
    sessions: &[&str],
    expected: &[(u64, u64)],
) -> ScanIndex {
    page.finish();
    assert_eq!(sessions.len(), expected.len());
    for (position, (&session, &shared_expected)) in sessions.iter().zip(expected).enumerate() {
        let Some(item) = body(&page, session).cloned() else {
            panic!(
                "a scheduled body: {session} (position {position} of {sessions:?}), sent {:?}",
                sent_bodies(&page)
            );
        };
        let (status, _, _) = upload(std::slice::from_ref(&item), progress, |batch| {
            let response = ack(batch)?;
            assert_eq!(response.accepted_entities.len(), 1);
            ledger.insert(
                session.into(),
                (item.request_count, item.removed_request_count.unwrap_or(0)),
            );
            assert_eq!(shared(ledger), shared_expected, "after {session} ACK");
            Ok(response)
        });
        assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
    }
    let holds = LocalHoldSettlement::classify(
        SnapshotSource::ClaudeCode,
        &mut page.index,
        &mut page.scan,
        &page.disposition,
    );
    let mut selected = settle_completed_upload(page.index, &page.committed, progress, &holds);
    settle_index_after_upload(&mut selected.index, &page.committed, progress);
    accept_upload_context_acks_for_test(
        &mut selected.index,
        &page.scan.snapshots,
        &progress.fresh_context_body_acks,
    );
    c.reload(&mut selected.index)
}

/// [money] The same locally decided bodies converge in both ACK orders. A
/// copy found first sends its prefix once, then one smaller replacement after
/// source discovery. Restart preserves that correction and the next pass is
/// quiet. The route comparison includes accounts, hours and accepted shares.
#[test]
fn local_copy_ownership_ack_orders_and_copy_first_restart() {
    for copy_first in [false, true] {
        for reverse in [false, true] {
            with_e2(|| {
                let mut c = corpus("local-copy-ownership-orders");
                if !copy_first {
                    c.root(ROOT, &resumed(ROOT, &[A, B]));
                }
                let path = c.write_at(
                    &file(COPY),
                    &resumed(COPY, &[A, B, C]),
                    "2026-08-02T07:03:00Z",
                );
                input_clock(&path);
                let scanner = E2ScanFixture::capturing_identity();
                let mut progress = e2_progress();
                let mut ledger = Ledger::new();
                let mut prior = ScanIndex::default();
                if copy_first {
                    let mut first = c.raw(&scanner, prior, 1, false, &[]);
                    first.enrich(&c);
                    assert_eq!(body(&first, COPY).unwrap().request_count, 3);
                    prior = acknowledge_ordered(
                        &c,
                        first,
                        &mut progress,
                        &mut ledger,
                        &[COPY],
                        &[(0, 2)],
                    );
                    let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
                    input_clock(&holder);
                    let mut source = next_body_page(&c, prior, ROOT, &mut progress);
                    source.finish();
                    if reverse {
                        // Retain the first one-file page while the next one
                        // decides B from A's locally built body. Independent
                        // entity delivery can ACK B before A reaches the server.
                        // A provider progress write selects B's unchanged money
                        // through the ordinary scanner, with no selector seam.
                        append(&path, "\n");
                        let mut correction = c.raw(&scanner, source.index.clone(), 1, false, &[]);
                        assert_eq!(
                            scanner.paths(),
                            vec![path.clone()],
                            "one file in the correction page"
                        );
                        correction.enrich(&c);
                        correction.committed = source.committed;
                        correction.scan.snapshots.extend(source.scan.snapshots);
                        prior = acknowledge_ordered(
                            &c,
                            correction,
                            &mut progress,
                            &mut ledger,
                            &[COPY, ROOT],
                            &[(0, 0), (2, 0)],
                        );
                    } else {
                        prior = acknowledge_ordered(
                            &c,
                            source,
                            &mut progress,
                            &mut ledger,
                            &[ROOT],
                            &[(2, 2)],
                        );
                        let correction = next_body_page(&c, prior, COPY, &mut progress);
                        prior = acknowledge_ordered(
                            &c,
                            correction,
                            &mut progress,
                            &mut ledger,
                            &[COPY],
                            &[(2, 0)],
                        );
                    }
                } else {
                    let mut both = c.raw(&scanner, prior, 100, false, &[]);
                    both.enrich(&c);
                    assert_eq!(body(&both, COPY).unwrap().request_count, 1);
                    prior = if reverse {
                        acknowledge_ordered(
                            &c,
                            both,
                            &mut progress,
                            &mut ledger,
                            &[COPY, ROOT],
                            &[(0, 0), (2, 0)],
                        )
                    } else {
                        acknowledge_ordered(
                            &c,
                            both,
                            &mut progress,
                            &mut ledger,
                            &[ROOT, COPY],
                            &[(2, 0), (2, 0)],
                        )
                    };
                }
                assert_eq!(shared(&ledger), (2, 0));
                let mut followup =
                    c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
                followup.enrich(&c);
                assert!(followup
                    .scan
                    .snapshots
                    .iter()
                    .all(|item| item.source_session_id == COPY));
                let sessions = if body(&followup, COPY).is_some() {
                    vec![COPY]
                } else {
                    vec![]
                };
                prior = acknowledge_ordered(
                    &c,
                    followup,
                    &mut progress,
                    &mut ledger,
                    &sessions,
                    &vec![(2, 0); sessions.len()],
                );
                let mut quiet = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
                quiet.enrich(&c);
                quiet.finish();
                assert!(quiet.scan.snapshots.is_empty());
                assert_eq!(quiet.modes.0, 0);
            });
        }
    }
}

fn refuse_original(items: &[SnapshotItem], progress: &mut SnapshotUploadProgress) {
    let original = items
        .iter()
        .find(|item| item.source_session_id == ROOT)
        .unwrap();
    let (result, _, _) = upload(std::slice::from_ref(original), progress, |batch| {
        let mut response = ack(batch)?;
        response.accepted = 0;
        response.sessions_reconciled = 0;
        response.accepted_entities.clear();
        response.rejected_entities = vec![serde_json::from_value(json!({
            "source_session_id": ROOT, "snapshot_fingerprint": original.snapshot_fingerprint,
            "reason": "accepted_log_stale_older_upload", "detail": "synthetic refusal",
            "permanent": true, "occurrence_count": 1
        }))
        .unwrap()];
        Ok(response)
    });
    assert!(matches!(
        result.unwrap(),
        ResumableUploadResult::Rejected { .. }
    ));
}

/// [money] A provisional promise that fails cannot strand a reduced copy.
/// A refusal of a newer original preserves its earlier accepted coverage.
/// Progress may reach disk before the index; restart must still publish the
/// dependent mark with the refusal. Deleting a holder preserves only accepted
/// coverage. Every copy replacement is checked after its entity ACK.
#[test]
fn local_copy_refusal_deletion_and_progress_first_restart() {
    for accepted_before in [false, true] {
        for deleted in [false, true] {
            with_e2(|| {
                let mut c = corpus("local-copy-refusal-delete");
                let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
                let path = c.write_at(
                    &file(COPY),
                    &resumed(COPY, &[A, B, C]),
                    "2026-08-02T07:03:00Z",
                );
                let scanner = E2ScanFixture::capturing_identity();
                let mut progress = e2_progress();
                let mut ledger = Ledger::new();
                let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
                page.enrich(&c);
                page.finish();
                let (status, _, _) = upload(
                    std::slice::from_ref(body(&page, COPY).unwrap()),
                    &mut progress,
                    |batch| {
                        let response = ack(batch)?;
                        ledger.insert(
                            COPY.into(),
                            (
                                batch[0].request_count,
                                batch[0].removed_request_count.unwrap_or(0),
                            ),
                        );
                        assert_eq!(shared(&ledger), (0, 0));
                        Ok(response)
                    },
                );
                assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
                if accepted_before {
                    let original = body(&page, ROOT).unwrap();
                    upload(std::slice::from_ref(original), &mut progress, |batch| {
                        let response = ack(batch)?;
                        ledger.insert(ROOT.into(), (batch[0].request_count, 0));
                        assert_eq!(shared(&ledger), (2, 0));
                        Ok(response)
                    })
                    .0
                    .unwrap();
                    accept_upload_context_acks_for_test(
                        &mut page.index,
                        &page.scan.snapshots,
                        &progress.fresh_context_body_acks,
                    );
                    // An exact accepted body is suppressed by the uploader.
                    // Refuse a real newer revision while keeping that ACK.
                    append(&holder, &resumed(ROOT, &[D]));
                    let mut grown = c.raw(
                        &scanner,
                        page.index.clone(),
                        100,
                        false,
                        std::slice::from_ref(&holder),
                    );
                    grown.enrich(&c);
                    grown.finish();
                    let newer = body(&grown, ROOT)
                        .expect("the holder's newer body publishes")
                        .clone();
                    assert_ne!(
                        newer.snapshot_fingerprint,
                        body(&page, ROOT).unwrap().snapshot_fingerprint
                    );
                    page.index = grown.index;
                    *page
                        .scan
                        .snapshots
                        .iter_mut()
                        .find(|item| item.source_session_id == ROOT)
                        .unwrap() = newer;
                }
                // A later revision may be refused even after this body earned
                // its durable file receipt. Neither refusal nor deletion erases it.
                refuse_original(&page.scan.snapshots, &mut progress);
                progress
                    .save_fixture(&c.base.join("progress.json"))
                    .unwrap();
                assert_eq!(shared(&ledger), (if accepted_before { 2 } else { 0 }, 0));
                let holds = LocalHoldSettlement::classify(
                    SnapshotSource::ClaudeCode,
                    &mut page.index,
                    &mut page.scan,
                    &page.disposition,
                );
                let mut selected = settle_checkpointed_upload(
                    page.index,
                    &page.committed,
                    &progress,
                    &holds,
                    true,
                    UnsettledUploadCause::DeferredConflict,
                )
                .index;
                settle_index_after_upload(&mut selected, &page.committed, &progress);
                accept_upload_context_acks_for_test(
                    &mut selected,
                    &page.scan.snapshots,
                    &progress.fresh_context_body_acks,
                );
                let prior = c.reload(&mut selected);
                if deleted {
                    std::fs::remove_file(&holder).unwrap();
                }
                let mut correction = c.raw(
                    &E2ScanFixture::capturing_identity(),
                    prior,
                    100,
                    false,
                    &[path],
                );
                correction.enrich(&c);
                correction.finish();
                if accepted_before {
                    assert!(
                        body(&correction, COPY).is_none(),
                        "accepted ownership stays stable"
                    );
                    assert_eq!(shared(&ledger), (2, 0));
                } else {
                    let item =
                        body(&correction, COPY).expect("restoration remains owed after reload");
                    assert_eq!(
                        (item.request_count, item.removed_request_count),
                        (3, Some(0))
                    );
                    let prior = acknowledge_ordered(
                        &c,
                        correction,
                        &mut progress,
                        &mut ledger,
                        &[COPY],
                        &[(0, 2)],
                    );
                    let mut quiet =
                        c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
                    quiet.enrich(&c);
                    quiet.finish();
                    assert!(body(&quiet, COPY).is_none());
                }
            });
        }
    }
}

/// [money] A previously accepted copied prefix is removed with its declared
/// tokens and accepted identity shares. Distinct models/hours, two accounts,
/// a switch, a side call and an evidence gap exercise placement as well as totals.
#[test]
fn copy_first_correction_preserves_native_money_and_placement() {
    with_e2(|| {
        let mut c = corpus("copy-first-placement");
        let late = line_by(COPY, "e", "2026-08-02T08:09:10Z", 10, RESUME_WRITER)
            .replace("claude-haiku-4-5", "claude-sonnet-4-5");
        let path = c.write_at(
            &file(COPY),
            &(resumed(COPY, &[A, B, C, D]) + &late),
            "2026-08-02T07:03:00Z",
        );
        input_clock(&path);
        copy_evidence(&c, true);
        let scanner = E2ScanFixture::capturing_identity();
        let mut progress = e2_progress();
        let mut accepted = BTreeMap::<String, SnapshotItem>::new();
        let mut post = |page: &mut Page, progress: &mut SnapshotUploadProgress, expected: u64| {
            page.finish();
            let (status, _, _) = upload(&page.scan.snapshots, progress, |batch| {
                let response = ack(batch)?;
                for entity in &response.accepted_entities {
                    let item = batch
                        .iter()
                        .find(|s| s.snapshot_fingerprint == entity.snapshot_fingerprint)
                        .unwrap();
                    accepted.insert(item.source_session_id.clone(), (*item).clone());
                    assert_eq!(
                        accepted.values().map(|s| s.request_count).sum::<u64>(),
                        expected
                    );
                }
                Ok(response)
            });
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
        };
        let mut first = c.raw(&scanner, ScanIndex::default(), 1, false, &[]);
        first.enrich(&c);
        post(&mut first, &mut progress, 6);
        let mut prior = settle(&c, &ScanIndex::default(), first, &mut progress);
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        input_clock(&holder);
        let mut source = next_body_page(&c, prior, ROOT, &mut progress);
        post(&mut source, &mut progress, 8);
        let committed = source.committed.clone();
        prior = settle(&c, &committed, source, &mut progress);
        let mut correction = next_body_page(&c, prior.clone(), COPY, &mut progress);
        correction.finish();
        assert_eq!(
            body(&correction, COPY).unwrap().removed_request_count,
            Some(2)
        );
        let mut cold = c.raw(
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            100,
            false,
            &[],
        );
        cold.enrich(&c);
        cold.finish();
        let route = |page: &Page, mode| {
            let item = body(page, COPY).unwrap();
            let (status, wire, _) = upload(std::slice::from_ref(item), &mut e2_progress(), ack);
            assert_eq!(status.unwrap(), ResumableUploadResult::Completed);
            RouteResult::emitted(
                mode,
                SnapshotSource::ClaudeCode,
                wire,
                std::slice::from_ref(item),
            )
        };
        let control = route(&cold, Mode::ColdFull);
        assert!(accounts(&control) >= 2);
        money_oracle::assert_equivalent(&control, &route(&correction, Mode::Restart));
        post(&mut correction, &mut progress, 6);
        let committed = correction.committed.clone();
        prior = settle(&c, &committed, correction, &mut progress);
        let mut quiet = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
        quiet.enrich(&c);
        quiet.finish();
        assert!(quiet.scan.snapshots.is_empty());
        assert_eq!(quiet.modes.0, 0);
    });
}

/// [money] A failed same-page holder's provisional groups cannot outlive its
/// retry custody or local deletion. Its already accepted copy is re-offered
/// with the prefix, even after restart.
#[test]
fn failed_same_page_holder_drops_provisional_groups_before_deletion() {
    with_e2(|| {
        let mut c = corpus("provisional-copy-holder");
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut progress = e2_progress();
        let mut ledger = Ledger::new();
        let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
        page.enrich(&c);
        page.finish();
        let copy = body(&page, COPY).unwrap();
        upload(std::slice::from_ref(copy), &mut progress, |batch| {
            let response = ack(batch)?;
            ledger.insert(
                COPY.into(),
                (copy.request_count, copy.removed_request_count.unwrap_or(0)),
            );
            assert_eq!(shared(&ledger), (0, 0));
            Ok(response)
        })
        .0
        .unwrap();
        let original = body(&page, ROOT).unwrap();
        assert!(upload(std::slice::from_ref(original), &mut progress, |_| {
            Err(anyhow!("synthetic transport outage"))
        })
        .0
        .is_err());
        progress.hold_outage_bodies(&page.scan.snapshots, u64::MAX);
        progress
            .save_fixture(&c.base.join("progress.json"))
            .unwrap();
        let mut selected = page.index.committable_subset_for_upload(
            &page.committed,
            &progress.accepted_fingerprints,
            &progress.quarantined_fingerprints,
            &BTreeSet::new(),
            false,
        );
        accept_upload_context_acks_for_test(
            &mut selected,
            &page.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        let prior = c.reload(&mut selected);
        let copy_key = crate::snapshots::claude_money_birth_store::location_key(
            &c.root.join(file(COPY)).to_string_lossy(),
        );
        assert!(prior.claude_copy_removals.get(copy_key).is_empty());
        assert!(prior.claude_copy_removals.pending(copy_key));
        std::fs::remove_file(holder).unwrap();
        let mut correction = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
        correction.enrich(&c);
        let _ = acknowledge_ordered(
            &c,
            correction,
            &mut progress,
            &mut ledger,
            &[COPY],
            &[(0, 2)],
        );
    });
}

/// [money] A copy consisting entirely of the shared prefix can replace a
/// previously accepted nonzero body with a declared zero body.
#[test]
fn all_copy_body_replaces_previously_accepted_requests_with_zero() {
    with_e2(|| {
        let mut c = corpus("all-copy-local-owner");
        c.write_at(&file(COPY), &resumed(COPY, &[A, B]), "2026-08-02T07:03:00Z");
        let scanner = E2ScanFixture::capturing_identity();
        let mut progress = e2_progress();
        let old = ScanIndex::default();
        let first = ready(&c, &scanner, old.clone(), 1, false);
        assert_eq!(body(&first, COPY).unwrap().request_count, 2);
        let mut prior = settle(&c, &old, first, &mut progress);
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let source = next_body_page(&c, prior, ROOT, &mut progress);
        let committed = source.committed.clone();
        prior = settle(&c, &committed, source, &mut progress);
        let mut correction = next_body_page(&c, prior.clone(), COPY, &mut progress);
        correction.finish();
        let zero = body(&correction, COPY).expect("a zero replacement must reach the server");
        assert_eq!(
            (zero.request_count, zero.removed_request_count),
            (0, Some(2))
        );
        assert_eq!(zero.removed_usage.as_ref().unwrap().input_tokens, 20);
        let committed = correction.committed.clone();
        prior = settle(&c, &committed, correction, &mut progress);
        let quiet = ready(&c, &E2ScanFixture::capturing_identity(), prior, 100, false);
        assert!(body(&quiet, COPY).is_none());
    });
}

/// [money] A refused first holder leaves one fallback owner in an ordered
/// chain, even when corrections are read one file per page and restarted.
#[test]
fn refused_origin_chain_converges_with_one_file_pages() {
    with_e2(|| {
        let mut c = corpus("local-copy-chain");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        c.write_at(
            &file(THIRD),
            &resumed(THIRD, &[A, B, C, D]),
            "2026-08-02T07:06:00Z",
        );
        let mut progress = e2_progress();
        let mut ledger = Ledger::new();
        let mut page = c.raw(
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            100,
            false,
            &[],
        );
        page.enrich(&c);
        page.finish();
        for session in [THIRD, COPY] {
            let item = body(&page, session).unwrap();
            upload(std::slice::from_ref(item), &mut progress, |batch| {
                let response = ack(batch)?;
                ledger.insert(
                    session.into(),
                    (item.request_count, item.removed_request_count.unwrap_or(0)),
                );
                assert_eq!(shared(&ledger), (0, 0));
                assert_eq!(item.request_count, 1);
                Ok(response)
            })
            .0
            .unwrap();
        }
        refuse_original(&page.scan.snapshots, &mut progress);
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut page.index,
            &mut page.scan,
            &page.disposition,
        );
        let mut selected = settle_checkpointed_upload(
            page.index,
            &page.committed,
            &progress,
            &holds,
            true,
            UnsettledUploadCause::DeferredConflict,
        )
        .index;
        settle_index_after_upload(&mut selected, &page.committed, &progress);
        accept_upload_context_acks_for_test(
            &mut selected,
            &page.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        let mut prior = c.reload(&mut selected);
        for _ in 0..3 {
            let mut correction = c.raw(
                &E2ScanFixture::capturing_identity(),
                prior.clone(),
                1,
                false,
                &[],
            );
            correction.enrich(&c);
            correction.finish();
            upload(&correction.scan.snapshots, &mut progress, |batch| {
                let response = ack(batch)?;
                for entity in &response.accepted_entities {
                    let item = batch
                        .iter()
                        .find(|s| s.snapshot_fingerprint == entity.snapshot_fingerprint)
                        .unwrap();
                    assert_ne!(item.source_session_id, ROOT);
                    ledger.insert(
                        item.source_session_id.clone(),
                        (item.request_count, item.removed_request_count.unwrap_or(0)),
                    );
                    assert_eq!(ledger[THIRD].0, 1);
                    assert!(ledger.values().map(|(n, _)| *n).sum::<u64>() <= 4);
                }
                Ok(response)
            })
            .0
            .unwrap();
            prior = settle(&c, &prior, correction, &mut progress);
        }
        assert_eq!(ledger[COPY].0, 3);
        assert_eq!(ledger[THIRD].0, 1);
        assert_eq!(ledger.values().map(|(n, _)| *n).sum::<u64>(), 4);
    });
}

/// [money] A real progress/index crash discards the refused page, its pending
/// dependencies and the upload object. Recovery must republish B's correction
/// mark from the old disk index and the durable refusal, then restore B once.
#[test]
fn refused_holder_mark_survives_progress_only_crash() {
    with_e2(|| {
        let mut c = corpus("copy-progress-only-crash");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        let index_path = c.base.join("scan-index.json");
        ScanIndex::default().save_fixture(&index_path).unwrap();
        let mut ledger = Ledger::new();
        let progress_path = c.base.join("progress.json");
        {
            let scanner = E2ScanFixture::capturing_identity();
            let mut page = c.raw(
                &scanner,
                ScanIndex::load(&index_path).unwrap(),
                100,
                false,
                &[],
            );
            page.enrich(&c);
            page.finish();
            let mut progress = e2_progress();
            let copy = body(&page, COPY).unwrap();
            upload(std::slice::from_ref(copy), &mut progress, |batch| {
                let response = ack(batch)?;
                ledger.insert(
                    COPY.into(),
                    (
                        batch[0].request_count,
                        batch[0].removed_request_count.unwrap_or(0),
                    ),
                );
                assert_eq!(shared(&ledger), (0, 0));
                Ok(response)
            })
            .0
            .unwrap();
            refuse_original(&page.scan.snapshots, &mut progress);
            progress.save_fixture(&progress_path).unwrap();
            // Crash here: page, committed baseline, scanner and progress drop.
            // No index save or settlement occurs after the progress publication.
        }
        let template = e2_progress();
        let mut progress = SnapshotUploadProgress::load(
            &progress_path,
            &template.destination_namespace_hash,
            template.active_quarantine_witness.unwrap(),
        )
        .unwrap();
        let prior = ScanIndex::load(&index_path).unwrap();
        assert!(prior.files.is_empty());
        assert!(prior.quarantined_snapshot_fingerprints.is_empty());
        assert!(!progress.permanent_rejections.is_empty());
        let scanner = E2ScanFixture::capturing_identity();
        let mut recovered = c.raw(&scanner, prior, 100, false, &[]);
        recovered.enrich(&c);
        recovered.finish();
        let (result, _, _) = upload(&recovered.scan.snapshots, &mut progress, |_| {
            panic!("the exact ACK and refusal already reached durable progress")
        });
        assert!(matches!(
            result.unwrap(),
            ResumableUploadResult::Rejected { .. }
        ));
        let holds = LocalHoldSettlement::classify(
            SnapshotSource::ClaudeCode,
            &mut recovered.index,
            &mut recovered.scan,
            &recovered.disposition,
        );
        let mut selected = settle_checkpointed_upload(
            recovered.index,
            &recovered.committed,
            &progress,
            &holds,
            true,
            UnsettledUploadCause::DeferredConflict,
        )
        .index;
        settle_index_after_upload(&mut selected, &recovered.committed, &progress);
        accept_upload_context_acks_for_test(
            &mut selected,
            &recovered.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        let prior = c.reload(&mut selected);
        let copy_key = crate::snapshots::claude_money_birth_store::location_key(
            &c.root.join(file(COPY)).to_string_lossy(),
        );
        assert!(
            prior.claude_copy_removals.pending(copy_key),
            "refusal and mark publish together after restart"
        );
        assert!(prior.claude_copy_removals.get(copy_key).is_empty());
        let correction = next_body_page(&c, prior, COPY, &mut progress);
        let copy = body(&correction, COPY).unwrap();
        assert_eq!(
            (copy.request_count, copy.input_tokens, copy.output_tokens),
            (3, 30, 30)
        );
        let prior = acknowledge_ordered(
            &c,
            correction,
            &mut progress,
            &mut ledger,
            &[COPY],
            &[(0, 2)],
        );
        let mut quiet = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
        quiet.enrich(&c);
        quiet.finish();
        assert!(body(&quiet, COPY).is_none());
        assert_eq!(shared(&ledger), (0, 2));
    });
}

/// [money] The named-parent rule still removes an all-copy branch after the
/// parent's accepted census retires. Both bodies reach the real uploader and
/// settlement, and a disk restart keeps the accepted ledger quiet.
#[test]
fn named_parent_with_retired_census_through_pipeline() {
    with_e2(|| {
        let mut c = corpus("copy-retired-parent-pipeline");
        let parent = c.root(ROOT, &resumed(ROOT, &[A, B]));
        let mut progress = e2_progress();
        let mut ledger = Ledger::new();
        let mut source = c.raw(
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            1,
            false,
            &[],
        );
        source.enrich(&c);
        let mut prior =
            acknowledge_ordered(&c, source, &mut progress, &mut ledger, &[ROOT], &[(2, 0)]);
        e2::pipeline_test_observer::retire_census(&mut prior, &file(ROOT));
        prior = c.reload(&mut prior);
        c.write_at(
            &file(COPY),
            &(fork_ref(COPY, ROOT) + &resumed(COPY, &[A, B])),
            "2026-08-02T07:03:00Z",
        );
        let branch = next_body_page(&c, prior, COPY, &mut progress);
        let copy = body(&branch, COPY).expect("the named parent proves the zero replacement");
        assert_eq!(
            (copy.request_count, copy.removed_request_count),
            (0, Some(2))
        );
        assert_eq!(copy.removed_usage.as_ref().unwrap().input_tokens, 20);
        let prior = acknowledge_ordered(&c, branch, &mut progress, &mut ledger, &[COPY], &[(2, 0)]);
        std::fs::remove_file(parent).unwrap();
        // Change the removed usage, so finalization publishes a new zero
        // body rather than suppressing a semantic no-op newline edit.
        std::fs::write(
            c.root.join(file(COPY)),
            fork_ref(COPY, ROOT) + &line_by(COPY, A.0, A.1, 20, A.2) + &resumed(COPY, &[B]),
        )
        .unwrap();
        let mut reread = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
        reread.enrich(&c);
        assert_eq!(
            body(&reread, COPY).unwrap().request_count,
            0,
            "the accepted parent's coverage survives local deletion"
        );
        let prior = acknowledge_ordered(&c, reread, &mut progress, &mut ledger, &[COPY], &[(2, 0)]);
        let mut quiet = c.raw(&E2ScanFixture::capturing_identity(), prior, 100, false, &[]);
        quiet.enrich(&c);
        quiet.finish();
        assert!(quiet.scan.snapshots.is_empty());
        assert_eq!(shared(&ledger), (2, 0));
    });
}

/// [money] A real native account hold consumes one marked read. Ten unchanged
/// passes through scan, enrichment, finalization, upload and settlement cannot
/// turn that mark into a busy reread loop or alter the accepted copy's money.
#[test]
fn held_copy_mark_reads_once_over_ten_pipeline_passes() {
    with_e2(|| {
        let mut c = corpus("held-copy-mark-pipeline");
        c.root(ROOT, &resumed(ROOT, &[A, B]));
        let path = c.write_at(
            &file(COPY),
            &resumed(COPY, &[A, B, C]),
            "2026-08-02T07:03:00Z",
        );
        let scanner = E2ScanFixture::capturing_identity();
        let mut progress = e2_progress();
        let mut ledger = Ledger::new();
        let mut first = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
        first.enrich(&c);
        let mut prior = acknowledge_ordered(
            &c,
            first,
            &mut progress,
            &mut ledger,
            &[ROOT, COPY],
            &[(2, 0), (2, 0)],
        );
        let (held, holds) = native_account_held_page(&c, &scanner, prior, COPY);
        assert!(
            held.scan.snapshots.is_empty(),
            "the setup has no uploadable body"
        );
        let mut selected =
            settle_completed_upload(held.index, &held.committed, &progress, &holds).index;
        settle_index_after_upload(&mut selected, &held.committed, &progress);
        prior = crate::snapshots::e2_pipeline_scan_fixture::save_reload_for_test(
            &mut selected,
            &c.base.join("scan-index.json"),
        );
        let key = path.to_string_lossy().into_owned();
        // Only debt is injected; every read/hold/clear decision below is real.
        let location = crate::snapshots::claude_money_birth_store::location_key(&key);
        prior.claude_copy_removals.mark(location);
        let mut reads = 0;
        for pass in 0..10 {
            let mut page = c.raw(&scanner, prior.clone(), 100, true, &[]);
            reads += usize::from(scanner.paths().contains(&path));
            page.enrich(&c);
            let holds = page.finish();
            upload(&page.scan.snapshots, &mut progress, |_| {
                panic!("held B must never POST")
            })
            .0
            .unwrap();
            assert_eq!(shared(&ledger), (2, 0), "after pass {pass}");
            let mut selected =
                settle_completed_upload(page.index, &page.committed, &progress, &holds).index;
            settle_index_after_upload(&mut selected, &page.committed, &progress);
            prior = crate::snapshots::e2_pipeline_scan_fixture::save_reload_for_test(
                &mut selected,
                &c.base.join("scan-index.json"),
            );
            assert!(!prior.claude_copy_removals.pending(location));
        }
        assert_eq!(
            reads, 1,
            "one marked read, then unchanged held passes skip B"
        );
        assert_eq!(shared(&ledger), (2, 0));
    });
}
