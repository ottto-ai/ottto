// Accepted identity hints for more sessions than one page holds, through the
// native scan, identity tagging, upload/ACK and progress restart adapters.
// The revisited session is ACKed first; later sessions are ACKed one page at
// a time with a progress restart between pages, so every leg below reads the
// same seeded ACK history.
use super::claude_login_only_org_tests::{parts_conserve, placements, Placement};
use super::state_v2_money_tests::routed;
use super::*;
use crate::snapshots::claude_request_identity::{AcceptedBuckets, TELEMETRY};
use crate::snapshots::e2_pipeline_scan_fixture::route_of;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle::{assert_equivalent, assert_no_smaller_reemit, assert_quiet_restart_zero_bytes},
    observe_consumed, Mode, RouteResult,
};

/// (login, org) characters of the synthetic authorities. S starts the
/// session, A is the authority its first ACK froze, B re-tags A's request
/// later, C is a mid-session switch.
const S: (char, char) = ('e', 'f');
const A: (char, char) = ('a', 'b');
const B: (char, char) = ('9', '8');
const C: (char, char) = ('c', 'd');
const PAGE: usize = 100;

#[derive(Clone, Copy, Debug)]
enum Growth {
    /// The revisit only re-tags, plus a new hour under C.
    NextHour,
    /// The re-tagged frozen row also grows in its own hour under B.
    SameHour,
    /// No re-tag: a new hour under C only.
    Unchanged,
}

fn own((login, org): (char, char)) -> Placement {
    (
        TELEMETRY.to_owned(),
        Some(login.to_string().repeat(64)),
        Some(org.to_string().repeat(64)),
        None,
    )
}

fn untagged() -> Placement {
    (String::new(), None, None, None)
}

fn sibling(n: usize) -> String {
    format!("9{n:07x}-f36e-4cbc-a5bb-50fc66430ba5")
}

fn at(time: &str) -> String {
    format!("2026-08-02T{time}Z")
}

/// `who`'s complete telemetry for `request`, observed at its line's `time`.
fn told(
    session: &str,
    request: &str,
    tokens: u64,
    (login, org): (char, char),
    time: &str,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = api_login(session, request, tokens, login, Some(org));
    row.observed_at = at(time);
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}

fn publish(c: &Corpus, session: &str, rows: &[crate::claude_local_otel::ClaudeLocalOtelEvidence]) {
    let traces = rows
        .iter()
        .map(|row| trace_for(session, &row.request_id, ""))
        .collect::<Vec<_>>();
    c.evidence_for(session, rows, &traces);
}

/// The process restart of the identity-hint owner: its progress is saved,
/// loaded and re-keyed as the next cycle does.
fn restarted(c: &Corpus, mut progress: SnapshotUploadProgress) -> SnapshotUploadProgress {
    let path = c.base.join("claude-upload-progress.json");
    progress.save(&path).unwrap();
    let mut loaded = SnapshotUploadProgress::load(
        &path,
        &format!("{:064x}", 99),
        snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
    )
    .unwrap();
    loaded
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    loaded
}

/// `page` with only `session`'s bodies.
fn only(page: &Page, session: &str) -> Page {
    let mut kept = twin(page);
    kept.scan
        .snapshots
        .retain(|item| item.source_session_id == session);
    assert!(!kept.scan.snapshots.is_empty(), "{session} publishes");
    kept
}

/// One finished page of `scanner` over `index`, tagged under `ledger`.
fn leg(c: &Corpus, scanner: &E2ScanFixture, index: ScanIndex, mut ledger: AcceptedBuckets) -> Page {
    let mut page = c.raw(scanner, index, PAGE * 8, true, &[]);
    page.enrich_with(c, Some(&mut ledger));
    page.finish();
    page
}

fn owner(prior: &ScanIndex) -> E2ScanFixture {
    let scanner = E2ScanFixture::capturing_identity();
    scanner.on_committed_route(&route_of(prior).unwrap());
    scanner
}

struct Seeded {
    c: Corpus,
    path: PathBuf,
    scanner: E2ScanFixture,
    prior: ScanIndex,
    progress: SnapshotUploadProgress,
    rows: Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>,
    /// The last sibling, tagged A and never changed, as it was ACKed.
    control: Option<RouteResult>,
}

/// ROOT: r0 under S, r1 under A, gap r2, then a switch to C at r3 and a side
/// call under C, all in one hour. ROOT is ACKed first; then `siblings`
/// sessions are ACKed a page at a time, restarting progress after each page.
fn seed(name: &str, siblings: usize) -> Seeded {
    let mut c = Corpus::new(name);
    let path = c.root(
        ROOT,
        &(line(ROOT, "r0", &at("07:00:10"), 10)
            + &line(ROOT, "r1", &at("07:00:20"), 11)
            + &line(ROOT, "r2", &at("07:00:30"), 12)
            + &line(ROOT, "r3", &at("07:00:40"), 13)),
    );
    let rows = vec![
        told(ROOT, "r0", 10, S, "07:00:10"),
        told(ROOT, "r1", 11, A, "07:00:20"),
        told(ROOT, "r3", 13, C, "07:00:40"),
        told(ROOT, "side", 4, C, "07:00:45"),
    ];
    publish(&c, ROOT, &rows);
    let scanner = E2ScanFixture::capturing_identity();
    let mut progress = e2_progress();
    progress
        .accepted_identity_buckets
        .bind_test_key(Some([0x42; 32]));
    let mut first = c.raw(&scanner, ScanIndex::default(), PAGE, true, &[]);
    first.enrich_with(&c, Some(&mut progress.accepted_identity_buckets));
    let acked = placements(body(&first, ROOT).expect("ROOT publishes"));
    for who in [S, A, C] {
        assert!(acked.contains_key(&own(who)), "{who:?} tagged: {acked:?}");
    }
    let mut prior = settle(&c, &ScanIndex::default(), first, &mut progress);
    progress = restarted(&c, progress);
    let mut control = None;
    for n in 0..siblings {
        let id = sibling(n);
        c.root(&id, &line(&id, &format!("s{n}"), &at("07:30:00"), 5));
        if n + 1 == siblings {
            publish(&c, &id, &[told(&id, &format!("s{n}"), 5, A, "07:30:00")]);
        }
    }
    // The scanner's own page bound splits the siblings; every page is ACKed
    // and progress restarts before the next one.
    let mut acked = BTreeSet::new();
    while acked.len() < siblings {
        let mut page = c.raw(&scanner, prior.clone(), PAGE, true, &[]);
        page.enrich_with(&c, Some(&mut progress.accepted_identity_buckets));
        let ids = page
            .scan
            .snapshots
            .iter()
            .map(|item| &item.source_session_id);
        let before = acked.len();
        acked.extend(ids.filter(|id| id.as_str() != ROOT).cloned());
        assert!(acked.len() > before, "each page ACKs new siblings");
        let last = sibling(siblings - 1);
        if body(&page, &last).is_some() {
            let mut sent = only(&page, &last);
            sent.finish();
            control = Some(routed(&sent, sent.upload_policy));
        }
        prior = settle(&c, &prior, page, &mut progress);
        progress = restarted(&c, progress);
    }
    Seeded {
        c,
        path,
        scanner,
        prior,
        progress,
        rows,
        control,
    }
}

/// Each emitted bucket row's totals, in order.
fn row_totals(item: &SnapshotItem) -> Vec<serde_json::Value> {
    let item = serde_json::to_value(item).unwrap();
    item["usage_buckets"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|bucket| {
            bucket["model_usage"]
                .as_array()
                .into_iter()
                .flatten()
                .map(move |row| {
                    json!([
                        bucket["bucket_start"],
                        row["model"],
                        row["input_tokens"],
                        row["output_tokens"],
                        row["cache_read_tokens"],
                        row["request_count"],
                        row["cost_usd"]
                    ])
                })
        })
        .collect()
}

fn session_totals(item: &SnapshotItem) -> serde_json::Value {
    let item = serde_json::to_value(item).unwrap();
    json!([
        item["input_tokens"],
        item["output_tokens"],
        item["cache_read_tokens"],
        item["cache_creation_5m_tokens"],
        item["cache_creation_1h_tokens"],
        item["request_count"],
        item["cost"]
    ])
}

/// Pins the current fallback for a refused share: the body sends the refused
/// amount untagged with a refusal count, and the receiver places it at the
/// session's starting binding, which here is S, not the frozen authority A.
/// The expected body is the unprotected one with every share of the new
/// authority B moved to the untagged share; S and C keep theirs. A ruling on
/// that fallback changes only its disclosure, never this path.
fn assert_refused_share_takes_start_binding_fallback(
    item: &SnapshotItem,
    unprotected: &SnapshotItem,
) {
    assert!(
        item.request_identity_refusals > 0,
        "a re-tag of an accepted share is refused"
    );
    let mut expected = BTreeMap::<Placement, u64>::new();
    for (key, requests) in placements(unprotected) {
        let key = if key == own(B) { untagged() } else { key };
        *expected.entry(key).or_default() += requests;
    }
    let placed = placements(item);
    assert_eq!(
        placed, expected,
        "only the new authority's share moves, untagged"
    );
    assert!(
        placed.contains_key(&own(S)),
        "the starting binding keeps its share"
    );
    assert!(
        !placed.contains_key(&own(A)),
        "the frozen authority is not restored"
    );
}

/// Equal row and session totals; placement as pinned above, or unchanged.
fn assert_revisit(item: &SnapshotItem, unprotected: &SnapshotItem, growth: Growth) {
    assert!(parts_conserve(item));
    assert_eq!(row_totals(item), row_totals(unprotected), "row totals");
    assert_eq!(
        session_totals(item),
        session_totals(unprotected),
        "session totals"
    );
    match growth {
        Growth::Unchanged => {
            assert_eq!(item.request_identity_refusals, 0, "no refusal");
            assert_eq!(placements(item), placements(unprotected));
        }
        _ => assert_refused_share_takes_start_binding_fallback(item, unprotected),
    }
}

/// Revisit ROOT after its seeding: re-tag r1 A→B (unless unchanged) and grow.
fn revisit(f: &mut Seeded, growth: Growth) {
    let mut rows = f.rows.clone();
    if !matches!(growth, Growth::Unchanged) {
        rows[1] = told(ROOT, "r1", 11, B, "07:00:20");
    }
    let (request, time, who) = match growth {
        Growth::SameHour => ("r5", "07:00:50", B),
        _ => ("r4", "08:00:10", C),
    };
    append(&f.path, &line(ROOT, request, &at(time), 14));
    rows.push(told(ROOT, request, 14, who, time));
    publish(&f.c, ROOT, &rows);
}

/// [money] Revisit the earliest of `siblings + 1` ACKed sessions after a
/// restart. Full, Tail, restore and the seeded restart-between-pages history
/// agree, and a quiet restart reads no transcript byte.
fn revisit_case(name: &str, siblings: usize, growth: Growth) {
    with_e2(|| {
        let mut f = seed(name, siblings);
        revisit(&mut f, growth);
        let ledger = f.progress.accepted_identity_buckets.clone();
        let unprotected = only(
            &leg(
                &f.c,
                &owner(&f.prior),
                f.prior.clone(),
                AcceptedBuckets::for_test(),
            ),
            ROOT,
        );
        let restored = only(
            &leg(&f.c, &owner(&f.prior), f.prior.clone(), ledger.clone()),
            ROOT,
        );
        let expected = body(&unprotected, ROOT).unwrap();
        assert_revisit(body(&restored, ROOT).unwrap(), expected, growth);
        if siblings > PAGE {
            return;
        }
        // Both owners read the same committed heads without committing; only
        // the retained owner's page is settled below.
        let tail_page = leg(&f.c, &f.scanner, f.prior.clone(), ledger.clone());
        let tail = only(&tail_page, ROOT);
        let cold_page = leg(
            &f.c,
            &E2ScanFixture::capturing_identity(),
            ScanIndex::default(),
            ledger,
        );
        let cold = only(&cold_page, ROOT);
        let cold_route = routed(&cold, cold.upload_policy);
        for page in [&tail, &restored] {
            let route = routed(page, page.upload_policy);
            assert_equivalent(&cold_route, &route);
            assert_no_smaller_reemit(ROOT, &cold_route, &route, &cold_route, false);
        }
        if let Some(control) = &f.control {
            let id = sibling(siblings - 1);
            let now = only(&cold_page, &id);
            assert_equivalent(control, &routed(&now, now.upload_policy));
        }
        let settled = settle(&f.c, &f.prior, tail_page, &mut f.progress);
        let quiet_owner = owner(&settled);
        let ((quiet, bytes), samples) = crate::transcript_acquisition::capture_sample_reads(|| {
            observe_consumed(|| ready(&f.c, &quiet_owner, settled, PAGE, true))
        });
        assert!(
            quiet_owner.paths().is_empty(),
            "quiet restart selects no transcript"
        );
        let mut quiet_route = routed(&quiet, quiet.upload_policy);
        quiet_route.mode = Mode::Restart;
        quiet_route.modes = quiet.modes;
        quiet_route.io.consumed = bytes;
        quiet_route.io.cheap_checks = Some(0);
        quiet_route.io.other_reads = Some(0);
        quiet_route.io.anchor_reads = Some(
            samples
                .iter()
                .map(|read| u64::try_from(read.result.expect("sample read succeeds")).unwrap())
                .sum(),
        );
        assert_quiet_restart_zero_bytes(&quiet_route);
        assert!(quiet.scan.snapshots.is_empty(), "no replacement body");
    });
}

/// [money] More sessions than the former ledger held: the earliest session's
/// login re-tag A→B is refused after a restart, with equal totals.
#[test]
fn identity_cap_revisit_earliest_of_17_refuses_retag() {
    revisit_case("identity-cap-retag-17", 16, Growth::NextHour);
}
/// [money] The same row over 736 sessions, restored leg only.
#[test]
fn identity_cap_revisit_earliest_of_736_refuses_retag() {
    revisit_case("identity-cap-retag-736", 735, Growth::NextHour);
}

/// [money] The re-tagged frozen row also grows in its own hour under the new
/// login: the whole unfrozen share is untagged, totals equal.
#[test]
fn identity_cap_revisit_same_hour_growth_is_untagged() {
    revisit_case("identity-cap-same-hour", 16, Growth::SameHour);
}

/// [money] Positive control: two accounts, a switch, a side call and a gap
/// keep every tag with no refusal when no authority changes, and the tagged
/// sibling's body stays identical to the one it ACKed.
#[test]
fn identity_cap_unchanged_authority_control() {
    revisit_case("identity-cap-control", 16, Growth::Unchanged);
}

/// [money] Placement pin on one session: the starting binding S differs from
/// the frozen authority A, and the refused share takes today's fallback.
#[test]
fn identity_cap_refused_share_start_binding_pin() {
    revisit_case("identity-cap-start-binding", 0, Growth::NextHour);
}
