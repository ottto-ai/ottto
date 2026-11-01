// Settled-history segments ON through the real scan, sidecar read, account
// reconcile (the carry), contract-5 tagging, the shared cut, finalization,
// batching and ACK. Synthetic files only; the clock is the capability's.
use super::money_equivalence_tests::{claude_pages, compare_claude_uploads, corpus, input_clock, Disk};
use super::state_v2_money_tests::tagged_api;
use super::*;
use crate::snapshots::claude_request_identity::AcceptedBuckets;
use crate::snapshots::history_segments::with_trigger_for_test;

const WEEK: i64 = 7 * 86_400;
/// Four windows (three settled) keep the transcript inside one retained
/// entry; the cut trigger is lowered on this thread so the session crosses it.
const WEEKS: i64 = 4;
const TRIGGER: usize = 32 * 1024;
/// Hours at the start of each window whose telemetry carries no checked
/// login: the scan's reconcile carries the earlier request's account in.
const CARRIED_HOURS: i64 = 2;

fn rfc(at: i64) -> String {
    OffsetDateTime::from_unix_timestamp(at)
        .unwrap()
        .format(&Rfc3339)
        .unwrap()
}

/// The login every request of a 7-day window ran on.
fn account(at: i64) -> String {
    format!("{:064x}", at.div_euclid(WEEK).rem_euclid(3) + 1)
}

/// The login a request's rows must carry: its own, or for a carried hour the
/// previous window's last.
fn expected_account(at: i64) -> String {
    if at.rem_euclid(WEEK) < CARRIED_HOURS * 3_600 {
        account(at - CARRIED_HOURS * 3_600)
    } else {
        account(at)
    }
}

/// Hourly requests from 12 hours into an aligned window: (request, at, tokens).
fn requests(hours: i64) -> Vec<(String, i64, u64)> {
    let start = 1_780_000_000_i64.div_euclid(WEEK) * WEEK + 12 * 3_600;
    (0..hours)
        .map(|hour| {
            (
                format!("req-{hour:05}"),
                start + hour * 3_600 + 600,
                10 + hour.rem_euclid(7) as u64,
            )
        })
        .collect()
}

/// One telemetry row per request at its own time; carried hours keep an
/// unchecked (pre-identity) row, so the account comes from the scan.
fn telemetry(c: &Corpus, requests: &[(String, i64, u64)]) {
    let rows = requests
        .iter()
        .enumerate()
        .map(|(sequence, (request, at, tokens))| {
            let login = account(*at);
            let mut row = if at.rem_euclid(WEEK) < CARRIED_HOURS * 3_600 {
                api(request, *tokens, tokens * 10)
            } else {
                tagged_api(request, *tokens, Some(login.as_str()))
            };
            row.observed_at = rfc(*at);
            row.event_sequence = Some(sequence as u64 + 1);
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            row
        })
        .collect::<Vec<_>>();
    let traces = requests
        .iter()
        .map(|(request, _, _)| trace(request, ""))
        .collect::<Vec<_>>();
    c.evidence(&rows, &traces);
}

/// Per bucket start, the logins its rows carry (parts included).
fn bucket_logins(items: &[SnapshotItem]) -> BTreeMap<String, BTreeSet<Option<String>>> {
    let mut found = BTreeMap::<String, BTreeSet<Option<String>>>::new();
    for item in items {
        for bucket in &item.usage_buckets {
            let logins = found.entry(bucket.bucket_start.clone()).or_default();
            for row in &bucket.model_usage {
                match &row.identity_parts {
                    Some(parts) => logins.extend(
                        parts
                            .iter()
                            .map(|part| part.account_identifier_hash.clone()),
                    ),
                    None => {
                        logins.insert(row.account_identifier_hash.clone());
                    }
                }
            }
        }
    }
    found
}

fn hour_start(at: i64) -> i64 {
    at.div_euclid(3_600) * 3_600
}

fn totals(items: &[SnapshotItem]) -> [u64; 5] {
    items.iter().fold([0; 5], |mut sum, item| {
        for (total, value) in sum.iter_mut().zip([
            item.input_tokens,
            item.output_tokens,
            item.cache_read_tokens,
            item.cache_creation_5m_tokens,
            item.request_count,
        ]) {
            *total += value;
        }
        sum
    })
}

/// [money] Segmentation ON, binding oracle: a long multi-account session is
/// cut into settled windows; cold Full, the retained RAM Tail and a restarted
/// owner's restored Tail emit byte-identical envelopes (totals AND
/// placement), the pieces conserve the OFF whole's totals, every bucket row
/// keeps the account the scan placed (window boundaries carried by the
/// scan's own reconcile, never injected), and a crash before the group's ACK
/// resends the same group after restart.
#[test]
fn segmented_session_cold_full_ram_and_restored_tail_agree() {
    let name = "segmented_session_oracle";
    if !crate::heap_layout_bound::layout_supported() {
        println!("MONEY_EQUIVALENCE {name} UNEXECUTED: native retained layout unavailable");
        return;
    }
    with_e2(|| with_trigger_for_test(TRIGGER, || {
        let mut requests = requests(WEEKS * 168 - 12);
        let mut c = corpus(name);
        let text = requests
            .iter()
            .map(|(request, at, tokens)| line(ROOT, request, &rfc(*at), *tokens))
            .collect::<String>();
        let path = c.write_at(&format!("{ROOT}.jsonl"), &text, &rfc(requests[0].1 - 60));
        input_clock(&path);
        telemetry(&c, &requests);
        let grown_at = requests.last().unwrap().1 + 3_600;
        let now = grown_at + 3_600;
        let segments = AcceptedBuckets::segments_for_test();
        let disk = Disk::new(&c);
        let scanner = E2ScanFixture::default();
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
        warm.enrich_with_segments(&c, None, Some((&segments, now)));
        warm.finish();
        let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
        assert!(disk.records() > 0, "the warm owner persists its records");

        append(&path, &line(ROOT, "req-grown", &rfc(grown_at), 20));
        input_clock(&path);
        requests.push(("req-grown".into(), grown_at, 20));
        telemetry(&c, &requests);
        let restart = disk.owner(SnapshotSource::ClaudeCode);
        let mut off = c.raw(&E2ScanFixture::default(), prior.clone(), 100, true, &[]);
        off.enrich(&c);
        off.finish();
        let mut pages = claude_pages(
            &c,
            &scanner,
            &restart,
            [prior.clone(), prior.clone(), prior],
            (0, 1, 0),
            (0, 1, 0),
        );
        for page in &mut pages {
            page.enrich_with_segments(&c, None, Some((&segments, now)));
            page.finish();
        }
        compare_claude_uploads(&pages);

        let full = &pages[1].scan.snapshots;
        let cut = full
            .iter()
            .filter(|item| item.history_segment.is_some())
            .collect::<Vec<_>>();
        let live = full
            .iter()
            .find(|item| item.source_session_id == ROOT)
            .unwrap();
        let through = live
            .history_segments
            .as_ref()
            .expect("the long session is cut");
        assert_eq!(through.count, cut.len() as u64);
        assert_eq!(cut.len() as i64, WEEKS - 1, "every settled window is its own segment");
        assert!(cut
            .iter()
            .all(|segment| segment.history_segment.as_ref().unwrap().of == ROOT));
        // The OFF whole and the ON pieces carry the same money.
        assert_eq!(off.scan.snapshots.len(), 1);
        assert!(off.scan.snapshots[0].history_segments.is_none());
        assert_eq!(totals(full), totals(&off.scan.snapshots));
        // Placement: every bucket row keeps the scan's account; the first
        // hours of each later window carry the previous window's login.
        let logins = bucket_logins(full);
        assert_eq!(logins.len(), requests.len());
        let mut carried = 0;
        for (_, at, _) in &requests {
            let start = rfc(hour_start(*at));
            assert_eq!(
                logins.get(&start),
                Some(&BTreeSet::from([Some(expected_account(*at))])),
                "bucket {start}"
            );
            carried += usize::from(at.rem_euclid(WEEK) < CARRIED_HOURS * 3_600);
        }
        assert!(carried >= 2 * cut.len(), "boundary hours exist in every later window");

        // Restart mid-group: the receiver may have stored parts, but the
        // daemon lost the group's ACK. The saved progress resends the whole
        // group with the same bytes as cold Full.
        let (_, cold_wire, _) = upload(full, &mut e2_progress(), ack);
        let mut progress = e2_progress();
        let (crashed, _, _) = upload(
            full,
            &mut progress,
            |_| -> Result<crate::snapshot_client::SnapshotBatchResponse> {
                anyhow::bail!("synthetic crash before the group's ACK")
            },
        );
        assert!(crashed.is_err());
        let mut progress: SnapshotUploadProgress =
            serde_json::from_slice(&serde_json::to_vec(&progress).unwrap()).unwrap();
        let (resumed, wire, _) = upload(full, &mut progress, ack);
        assert_eq!(resumed.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(wire, cold_wire);
    }));
}
