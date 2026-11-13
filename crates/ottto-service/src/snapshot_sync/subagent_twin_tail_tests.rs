use super::*;
use crate::snapshots::e2_pipeline_scan_fixture::origin_accepted_for_test;

/// The API row of one transcript request, observed at the request's time.
fn observed(
    request: &str,
    at: &str,
    tokens: u64,
) -> crate::claude_local_otel::ClaudeLocalOtelEvidence {
    let mut row = api(request, tokens, tokens * 10);
    row.observed_at = at.into();
    row.fingerprint.clear();
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).unwrap())
    );
    row
}

/// (requests, removed requests) over the session's posted bodies.
fn counts(page: &Page, session: &str) -> (u64, u64) {
    page.scan
        .snapshots
        .iter()
        .filter(|item| item.source_session_id == session)
        .fold((0, 0), |(requests, removed), item| {
            (
                requests + item.request_count,
                removed + item.removed_request_count.unwrap_or(0),
            )
        })
}

/// [money] Two subagents, each stored in two homes. The later home is born
/// 114 ms after the last shared response, so that response is inside the
/// 2 s copy slack. agent-000 dates from 2026-08 and its later home keeps an
/// accepted copy body (its re-read is accepted history); agent-001 dates
/// from 2026-11. First sight, then an own turn in each later home. The
/// retained, cold and restarted owners emit the same envelopes. Each shared
/// request counts once, at the earlier home; the later home removes all three.
#[cfg(unix)]
#[test]
fn subagent_twin_slack_tail() {
    let name = "subagent_twin_slack_tail";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let mut c = corpus(name);
        let old = "2026-08-01T07:00:00Z";
        let root = line(ROOT, "r1", "2026-08-02T00:00:00Z", 10);
        let resumed = root.clone() + &line(ROOT, "r2", "2026-08-02T07:04:00Z", 30);
        let mut paths = vec![
            c.write_at(&format!("old/{ROOT}.jsonl"), &root, old),
            c.write_at(
                &format!("new/{ROOT}.jsonl"),
                &resumed,
                "2026-08-02T07:03:00Z",
            ),
        ];
        let mut rows = vec![api("r1", 10, 100), api("r2", 30, 300)];
        let days = ["2026-08-02", "2026-11-06"];
        let mut later = Vec::new();
        for (n, day) in days.iter().enumerate() {
            let mut text = String::new();
            for (k, clock, tokens) in [
                (1, "07:01:00Z", 20),
                (2, "07:02:00Z", 21),
                (3, "07:02:59.886Z", 22),
            ] {
                let (request, at) = (format!("tail-{n}-{k}"), format!("{day}T{clock}"));
                text += &line(ROOT, &request, &at, tokens);
                rows.push(observed(&request, &at, tokens));
            }
            let born = format!("{day}T07:03:00Z");
            for (home, birth) in [("old", old), ("new", born.as_str())] {
                let relative = format!("{home}/{ROOT}/subagents/agent-{n:03}.jsonl");
                paths.push(c.write_at(&relative, &text, birth));
            }
            later.push(paths.last().unwrap().clone());
        }
        for path in &paths {
            input_clock(path);
        }
        c.evidence(&rows, &[]);
        let agents = [0, 1].map(|n| format!("{ROOT}_agent-{n:03}"));
        // The homes' historical births, observed before any parse, so
        // discovery order cannot use today's file-system birth.
        let mut seeded = ScanIndex::default();
        for path in &paths[2..] {
            let member = &agents[usize::from(path.ends_with("agent-001.jsonl"))];
            seeded.claude_money_birth_store.record_observation(
                member,
                &path.to_string_lossy(),
                c.births[path],
            );
        }
        let disk = Disk::new(&c);
        let owner = E2ScanFixture::with_subagent_births();
        disk.begin(&owner, SnapshotSource::ClaudeCode);
        // Committed, so every arm starts from the same stored observations.
        let seeded = disk.commit(&owner.cache, SnapshotSource::ClaudeCode, &mut seeded);
        let mut bodies = Vec::new();
        // First sight: every arm reads both homes of both subagents.
        let mut pages = [
            resumed_page(&c, &owner, seeded.clone()),
            resumed_page(&c, &E2ScanFixture::with_subagent_births(), seeded.clone()),
            resumed_page(&c, &E2ScanFixture::with_subagent_births(), seeded),
        ];
        finish_claude_pages(&c, &mut pages);
        for page in &pages {
            for agent in &agents {
                assert_eq!(counts(page, agent), (3, 3), "{agent}: 3 shared, once");
            }
        }
        bodies.push(compare_claude_uploads(&pages));
        let [mut warm, _, _] = pages;
        accept_page(&mut warm);
        // agent-000's later home holds an accepted copy body, as one settled
        // by an earlier release: COPY mark, accepted body, no stored removal.
        let key = later[0].to_string_lossy().into_owned();
        warm.index
            .claude_money_birth_store
            .set_money_marks(&key, e2::money_mark::COPY);
        origin_accepted_for_test(&mut warm.index, &key);
        let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
        for (n, (path, day)) in later.iter().zip(days).enumerate() {
            let (request, at) = (format!("own-{n}"), format!("{day}T07:05:00Z"));
            append(path, &line(ROOT, &request, &at, 23));
            input_clock(path);
            rows.push(observed(&request, &at, 23));
        }
        c.evidence(&rows, &[]);
        let restart = E2ScanFixture::with_subagent_births();
        disk.begin(&restart, SnapshotSource::ClaudeCode);
        let mut pages = [
            resumed_page(&c, &owner, prior.clone()),
            resumed_page(&c, &E2ScanFixture::with_subagent_births(), prior.clone()),
            resumed_page(&c, &restart, prior),
        ];
        finish_claude_pages(&c, &mut pages);
        for page in &pages {
            for agent in &agents {
                assert_eq!(counts(page, agent), (4, 3), "{agent}: own turn, tail once");
            }
        }
        bodies.push(compare_claude_uploads(&pages));
        save_inputs(&c);
        receipt(name, &bodies);
    });
}
