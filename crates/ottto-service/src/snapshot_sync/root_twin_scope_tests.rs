use super::*;

/// [money] A main with a stale second copy, two child pairs and an untwinned
/// child: an append to the main's live copy alone, then a move of the main's
/// usage logs alone. The retained, cold and restarted owners emit the same
/// envelopes; the append re-sends no child.
#[cfg(unix)]
#[test]
fn root_twin_scoped_family() {
    let name = "root_twin_scoped_family";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let mut c = corpus(name);
        let old = "2026-08-01T07:00:00Z";
        let copy = "2026-08-02T07:03:00Z";
        let root = line(ROOT, "r1", "2026-08-02T00:00:00Z", 10);
        let resumed = root.clone() + &line(ROOT, "r2", "2026-08-02T07:04:00Z", 30);
        let live = c.write_at(&format!("new/{ROOT}.jsonl"), &resumed, copy);
        let mut paths = vec![
            c.write_at(&format!("old/{ROOT}.jsonl"), &root, old),
            live.clone(),
        ];
        for n in 0..2 {
            let text =
                root.clone() + &line(ROOT, &format!("child-{n}"), "2026-08-02T07:01:00Z", 20);
            for (home, birth) in [("old", old), ("new", copy)] {
                let relative = format!("{home}/{ROOT}/subagents/agent-{n:03}.jsonl");
                paths.push(c.write_at(&relative, &text, birth));
            }
        }
        let untwinned = line(ROOT, "child-2", "2026-08-02T07:01:00Z", 20);
        paths.push(c.write_at(
            &format!("old/{ROOT}/subagents/agent-002.jsonl"),
            &untwinned,
            old,
        ));
        for path in &paths {
            input_clock(path);
        }
        let mut rows = family_rows();
        rows.push(api("r2", 30, 300));
        c.evidence(&rows, &[]);
        let disk = Disk::new(&c);
        let mut owner = E2ScanFixture::capturing_identity();
        disk.begin(&owner, SnapshotSource::ClaudeCode);
        let mut warm = finish_resumed(&c, resumed_page(&c, &owner, ScanIndex::default()));
        assert_eq!(
            posted_sessions(&warm).len(),
            4,
            "the main and three children"
        );
        accept_page(&mut warm);
        let mut prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
        let mut bodies = Vec::new();
        for usage_logs_only in [false, true] {
            if usage_logs_only {
                // A late priced side call the main owns.
                rows.push(api("late-side", 5, 50));
                c.evidence(&rows, &[trace("late-side", "")]);
            } else {
                append(&live, &line(ROOT, "r3", "2026-08-02T07:05:00Z", 7));
                input_clock(&live);
            }
            let restart = E2ScanFixture::capturing_identity();
            disk.begin(&restart, SnapshotSource::ClaudeCode);
            let mut pages = [
                resumed_page(&c, &owner, prior.clone()),
                resumed_page(&c, &E2ScanFixture::capturing_identity(), prior.clone()),
                resumed_page(&c, &restart, prior),
            ];
            finish_claude_pages(&c, &mut pages);
            for page in &pages {
                let posted = posted_sessions(page);
                assert!(posted.contains(ROOT), "{usage_logs_only}: the main");
                assert!(
                    usage_logs_only || posted.len() == 1,
                    "the append re-sends no child"
                );
            }
            bodies.push(compare_claude_uploads(&pages));
            let [_, _, mut restarted] = pages;
            accept_page(&mut restarted);
            prior = disk.commit(
                &restarted.cache,
                SnapshotSource::ClaudeCode,
                &mut restarted.index,
            );
            owner = restart;
        }
        save_inputs(&c);
        receipt(name, &bodies);
    });
}
