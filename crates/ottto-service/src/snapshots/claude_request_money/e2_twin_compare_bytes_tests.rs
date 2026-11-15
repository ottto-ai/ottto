//! Bytes the redundant-twin comparison reads: counted on the diagnostics
//! scope the finish decision opens, never changing the twin decision.
use super::*;
use crate::local_resource_diagnostics::claude_reread::Scope;

/// [behaviour] An off-page twin compared against its on-page copy counts both
/// readers' bytes; a co-paged twin is never compared and counts none. The
/// published result is the same with or without a diagnostics scope.
#[test]
fn twin_comparison_bytes_reach_the_finish_scope_and_leave_the_decision_alone() {
    let earlier = root_file("twin-bytes-earlier");
    let copy = root_file("twin-bytes-copy");
    let unlisted = |value: Value| versioned(value, "2.1.222");
    let history = vec![unlisted(line("a", &at(1), 10))];
    let mut resumed = history.clone();
    resumed.push(unlisted(line("b", &at(101), 20)));
    for (path, lines) in [(&earlier, &history), (&copy, &resumed)] {
        let text = lines.iter().map(|line| line.to_string() + "\n");
        fs::write(path, text.collect::<String>()).unwrap();
    }
    let mut index = ScanIndex::default();
    index.files.insert(local_index_key(&earlier), entry());
    index.files.insert(local_index_key(&copy), entry());
    let birth = t0() + 100_000_000_000;
    stage_twins(&mut index, &[(&earlier, t0()), (&copy, birth)]);
    let both = fs::metadata(&earlier).unwrap().len() + fs::metadata(&copy).unwrap().len();
    // (earlier path on the page, compared bytes, sent as redundant)
    for (co_paged, bytes, redundant) in [(false, both, 1), (true, 0, 0)] {
        let page = || {
            let mut page = vec![parse(&copy, Some(birth), &index, &resumed)];
            if co_paged {
                page.insert(0, parse(&earlier, Some(t0()), &index, &history));
            }
            take_diag();
            let got = publish(page, None, TelemetryRead::Loaded, &index);
            let diag = take_diag();
            let count = |key: &str| diag.get(key).copied().unwrap_or(0);
            let got = got
                .iter()
                .map(|item| (item.request_count, item.snapshot_fingerprint.clone()))
                .collect::<Vec<_>>();
            (got, count("twin_redundant"), count("held_absent_twin"))
        };
        let unscoped = page();
        // The scope `finish_sync_source` opens around the Claude finish decision.
        let scope = Scope::finish_decision(true);
        let scoped = page();
        let counts = scope.finish();
        assert_eq!(scoped, unscoped, "co-paged {co_paged}: decision unchanged");
        assert_eq!((scoped.1, scoped.2), (redundant, 0), "co-paged {co_paged}");
        assert_eq!(counts.twin_compare_bytes, bytes, "co-paged {co_paged}");
    }
    cleanup(&[&earlier, &copy]);
}
