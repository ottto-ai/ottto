// Durable holder-forced twins: acquisition cost and page/money parity.
// Lives beside Disk so save/reload and after_source_save stay real.
use super::*;
use crate::snapshots::claude_request_census::ClaudeRequestCensusShape;
use crate::snapshots::e2_pipeline_scan_fixture::{
    continuation_for_test, damage_tail_for_test, forced_needs_native_for_test, pace_cap_for_test,
};
use crate::snapshots::sampled_scan::transition_fixture::upgrade_from_legacy_store;
use crate::snapshots::sampled_scan::transition_fixture::{money_oracle, observe_consumed, Mode};
use crate::transcript_acquisition::{capture_sample_reads, FullReason, ReadMode};

use crate::snapshots::e2_pipeline_scan_fixture::twin_diagnostics as diag;

// Keep all existing decisions and comparisons; attach the same compact trace
// to assertion failures. The guard also dumps it for unwrap/oracle panics.
macro_rules! assert {
    ($condition:expr $(,)?) => {
        std::assert!($condition, "{}", diag::context())
    };
    ($condition:expr, $($message:tt)+) => {
        std::assert!($condition, "{}\n{}", format_args!($($message)+), diag::context())
    };
}
macro_rules! assert_eq {
    ($left:expr, $right:expr $(,)?) => {
        std::assert_eq!($left, $right, "{}", diag::context())
    };
    ($left:expr, $right:expr, $($message:tt)+) => {
        std::assert_eq!($left, $right, "{}\n{}", format_args!($($message)+), diag::context())
    };
}

const FIRST: &str = "0338a80a-f36e-4cbc-a5bb-50fc66430ba5";
const BORN: &str = "2026-08-02T07:03:00Z";

struct Twin {
    _diagnostics: diag::DumpOnPanic,
    c: Corpus,
    disk: Disk,
    owner: E2ScanFixture,
    prior: ScanIndex,
    holder: PathBuf,
    twin: PathBuf,
    key: String,
}
impl Twin {
    #[track_caller]
    fn new(name: &str, incomplete: bool) -> Self {
        let diagnostics = diag::begin(name);
        let mut c = corpus(name);
        let holder = c.root(ROOT, &resumed(ROOT, &[A, B]));
        diag::register(&holder, "holder");
        input_clock(&holder);
        c.evidence(
            &[
                api_login(ROOT, "a", 10, '1', Some('7')),
                api_login(ROOT, "b", 10, '2', Some('8')),
                api_login(ROOT, "side", 5, '2', Some('8')),
            ],
            &[
                trace_for(ROOT, "a", ""),
                trace_for(ROOT, "b", ""),
                trace_for(ROOT, "side", ""),
            ],
        );
        let disk = Disk::new(&c);
        let owner = E2ScanFixture::capturing_identity();
        disk.begin(&owner, SnapshotSource::ClaudeCode);
        let mut first = c.raw(&owner, ScanIndex::default(), 100, true, &[]);
        first.enrich(&c);
        first.finish();
        accept_page(&mut first);
        let prior = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
        let mut contents = resumed(ROOT, &[A, B]);
        contents += &resumed(ROOT, &[C]);
        if incomplete {
            let mut gap: Value = serde_json::from_str(line(ROOT, "gap", AT, 12).trim()).unwrap();
            gap.as_object_mut().unwrap().remove("requestId");
            gap["message"].as_object_mut().unwrap().remove("id");
            contents += &(gap.to_string() + "\n");
        }
        let twin = c.write_at(&file(FIRST), &contents, BORN);
        diag::register(&twin, "twin");
        input_clock(&twin);
        let mut both = c.raw(&owner, prior, 100, true, &[]);
        both.enrich(&c);
        both.finish();
        accept_page(&mut both);
        let key = twin.to_string_lossy().into_owned();
        let record = both
            .index
            .claude_request_census_for_test()
            .get(&key)
            .unwrap();
        assert!(record.is_twin() && !record.can_bind_recomposed_body());
        assert!(!record.unverified_for_test());
        assert_eq!(
            record.shape_for_test(),
            if incomplete {
                ClaudeRequestCensusShape::IdentityIncomplete
            } else {
                ClaudeRequestCensusShape::Exact
            }
        );
        assert!(!forced_needs_native_for_test(&both.index, &twin));
        // Keep the holder native so the page byte budget attributes every
        // other consumed byte to the twin, including the unchanged row.
        damage_tail_for_test(&both.index, &holder.to_string_lossy(), "missing");
        let prior = disk.commit(&both.cache, SnapshotSource::ClaudeCode, &mut both.index);
        Self {
            _diagnostics: diagnostics,
            c,
            disk,
            owner,
            prior,
            holder,
            twin,
            key,
        }
    }
    fn restart(&self) -> E2ScanFixture {
        let owner = E2ScanFixture::capturing_identity();
        self.disk.begin(&owner, SnapshotSource::ClaudeCode);
        owner
    }
    fn pages(&self, restart: &E2ScanFixture, tail: Page) -> [Page; 3] {
        [
            tail,
            self.page_as(&E2ScanFixture::capturing_identity(), "cold"),
            self.page_as(restart, "restart"),
        ]
    }
    fn force(&self, request: &str) {
        append(&self.holder, &line(ROOT, request, AT, 10));
        input_clock(&self.holder);
    }
    #[track_caller]
    fn page(&self, owner: &E2ScanFixture) -> Page {
        self.page_as(owner, "RAM")
    }
    #[track_caller]
    fn page_as(&self, owner: &E2ScanFixture, label: &'static str) -> Page {
        diag::owner(label);
        self.c.raw(
            owner,
            self.prior.clone(),
            1,
            true,
            std::slice::from_ref(&self.holder),
        )
    }
    #[track_caller]
    fn assert_read(&self, owner: &E2ScanFixture, label: &'static str, mode: ReadMode, start: u64) {
        diag::owner(label);
        let reads = owner.acquisitions.lock().unwrap();
        let read = reads
            .iter()
            .rev()
            .find(|read| read.path == self.twin)
            .unwrap_or_else(|| panic!("twin is on holder's page\n{}", diag::context()));
        assert_eq!(
            read.reason,
            Some(crate::snapshots::CandidateParseReason::ForcedFamily)
        );
        assert_eq!((read.mode, read.start), (mode, start));
    }
    #[track_caller]
    fn compare(&self, pages: &mut [Page; 3]) {
        for (page, label) in pages.iter_mut().zip(["RAM", "cold", "restart"]) {
            diag::owner(label);
            page.enrich(&self.c);
            page.finish();
        }
        compare_claude_uploads(pages);
        let routes = [Mode::Ram, Mode::ColdFull, Mode::DiskRestore];
        let routes =
            std::array::from_fn::<_, 3, _>(|i| mixed_route(&pages[i], &e2_progress(), routes[i]));
        for i in [0, 2] {
            money_oracle::assert_no_smaller_reemit(ROOT, &routes[1], &routes[i], &routes[1], false);
            assert_eq!(
                pages[i].index.claude_copy_removals,
                pages[1].index.claude_copy_removals
            );
        }
        assert!(super::copy_prefix_route_tests::accounts(&routes[1]) >= 2);
        let b = pages[1]
            .index
            .claude_request_census_for_test()
            .get(&self.key)
            .unwrap();
        for page in [&pages[0], &pages[2]] {
            let a = page
                .index
                .claude_request_census_for_test()
                .get(&self.key)
                .unwrap();
            assert_eq!(a.request_hashes_for_test(), b.request_hashes_for_test());
            assert_eq!(a.shape_for_test(), b.shape_for_test());
            assert_eq!(a.is_twin(), b.is_twin());
        }
        let item = &routes[1].snapshots[ROOT];
        assert!(
            item["request_evidence"].as_array().unwrap().len() >= 2,
            "account switch plus side call"
        );
        assert_mixed_placement_corruption_detected(&routes[1], &routes[2]);
    }
    fn commit(&mut self, mut page: Page) {
        accept_page(&mut page);
        damage_tail_for_test(&page.index, &self.holder.to_string_lossy(), "missing");
        self.prior = self
            .disk
            .commit(&page.cache, SnapshotSource::ClaudeCode, &mut page.index);
    }
}

/// [money] Unchanged first, then append and a second force, across retained
/// owners and save/reloaded owners. Exact growth deliberately alternates back
/// to native on the next force; IdentityIncomplete preserves continuation.
#[test]
fn forced_verified_twin_reuses_certified_tail_and_restarts() {
    if !supported("forced_verified_twin") {
        return;
    }
    with_e2(|| {
        for incomplete in [false, true] {
            let mut f = Twin::new(&format!("forced-verified-twin-{incomplete}"), incomplete);
            for round in 0..3 {
                diag::round(round);
                diag::owner("RAM");
                let sealed = continuation_for_test(
                    SnapshotSource::ClaudeCode,
                    &f.owner.cache,
                    &f.prior,
                    &f.key,
                )
                .unwrap()
                .sealed_offset();
                assert_eq!(sealed, std::fs::metadata(&f.twin).unwrap().len());
                let suffix = if round == 1 {
                    line(ROOT, "own-later", AT, 9)
                } else {
                    String::new()
                };
                append(&f.twin, &suffix);
                if !suffix.is_empty() {
                    input_clock(&f.twin);
                }
                f.force(&format!("holder-{round}"));
                let restart = f.restart();
                let ((tail, consumed), samples) =
                    capture_sample_reads(|| observe_consumed(|| f.page(&f.owner)));
                let native = round == 2 && !incomplete;
                let mode = if native {
                    ReadMode::Full(FullReason::StateMissing)
                } else if round == 1 {
                    ReadMode::Tail
                } else {
                    ReadMode::Unchanged
                };
                let start = if native { 0 } else { sealed };
                f.assert_read(&f.owner, "RAM", mode, start);
                let twin_bytes = if native { sealed } else { suffix.len() as u64 };
                assert_eq!(
                    consumed,
                    std::fs::metadata(&f.holder).unwrap().len() + twin_bytes,
                    "exact page budget: unchanged twin consumes zero parser bytes"
                );
                let sample_bytes: usize = samples
                    .iter()
                    .map(|r| r.result.as_ref().copied().unwrap())
                    .sum();
                let restored_samples =
                    2 * sealed.min(crate::transcript_acquisition::SAMPLE_BYTES as u64);
                if round == 0 {
                    assert_eq!(
                        sample_bytes as u64, restored_samples,
                        "unchanged certificate probes"
                    );
                } else if !native {
                    assert!(sample_bytes as u64 >= restored_samples);
                }
                assert!(samples
                    .iter()
                    .all(|read| read.requested <= crate::transcript_acquisition::SAMPLE_BYTES));
                let mut pages = f.pages(&restart, tail);
                f.assert_read(&restart, "restart", mode, start);
                f.compare(&mut pages);
                if round == 0 {
                    let legacy =
                        upgrade_from_legacy_store(&f.prior, &f.c.base.join("upgrade.json"));
                    diag::owner("restart");
                    let mut upgraded = f.c.raw(
                        &E2ScanFixture::capturing_identity(),
                        legacy,
                        1,
                        true,
                        std::slice::from_ref(&f.holder),
                    );
                    upgraded.enrich(&f.c);
                    upgraded.finish();
                    money_oracle::assert_equivalent(
                        &mixed_route(&pages[1], &e2_progress(), Mode::ColdFull),
                        &mixed_route(&upgraded, &e2_progress(), Mode::Restart),
                    );
                }
                let record = pages[2]
                    .index
                    .claude_request_census_for_test()
                    .get(&f.key)
                    .unwrap();
                assert!(record.is_twin() && !record.can_bind_recomposed_body());
                assert_eq!(record.unverified_for_test(), round == 1 && !incomplete);
                assert!(!record.current_for(&pages[2].index.files[&f.key].source_file_fingerprint));
                assert_eq!(
                    forced_needs_native_for_test(&pages[2].index, &f.twin),
                    round == 1 && !incomplete
                );
                let [_, _, page] = pages;
                f.commit(page);
            }
            diag::round("quiet");
            diag::owner("restart");
            let restart = f.restart();
            let ((mut quiet, consumed), samples) = capture_sample_reads(|| {
                observe_consumed(|| f.c.raw(&restart, f.prior.clone(), 100, true, &[]))
            });
            quiet.enrich(&f.c);
            quiet.finish();
            let mut result = mixed_route(&quiet, &e2_progress(), Mode::Restart);
            assert!(
                restart.paths().is_empty(),
                "quiet restart selects no transcript"
            );
            result.io.consumed = consumed;
            result.io.cheap_checks = Some(0);
            result.io.other_reads = Some(0);
            result.io.anchor_reads = Some(samples.iter().map(|r| r.result.unwrap() as u64).sum());
            money_oracle::assert_quiet_restart_zero_bytes(&result);
        }
    });
}

/// [money] Each newly reachable delay falls back to native on the same page:
/// (a) cap pacing, (b) an unfunded completion, (c) a future-head hold.
#[test]
fn forced_verified_twin_stays_on_its_page_without_tail_capacity() {
    if !supported("forced_twin_page") {
        return;
    }
    with_e2(|| {
        for arm in ["cap", "completion", "future"] {
            let mut f = Twin::new(&format!("forced-twin-{arm}"), true);
            diag::round(0);
            append(&f.twin, &line(ROOT, "own-later", AT, 9));
            input_clock(&f.twin);
            if arm == "future" {
                damage_tail_for_test(&f.prior, &f.key, "future");
                f.prior = f
                    .disk
                    .commit(&f.owner.cache, SnapshotSource::ClaudeCode, &mut f.prior);
            }
            if arm == "completion" {
                // Held-new custody has a census and committed head but no
                // entry: it bypasses the cap gate and would pend at completion.
                assert!(f.prior.files.remove(&f.key).is_some());
            }
            f.force("holder-later");
            let mut restart = f.restart();
            if arm != "future" {
                f.owner.set_audit_slots(0);
                restart.set_audit_slots(0);
            }
            if arm == "cap" {
                pace_cap_for_test(&f.owner, &f.twin);
                pace_cap_for_test(&restart, &f.twin);
            }
            let mut pages = f.pages(&restart, f.page(&f.owner));
            f.assert_read(&f.owner, "RAM", ReadMode::Full(FullReason::StateMissing), 0);
            f.assert_read(
                &restart,
                "restart",
                ReadMode::Full(FullReason::StateMissing),
                0,
            );
            f.compare(&mut pages);
            assert!(!pages[2].index.files[&f.key]
                .scan_identity_version
                .as_deref()
                .unwrap()
                .contains("sampled_unverified"));
        }
    });
}

/// [money] A corrupt committed head reconstructs natively on its holder's page.
/// Loader damage and prefix-certificate refusal tables cover the other fallback
/// variants; this row checks the twin's full page, ACK and placement parity.
#[test]
fn forced_verified_twin_falls_back_without_valid_head() {
    if !supported("forced_twin_fallback") {
        return;
    }
    with_e2(|| {
        let mut f = Twin::new("forced-twin-fallback-corrupt", false);
        diag::round(0);
        damage_tail_for_test(&f.prior, &f.key, "corrupt");
        f.prior = f
            .disk
            .commit(&f.owner.cache, SnapshotSource::ClaudeCode, &mut f.prior);
        f.force("holder-later");
        let restart = f.restart();
        let mut pages = f.pages(&restart, f.page(&f.owner));
        f.assert_read(&f.owner, "RAM", ReadMode::Full(FullReason::StateMissing), 0);
        f.assert_read(
            &restart,
            "restart",
            ReadMode::Full(FullReason::StateMissing),
            0,
        );
        f.compare(&mut pages);
    });
}
