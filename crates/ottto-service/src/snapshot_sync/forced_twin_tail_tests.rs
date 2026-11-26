// Durable holder-forced twins: acquisition cost and page/money parity.
// Lives beside Disk so save/reload and after_source_save stay real.
use super::*;
use crate::snapshots::claude_request_census::ClaudeRequestCensusShape;
use crate::snapshots::e2_pipeline_scan_fixture::{
    continuation_for_test, damage_tail_for_test, forced_needs_native_for_test, pace_cap_for_test,
};
use crate::snapshots::sampled_scan::transition_fixture::upgrade_from_legacy_store;
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle, observe_consumed, with_scan_clock, Mode, RouteResult,
};
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
    now: std::cell::Cell<u64>,
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
        let mut prior = disk.commit(&both.cache, SnapshotSource::ClaudeCode, &mut both.index);
        let mut now = crate::scan_clock::utc_seconds();
        let revision = effective_upload_body_witness_revision(SnapshotSource::ClaudeCode);
        // Discovery can hold a twin-only page until its holder joins. Pay
        // that adoption debt through real pages before measuring forced reads.
        for attempt in 0..8 {
            // A previous native growth claim may need its six-hour interval.
            now += 7 * 60 * 60;
            let (next, complete, progress_blocking) = with_scan_clock(now, || {
                let mut page = c.raw(&owner, prior, 100, true, std::slice::from_ref(&holder));
                page.enrich(&c);
                let holds = page.finish();
                let complete = mixed_route(&page, &e2_progress(), Mode::Ram)
                    .snapshots
                    .contains_key(ROOT);
                accept_page(&mut page);
                (
                    disk.commit(&page.cache, SnapshotSource::ClaudeCode, &mut page.index),
                    complete,
                    holds.progress_blocking,
                )
            });
            prior = next;
            // Reload drops the runtime destination; check the durable proof
            // against the context that received the setup page's exact ACKs.
            prior.activate_upload_context("e2-synthetic-destination".into());
            let settled = [&holder, &twin].iter().all(|path| {
                prior.files[path.to_string_lossy().as_ref()].effective_upload_body_witness_revision
                    == revision
                    && !upload_context_owed_for_test(&prior, path)
            });
            if complete && settled {
                assert!(!progress_blocking, "setup leaves no held session");
                let paths = owner.paths();
                assert!(paths.contains(&holder) && paths.contains(&twin));
                break;
            }
            assert!(attempt < 7, "twin setup did not settle within eight pages");
        }
        for path in [&holder, &twin] {
            assert_eq!(
                prior.files[path.to_string_lossy().as_ref()].effective_upload_body_witness_revision,
                revision,
                "setup adopts the active body revision"
            );
            // A folded twin may have a local suppression proof, not an ACK
            // receipt for the holder's body. Either must settle its context.
            assert!(!upload_context_owed_for_test(&prior, path));
        }
        let record = prior.claude_request_census_for_test().get(&key).unwrap();
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
        assert!(!forced_needs_native_for_test(&prior, &twin));
        owner.acquisitions.lock().unwrap().clear();
        // Retire the holder's head to exercise native reconstruction too.
        // A route save can publish a staged head, so budget its actual range.
        damage_tail_for_test(&prior, &holder.to_string_lossy(), "missing");
        Self {
            _diagnostics: diagnostics,
            c,
            disk,
            owner,
            prior,
            holder,
            twin,
            key,
            now: std::cell::Cell::new(now),
        }
    }
    fn restart(&self) -> E2ScanFixture {
        let owner = E2ScanFixture::capturing_identity();
        self.disk.begin(&owner, SnapshotSource::ClaudeCode);
        owner
    }
    fn pages(&self, cold: &E2ScanFixture, restart: &E2ScanFixture, tail: Page) -> [Page; 3] {
        [
            tail,
            self.page_as(cold, "cold"),
            self.page_as(restart, "restart"),
        ]
    }
    fn force(&self, request: &str) {
        // Each new append is a later visit, beyond any preceding growth
        // Full claim, including a claim taken while settling the restart.
        self.now.set(self.now.get() + 7 * 60 * 60);
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
        // Leave room for the reserved census slot beside the holder hint.
        // With one slot an unchanged census twin displaces the hinted holder;
        // with two the holder runs first and forces the queued twin.
        with_scan_clock(self.now.get(), || {
            self.c.raw(
                owner,
                self.prior.clone(),
                2,
                true,
                std::slice::from_ref(&self.holder),
            )
        })
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
    fn settle(
        &self,
        owner: &E2ScanFixture,
        label: &'static str,
        mut page: Page,
        cold: Option<&RouteResult>,
    ) -> Page {
        let mode = match label {
            "RAM" => Mode::Ram,
            "cold" => Mode::ColdFull,
            "restart" => Mode::DiskRestore,
            _ => unreachable!(),
        };
        for attempt in 0..8 {
            diag::owner(label);
            // Recomposition keeps the first file's physical witness. A retry
            // can discover the twin first; give every synthetic arm the same
            // carrier before comparing their exact envelopes. Acquisition
            // order and all money/placement comparisons remain observable.
            let holder_witness =
                &page.index.files[self.holder.to_string_lossy().as_ref()].source_file_fingerprint;
            page.scan
                .snapshots
                .sort_by_key(|item| item.source_file_fingerprint.as_ref() != Some(holder_witness));
            with_scan_clock(self.now.get(), || {
                page.enrich(&self.c);
                page.finish();
            });
            let route = mixed_route(&page, &e2_progress(), mode);
            let holder_acquired = {
                let reads = owner.acquisitions.lock().unwrap();
                let holder = reads.iter().any(|read| read.path == self.holder);
                if holder {
                    assert!(
                        reads.iter().any(|read| read.path == self.twin),
                        "twin is on holder's page"
                    );
                }
                holder
            };
            if route.snapshots.contains_key(ROOT) {
                // Every replacement, including intermediate pages, must be
                // the whole session with the cold account placement.
                if let Some(cold) = cold {
                    money_oracle::assert_no_smaller_reemit(ROOT, cold, &route, cold, false);
                }
                assert!(holder_acquired, "a body waits until its holder is acquired");
                return page;
            }
            assert!(attempt < 7, "{label} did not settle within eight pages");
            let prior = with_scan_clock(self.now.get(), || {
                if label == "cold" {
                    self.c.reload(&mut page.index)
                } else {
                    self.disk
                        .commit(&page.cache, SnapshotSource::ClaudeCode, &mut page.index)
                }
            });
            // A growth Full claim is paced for six hours, not for a number
            // of pages. Visit after that interval using the existing clock
            // seam, as the native continuation fixtures do.
            self.now.set(self.now.get() + 7 * 60 * 60);
            page = with_scan_clock(self.now.get(), || {
                diag::owner(label);
                self.c
                    .raw(owner, prior, 2, true, std::slice::from_ref(&self.holder))
            });
        }
        unreachable!()
    }
    #[track_caller]
    fn compare(
        &self,
        cold: &E2ScanFixture,
        restart: &E2ScanFixture,
        pages: [Page; 3],
    ) -> [Page; 3] {
        let [ram_page, cold_page, restart_page] = pages;
        let cold_page = self.settle(cold, "cold", cold_page, None);
        let reference = mixed_route(&cold_page, &e2_progress(), Mode::ColdFull);
        let pages = [
            self.settle(&self.owner, "RAM", ram_page, Some(&reference)),
            cold_page,
            self.settle(restart, "restart", restart_page, Some(&reference)),
        ];
        compare_claude_uploads(&pages);
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
        pages
    }
    fn commit(&mut self, mut page: Page) {
        accept_page(&mut page);
        damage_tail_for_test(&page.index, &self.holder.to_string_lossy(), "missing");
        self.prior = with_scan_clock(self.now.get(), || {
            self.disk
                .commit(&page.cache, SnapshotSource::ClaudeCode, &mut page.index)
        });
    }
}

/// [money] Unchanged first, then append and a second force, across retained
/// owners and save/reloaded owners. Exact growth requires native verification
/// on the next force; IdentityIncomplete preserves continuation. A paced
/// restart may pay that verification while settling the current force.
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
                let native = forced_needs_native_for_test(&f.prior, &f.twin);
                let mode = if native {
                    ReadMode::Full(FullReason::StateMissing)
                } else if round == 1 {
                    ReadMode::Tail
                } else {
                    ReadMode::Unchanged
                };
                let start = if native { 0 } else { sealed };
                f.assert_read(&f.owner, "RAM", mode, start);
                let (holder_mode, holder_start) = f
                    .owner
                    .acquisitions
                    .lock()
                    .unwrap()
                    .iter()
                    .rev()
                    .find(|read| read.path == f.holder)
                    .map(|read| (read.mode, read.start))
                    .unwrap();
                let twin_bytes = match mode {
                    ReadMode::Full(_) => std::fs::metadata(&f.twin).unwrap().len(),
                    ReadMode::Tail => suffix.len() as u64,
                    ReadMode::Unchanged => 0,
                };
                assert_eq!(
                    consumed,
                    std::fs::metadata(&f.holder).unwrap().len() - holder_start + twin_bytes,
                    "exact page budget: unchanged twin consumes zero parser bytes"
                );
                let sample_bytes: usize = samples
                    .iter()
                    .map(|r| r.result.as_ref().copied().unwrap())
                    .sum();
                let restored_samples = 2
                    * (sealed.min(crate::transcript_acquisition::SAMPLE_BYTES as u64)
                        + holder_start.min(crate::transcript_acquisition::SAMPLE_BYTES as u64));
                if round == 0 {
                    // Restoring both heads probes their certificates. The grown
                    // holder's Tail acquisition then checks its two windows again;
                    // the Unchanged twin needs no additional acquisition samples.
                    let holder_guards = if holder_mode == ReadMode::Tail {
                        2 * holder_start.min(crate::transcript_acquisition::SAMPLE_BYTES as u64)
                    } else {
                        0
                    };
                    assert_eq!(
                        sample_bytes as u64,
                        restored_samples + holder_guards,
                        "unchanged certificate probes"
                    );
                } else if !native {
                    assert!(sample_bytes as u64 >= restored_samples);
                }
                assert!(samples
                    .iter()
                    .all(|read| read.requested <= crate::transcript_acquisition::SAMPLE_BYTES));
                let cold = E2ScanFixture::capturing_identity();
                let pages = f.pages(&cold, &restart, tail);
                f.assert_read(&restart, "restart", mode, start);
                let pages = f.compare(&cold, &restart, pages);
                if round == 0 {
                    let legacy =
                        upgrade_from_legacy_store(&f.prior, &f.c.base.join("upgrade.json"));
                    diag::owner("restart");
                    let mut upgraded = with_scan_clock(f.now.get(), || {
                        f.c.raw(
                            &E2ScanFixture::capturing_identity(),
                            legacy,
                            2,
                            true,
                            std::slice::from_ref(&f.holder),
                        )
                    });
                    upgraded.enrich(&f.c);
                    upgraded.finish();
                    money_oracle::assert_equivalent(
                        &mixed_route(&pages[1], &e2_progress(), Mode::ColdFull),
                        &mixed_route(&upgraded, &e2_progress(), Mode::Restart),
                    );
                }
                // The RAM page records the initial forced continuation.
                // Restart settlement can force the Exact twin again and
                // verify it natively before this round is committed.
                let record = pages[0]
                    .index
                    .claude_request_census_for_test()
                    .get(&f.key)
                    .unwrap();
                assert!(record.is_twin() && !record.can_bind_recomposed_body());
                assert_eq!(record.unverified_for_test(), round == 1 && !incomplete);
                assert!(!record.current_for(&pages[0].index.files[&f.key].source_file_fingerprint));
                assert_eq!(
                    forced_needs_native_for_test(&pages[0].index, &f.twin),
                    round == 1 && !incomplete
                );
                let [_, _, page] = pages;
                f.commit(page);
            }
            diag::round("quiet");
            diag::owner("restart");
            let restart = f.restart();
            let ((mut quiet, consumed), samples) = capture_sample_reads(|| {
                observe_consumed(|| {
                    with_scan_clock(f.now.get(), || {
                        f.c.raw(&restart, f.prior.clone(), 100, true, &[])
                    })
                })
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

/// [money] [regress] The twin's later record (no usage) is the body's last
/// clock while the holder carries the session: identical on the Tail-read
/// RAM arm, the cold Full arm and the disk restart, with no end set.
#[test]
fn forced_twin_last_clock_is_equal_on_tail_full_and_restart() {
    if !supported("forced_twin_last_clock") {
        return;
    }
    with_e2(|| {
        const LATER: &str = "2026-08-02T07:09:00Z";
        let f = Twin::new("forced-twin-last-clock", false);
        diag::round(0);
        let sealed =
            continuation_for_test(SnapshotSource::ClaudeCode, &f.owner.cache, &f.prior, &f.key)
                .unwrap()
                .sealed_offset();
        let note = json!({"type":"user","sessionId":ROOT,"timestamp":LATER,
            "message":{"role":"user","content":"later"}})
        .to_string()
            + "\n";
        append(&f.twin, &note);
        input_clock(&f.twin);
        f.force("holder-later");
        let restart = f.restart();
        let tail = f.page(&f.owner);
        let native = forced_needs_native_for_test(&f.prior, &f.twin);
        let (mode, start) = if native {
            (ReadMode::Full(FullReason::StateMissing), 0)
        } else {
            (ReadMode::Tail, sealed)
        };
        f.assert_read(&f.owner, "RAM", mode, start);
        let cold = E2ScanFixture::capturing_identity();
        let pages = f.pages(&cold, &restart, tail);
        let pages = f.compare(&cold, &restart, pages);
        for page in &pages {
            let item = body(page, ROOT).unwrap();
            assert_eq!(
                item.source_file_fingerprint.as_ref(),
                Some(
                    &page.index.files[f.holder.to_string_lossy().as_ref()].source_file_fingerprint
                ),
                "the holder carries"
            );
            assert_eq!(
                (
                    item.source_last_activity_at.as_deref(),
                    item.source_ended_at.as_deref()
                ),
                (Some(LATER), None)
            );
        }
    });
}

/// [money] Two delays fall back to native on the same page: (a) cap pacing
/// and (b) an unfunded completion. (c) A future head holds the twin and the
/// session's dependent body until recovery can match cold Full.
/// A restart without audit capacity holds the session until its holder joins.
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
                use crate::snapshots::state_v2::{
                    replace_tail_head_bytes_for_test, seed_future_carrier_head_for_test,
                    tail_head_bytes_for_test,
                };

                let source = SnapshotSource::ClaudeCode;
                f.prior = f.disk.commit(&f.owner.cache, source, &mut f.prior);
                let route = f.disk.path(source);
                let readable_head = tail_head_bytes_for_test(&f.prior, &f.key);
                seed_future_carrier_head_for_test(&f.prior, &f.key);
                f.prior = ScanIndex::load(route).unwrap();
                let future_head = tail_head_bytes_for_test(&f.prior, &f.key);

                f.force("holder-later");
                let restart = f.restart();
                let mut held = f.page_as(&restart, "restart");
                assert!(restart.paths().contains(&f.holder));
                assert!(!restart.paths().contains(&f.twin));
                assert!(held.scan.newer_build_held.contains(&f.key));
                with_scan_clock(f.now.get(), || held.enrich(&f.c));
                assert_withheld(&held, ROOT, "the holder needs the newer-build twin");
                assert!(held
                    .disposition
                    .request_owned_hold_reasons
                    .contains_key("absent_content_twin"));
                let mut sent = twin(&held);
                let holds = with_scan_clock(f.now.get(), || sent.finish());
                assert!(holds.progress_blocking);
                assert!(body(&sent, ROOT).is_none());

                let cold = E2ScanFixture::capturing_identity();
                let cold_page = f.settle(&cold, "cold", f.page_as(&cold, "cold"), None);
                let reference = mixed_route(&cold_page, &e2_progress(), Mode::ColdFull);
                let committed = held.committed.clone();
                let prior = with_scan_clock(f.now.get(), || {
                    settle(&f.c, &committed, held, &mut e2_progress())
                });
                assert_eq!(tail_head_bytes_for_test(&prior, &f.key), future_head);

                // Replace the incompatible envelope with a readable one,
                // keeping the transcript and its committed pages in place.
                replace_tail_head_bytes_for_test(&prior, &f.key, &readable_head);
                f.prior = ScanIndex::load(route).unwrap();
                f.now.set(f.now.get() + 7 * 60 * 60);
                diag::round("recovery");
                let restart = f.restart();
                let page = f.page_as(&restart, "restart");
                f.settle(&restart, "restart", page, Some(&reference));
                continue;
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
            let cold = E2ScanFixture::capturing_identity();
            let mut pages = f.pages(&cold, &restart, f.page(&f.owner));
            f.assert_read(&f.owner, "RAM", ReadMode::Full(FullReason::StateMissing), 0);
            if arm != "future" {
                // Depends on the content-session co-scheduling fix landing
                // first: a pre-acquisition holder deferral must hold the whole
                // session, even when its pulled twin completes natively.
                let held_page = &mut pages[2];
                with_scan_clock(f.now.get(), || {
                    held_page.enrich(&f.c);
                    held_page.finish();
                });
                let held = mixed_route(held_page, &e2_progress(), Mode::DiskRestore);
                assert!(
                    !held.snapshots.contains_key(ROOT),
                    "the deferred holder holds the session; no partial body publishes"
                );
                let prior = with_scan_clock(f.now.get(), || {
                    f.disk.commit(
                        &held_page.cache,
                        SnapshotSource::ClaudeCode,
                        &mut held_page.index,
                    )
                });
                restart.set_audit_slots(256);
                diag::round("retry");
                diag::owner("restart");
                pages[2] = with_scan_clock(f.now.get(), || {
                    f.c.raw(&restart, prior, 2, true, std::slice::from_ref(&f.holder))
                });
            }
            let pages = f.compare(&cold, &restart, pages);
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
        let cold = E2ScanFixture::capturing_identity();
        let pages = f.pages(&cold, &restart, f.page(&f.owner));
        f.assert_read(&f.owner, "RAM", ReadMode::Full(FullReason::StateMissing), 0);
        f.assert_read(
            &restart,
            "restart",
            ReadMode::Full(FullReason::StateMissing),
            0,
        );
        f.compare(&cold, &restart, pages);
    });
}

/// What decides and proves the session's owner, for each copy: source
/// witness, entity and body, receipt, entity set, census membership and
/// owed upload context; and the index's upload-context stamps and copy
/// removals.
fn owner_facts(index: &ScanIndex, paths: &[&PathBuf]) -> Value {
    let files = paths
        .iter()
        .map(|path| {
            let key = path.to_string_lossy().into_owned();
            let entry = &index.files[key.as_str()];
            let census = index
                .claude_request_census_for_test()
                .get(&key)
                .map(|record| (record.request_hashes_for_test().to_vec(), record.is_twin()));
            serde_json::json!({
                "source_witness": entry.source_file_fingerprint,
                "entity": entry.last_snapshot_fingerprint,
                "body": entry.last_upload_body_witness,
                "receipt": entry.upload_context_receipt,
                "entities": index.file_snapshot_fingerprints.get(&key),
                "empty": index.confirmed_empty_files.contains(&key),
                "census": census,
                "owed": upload_context_owed_for_test(index, path),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "files": files,
        "stamps": index.upload_context_proof,
        "removals": format!("{:?}", index.claude_copy_removals),
    })
}

impl Twin {
    /// One unhinted page a visit later, delivered and committed. Returns the
    /// committed index (under the setup's destination) and what it offered.
    fn visit(&mut self) -> (ScanIndex, BTreeMap<String, Value>) {
        self.now.set(self.now.get() + 7 * 60 * 60);
        let (mut index, offered) = with_scan_clock(self.now.get(), || {
            let mut page = self.c.raw(&self.owner, self.prior.clone(), 2, true, &[]);
            page.enrich(&self.c);
            page.finish();
            let offered = mixed_route(&page, &e2_progress(), Mode::Ram).snapshots;
            accept_page(&mut page);
            let index = self
                .disk
                .commit(&page.cache, SnapshotSource::ClaudeCode, &mut page.index);
            (index, offered)
        });
        self.prior = index.clone();
        index.activate_upload_context("e2-synthetic-destination".into());
        (index, offered)
    }
    fn acquired(&self, path: &Path) -> bool {
        let reads = self.owner.acquisitions.lock().unwrap();
        reads.iter().any(|read| read.path == path)
    }
}

/// [money] A twin pair with a settled owner; the copy that does not own the
/// session changes only its ctime (a permission round trip, or a lease
/// renewal that sets the mtime it already had): same bytes, size, mtime,
/// inode and birth. Nothing selects it: the owner, both copies' witnesses,
/// entities, receipts and the upload-context stamps stay, and nothing is
/// offered. Write generation counts never enter a ctime-only change, so the
/// run without counts asserts the same. A real same-size edit of that copy
/// is still read and re-decided (positive control).
#[test]
fn a_ctime_only_touch_of_the_twin_copy_keeps_the_owner() {
    use crate::transcript_acquisition::{Generations, UseGenerations};
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    with_e2(|| {
        for generations in [Generations::Simulated, Generations::Off] {
            for lease in [false, true] {
                let _counts = UseGenerations::new(generations);
                let case = format!("{generations:?} lease={lease}");
                let mut t = Twin::new(&format!("twin-ctime-only-{generations:?}-{lease}"), false);
                // Settle what setup left (its retired holder head), then
                // require a quiet visit: the owner is settled.
                t.visit();
                t.owner.acquisitions.lock().unwrap().clear();
                let (settled, offered) = t.visit();
                assert!(!offered.contains_key(ROOT), "{case}: settled");
                assert!(!t.acquired(&t.twin), "{case}: settled");
                let (holder, twin) = (t.holder.clone(), t.twin.clone());
                let paths = [&holder, &twin];
                let before = owner_facts(&settled, &paths);

                let stat = std::fs::metadata(&twin).unwrap();
                if lease {
                    std::fs::File::options()
                        .write(true)
                        .open(&twin)
                        .unwrap()
                        .set_modified(stat.modified().unwrap())
                        .unwrap();
                } else {
                    let mode = stat.permissions().mode();
                    std::fs::set_permissions(&twin, std::fs::Permissions::from_mode(mode ^ 0o100))
                        .unwrap();
                    std::fs::set_permissions(&twin, std::fs::Permissions::from_mode(mode)).unwrap();
                }
                let now = std::fs::metadata(&twin).unwrap();
                assert_eq!(
                    (now.len(), now.modified().unwrap(), now.ino()),
                    (stat.len(), stat.modified().unwrap(), stat.ino()),
                    "{case}"
                );
                assert_ne!(
                    (now.ctime(), now.ctime_nsec()),
                    (stat.ctime(), stat.ctime_nsec()),
                    "{case}: the ctime moved"
                );

                t.owner.acquisitions.lock().unwrap().clear();
                let (touched, offered) = t.visit();
                assert!(
                    !t.acquired(&twin),
                    "{case}: a ctime-only change selects nothing"
                );
                assert!(!offered.contains_key(ROOT), "{case}: no new offer");
                assert_eq!(owner_facts(&touched, &paths), before, "{case}");

                if !lease {
                    let bytes = std::fs::read_to_string(&twin).unwrap();
                    let edited = bytes.replacen("claude-haiku-4-5", "claude-haiku-4-6", 1);
                    assert_ne!(edited, bytes);
                    assert_eq!(edited.len(), bytes.len());
                    std::fs::OpenOptions::new()
                        .write(true)
                        .open(&twin)
                        .unwrap()
                        .write_all(edited.as_bytes())
                        .unwrap();
                    t.owner.acquisitions.lock().unwrap().clear();
                    t.visit();
                    assert!(t.acquired(&twin), "{case}: an edit is read and re-decided");
                }
            }
        }
    });
}
