// Ordinary queue tests; no money-equivalence workflow or runtime activation.
use super::*;
use crate::claude_local_otel::{with_durable_sidecar_reader, DurableSidecarTestReader};
use crate::locked_state_dir::LockedStateDir;
// DEPENDENCY(#882): use the shared comparator at its final API/path. The
// current branch includes only that unchanged API subset, not E1's drivers.
use crate::snapshots::sampled_scan::transition_fixture::{
    money_oracle, Accepted, Mode, RouteResult,
};

struct Slots {
    path: PathBuf,
    index: ScanIndex,
    writer: Option<LockedStateDir>,
}
impl Slots {
    fn new(corpus: &Corpus) -> Self {
        let state = corpus.base.join("sidecar-state");
        let writer = Some(LockedStateDir::acquire(&state).unwrap());
        let path = state.join("scan-index.json");
        let mut index = ScanIndex::default();
        index.save(&path).unwrap();
        Self {
            path,
            index,
            writer,
        }
    }
    fn reader(&self, corpus: &Corpus) -> DurableSidecarTestReader {
        DurableSidecarTestReader::new(
            &corpus.support,
            &self.path,
            "sidecar-money",
            self.index.generation,
        )
    }
    fn save(&mut self, reader: &mut DurableSidecarTestReader) {
        self.index.save(&self.path).unwrap();
        reader
            .write_after_save(self.writer.as_ref().unwrap(), &self.index)
            .unwrap();
    }
    fn restart(&mut self, corpus: &Corpus) -> DurableSidecarTestReader {
        self.writer.take();
        self.writer = Some(LockedStateDir::acquire(self.path.parent().unwrap()).unwrap());
        self.index = ScanIndex::load(&self.path).unwrap();
        self.reader(corpus)
    }
}
fn sidecar_path(corpus: &Corpus, trace: bool) -> PathBuf {
    sidecar_path_for(corpus, trace, ROOT)
}
fn sidecar_path_for(corpus: &Corpus, trace: bool, session: &str) -> PathBuf {
    corpus
        .support
        .join("local-otel")
        .join(if trace {
            "claude-code-trace-ownership"
        } else {
            "claude-code-effort"
        })
        .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())))
}
fn finish_route(page: &mut Page, mode: Mode) -> (RouteResult, LocalHoldSettlement) {
    // Classification consumes held items. Carry its actual result through
    // upload/settlement; never classify an already-filtered page a second time.
    let holds = page.finish();
    let (result, batches, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    (
        RouteResult::emitted(
            mode,
            SnapshotSource::ClaudeCode,
            batches,
            &page.scan.snapshots,
        ),
        holds,
    )
}
fn route(page: &mut Page, mode: Mode) -> RouteResult {
    finish_route(page, mode).0
}
fn render(
    corpus: &Corpus,
    index: ScanIndex,
    mode: Mode,
) -> (Page, RouteResult, LocalHoldSettlement) {
    let mut page = ready(corpus, &E2ScanFixture::default(), index, 100, false);
    let (output, holds) = finish_route(&mut page, mode);
    (page, output, holds)
}
fn settle_route(
    corpus: &Corpus,
    committed: &ScanIndex,
    page: Page,
    progress: &mut SnapshotUploadProgress,
    holds: LocalHoldSettlement,
) -> ScanIndex {
    upload(&page.scan.snapshots, progress, ack).0.unwrap();
    let mut settled = settle_completed_upload(page.index, committed, progress, &holds);
    settle_index_after_upload(&mut settled.index, committed, progress);
    corpus.reload(&mut settled.index)
}
fn cold(corpus: &Corpus) -> RouteResult {
    render(corpus, ScanIndex::default(), Mode::ColdFull).1
}
fn assert_reported(result: &RouteResult, requests: u64) {
    let body = &result.snapshots[ROOT];
    assert_eq!(body["request_count"], requests);
    assert_eq!(body["telemetry_owned_complete"], true);
    assert!(body["cost"]["total_cost_usd"].is_string());
    assert!(!body["model_usage"].as_array().unwrap().is_empty());
}

#[test]
fn durable_sidecar_money_full_ram_disk_tail_late_latest_wins() {
    with_e2(|| {
        let mut c = Corpus::new("sidecar-money-routes");
        let native = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let expected = cold(&c);
        assert_reported(&expected, 1);
        let mut slots = Slots::new(&c);
        let (mut reader, (first_page, first, first_holds)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        money_oracle::assert_equivalent(&expected, &first);
        assert!(reader.body_bytes()[0] > 0);
        slots.save(&mut reader);
        // Real ACK + Completed settlement supplies the accepted-body premise.
        let mut progress = e2_progress();
        let accepted_index = settle_route(
            &c,
            &ScanIndex::default(),
            first_page,
            &mut progress,
            first_holds,
        );
        assert!(!accepted_index.current_snapshot_fingerprints().is_empty());
        let native_before = std::fs::metadata(&native).unwrap();
        let trace_row = serde_json::to_string(&trace("r2", "")).unwrap() + "\n";
        append(&sidecar_path(&c, true), &trace_row);
        let row = serde_json::to_string(&api("r2", 20, 200)).unwrap() + "\n";
        append(&sidecar_path(&c, false), &row);
        assert_eq!(
            std::fs::metadata(&native).unwrap().len(),
            native_before.len()
        );
        assert_eq!(
            std::fs::metadata(&native).unwrap().modified().unwrap(),
            native_before.modified().unwrap()
        );
        let expected = cold(&c);
        assert_reported(&expected, 2);
        reader.begin_pass();
        let (reader, (_, ram, _)) =
            with_durable_sidecar_reader(reader, || render(&c, accepted_index.clone(), Mode::Ram));
        assert_eq!(
            reader.body_bytes(),
            [row.len() as u64, trace_row.len() as u64]
        );
        assert_reported(&ram, 2);
        money_oracle::assert_no_smaller_reemit(ROOT, &first, &ram, &expected, false);
        // Do not save this suffix: restore the prior offset and replay it.
        drop(reader);
        let (mut reader, (_, mut disk, _)) = with_durable_sidecar_reader(slots.restart(&c), || {
            render(&c, accepted_index, Mode::DiskRestore)
        });
        assert_eq!(
            reader.body_bytes(),
            [row.len() as u64, trace_row.len() as u64]
        );
        disk.restored = reader.restored_records();
        assert_eq!(disk.restored, 1, "real paired record restored before Tail");
        money_oracle::assert_equivalent(&expected, &disk);
        slots.save(&mut reader);
        // Independent projections after two process-owned reader/lock resets.
        drop(reader);
        for mode in [Mode::Restart, Mode::EvictRetry] {
            let (mut reader, (_, mut restored, _)) =
                with_durable_sidecar_reader(slots.restart(&c), || {
                    render(&c, ScanIndex::default(), mode)
                });
            money_oracle::assert_equivalent(&expected, &restored);
            restored.restored = reader.restored_records();
            assert_eq!(restored.restored, 1, "real paired record restored");
            assert_eq!(reader.body_bytes(), [0, 0]);
            slots.save(&mut reader);
        }
    });
}

#[test]
fn durable_sidecar_money_accepted_refusal_holds_then_recovers() {
    with_e2(|| {
        crate::claude_local_otel::take_sidecar_read_counts();
        let mut c = Corpus::new("sidecar-money-held");
        let native = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let expected = cold(&c);
        let mut slots = Slots::new(&c);
        let (mut reader, (page, mut prior, prior_holds)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        assert_reported(&prior, 1);
        let witness = snapshot_upload_body_witness(&page.scan.snapshots[0]);
        prior.accepted.insert(
            ROOT.into(),
            Accepted {
                body: prior.snapshots[ROOT].clone(),
                witness,
            },
        );
        let mut progress = e2_progress();
        let accepted = settle_route(&c, &ScanIndex::default(), page, &mut progress, prior_holds);
        let before = stored_bodies(&accepted);
        slots.save(&mut reader);
        append(&native, &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20));
        let path = sidecar_path(&c, false);
        let saved = path.with_extension("held");
        std::fs::rename(&path, &saved).unwrap();
        reader.begin_pass();
        reader.set_time(100);
        let (mut reader, (held_page, mut held, held_holds)) =
            with_durable_sidecar_reader(reader, || render(&c, accepted.clone(), Mode::Ram));
        assert!(
            held.snapshots.is_empty(),
            "S2 forbids an estimate replacement"
        );
        let held_index = settle_route(&c, &accepted, held_page, &mut progress, held_holds);
        assert_eq!(stored_bodies(&held_index), before);
        // Carry the real accepted body only after proving its native tuple
        // survived the production hold and settlement. No acquisition credit.
        held.accepted = prior.accepted.clone();
        money_oracle::assert_held(ROOT, &prior, &held, &expected);
        assert!(
            crate::claude_local_otel::take_sidecar_read_counts()["sidecar_s2_hold_entities"] > 0
        );
        for (age, alarm) in [(24 * 60 * 60 - 60, false), (24 * 60 * 60 + 1, true)] {
            reader.begin_pass();
            reader.set_time(100 + age);
            let (next, (page, mut aged, holds)) =
                with_durable_sidecar_reader(reader, || render(&c, held_index.clone(), Mode::Ram));
            reader = next;
            let aged_index = settle_route(&c, &held_index, page, &mut progress, holds);
            assert_eq!(stored_bodies(&aged_index), before);
            aged.accepted = prior.accepted.clone();
            money_oracle::assert_held(ROOT, &prior, &aged, &expected);
            let counts = crate::claude_local_otel::take_sidecar_read_counts();
            assert_eq!(counts["sidecar_s2_hold_entities"], 1);
            assert_eq!(counts["sidecar_s2_hold_oldest_age"], age);
            assert_eq!(
                counts.get("sidecar_s2_hold_alarm").copied().unwrap_or(0),
                u64::from(alarm)
            );
        }
        std::fs::rename(saved, &path).unwrap();
        append(
            &path,
            &(serde_json::to_string(&api("r2", 20, 200)).unwrap() + "\n"),
        );
        let expected = cold(&c);
        reader.begin_pass();
        let (_, (_, recovery, _)) =
            with_durable_sidecar_reader(reader, || render(&c, held_index, Mode::Ram));
        money_oracle::assert_equivalent(&expected, &recovery);
        assert_reported(&recovery, 2);
    });
}

#[test]
fn durable_sidecar_money_rotation_rebuild_is_one_whole_body() {
    with_e2(|| {
        let mut c = Corpus::new("sidecar-money-rotation");
        c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let mut slots = Slots::new(&c);
        let (mut reader, _) = with_durable_sidecar_reader(slots.reader(&c), || cold(&c));
        slots.save(&mut reader);
        let path = sidecar_path(&c, false);
        std::fs::rename(&path, path.with_extension("rotated")).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string(&api("r1", 10, 100)).unwrap() + "\n",
        )
        .unwrap();
        let expected = cold(&c);
        reader.begin_pass();
        let (mut reader, (_, actual, _)) =
            with_durable_sidecar_reader(reader, || render(&c, ScanIndex::default(), Mode::Ram));
        assert_eq!(reader.rebuilds(), [1, 0]);
        money_oracle::assert_equivalent(&expected, &actual);
        slots.save(&mut reader);
    });
}

#[test]
fn durable_sidecar_money_prepared_and_paid_routes_equal_whole_file() {
    with_e2(|| {
        let mut c = Corpus::new("sidecar-money-prepared");
        c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let expected = cold(&c);
        let mut slots = Slots::new(&c);
        let (mut reader, _) = with_durable_sidecar_reader(slots.reader(&c), || cold(&c));
        slots.save(&mut reader);
        for paid_route in [false, true] {
            if paid_route && !crate::heap_layout_bound::layout_supported() {
                eprintln!("UNEXECUTED durable sidecar emitted paid route: unsupported layout");
                continue;
            }
            reader.begin_pass();
            let (next, actual) = with_durable_sidecar_reader(reader, || {
                let scanner = E2ScanFixture::default();
                let mut page = c.raw(&scanner, ScanIndex::default(), 100, false, &[]);
                let mut value = serde_json::to_value(&page.index).unwrap();
                value["claude_usage_family_witnesses"][ROOT] = serde_json::json!({
                    "evidence_fingerprint": "synthetic-prepared-selection",
                    "member_request_id_fingerprints": {}, "assigned_request_id_fingerprints": {}
                });
                // Selection-only E-empty witness; the native money fold below
                // keeps its original index, with no fabricated census proof.
                let selection: ScanIndex = serde_json::from_value(value).unwrap();
                assert!(
                    crate::snapshots::claude_native_comparison::early_root_is_eligible(
                        &selection, ROOT
                    )
                );
                let prepared = if paid_route {
                    let mut paid = crate::source_rotation::PaidReservation::from_remainder(
                        Some(256 * 1024 * 1024),
                        0,
                        0,
                    )
                    .unwrap();
                    PreparedClaudeLocalEvidence::load_paid_eligible(
                        &c.support,
                        &selection,
                        [ROOT].into_iter(),
                        &mut paid,
                        0,
                    )
                    .unwrap()
                } else {
                    PreparedClaudeLocalEvidence::load(&c.support, &page.scan.snapshots, &selection)
                };
                assert!(
                    prepared.frozen_roots_are_current(&c.support, &BTreeSet::from([ROOT.into()]))
                );
                page.enrich_prepared(&c, Some(prepared));
                route(&mut page, Mode::Ram)
            });
            reader = next;
            assert_eq!(reader.body_bytes(), [0, 0]);
            money_oracle::assert_equivalent(&expected, &actual);
        }
    });
}

// DEPENDENCY(#882): its current quiet helper requires zero cheap/other I/O,
// whereas v1 sidecar restore deliberately measures anchor reads. Do not label
// these reads zero. The active route above asserts body_bytes == [0, 0].
#[test]
#[ignore = "19b: #882 quiet oracle needs a measured anchor allowance"]
fn durable_sidecar_money_quiet_restart_shared_oracle() {
    with_e2(|| {
        let mut c = Corpus::new("sidecar-money-quiet-oracle");
        c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let mut slots = Slots::new(&c);
        let (mut reader, _) = with_durable_sidecar_reader(slots.reader(&c), || cold(&c));
        slots.save(&mut reader);
        drop(reader);
        let (reader, (_, mut quiet, _)) = with_durable_sidecar_reader(slots.restart(&c), || {
            render(&c, ScanIndex::default(), Mode::Restart)
        });
        quiet.io.consumed = reader.body_bytes().into_iter().sum();
        // None honestly discloses guard accounting absent from the oracle API.
        quiet.io.cheap_checks = None;
        money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    });
}

#[test]
fn durable_sidecar_money_cohort_refusal_cannot_downgrade_healthy_strict_root() {
    with_e2(|| {
        const BROKEN: &str = "0338a80a-f36e-4cbc-a5bb-50fc66430ba5";
        let mut c = Corpus::new("sidecar-money-cohort-floor");
        let native = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let mut slots = Slots::new(&c);
        let (mut reader, (page, mut prior, prior_holds)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        assert_reported(&prior, 1);
        prior.accepted.insert(
            ROOT.into(),
            Accepted {
                body: prior.snapshots[ROOT].clone(),
                witness: snapshot_upload_body_witness(&page.scan.snapshots[0]),
            },
        );
        let mut progress = e2_progress();
        let accepted = settle_route(&c, &ScanIndex::default(), page, &mut progress, prior_holds);
        let before = stored_bodies(&accepted);
        assert_eq!(before.len(), 1);
        slots.save(&mut reader);
        append(&native, &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20));
        c.root(BROKEN, &line(BROKEN, "broken", AT, 1));
        c.evidence_for(BROKEN, &[], &[]);
        let broken_api = sidecar_path_for(&c, false, BROKEN);
        std::fs::remove_file(&broken_api).unwrap();
        std::fs::create_dir(&broken_api).unwrap();
        let expected = cold(&c);
        reader.begin_pass();
        let (mut reader, (page, mut held, holds)) = with_durable_sidecar_reader(reader, || {
            // Prove the mixed premise through the real public loaders: the
            // permissive cohort fails, but this accepted root's strict API
            // report is independently healthy. Neither grants body acceptance.
            assert!(crate::claude_local_otel::ClaudeApiEvidenceRead::load(
                &c.support,
                [BROKEN.to_owned(), ROOT.to_owned()]
            )
            .is_err());
            let mut strict = crate::claude_local_otel::ClaudeApiEvidenceRead::load(
                &c.support,
                [ROOT.to_owned()],
            )
            .unwrap();
            assert!(strict
                .take_strict_report(&c.support, ROOT)
                .health
                .is_complete());
            render(&c, accepted.clone(), Mode::Ram)
        });
        assert!(
            !held.snapshots.contains_key(ROOT),
            "accepted complete body must hold despite healthy strict rows"
        );
        assert!(holds.held_entity_count > 0);
        assert!(!holds.held_fingerprints.is_empty());
        let held_index = settle_route(&c, &accepted, page, &mut progress, holds);
        let after = stored_bodies(&held_index);
        for (key, tuple) in &before {
            assert_eq!(
                after.get(key),
                Some(tuple),
                "accepted ROOT body/witness survives mixed-cohort refusal"
            );
        }
        held.accepted = prior.accepted.clone();
        money_oracle::assert_held(ROOT, &prior, &held, &expected);
        std::fs::remove_dir(&broken_api).unwrap();
        c.evidence_for(BROKEN, &[api_for(BROKEN, "broken", 1, 10)], &[]);
        append(
            &sidecar_path(&c, false),
            &(serde_json::to_string(&api("r2", 20, 200)).unwrap() + "\n"),
        );
        let expected = cold(&c);
        reader.begin_pass();
        let (_, (_, recovered, _)) =
            with_durable_sidecar_reader(reader, || render(&c, held_index, Mode::Ram));
        money_oracle::assert_equivalent(&expected, &recovered);
        assert_reported(&recovered, 2);
    });
}

#[test]
fn durable_sidecar_money_refusal_holds_accepted_root_and_agent_entities() {
    with_e2(|| {
        let agent_session = format!("{ROOT}_agent-000");
        let mut c = Corpus::new("sidecar-money-agent-floor");
        let root_path = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        let agent_path = c.agent(0, &line(ROOT, "a1", AT, 20));
        c.evidence(
            &[api("r1", 10, 100), api("a1", 20, 200)],
            &[trace("a1", "agent-000")],
        );
        let expected = cold(&c);
        assert_reported(&expected, 1);
        assert_eq!(
            expected.snapshots[&agent_session]["telemetry_owned_complete"],
            true
        );
        assert!(expected.snapshots[&agent_session]["cost"]["total_cost_usd"].is_string());
        let mut slots = Slots::new(&c);
        let (mut reader, (page, prior, holds)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        money_oracle::assert_equivalent(&expected, &prior);
        let mut progress = e2_progress();
        let accepted = settle_route(&c, &ScanIndex::default(), page, &mut progress, holds);
        let before = stored_bodies(&accepted);
        assert_eq!(
            before.len(),
            2,
            "root and agent have accepted native tuples"
        );
        assert_eq!(progress.accepted_fingerprints.len(), 2);
        slots.save(&mut reader);
        append(&root_path, &line(ROOT, "r2", "2026-08-02T07:01:00Z", 30));
        append(&agent_path, &line(ROOT, "a2", "2026-08-02T07:01:00Z", 40));
        let api_path = sidecar_path(&c, false);
        let parked = api_path.with_extension("refused");
        std::fs::rename(&api_path, &parked).unwrap();
        reader.begin_pass();
        let (mut reader, (page, held, holds)) =
            with_durable_sidecar_reader(reader, || render(&c, accepted.clone(), Mode::Ram));
        assert!(
            held.snapshots.is_empty(),
            "both exact entity IDs hold; no agent estimate may escape"
        );
        assert!(held.batches.is_empty());
        assert_eq!(holds.held_entity_count, 2);
        assert!(!holds.held_fingerprints.is_empty());
        let held_index = settle_route(&c, &accepted, page, &mut progress, holds);
        assert_eq!(
            stored_bodies(&held_index),
            before,
            "both accepted bodies/witnesses survive"
        );
        assert_eq!(
            progress.accepted_fingerprints.len(),
            2,
            "refusal grants no new ACK"
        );
        std::fs::rename(parked, &api_path).unwrap();
        for row in [api("r2", 30, 300), api("a2", 40, 400)] {
            append(&api_path, &(serde_json::to_string(&row).unwrap() + "\n"));
        }
        append(
            &sidecar_path(&c, true),
            &(serde_json::to_string(&trace("a2", "agent-000")).unwrap() + "\n"),
        );
        let expected = cold(&c);
        reader.begin_pass();
        let (_, (_, recovery, _)) =
            with_durable_sidecar_reader(reader, || render(&c, held_index, Mode::Ram));
        money_oracle::assert_equivalent(&expected, &recovery);
        assert_reported(&recovery, 2);
        assert_eq!(recovery.snapshots[&agent_session]["request_count"], 2);
        assert_eq!(
            recovery.snapshots[&agent_session]["telemetry_owned_complete"],
            true
        );
    });
}

#[test]
fn durable_sidecar_money_new_agent_estimate_survives_accepted_root_hold() {
    with_e2(|| {
        let agent_session = format!("{ROOT}_agent-000");
        let mut c = Corpus::new("sidecar-money-new-agent-estimate");
        let native = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let mut slots = Slots::new(&c);
        let (mut reader, (page, mut prior, holds)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        assert_reported(&prior, 1);
        prior.accepted.insert(
            ROOT.into(),
            Accepted {
                body: prior.snapshots[ROOT].clone(),
                witness: snapshot_upload_body_witness(&page.scan.snapshots[0]),
            },
        );
        let mut progress = e2_progress();
        let accepted = settle_route(&c, &ScanIndex::default(), page, &mut progress, holds);
        let before = stored_bodies(&accepted);
        assert_eq!(before.len(), 1, "only ROOT has any accepted body");
        slots.save(&mut reader);
        append(&native, &line(ROOT, "r2", "2026-08-02T07:01:00Z", 30));
        c.agent(0, &line(ROOT, "new-agent", AT, 20));
        let path = sidecar_path(&c, false);
        let parked = path.with_extension("unavailable");
        std::fs::rename(&path, &parked).unwrap();
        let expected = cold(&c);
        reader.begin_pass();
        let (_, (page, mut held, holds)) =
            with_durable_sidecar_reader(reader, || render(&c, accepted.clone(), Mode::Ram));
        assert_eq!(
            holds.held_entity_count, 1,
            "the new agent has no accepted-money floor"
        );
        assert!(!held.snapshots.contains_key(ROOT));
        assert_eq!(held.snapshots[&agent_session]["request_count"], 1);
        assert_eq!(
            held.snapshots[&agent_session]["telemetry_owned_complete"],
            false
        );
        assert!(held.snapshots[&agent_session]["cost"].is_null());
        let held_index = settle_route(&c, &accepted, page, &mut progress, holds);
        let after = stored_bodies(&held_index);
        for (key, tuple) in &before {
            assert_eq!(after.get(key), Some(tuple));
        }
        held.accepted = prior.accepted.clone();
        money_oracle::assert_held(ROOT, &prior, &held, &expected);
        // The sibling estimate is a real new ACK; ROOT's body stays unchanged.
        assert_eq!(progress.accepted_fingerprints.len(), 2);
    });
}

#[test]
fn durable_sidecar_money_newer_format_waits_without_downgrade_then_reupgrade_equals_full() {
    with_e2(|| {
        crate::claude_local_otel::take_sidecar_read_counts();
        let mut c = Corpus::new("sidecar-money-newer-hold");
        let native = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        c.evidence(&[api("r1", 10, 100)], &[]);
        let expected = cold(&c);
        let mut slots = Slots::new(&c);
        let (mut reader, (page, mut prior, holds)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        assert_reported(&prior, 1);
        prior.accepted.insert(
            ROOT.into(),
            Accepted {
                body: prior.snapshots[ROOT].clone(),
                witness: snapshot_upload_body_witness(&page.scan.snapshots[0]),
            },
        );
        let mut progress = e2_progress();
        let accepted = settle_route(&c, &ScanIndex::default(), page, &mut progress, holds);
        let before = stored_bodies(&accepted);
        slots.save(&mut reader);
        let api_end = std::fs::metadata(sidecar_path(&c, false)).unwrap().len();
        let trace_end = std::fs::metadata(sidecar_path(&c, true)).unwrap().len();
        drop(reader);
        append(&native, &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20));
        // A never-accepted dependent also waits: Unknown cannot become $0 or
        // a sidecar-less estimate merely because the reader is downgraded.
        c.agent(0, &line(ROOT, "new-agent", AT, 30));
        let mut older = slots.restart(&c).into_older_reader();
        let mut held_index = accepted;
        for _ in 0..3 {
            older.begin_pass();
            let (next, (page, mut held, holds)) =
                with_durable_sidecar_reader(older, || render(&c, held_index.clone(), Mode::Ram));
            older = next;
            assert_eq!(older.body_bytes(), [0, 0]);
            assert!(held.batches.is_empty());
            assert!(held.snapshots.is_empty());
            assert_eq!(holds.held_entity_count, 2);
            let settled = settle_route(&c, &held_index, page, &mut progress, holds);
            assert_eq!(
                stored_bodies(&settled),
                before,
                "accepted tokens/cost/witness stay exact"
            );
            held.accepted = prior.accepted.clone();
            money_oracle::assert_held(ROOT, &prior, &held, &expected);
            held_index = settled;
            assert_eq!(
                crate::claude_local_otel::take_sidecar_read_counts()["sidecar_hold_newer_format"],
                1
            );
        }
        drop(older);
        // The current reader resumes the untouched record and only the suffix.
        for row in [api("r2", 20, 200), api("new-agent", 30, 300)] {
            append(
                &sidecar_path(&c, false),
                &(serde_json::to_string(&row).unwrap() + "\n"),
            );
        }
        append(
            &sidecar_path(&c, true),
            &(serde_json::to_string(&trace("new-agent", "agent-000")).unwrap() + "\n"),
        );
        let expected = cold(&c);
        let (reader, (_, recovered, _)) = with_durable_sidecar_reader(slots.restart(&c), || {
            render(&c, held_index, Mode::DiskRestore)
        });
        assert_eq!(reader.restored_records(), 1);
        assert_eq!(
            reader.body_bytes(),
            [
                std::fs::metadata(sidecar_path(&c, false)).unwrap().len() - api_end,
                std::fs::metadata(sidecar_path(&c, true)).unwrap().len() - trace_end,
            ],
            "re-upgrade consumes only the appended suffix"
        );
        money_oracle::assert_equivalent(&expected, &recovered);
        assert_reported(&recovered, 2);
    });
}
