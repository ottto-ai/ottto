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
    corpus
        .support
        .join("local-otel")
        .join(if trace {
            "claude-code-trace-ownership"
        } else {
            "claude-code-effort"
        })
        .join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes())))
}
fn route(page: &mut Page, mode: Mode) -> RouteResult {
    page.finish();
    let (result, batches, _) = upload(&page.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
    RouteResult::emitted(
        mode,
        SnapshotSource::ClaudeCode,
        batches,
        &page.scan.snapshots,
    )
}
fn render(corpus: &Corpus, index: ScanIndex, mode: Mode) -> (Page, RouteResult) {
    let mut page = ready(corpus, &E2ScanFixture::default(), index, 100, false);
    let output = route(&mut page, mode);
    (page, output)
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
        let (mut reader, (first_page, first)) =
            with_durable_sidecar_reader(slots.reader(&c), || {
                render(&c, ScanIndex::default(), Mode::Ram)
            });
        money_oracle::assert_equivalent(&expected, &first);
        assert!(reader.body_bytes()[0] > 0);
        slots.save(&mut reader);
        // Real ACK + Completed settlement supplies the accepted-body premise.
        let mut progress = e2_progress();
        let accepted_index = settle(&c, &ScanIndex::default(), first_page, &mut progress);
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
        let (mut reader, (_, ram)) =
            with_durable_sidecar_reader(reader, || render(&c, accepted_index.clone(), Mode::Ram));
        assert_eq!(
            reader.body_bytes(),
            [row.len() as u64, trace_row.len() as u64]
        );
        assert_reported(&ram, 2);
        money_oracle::assert_no_smaller_reemit(ROOT, &first, &ram, &expected, false);
        // Do not save this suffix: restore the prior offset and replay it.
        drop(reader);
        let (mut reader, (_, disk)) = with_durable_sidecar_reader(slots.restart(&c), || {
            render(&c, accepted_index, Mode::DiskRestore)
        });
        assert_eq!(
            reader.body_bytes(),
            [row.len() as u64, trace_row.len() as u64]
        );
        money_oracle::assert_equivalent(&expected, &disk);
        slots.save(&mut reader);
        // Independent projections after two process-owned reader/lock resets.
        drop(reader);
        for mode in [Mode::Restart, Mode::EvictRetry] {
            let (mut reader, (_, restored)) =
                with_durable_sidecar_reader(slots.restart(&c), || {
                    render(&c, ScanIndex::default(), mode)
                });
            money_oracle::assert_equivalent(&expected, &restored);
            assert_eq!(
                restored.restored, 0,
                "E1 restore telemetry is not wired in this adapter"
            );
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
        let (mut reader, (page, mut prior)) = with_durable_sidecar_reader(slots.reader(&c), || {
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
        let accepted = settle(&c, &ScanIndex::default(), page, &mut progress);
        let before = stored_bodies(&accepted);
        slots.save(&mut reader);
        append(&native, &line(ROOT, "r2", "2026-08-02T07:01:00Z", 20));
        let path = sidecar_path(&c, false);
        let saved = path.with_extension("held");
        std::fs::rename(&path, &saved).unwrap();
        reader.begin_pass();
        let (mut reader, (held_page, mut held)) =
            with_durable_sidecar_reader(reader, || render(&c, accepted.clone(), Mode::Ram));
        assert!(
            held.snapshots.is_empty(),
            "S2 forbids an estimate replacement"
        );
        let held_index = settle(&c, &accepted, held_page, &mut progress);
        assert_eq!(stored_bodies(&held_index), before);
        // Carry the real accepted body only after proving its native tuple
        // survived the production hold and settlement. No acquisition credit.
        held.accepted = prior.accepted.clone();
        money_oracle::assert_held(ROOT, &prior, &held, &expected);
        assert!(
            crate::claude_local_otel::take_sidecar_read_counts()["sidecar_accepted_body_holds"] > 0
        );
        std::fs::rename(saved, &path).unwrap();
        append(
            &path,
            &(serde_json::to_string(&api("r2", 20, 200)).unwrap() + "\n"),
        );
        let expected = cold(&c);
        reader.begin_pass();
        let (_, (_, recovery)) =
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
        let (mut reader, (_, actual)) =
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
                page.index = serde_json::from_value(value).unwrap();
                assert!(
                    crate::snapshots::claude_native_comparison::early_root_is_eligible(
                        &page.index,
                        ROOT
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
                        &page.index,
                        [ROOT].into_iter(),
                        &mut paid,
                        0,
                    )
                    .unwrap()
                } else {
                    PreparedClaudeLocalEvidence::load(&c.support, &page.scan.snapshots, &page.index)
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
        let (reader, (_, mut quiet)) = with_durable_sidecar_reader(slots.restart(&c), || {
            render(&c, ScanIndex::default(), Mode::Restart)
        });
        quiet.io.consumed = reader.body_bytes().into_iter().sum();
        // None honestly discloses guard accounting absent from the oracle API.
        quiet.io.cheap_checks = None;
        money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    });
}
