use super::super::super::line_delivery::{
    DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want,
};
use super::super::super::scan_index_persistence::Source;
use sampled_scan::transition_fixture::{self as oracle, money_oracle, Accepted, Mode, RouteResult};

const MAIN: &str = "019e5a00-0000-7000-8000-00000000000a";
const OTHER: &str = "019e5a00-0000-7000-8000-00000000000b";
const SIDE: &str = "019e5a00-0000-7000-8000-00000000000c";
const GAP: &str = "019e5a00-0000-7000-8000-00000000000d";
const REVISION: u32 = <tail_source::codex::Codex as tail_source::TailSource>::REDUCTION_REVISION;

#[derive(Clone, Default)]
struct Delivered(Arc<Mutex<Vec<(DeliveryMode, u64)>>>);
impl LineObserver for Delivered {
    fn begin(&mut self, view: &FileView) -> Want {
        self.0.lock().unwrap().push((view.mode, view.start));
        Want::Lines
    }
    fn line(&mut self, _: &FileView, _: &PhysicalLine<'_>) {}
    fn end(&mut self, _: &FileView, _: &DeliveryEnd) {}
}

struct Corpus {
    scratch: crate::test_scratch::ScratchDir,
    sessions: PathBuf,
    archived: PathBuf,
}
impl Corpus {
    fn new() -> Self {
        let scratch = crate::test_scratch::ScratchDir::canonical("codex-encoding-transitions");
        let home = fs::canonicalize(scratch.as_ref()).unwrap();
        crate::test_scratch::create_private_dir(&home.join("state")).unwrap();
        let sessions = home.join("sessions");
        let archived = home.join("archived_sessions");
        fs::create_dir_all(&sessions).unwrap();
        fs::create_dir_all(&archived).unwrap();
        Self {
            scratch,
            sessions,
            archived,
        }
    }
    fn path(&self, id: &str) -> PathBuf {
        self.sessions.join(format!("rollout-{id}.jsonl"))
    }
    fn roots(&self) -> [PathBuf; 2] {
        [self.sessions.clone(), self.archived.clone()]
    }
    fn write(&self, id: &str, account: Option<&str>) {
        fs::write(self.path(id), rollout(id, account)).unwrap();
    }
}
fn header(id: &str, account: Option<&str>) -> String {
    let mut payload = json!({"id": id, "timestamp":"2026-10-07T09:00:00Z", "source":"cli"});
    if let Some(account) = account {
        payload["creator_user_id"] = json!(format!("synthetic-user-{account}"));
        payload["creator_account_id"] = json!(format!("synthetic-workspace-{account}"));
    }
    json!({"type":"session_meta", "timestamp":"2026-10-07T09:00:00Z", "payload":payload})
        .to_string()
        + "\n"
}
fn turn(n: u64) -> String {
    json!({"type":"event_msg", "timestamp":"2026-10-07T10:00:00Z",
        "payload":{"type":"token_count", "info":{"model":"gpt-5.2",
        "total_token_usage":{"input_tokens":n*100,"cached_input_tokens":n*50,"output_tokens":n*10},
        "last_token_usage":{"input_tokens":100,"cached_input_tokens":50,"output_tokens":10}}}})
    .to_string()
        + "\n"
}
fn rollout(id: &str, account: Option<&str>) -> Vec<u8> {
    let first = if id == SIDE {
        let mut value: Value = serde_json::from_str(header(id, account).trim_end()).unwrap();
        value["payload"]["source"] =
            json!({"subagent": {"thread_spawn": {"parent_thread_id": OTHER}}});
        value.to_string() + "\n"
    } else {
        header(id, account)
    };
    (first + &turn(1) + &turn(2)).into_bytes()
}
fn append(path: &Path, text: &str) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}

// The ordinary scan/policy/checkpoint route; no carry helper is invoked here.
fn page(
    c: &Corpus,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    let delivered = Delivered::default();
    let ((answer, consumed), logs) = crate::local_resource_diagnostics::capture(|| {
        oracle::observe_consumed(|| {
            let mut scan = OwnedSourceScan::new(
                SnapshotSource::Codex,
                &c.roots(),
                index,
                NOW,
                BACKFILL_WINDOW_DAYS,
                100,
                None,
                &[],
                false,
            )
            .with_sampled_acquisition(cache, Scope("encoding-money-transition".into()))
            .with_line_observer("test", Box::new(delivered.clone()));
            for _ in 0..100_000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(next) => scan = next,
                    OwnedSourceScanStep::Complete {
                        mut index,
                        mut scan,
                        ..
                    } => {
                        index.bind_session_accounts(
                            SnapshotSource::Codex,
                            "synthetic-machine",
                            &mut scan.snapshots,
                            &[],
                        );
                        apply_upload_policy(
                            SnapshotSource::Codex,
                            &mut scan.snapshots,
                            SnapshotUploadPolicy::default(),
                        );
                        finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                        scan.finish_codex_capture_boundary(&mut index);
                        return (index, scan);
                    }
                }
            }
            panic!("ordinary scan did not finish");
        })
    });
    (answer.0, answer.1, delivered, consumed, logs)
}
fn route(index: &ScanIndex, scan: &SourceScanResult, posts: Vec<Vec<u8>>) -> RouteResult {
    let mut route = RouteResult::emitted(Mode::Ram, SnapshotSource::Codex, posts, &scan.snapshots);
    route.codex_evidence = oracle::codex_evidence(index, scan);
    for item in &scan.snapshots {
        if index
            .accepted_snapshot_fingerprints
            .contains(&item.snapshot_fingerprint)
        {
            route.accepted.insert(
                item.source_session_id.clone(),
                Accepted {
                    body: route.snapshots[&item.source_session_id].clone(),
                    witness: snapshot_upload_body_witness(item),
                },
            );
        }
    }
    route
}
fn emitted(index: &ScanIndex, scan: &SourceScanResult) -> RouteResult {
    let posts = crate::snapshot_sync::codex_transition_cold_batches(&scan.snapshots);
    let mut result = RouteResult::emitted(Mode::Ram, SnapshotSource::Codex, posts, &scan.snapshots);
    result.codex_evidence = oracle::codex_evidence(index, scan);
    result
}
fn assert_quiet(c: &Corpus, prior: ScanIndex, expected: &RouteResult) -> (ScanIndex, RouteResult) {
    let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let activity = codex_zst_refusal_tests::activity();
    let (mut index, scan, delivery, consumed, logs) =
        page(c, prior, Arc::new(sampled_scan::SharedCache::default()));
    assert_eq!(
        samples,
        START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get),
        "no identity sample"
    );
    assert_eq!(
        activity,
        codex_zst_refusal_tests::activity(),
        "no header parse or decoder construction"
    );
    assert_eq!(full_decodes(&logs), 0);
    assert!(delivery.0.lock().unwrap().is_empty());
    let previous = index.clone();
    let (next, posts) = index.checkpoint_with_captured_posts(&scan, &previous, "accept");
    index = next;
    assert!(
        posts.is_empty(),
        "representation-only change emitted a POST"
    );
    let mut quiet = route(&index, &scan, posts);
    quiet.accepted = expected.accepted.clone();
    quiet.mode = Mode::Restart;
    // Metadata-only secure opens are permitted. All byte-reading seams are
    // observed independently: identity samples, header parses, decoder and JSONL.
    let measured = (samples == START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get)
        && activity == codex_zst_refusal_tests::activity()
        && consumed == 0)
        .then_some(0);
    quiet.io = oracle::IoBytes {
        consumed,
        cheap_checks: measured,
        anchor_reads: measured,
        other_reads: measured,
        ..Default::default()
    };
    money_oracle::assert_quiet_restart_zero_bytes(&quiet);
    (index, quiet)
}

/// [regress] Provider compression and same-object relocation preserve all
/// logical state, money placement and ACKs without parsing or uploading.
/// New plaintext materialization follows the ordinary counted Full path.
#[test]
fn compressed_rename_keeps_all_state_without_read_or_upload() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for acked in [true, false] {
        let c = Corpus::new();
        c.write(MAIN, Some("a"));
        c.write(OTHER, Some("b"));
        // Codex's native side-work control is a native spawned session under B. Its
        // creator is independent; no per-request account tags are invented.
        c.write(SIDE, Some("b"));
        c.write(GAP, None);
        let (session, prior) = StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &c.scratch.join("state"),
        );
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (working, first, _, _, _) = page(&c, prior.clone(), cache.clone());
        let (index, posts) = working.checkpoint_with_captured_posts(&first, &prior, "accept");
        assert_eq!(posts.len(), 1);
        let first_route = route(&index, &first, posts);
        assert_ne!(
            first_route.snapshots[MAIN]["session_account_evidence"],
            first_route.snapshots[OTHER]["session_account_evidence"]
        );
        assert!(
            first_route.snapshots[OTHER]["session_account_evidence"].is_object(),
            "tagged positive control"
        );
        assert!(
            first_route.snapshots[GAP]["session_account_evidence"].is_null(),
            "evidence gap"
        );
        append(&c.path(MAIN), &(turn(3) + &header(MAIN, Some("switched"))));
        let before = index.clone();
        let (working, switched, _, _, _) = page(&c, index, cache);
        assert_eq!(switched.snapshots.len(), 1);
        assert!(
            switched.snapshots[0].session_account_evidence.is_none(),
            "contradicting creator clears the witness"
        );
        let (mut index, switched_posts) = if acked {
            working.checkpoint_with_captured_posts(&switched, &before, "accept")
        } else {
            // Keep an unACKed exact body in the scan graph; committing Tail
            // does not manufacture a destination ACK for that revision.
            let mut working = working;
            working.save(session.path()).unwrap();
            (ScanIndex::load(session.path()).unwrap(), Vec::new())
        };
        let mut expected = emitted(&index, &switched);
        expected.accepted = first_route.accepted.clone();
        if acked {
            assert_eq!(switched_posts.len(), 1);
            expected = route(&index, &switched, switched_posts);
        }
        let original = c.path(MAIN);
        let old_key = local_index_key(&original);
        let logical_entry = serde_json::to_value(&index.files[&old_key]).unwrap();
        let entity_set = index.file_snapshot_fingerprints[&old_key].clone();
        let accepted = index.accepted_snapshot_fingerprints.clone();
        let tombstones = serde_json::to_value(&index.codex_counting_tombstones).unwrap();
        let refusals = serde_json::to_value(&index.quarantined_snapshot_fingerprints).unwrap();
        let replay = index.historical_replay_generation.clone();
        let bindings = serde_json::to_value(&index.session_account_bindings).unwrap();
        let head = state_v2::load_head(&index, &old_key, REVISION)
            .unwrap()
            .unwrap();
        let mut revisions = Vec::new();
        state_v2::load_revisions(&index, &old_key, &head, |id, bytes| {
            revisions.push((id, bytes));
            Ok(())
        })
        .unwrap();
        let bytes = fs::read(&original).unwrap();
        // Keep this exact original object outside discovery for the same-object return row.
        let parked = c.scratch.join("original-object");
        fs::rename(&original, &parked).unwrap();
        let compressed = original.with_extension("jsonl.zst");
        fs::write(
            &compressed,
            zstd::stream::encode_all(&bytes[..], 1).unwrap(),
        )
        .unwrap();
        let new_key = local_index_key(&compressed);
        let previous = index.clone();
        let (working, quiet, delivery, consumed, logs) =
            page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
        assert_eq!(consumed, 0);
        assert!(delivery.0.lock().unwrap().is_empty());
        assert_eq!(full_decodes(&logs), 0);
        assert!(quiet.snapshots.is_empty());
        assert!(!working.files.contains_key(&old_key));
        assert_eq!(
            serde_json::to_value(&working.files[&new_key]).unwrap(),
            logical_entry
        );
        assert_eq!(working.file_snapshot_fingerprints[&new_key], entity_set);
        assert_eq!(working.accepted_snapshot_fingerprints, accepted);
        assert_eq!(
            serde_json::to_value(&working.codex_counting_tombstones).unwrap(),
            tombstones,
            "carry cannot retire the predecessor or mint a counting tombstone"
        );
        assert_eq!(
            serde_json::to_value(&working.quarantined_snapshot_fingerprints).unwrap(),
            refusals
        );
        assert_eq!(working.historical_replay_generation, replay);
        assert_eq!(
            serde_json::to_value(&working.session_account_bindings).unwrap(),
            bindings
        );
        let (next, posts) = working.checkpoint_with_captured_posts(&quiet, &previous, "accept");
        assert!(posts.is_empty());
        drop(next);
        // Restart observes the complete persisted pair and no old key.
        index = ScanIndex::load(session.path()).unwrap();
        assert!(!index.files.contains_key(&old_key));
        assert!(index.files.contains_key(&new_key));
        let moved_head = state_v2::load_head(&index, &new_key, REVISION)
            .unwrap()
            .unwrap();
        assert!(
            moved_head.table == head.table,
            "all page commitments unchanged"
        );
        let mut moved_revisions = Vec::new();
        state_v2::load_revisions(&index, &new_key, &moved_head, |id, bytes| {
            moved_revisions.push((id, bytes));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            moved_revisions, revisions,
            "revision ids, extents and first-change ages survive carry"
        );
        assert_eq!(moved_head.common.debt, head.common.debt);
        assert_eq!(
            moved_head.common.next_revision_id,
            head.common.next_revision_id
        );
        assert_eq!(moved_head.common.representation, head.common.representation);
        assert!(state_v2::load_head(&index, &old_key, REVISION)
            .unwrap()
            .is_none());
        // Same-object sessions <-> archived_sessions is a second no-body move.
        let archived = c.archived.join(compressed.file_name().unwrap());
        fs::rename(&compressed, &archived).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let (mut index, _) = assert_quiet(&c, index, &expected);
        assert!(index.files.contains_key(&local_index_key(&archived)));
        fs::rename(&archived, &compressed).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let (mut index, quiet) = assert_quiet(&c, index, &expected);
        // Held/unACKed money keeps its exact prior accepted floor through carry.
        let mut held_cold = emitted(&index, &switched);
        held_cold.accepted = expected.accepted.clone();
        let mut prior_money = held_cold.clone();
        prior_money.accepted = expected.accepted.clone();
        money_oracle::assert_held(MAIN, &prior_money, &quiet, &held_cold);
        money_oracle::assert_no_smaller_reemit(MAIN, &prior_money, &quiet, &held_cold, true);

        // An exact sibling has precedence before inventory: the compressed
        // object cannot become a second owner or decoded read.
        fs::rename(&parked, &original).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let (mut index, _) = assert_quiet(&c, index, &expected);
        append(&original, &turn(4));
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let before = index.clone();
        let (working, appended, delivery, _, logs) =
            page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
        assert_eq!(full_decodes(&logs), 0, "exact plaintext sibling wins");
        assert_eq!(appended.snapshots.len(), 1);
        // Same original object may Tail, and must consume only its suffix.
        assert_eq!(
            delivery.0.lock().unwrap().as_slice(),
            &[(DeliveryMode::Tail, bytes.len() as u64)]
        );
        let (mut index, posts) =
            working.checkpoint_with_captured_posts(&appended, &before, "accept");
        assert_eq!(posts.len(), 1);
        let appended_route = route(&index, &appended, posts);
        let (_, cold, _, _, _) = page(
            &c,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let mut cold_main = cold.clone();
        cold_main.snapshots.retain(|s| s.source_session_id == MAIN);
        money_oracle::assert_equivalent(&emitted(&index, &cold_main), &appended_route);

        // A newly created plaintext inode is ordinary Replaced, counted Full
        // once, even if its prefix happens to equal the old logical bytes.
        let current = fs::read(&original).unwrap();
        fs::write(
            &compressed,
            zstd::stream::encode_all(&current[..], 1).unwrap(),
        )
        .unwrap();
        fs::remove_file(&original).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let (mut index, _) = assert_quiet(&c, index, &appended_route);
        let fresh = c.scratch.join("fresh-plaintext");
        fs::write(&fresh, &current).unwrap();
        append(&fresh, &turn(5));
        fs::rename(&fresh, &original).unwrap();
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let before = index.clone();
        let (working, materialized, delivery, consumed, logs) =
            page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
        assert_eq!(
            delivery.0.lock().unwrap().as_slice(),
            &[(DeliveryMode::Full, 0)]
        );
        assert_eq!(consumed, fs::metadata(&original).unwrap().len());
        assert_eq!(full_decodes(&logs), 0);
        assert_eq!(materialized.snapshots.len(), 1);
        let counted_fulls = logs
            .iter()
            .filter_map(|row| {
                row["counts"]["sampled_acquisition"]["page_events"]["full_reasons"].as_object()
            })
            .flat_map(|reasons| reasons.values())
            .filter_map(Value::as_u64)
            .sum::<u64>();
        assert_eq!(
            counted_fulls, 1,
            "fresh plaintext materialization takes one ordinary counted Full"
        );
        let (index, posts) =
            working.checkpoint_with_captured_posts(&materialized, &before, "accept");
        assert_eq!(posts.len(), 1, "one new whole-session body");
        let (_, cold, _, _, _) = page(
            &c,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let mut cold_main = cold;
        cold_main.snapshots.retain(|s| s.source_session_id == MAIN);
        money_oracle::assert_equivalent(
            &emitted(&index, &cold_main),
            &route(&index, &materialized, posts),
        );
        assert_quiet(&c, index, &appended_route);
    }
}

/// [regress] A reachable body failure after a valid current owner header
/// holds its same-id joined history while an independent owner checkpoints.
#[test]
fn inventory_refusal_isolates_only_proven_dependants() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    // Both the retained member and its repaired sibling must satisfy main's
    // native group proof; a UI-only member is deliberately held by that proof.
    let mut native = codex_file_join::tests::member(MAIN, "root-response", 200, 200);
    native[0]["payload"]["source"] = json!("cli");
    native[0]["payload"]["creator_user_id"] = json!("synthetic-user-a");
    native[0]["payload"]["creator_account_id"] = json!("synthetic-workspace-a");
    fs::write(
        c.path(MAIN),
        native
            .iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("b"));
    c.write(GAP, None);
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let (working, first, _, _, _) = page(
        &c,
        prior.clone(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    let (mut index, posts) = working.checkpoint_with_captured_posts(&first, &prior, "accept");
    let accepted = route(&index, &first, posts);
    append(&c.path(OTHER), &turn(3));
    let sibling = c.sessions.join(format!("rollout-copy-{MAIN}.jsonl.zst"));
    // A complete first frame proves owner MAIN; corrupt body bytes in a
    // later frame fail only when acquisition advances past that header.
    let good_header = zstd::stream::encode_all(header(MAIN, Some("a")).as_bytes(), 1).unwrap();
    let mut damaged = good_header;
    damaged.extend_from_slice(b"not another zstd frame");
    fs::write(&sibling, damaged).unwrap();
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let before = index.clone();
    let (working, held_scan, _, _, _) =
        page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert!(held_scan
        .snapshots
        .iter()
        .all(|s| s.source_session_id != MAIN));
    assert!(held_scan
        .snapshots
        .iter()
        .any(|s| s.source_session_id == OTHER));
    let (mut index, posts) = working.checkpoint_with_captured_posts(&held_scan, &before, "accept");
    assert_eq!(posts.len(), 1);
    assert_eq!(
        index.files[&local_index_key(&c.path(MAIN))].last_upload_body_witness,
        before.files[&local_index_key(&c.path(MAIN))].last_upload_body_witness
    );
    assert!(!index
        .confirmed_empty_files
        .contains(&local_index_key(&sibling)));
    // Repair to a disjoint same-id response through the shared native rows.
    let rows = codex_file_join::tests::member(MAIN, "side-response", 100, 300);
    let repaired = rows.iter().map(|r| format!("{r}\n")).collect::<String>();
    // Group replay still requires physical plaintext certificates. The
    // provider's repaired plaintext takes the existing generic group path.
    fs::remove_file(&sibling).unwrap();
    fs::write(sibling.with_extension(""), repaired).unwrap();
    let (_, cold, _, _, _) = page(
        &c,
        ScanIndex::default(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    assert!(
        cold.snapshots
            .iter()
            .any(|item| item.source_session_id == MAIN),
        "the repaired cold owner must be admitted before testing its recovery"
    );
    let mut cold_b = cold.clone();
    cold_b.snapshots.retain(|s| {
        held_scan
            .snapshots
            .iter()
            .any(|actual| actual.source_session_id == s.source_session_id)
    });
    let captured_b = route(&index, &held_scan, posts);
    money_oracle::assert_equivalent(&emitted(&index, &cold_b), &captured_b);
    // Compare the held owner alone: Codex's extra tier/token evidence is
    // collected per offered set, so test healthy B independently above.
    let mut cold_a = cold.clone();
    cold_a.snapshots.retain(|s| s.source_session_id == MAIN);
    let mut held_a = held_scan.clone();
    held_a.snapshots.clear();
    let mut held = emitted(&index, &held_a);
    held.accepted = accepted.accepted.clone();
    money_oracle::assert_held(MAIN, &accepted, &held, &emitted(&index, &cold_a));
    money_oracle::assert_no_smaller_reemit(MAIN, &accepted, &held, &emitted(&index, &cold_a), true);
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let before = index.clone();
    let (working, recovered, _, _, _) =
        page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert_eq!(
        recovered
            .snapshots
            .iter()
            .filter(|s| s.source_session_id == MAIN)
            .count(),
        1
    );
    let (index, posts) = working.checkpoint_with_captured_posts(&recovered, &before, "accept");
    assert_eq!(posts.len(), 1);
    let mut cold_a = cold;
    cold_a.snapshots.retain(|s| {
        recovered
            .snapshots
            .iter()
            .any(|a| a.source_session_id == s.source_session_id)
    });
    money_oracle::assert_equivalent(&emitted(&index, &cold_a), &route(&index, &recovered, posts));
    let (mut index, _) = assert_quiet(&c, index, &accepted);
    // Unknown headers remain a wildcard, including a misleading owner name.
    fs::remove_file(sibling.with_extension("")).unwrap();
    fs::write(&sibling, b"unknown header").unwrap();
    append(&c.path(OTHER), &turn(4));
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let (_, unknown, _, _, _) = page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert!(
        unknown.snapshots.is_empty(),
        "unknown owner cannot prove another owner unique"
    );
    drop(session);
}

// The existing historical-binary driver receives two genuinely carried
// entries, with an exact ACK only for MAIN, plus retired JSON Held rows.
pub(super) fn carried_downgrade_index(root: &Path) -> ScanIndex {
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    c.write(OTHER, Some("b"));
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let (mut index, scan, _, _, _) =
        page(&c, prior, Arc::new(sampled_scan::SharedCache::default()));
    let accepted = scan
        .snapshots
        .iter()
        .filter(|s| s.source_session_id == MAIN)
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    index.record_accepted_snapshot_fingerprints(&accepted);
    index.save(session.path()).unwrap();
    index = ScanIndex::load(session.path()).unwrap();
    for id in [MAIN, OTHER] {
        let path = c.path(id);
        let bytes = fs::read(&path).unwrap();
        fs::write(
            path.with_extension("jsonl.zst"),
            zstd::stream::encode_all(&bytes[..], 1).unwrap(),
        )
        .unwrap();
        fs::remove_file(path).unwrap();
    }
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let (mut index, quiet, _, consumed, logs) =
        page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert!(quiet.snapshots.is_empty());
    assert_eq!(consumed, 0);
    assert_eq!(full_decodes(&logs), 0);
    index.save(session.path()).unwrap();
    let index = ScanIndex::load(session.path()).unwrap();
    let mut value = serde_json::to_value(state_v2::money_test_support::resident(&index)).unwrap();
    // Keep provider objects alive for any historical census the driver runs.
    let sessions = root.join("carried/sessions");
    fs::create_dir_all(&sessions).unwrap();
    for id in [MAIN, OTHER] {
        let name = format!("rollout-{id}.jsonl.zst");
        fs::copy(c.sessions.join(&name), sessions.join(&name)).unwrap();
    }
    // Decoder compatibility is over the actual carried logical state, not a
    // provider-history replay guarantee. The historical probe never scans it.
    value["traversal"] = Value::Null;
    serde_json::from_value(value).unwrap()
}

fn aged_mtime(path: &Path) {
    let before_window = rfc3339_unix_seconds(NOW).unwrap() - (FIRST_READ_WINDOW_DAYS + 1) * 86_400;
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(UNIX_EPOCH + std::time::Duration::from_secs(before_window))
        .unwrap();
}
fn legacy_age_corpus() -> (Corpus, PathBuf, Vec<u8>) {
    let c = Corpus::new();
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("a"));
    c.write(GAP, None);
    let body = [
        rollout(MAIN, Some("a")),
        (header(MAIN, Some("switched")) + &turn(3)).into_bytes(),
    ]
    .concat();
    let compressed = c.sessions.join(format!("rollout-{MAIN}.jsonl.zst"));
    let encoded = zstd::stream::encode_all(&body[..], 1).unwrap();
    fs::write(&compressed, &encoded).unwrap();
    (c, compressed, encoded)
}

/// [regress] An older archive Held for AdmissionRefused is already seen;
/// becoming readable still requires normal admission and counted acquisition.
#[test]
fn legacy_owed_held_archive_older_than_first_read_window_is_counted() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (c, compressed, encoded) = legacy_age_corpus();
    let (cold_index, cold, _, _, _) = page(
        &c,
        ScanIndex::default(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    let expected = emitted(&cold_index, &cold);
    assert_eq!(expected.snapshots.len(), 4);
    fs::write(&compressed, b"previously refused compressed input").unwrap();
    aged_mtime(&compressed);
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let key = local_index_key(&compressed);
    state_v2::seed_0217_archive_for_test(&prior, &key);
    let mut prior = ScanIndex::load(session.path()).unwrap();
    assert!(!prior.files.contains_key(&key));
    // A save before discovery must not erase the old first-seen evidence.
    prior.save(session.path()).unwrap();
    let prior = ScanIndex::load(session.path()).unwrap();
    assert!(!first_read_aged(
        &prior,
        &compressed,
        fs::metadata(&compressed)
            .unwrap()
            .modified()
            .ok()
            .and_then(unix_seconds)
            .unwrap(),
        rfc3339_unix_seconds(NOW)
    ));
    fs::write(&compressed, encoded).unwrap();
    aged_mtime(&compressed);
    let (working, scan, _, consumed, logs) = page(
        &c,
        prior.clone(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    assert!(consumed > 0);
    assert!(full_decodes(&logs) > 0, "compressed first read is counted");
    let (index, posts) = working.checkpoint_with_captured_posts(&scan, &prior, "accept");
    let actual = route(&index, &scan, posts);
    money_oracle::assert_equivalent(&expected, &actual);
    money_oracle::assert_no_smaller_reemit(MAIN, &expected, &actual, &expected, false);
    assert!(index.files.contains_key(&key));
}

/// [regress] The ordinary first-seen predicate excludes never-seen old input
/// equally for both encodings, while unrelated placed money still emits.
#[test]
fn never_seen_old_compressed_and_plain_rollouts_share_first_read_skip() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut control = None;
    let (c, compressed_path, encoded) = legacy_age_corpus();
    for compressed in [false, true] {
        let path = if compressed {
            fs::remove_file(c.path(MAIN)).unwrap();
            fs::write(&compressed_path, &encoded).unwrap();
            compressed_path.clone()
        } else {
            fs::remove_file(&compressed_path).unwrap();
            c.write(MAIN, Some("a"));
            c.path(MAIN)
        };
        aged_mtime(&path);
        let state = c.scratch.join(if compressed {
            "compressed-state"
        } else {
            "plain-state"
        });
        crate::test_scratch::create_private_dir(&state).unwrap();
        let (session, prior) =
            StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &state);
        let (index, scan, _, _, _) =
            page(&c, prior, Arc::new(sampled_scan::SharedCache::default()));
        assert!(!index.files.contains_key(&local_index_key(&path)));
        assert!(scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != MAIN));
        assert_eq!(scan.snapshots.len(), 3);
        assert!(
            state_v2::load_head(&index, &local_index_key(&path), u32::MAX)
                .unwrap()
                .is_none()
        );
        let actual = emitted(&index, &scan);
        if let Some(control) = &control {
            money_oracle::assert_equivalent(control, &actual);
        } else {
            control = Some(actual);
        }
        drop(session);
    }
}

/// [format] A release-shaped archive manifest plus member (header_attempts
/// included) loads inert and survives an unrelated ordinary save.
#[test]
fn release_0217_archive_manifest_members_and_header_attempts_load_inert() {
    let c = Corpus::new();
    let (session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let key = local_index_key(&c.sessions.join(format!("rollout-{MAIN}.jsonl.zst")));
    state_v2::seed_0217_archive_for_test(&prior, &key);
    let mut index = ScanIndex::load(session.path()).unwrap();
    assert!(index.decode_holds.is_empty());
    assert!(index.files.is_empty());
    assert!(index.accepted_snapshot_fingerprints.is_empty());
    assert!(state_v2::legacy_archive_was_seen(&index, &key).unwrap());
    assert!(state_v2::load_head(&index, &key, REVISION)
        .unwrap()
        .is_none());
    assert!(serde_json::to_value(&index)
        .unwrap()
        .get("archives")
        .is_none());
    index.save(session.path()).unwrap();
    let index = ScanIndex::load(session.path()).unwrap();
    assert!(state_v2::legacy_archive_was_seen(&index, &key).unwrap());
    assert!(index.decode_holds.is_empty());
    assert!(index.files.is_empty());
}
