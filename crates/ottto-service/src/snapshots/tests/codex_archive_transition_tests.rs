use crate::snapshots::line_delivery::{
    DeliveryEnd, DeliveryMode, FileView, LineObserver, PhysicalLine, Want,
};
use crate::snapshots::scan_index_persistence::Source;
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
    /// A fresh durable state session over an empty store.
    fn publish(&self) -> (StateV2ColdSession, ScanIndex) {
        StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &self.scratch.join("state"),
        )
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

thread_local! {
    /// Set while a row also runs at the first-import page total: every page
    /// carries the flag, as prepare sets it before each page.
    static FIRST_IMPORT_PAGES: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `rows` with every page of this fixture flagged as a first-import page.
fn with_first_import_pages(rows: impl FnOnce()) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FIRST_IMPORT_PAGES.with(|flag| flag.set(false));
        }
    }
    FIRST_IMPORT_PAGES.with(|flag| flag.set(true));
    let _reset = Reset;
    rows();
}

// The ordinary scan/policy/checkpoint route; no carry helper is invoked here.
fn page(
    c: &Corpus,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    page_observed(c, index, cache, |_| {})
}
fn page_observed(
    c: &Corpus,
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    observe: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    page_observed_on(&c.roots(), index, cache, observe)
}
/// `page_observed` over explicit scan roots, e.g. a second Codex home.
fn page_observed_on(
    roots: &[PathBuf],
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    observe: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    page_observed_with_limit(roots, index, cache, 100, &[], observe)
}
fn page_observed_with_limit(
    roots: &[PathBuf],
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    file_limit: usize,
    codex_slots: &[(String, String, usize)],
    observe: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    page_observed_hinted(roots, index, cache, file_limit, codex_slots, &[], observe)
}
/// `page_observed_with_limit` with the watcher's path hints.
fn page_observed_hinted(
    roots: &[PathBuf],
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    file_limit: usize,
    codex_slots: &[(String, String, usize)],
    hints: &[PathBuf],
    observe: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    page_observed_hinted_at(
        roots,
        index,
        cache,
        file_limit,
        codex_slots,
        hints,
        NOW,
        observe,
    )
}
/// `page_observed_with_limit` collected at `at`, e.g. a later generation.
fn page_observed_at(
    roots: &[PathBuf],
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    file_limit: usize,
    codex_slots: &[(String, String, usize)],
    at: &str,
    observe: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    page_observed_hinted_at(
        roots,
        index,
        cache,
        file_limit,
        codex_slots,
        &[],
        at,
        observe,
    )
}
#[expect(
    clippy::too_many_arguments,
    reason = "roots, store, cache, page limit, slots, hints, clock and observer"
)]
fn page_observed_hinted_at(
    roots: &[PathBuf],
    index: ScanIndex,
    cache: Arc<sampled_scan::SharedCache>,
    file_limit: usize,
    codex_slots: &[(String, String, usize)],
    hints: &[PathBuf],
    at: &str,
    mut observe: impl FnMut(&mut OwnedSourceScan),
) -> (ScanIndex, SourceScanResult, Delivered, u64, Vec<Value>) {
    let mut index = index;
    index.first_import_pending |= FIRST_IMPORT_PAGES.with(std::cell::Cell::get);
    let delivered = Delivered::default();
    let ((answer, consumed), logs) = crate::local_resource_diagnostics::capture(|| {
        oracle::observe_consumed(|| {
            let scope = Scope("encoding-money-transition".into());
            let mut scan = OwnedSourceScan::new_with_recovery_priority(
                SnapshotSource::Codex,
                roots,
                index,
                at,
                BACKFILL_WINDOW_DAYS,
                file_limit,
                None,
                hints,
                false,
                &mut ListingRequest::default(),
                false,
                &[],
                Some((&cache, &scope)),
                false,
            )
            .with_sampled_acquisition(cache, scope)
            .with_line_observer("test", Box::new(delivered.clone()));
            observe(&mut scan);
            for _ in 0..100_000 {
                match scan.step(None) {
                    OwnedSourceScanStep::Pending(mut next) => {
                        observe(&mut next);
                        scan = next;
                    }
                    OwnedSourceScanStep::Complete {
                        mut index,
                        mut scan,
                        ..
                    } => {
                        index.bind_session_accounts_with_mixed(
                            SnapshotSource::Codex,
                            "synthetic-machine",
                            &mut scan.snapshots,
                            &[],
                            (codex_slots, &mut [0; 9]),
                            &claude_request_accounts::MixedUploads::default(),
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
/// The Codex header lookup counts in each emitted cursor diagnostics window.
fn emitted_header_lookups(logs: &[Value]) -> Vec<Value> {
    logs.iter()
        .filter_map(|record| {
            record.pointer("/counts/sampled_acquisition/codex_cursor/during_scan_window")
        })
        .map(|window| {
            json!({"lookups": window.get("header_durable_lookups"),
                "reuse_hits": window.get("header_reuse_hits")})
        })
        .collect()
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
    assert_quiet_on(c, prior, expected, Arc::default())
}
/// `assert_quiet` on a given process cache.
fn assert_quiet_on(
    c: &Corpus,
    prior: ScanIndex,
    expected: &RouteResult,
    cache: Arc<sampled_scan::SharedCache>,
) -> (ScanIndex, RouteResult) {
    let ((mut index, scan, delivery, logs), io) = oracle::observe_codex_quiet_with_bytes(|| {
        let (index, scan, delivery, consumed, logs) = page(c, prior, cache);
        ((index, scan, delivery, logs), consumed)
    });
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
    quiet.io = io;
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
        let (working, first, _, _, logs) = page(&c, prior.clone(), cache.clone());
        // [regress] The page's own header inventory lookups land in its
        // emitted cursor window: one physical lookup per member, no reuse.
        assert_eq!(
            emitted_header_lookups(&logs),
            vec![json!({"lookups": 4, "reuse_hits": null})]
        );
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
            crate::snapshots::codex_rollout_carry::codex_archive_bytes(&bytes),
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
            crate::snapshots::codex_rollout_carry::codex_archive_bytes(&current),
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
        let (mut index, _) = assert_quiet(&c, index, &appended_route);
        // The accepted carried object keeps its ordinary grant as listing
        // generations expire; an unrelated discovery never regrants its Full.
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let cache = Arc::new(sampled_scan::SharedCache::default());
        let (_, quiet, delivery, consumed, logs) = page(&c, index, cache.clone());
        assert!(quiet.snapshots.is_empty());
        assert!(delivery.0.lock().unwrap().is_empty());
        assert_eq!(consumed, 0);
        assert_eq!(
            full_decodes(&logs),
            0,
            "no regranted Full after aged listing"
        );
        assert_eq!(cache.cursor_reserved(), 0);
    }
}

/// The reason counts on this pass's `codex_compression_carry_unproven` row.
fn unproven(logs: &[Value]) -> Value {
    logs.iter()
        .find(|row| row["stage"] == "codex_compression_carry_unproven")
        .map_or(Value::Null, |row| {
            row["counts"]["codex_compression_carry_unproven"].clone()
        })
}

/// [money] A Codex compression carries its predecessor's head only when the
/// archive records exactly the length the head read and that read ended on a
/// sealed line. Otherwise the archive is read once as a new file: turns
/// appended before compression count, the session's emitted or carried body,
/// placement and Codex evidence equal a cold Full's, the next pass is quiet,
/// and only the archive stays indexed. Two accounts, a side call and an
/// evidence gap stay in the corpus.
#[test]
fn compression_carries_only_a_proven_complete_read() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // (case, records its length, grown after the read, read ends unterminated, reason)
    for (case, recorded, grown, unsealed, reason) in [
        ("unchanged", true, false, false, None),
        ("grown", true, true, false, Some("length")),
        ("no length", false, false, false, Some("no_length")),
        ("no length, grown", false, true, false, Some("no_length")),
        ("unsealed", true, false, true, Some("unsealed")),
    ] {
        let c = Corpus::new();
        c.write(MAIN, Some("a"));
        c.write(OTHER, Some("b"));
        c.write(SIDE, Some("b"));
        c.write(GAP, None);
        let original = c.path(MAIN);
        if unsealed {
            // Codex was mid-line at the read and never finished it.
            append(&original, turn(3).trim_end());
        }
        let (_session, prior) = c.publish();
        let (working, first, _, _, _) = page(&c, prior.clone(), Arc::default());
        let (index, posts) = working.checkpoint_with_captured_posts(&first, &prior, "accept");
        assert_eq!(posts.len(), 1, "{case}");
        let first_route = route(&index, &first, posts);
        if grown {
            // Appended while this daemon did not read, then compressed.
            append(&original, &turn(3));
        }
        let plain = fs::read(&original).unwrap();
        let archive = if recorded {
            crate::snapshots::codex_rollout_carry::codex_archive_bytes(&plain)
        } else {
            zstd::stream::encode_all(&plain[..], 1).unwrap()
        };
        let compressed = original.with_extension("jsonl.zst");
        fs::write(&compressed, archive).unwrap();
        fs::remove_file(&original).unwrap();
        let (old_key, new_key) = (local_index_key(&original), local_index_key(&compressed));
        let before = index.clone();
        let (working, scan, _, _, logs) = page(&c, index, Arc::default());
        let (index, posts) = working.checkpoint_with_captured_posts(&scan, &before, "accept");
        let Some(reason) = reason else {
            assert_eq!(full_decodes(&logs), 0, "{case}: carried without a decode");
            assert!(scan.snapshots.is_empty(), "{case}");
            assert!(posts.is_empty(), "{case}");
            assert_eq!(unproven(&logs), Value::Null, "{case}");
            assert!(!index.files.contains_key(&old_key), "{case}");
            assert!(index.files.contains_key(&new_key), "{case}");
            continue;
        };
        assert_eq!(full_decodes(&logs), 1, "{case}: the archive is read once");
        assert_eq!(unproven(&logs), json!({reason: 1}), "{case}");
        let mut warm = route(&index, &scan, posts);
        if grown {
            assert_ne!(
                warm.snapshots[MAIN], first_route.snapshots[MAIN],
                "{case}: the appended turn changes the body"
            );
        }
        let mut carried = first_route.accepted.clone();
        carried.extend(warm.accepted.clone());
        warm.accepted = carried;
        // Only MAIN's file changed; the other sessions are not read again.
        let (_, mut cold, _, _, _) = page(&c, ScanIndex::default(), Arc::default());
        cold.snapshots.retain(|item| item.source_session_id == MAIN);
        money_oracle::assert_carried_equivalent(&emitted(&index, &cold), &warm);
        let (index, _) = assert_quiet(&c, index, &warm);
        assert!(!index.files.contains_key(&old_key), "{case}: the predecessor retired");
        assert!(index.files.contains_key(&new_key), "{case}");
    }
}

/// [regress] Header facts a warm process cache carries from earlier durable
/// lookups keep each page's money: every appended page's bodies and placement
/// equal a cold Full's, on one warm cache and with a restart (empty cache,
/// reloaded store; also what an upgrade leaves) between pages. Once the
/// accepted debt has settled, the warm last page looks up fewer heads than the
/// restarted one. [money] Two accounts with named creator slots (tagged
/// rows), a side call in archived_sessions, an evidence gap and a mid-session
/// switch.
#[test]
fn carried_header_facts_keep_money_on_warm_and_restarted_pages() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Named creator slots for both accounts, so rows carry account tags.
    let hash = |kind: &str, account: &str| {
        let value = if kind == "account" {
            "user"
        } else {
            "workspace"
        };
        ottto_core::billing_identity_hash("openai", kind, &format!("synthetic-{value}-{account}"))
            .unwrap()
    };
    let slots = ["a", "b"].map(|account| {
        (
            hash("account", account),
            hash("workspace", account),
            crate::codex_scan_diagnostics::CREATOR_NAMED,
        )
    });
    // Per arm, each page's (head lookups, header reuse hits).
    let mut counts = Vec::new();
    for restart in [false, true] {
        let page = |c: &Corpus, index, cache| {
            page_observed_with_limit(&c.roots(), index, cache, 100, &slots, |_| {})
        };
        let c = Corpus::new();
        c.write(MAIN, Some("a"));
        c.write(OTHER, Some("b"));
        c.write(SIDE, Some("b"));
        c.write(GAP, None);
        let side = c.path(SIDE);
        fs::rename(&side, c.archived.join(side.file_name().unwrap())).unwrap();
        let (session, prior) = StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &c.scratch.join("state"),
        );
        let warm = Arc::new(sampled_scan::SharedCache::default());
        let cache = || {
            if restart {
                Arc::default()
            } else {
                warm.clone()
            }
        };
        let mut index = prior;
        let mut arm = Vec::new();
        for page_number in 0..5 {
            match page_number {
                0 => {}
                1 => append(&c.path(MAIN), &(turn(3) + &header(MAIN, Some("switched")))),
                n => append(&c.path(MAIN), &turn(2 + n)),
            }
            if restart {
                index = ScanIndex::load(session.path()).unwrap();
            }
            let before = index.clone();
            let (working, scan, _, _, logs) = page(&c, index, cache());
            let (next, posts) = working.checkpoint_with_captured_posts(&scan, &before, "accept");
            index = next;
            assert_eq!(posts.len(), 1, "page {page_number}");
            let (_, mut cold, _, _, _) = page(
                &c,
                ScanIndex::default(),
                Arc::new(sampled_scan::SharedCache::default()),
            );
            if page_number > 0 {
                cold.snapshots.retain(|s| s.source_session_id == MAIN);
            } else {
                assert!(
                    cold.snapshots
                        .iter()
                        .flat_map(|item| &item.model_usage)
                        .any(|row| row.account_identifier_hash.is_some()),
                    "tagged positive control"
                );
            }
            money_oracle::assert_equivalent(&emitted(&index, &cold), &route(&index, &scan, posts));
            let window = emitted_header_lookups(&logs);
            let sum = |name: &str| {
                window
                    .iter()
                    .filter_map(|record| record[name].as_u64())
                    .sum::<u64>()
            };
            arm.push((sum("lookups"), sum("reuse_hits")));
        }
        counts.push(arm);
        drop(session);
    }
    assert!(
        counts[0][4].0 < counts[1][4].0,
        "warm vs restarted (lookups, reuse hits) per page: {counts:?}"
    );
}

/// [regress] A rollout created in an unrelated Codex home while a page is
/// open leaves that page's checkpoint valid: the page uploads and saves.
#[test]
fn unrelated_home_rollout_mid_page_keeps_the_checkpoint_valid() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    let unrelated = crate::test_scratch::ScratchDir::canonical("codex-unrelated-home");
    let unrelated_sessions = fs::canonicalize(unrelated.as_ref())
        .unwrap()
        .join("sessions");
    fs::create_dir_all(&unrelated_sessions).unwrap();
    let (_session, prior) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    let roots = [
        c.sessions.clone(),
        c.archived.clone(),
        unrelated_sessions.clone(),
    ];
    let mut created = false;
    let (working, scan, _, _, _) = page_observed_on(
        &roots,
        prior.clone(),
        Arc::new(sampled_scan::SharedCache::default()),
        |scan| {
            if scan.codex_join_prepared && !created {
                fs::write(
                    unrelated_sessions.join(format!("rollout-{OTHER}.jsonl")),
                    rollout(OTHER, Some("b")),
                )
                .unwrap();
                created = true;
            }
        },
    );
    assert!(created, "the unrelated rollout lands inside the page");
    assert!(scan.snapshots.iter().any(|s| s.source_session_id == MAIN));
    assert!(scan.snapshots.iter().all(|s| s.source_session_id != OTHER));
    scan.validate_codex_checkpoint().unwrap();
    scan.codex_joining_validator()
        .unwrap()
        .validate(&scan.snapshots)
        .unwrap();
    let (index, posts) = working.checkpoint_with_captured_posts(&scan, &prior, "accept");
    assert_eq!(posts.len(), 1);
    assert!(index.files.contains_key(&local_index_key(&c.path(MAIN))));
}

/// [regress] A reachable body failure after a valid current owner header
/// holds its same-id joined history while an independent owner checkpoints.
#[test]
fn inventory_refusal_isolates_only_proven_dependants() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
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
    // The transient failed companion disappears; the original object's
    // ordinary append supplies the next usage. Compressed grouped replay is
    // deliberately unsupported, so recovery uses the existing singleton path.
    fs::remove_file(&sibling).unwrap();
    append(&c.path(MAIN), &turn(3));
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
    assert_eq!(
        state_v2::runtime_path(&index).unwrap().as_deref(),
        Some(session.path())
    );
    state_v2::guard_local(
        session.path(),
        index.v2().persistence_v2.as_ref(),
        index.generation,
    )
    .expect("a prepared carry retains the next ordinary save's authenticated lineage");
    index.save(session.path()).unwrap();
    let index = ScanIndex::load(session.path()).unwrap();
    let mut value = serde_json::to_value(&index).unwrap();
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

/// [behaviour] A retired archive membership alone does not admit an aged rollout.
#[test]
fn membership_only_aged_archive_stays_unqueued_after_restart() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let (c, compressed, _) = legacy_age_corpus();
    let key = local_index_key(&compressed);
    let slots = named_creator_slots();
    let (mut cold_index, mut cold, _, _, _) = page_observed_with_limit(
        &c.roots(),
        ScanIndex::default(),
        Arc::default(),
        100,
        &slots,
        |_| {},
    );
    assert_eq!(cold.snapshots.len(), 4);
    cold.snapshots.retain(|item| item.source_session_id != MAIN);
    assert_eq!(cold.snapshots.len(), 3);
    cold_index.files.remove(&key);
    let expected = emitted(&cold_index, &cold);
    aged_mtime(&compressed);

    let (session, prior) = c.publish();
    state_v2::seed_0217_archive_for_test(&prior, &key);
    drop(prior);
    let prior = ScanIndex::load(session.path()).unwrap();
    assert!(prior.decode_holds.is_empty());
    assert!(prior.files.is_empty());
    assert!(prior.confirmed_empty_files.is_empty());
    assert!(prior.accepted_snapshot_fingerprints.is_empty());
    assert!(state_v2::load_head(&prior, &key, u32::MAX)
        .unwrap()
        .is_none());
    assert!(serde_json::to_value(&prior)
        .unwrap()
        .get("archives")
        .is_none());
    state_v2::assert_0217_archive_rows_for_test(&prior, &key, true);

    let scan_excluded = |index| {
        let (working, scan, _, _, logs) =
            page_observed_with_limit(&c.roots(), index, Arc::default(), 100, &slots, |step| {
                assert!(
                    !e2_pipeline_scan_fixture::pending_keys_for_test(&step.index).contains(&key)
                );
                assert!(!step.selected_flags.contains_key(&key));
            });
        assert!(!e2_pipeline_scan_fixture::pending_keys_for_test(&working).contains(&key));
        assert!(!working.files.contains_key(&key));
        assert!(state_v2::load_head(&working, &key, u32::MAX)
            .unwrap()
            .is_none());
        assert_eq!(full_decodes(&logs), 0);
        let actual = emitted(&working, &scan);
        assert!(!actual.snapshots.contains_key(MAIN));
        (working, actual)
    };

    let (mut working, actual) = scan_excluded(prior);
    money_oracle::assert_equivalent(&expected, &actual);
    let saved = session.save_reload(&mut working);
    state_v2::assert_0217_archive_rows_for_test(&saved, &key, false);
    drop((working, saved));
    state_v2::cold_close_for_test(session.path()).unwrap();

    let mut restarted = ScanIndex::load(session.path()).unwrap();
    assert!(restarted.decode_holds.is_empty());
    state_v2::assert_0217_archive_rows_for_test(&restarted, &key, false);
    restarted.traversal = None;
    scan_excluded(restarted);
}

/// One ordinary pass's reads and emissions, as the test seams observe them.
#[derive(Debug)]
struct PassFacts {
    stamp_matches: bool,
    identity_samples: u64,
    decoders: usize,
    parses: usize,
    zst_input_rows: usize,
    zst_decoded_bytes: u64,
    consumed: u64,
    counted_fulls: u64,
    delivered: Vec<(DeliveryMode, u64)>,
    snapshots: usize,
    posts: usize,
}

fn head_shape(index: &ScanIndex, key: &str) -> Option<(bool, state_v2::Representation)> {
    state_v2::load_head(index, key, u32::MAX)
        .unwrap()
        .map(|head| (head.metadata_only, head.common.representation))
}

/// One ordinary pass under `context` on the process's `cache`, then its
/// accepting checkpoint.
fn observed_pass(
    c: &Corpus,
    path: &Path,
    mut index: ScanIndex,
    context: &str,
    cache: &Arc<sampled_scan::SharedCache>,
) -> (ScanIndex, RouteResult, PassFacts) {
    index.activate_file_upload_context(SnapshotSource::Codex, context.into());
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let stamp_matches = index.listing_stamp_matches(path, &fs::metadata(path).unwrap());
    let samples = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let activity = codex_zst_refusal_tests::activity();
    let previous = index.clone();
    let (working, scan, delivery, consumed, logs) = page(c, index, cache.clone());
    let samples_after = START_IDENTITY_SAMPLE_FOR_TEST.with(std::cell::Cell::get);
    let activity_after = codex_zst_refusal_tests::activity();
    let zst = logs
        .iter()
        .filter(|row| row["stage"] == "codex_zst_input")
        .collect::<Vec<_>>();
    let counted_fulls = logs
        .iter()
        .filter_map(|row| {
            row["counts"]["sampled_acquisition"]["page_events"]["full_reasons"].as_object()
        })
        .flat_map(|reasons| reasons.values())
        .filter_map(Value::as_u64)
        .sum::<u64>();
    let (index, posts) = working.checkpoint_with_captured_posts(&scan, &previous, "accept");
    let facts = PassFacts {
        stamp_matches,
        identity_samples: samples_after.0 - samples.0,
        decoders: activity_after.0 - activity.0,
        parses: activity_after.1 - activity.1,
        zst_input_rows: zst.len(),
        zst_decoded_bytes: zst
            .iter()
            .filter_map(|row| row["counts"]["codex_zst_decoded_bytes"].as_u64())
            .sum(),
        consumed,
        counted_fulls,
        delivered: delivery.0.lock().unwrap().clone(),
        snapshots: scan.snapshots.len(),
        posts: posts.len(),
    };
    let emitted_route = route(&index, &scan, posts);
    (index, emitted_route, facts)
}

/// [regress] 0.1.219 left a never-read archived rollout as a metadata-only
/// head owing the whole archive, unread. Its ordinary counted Full and exact
/// ACK settle that debt: the file leaves the outstanding set, counts once
/// (equivalent to a cold run) and keeps only its archive inventory and job
/// decision in the head. Later passes in the same process (one process-lifetime cache, as the daemon keeps) are
/// quiet. After a restart (a fresh cache and a reloaded index) the archive
/// has its header decoded at most once, within the header bound, with no
/// identity sample, Full or POST; the next same-process pass is quiet. The
/// control is the same archive never seeded: no 0.1.219 head and no prior
/// debt. A failure under the decoder lock is resumed after it is released,
/// so it cannot poison other decoder rows.
#[test]
fn archive_whole_unread_debt_settles_after_one_counted_full() {
    use crate::session_attribution::job_template::JobState;
    use crate::snapshots::upload::freshness_debt::tests as g7;
    const CONTEXT: &str = "g7-archive-whole-context";
    struct Arm {
        seeded: bool,
        expected: RouteResult,
        read: RouteResult,
        seeded_head: Option<(bool, state_v2::Representation)>,
        owed: Value,
        first: PassFacts,
        restart: PassFacts,
        settled: Value,
        head: Option<(bool, state_v2::Representation, state_v2::DebtSummary)>,
        job: Option<JobState>,
        revisions: usize,
        after: Value,
        facts: String,
    }
    fn archive_whole_arm(seeded: bool, context: &str) -> Arm {
        // A fresh process per arm: no walk or aggregate carries over.
        crate::snapshots::money_freshness::restart_for_test();
        let c = Corpus::new();
        let compressed = c.archived.join(format!("rollout-{MAIN}.jsonl.zst"));
        let encoded = zstd::stream::encode_all(&rollout(MAIN, Some("a"))[..], 1).unwrap();
        fs::write(&compressed, &encoded).unwrap();
        File::options()
            .write(true)
            .open(&compressed)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(7 * 3600))
            .unwrap();
        let (cold_index, cold, _, _, _) = page(&c, ScanIndex::default(), Arc::default());
        let expected = emitted(&cold_index, &cold);
        let (session, mut prior) = StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &c.scratch.join("state"),
        );
        let key = local_index_key(&compressed);
        let mut owed = Value::Null;
        if seeded {
            g7::seed_archive_whole_unread(&prior, &compressed);
            prior.save(session.path()).unwrap();
            prior = ScanIndex::load(session.path()).unwrap();
            prior.activate_file_upload_context(SnapshotSource::Codex, context.into());
            owed = g7::walk(SnapshotSource::Codex, &c.roots(), &mut prior)["debt"].clone();
            prior.traversal = None;
        }
        let seeded_head = head_shape(&prior, &key);
        // One daemon process: its process-lifetime cache (lib.rs).
        let process = Arc::new(sampled_scan::SharedCache::default());
        let (index, read, first) = observed_pass(&c, &compressed, prior, context, &process);
        eprintln!("seeded={seeded} pass 1: {first:?}");
        let quiet = |mut index: ScanIndex, cache: &Arc<sampled_scan::SharedCache>| {
            index.activate_file_upload_context(SnapshotSource::Codex, context.into());
            e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
            let (index, quiet) = assert_quiet_on(&c, index, &read, cache.clone());
            assert!(quiet.snapshots.is_empty(), "quiet pass emitted a snapshot");
            index
        };
        // Passes 2 and 3 in the same process.
        let mut index = quiet(quiet(index, &process), &process);
        // A restart: the committed index, a fresh cache and no walk state.
        index.save(session.path()).unwrap();
        crate::snapshots::money_freshness::restart_for_test();
        let restarted = Arc::new(sampled_scan::SharedCache::default());
        let index = ScanIndex::load(session.path()).unwrap();
        let (index, _, restart) = observed_pass(&c, &compressed, index, context, &restarted);
        eprintln!("seeded={seeded} restart pass 4: {restart:?}");
        // Pass 5, the restarted process's next pass.
        let mut index = quiet(index, &restarted);
        index.activate_file_upload_context(SnapshotSource::Codex, context.into());
        let settled = g7::walk(SnapshotSource::Codex, &c.roots(), &mut index)["debt"].clone();
        index.save(session.path()).unwrap();
        let mut index = ScanIndex::load(session.path()).unwrap();
        let loaded = state_v2::load_head(&index, &key, u32::MAX).unwrap();
        let mut revisions = 0;
        if let Some(head) = &loaded {
            state_v2::load_revisions(&index, &key, head, |_, _| {
                revisions += 1;
                Ok(())
            })
            .unwrap();
        }
        let head = loaded.as_ref().map(|head| {
            (
                head.metadata_only,
                head.common.representation,
                head.common.debt,
            )
        });
        let job = loaded.and_then(|head| head.common.job.map(|job| job.state));
        index.activate_file_upload_context(SnapshotSource::Codex, context.into());
        let after = g7::walk(SnapshotSource::Codex, &c.roots(), &mut index)["debt"].clone();
        let facts = format!(
            "{} arm: compressed={} decoded={}\nseeded head: {seeded_head:?} owed: {owed}\n\
             pass 1: {first:?}\nrestart pass 4: {restart:?}\nsettled: {settled}\n\
             head: {head:?} job: {job:?} revisions={revisions}\nafter: {after}",
            if seeded { "seeded" } else { "control" },
            encoded.len(),
            rollout(MAIN, Some("a")).len(),
        );
        drop(session);
        Arm {
            seeded,
            expected,
            read,
            seeded_head,
            owed,
            first,
            restart,
            settled,
            head,
            job,
            revisions,
            after,
            facts,
        }
    }
    let collected = {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut arms = Vec::new();
            for seeded in [false, true] {
                arms.push(archive_whole_arm(seeded, CONTEXT));
            }
            arms
        }))
    };
    let arms = collected.unwrap_or_else(|panic| std::panic::resume_unwind(panic));
    let all = arms
        .iter()
        .map(|arm| arm.facts.as_str())
        .collect::<Vec<_>>()
        .join("\n\n");
    for arm in &arms {
        let label = if arm.seeded { "seeded" } else { "control" };
        if arm.seeded {
            assert_eq!(
                arm.seeded_head,
                Some((true, state_v2::Representation::Archive)),
                "{all}"
            );
            assert_eq!(arm.owed["outstanding_files"], 1, "{all}");
            assert_eq!(arm.owed["over_6h_files"], 1, "{all}");
        }
        assert!(
            arm.first.zst_decoded_bytes > 0 && arm.first.posts == 1,
            "{label}: pass 1 is the one counted Full\n{all}"
        );
        // The restart's first pass: at most one bounded header decode.
        let restart = &arm.restart;
        assert!(
            restart.identity_samples == 0
                && restart.decoders <= 1
                && restart.parses <= 1
                && restart.zst_input_rows <= 1
                && restart.zst_decoded_bytes
                    <= crate::snapshots::codex_file_join::MAX_HEADER_BYTES as u64
                && restart.consumed == 0
                && restart.counted_fulls == 0
                && restart.delivered.is_empty()
                && restart.snapshots == 0
                && restart.posts == 0,
            "{label}: the restart decodes at most one header\n{all}"
        );
        assert_eq!(arm.settled["outstanding_files"], 0, "{label}\n{all}");
        assert_eq!(arm.settled["over_6h_files"], 0, "{label}\n{all}");
        assert_eq!(arm.settled["unread_bytes"], 0, "{label}\n{all}");
        assert_eq!(
            arm.head,
            Some((true, state_v2::Representation::Archive, Default::default())),
            "{label}: archive metadata with no debt or reduction\n{all}"
        );
        assert_eq!(
            arm.job,
            Some(JobState::NoId),
            "{label}: archive predates cutoff"
        );
        assert_eq!(arm.revisions, 0, "{label}\n{all}");
        assert_eq!(arm.after["outstanding_files"], 0, "{label}\n{all}");
        assert_eq!(arm.after["over_6h_files"], 0, "{label}\n{all}");
        money_oracle::assert_equivalent(&arm.expected, &arm.read);
    }
}

const ARCHIVE_JOB_TASK: &str = "Inspect the service and explain every failure with clear evidence";

fn archive_with_terminal_job() -> (Corpus, StateV2ColdSession, ScanIndex, PathBuf) {
    use crate::snapshots::upload::freshness_debt::tests as g7;
    const CONTEXT: &str = "archive-job-context";
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    let (session, prior) = c.publish();
    let original = c.path(MAIN).with_extension("jsonl.zst");
    let prompt = json!({"type": "event_msg", "payload": {"type": "user_message", "message": ARCHIVE_JOB_TASK}});
    let bytes = header(MAIN, Some("a")) + &format!("{prompt}\n") + &turn(1);
    fs::write(
        &original,
        zstd::stream::encode_all(bytes.as_bytes(), 1).unwrap(),
    )
    .unwrap();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let (mut index, read, first) = observed_pass(&c, &original, prior, CONTEXT, &cache);
    assert_eq!(first.posts, 1);
    index.activate_file_upload_context(SnapshotSource::Codex, CONTEXT.into());
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let (mut index, _) = assert_quiet_on(&c, index, &read, cache);
    index.activate_file_upload_context(SnapshotSource::Codex, CONTEXT.into());
    let settled = g7::walk(SnapshotSource::Codex, &c.roots(), &mut index);
    assert_eq!(settled["debt"]["outstanding_files"], 0, "{settled}");
    index.save(session.path()).unwrap();
    (c, session, index, original)
}

/// A first decision made in an archive has file custody without a reduction.
#[test]
fn same_object_archive_rename_carries_terminal_job_without_progress() {
    use crate::session_attribution::job_template::{context, JobState};
    use std::os::unix::fs::MetadataExt;

    let (c, session, mut index, original) = archive_with_terminal_job();
    let from = local_index_key(&original);
    let progress = serde_json::to_value(&index.files[&from]).unwrap();
    let head = state_v2::load_head(&index, &from, REVISION)
        .unwrap()
        .unwrap();
    assert!(head.metadata_only);
    assert!(!head.table.contains_key(&state_v2::Collection::Revisions));
    let job = head.common.job.unwrap();
    assert_eq!(job.state, JobState::NoId);
    assert_ne!(job.birth_nanos, 0);

    let archived = c.archived.join(original.file_name().unwrap());
    fs::rename(&original, &archived).unwrap();
    let to = local_index_key(&archived);
    let stat = fs::metadata(&archived).unwrap();
    let mut candidate = codex_file_join::header_candidate(c.archived.clone(), archived, &stat);
    candidate.physical_identity = Some([stat.dev(), stat.ino()]);
    candidate.fingerprint_birth_nanos = crate::transcript_acquisition::birth_unix_nanos(&stat);
    assert_eq!(candidate.fingerprint_birth_nanos, job.birth_nanos);
    let carry = |index: &mut ScanIndex| {
        index
            .carry_codex_rollout_with_cache(
                session.path(),
                &candidate,
                vec![(from.clone(), c.sessions.clone(), MAIN.to_owned())],
                None,
            )
            .unwrap()
    };
    assert!(carry(&mut index));
    assert_eq!(serde_json::to_value(&index.files[&from]).unwrap(), progress);
    assert!(!index.files.contains_key(&to));
    assert!(state_v2::load_head(&index, &from, REVISION)
        .unwrap()
        .is_none_or(|head| head.common.job.is_none()));
    let head = state_v2::load_head(&index, &to, REVISION).unwrap().unwrap();
    assert!(head.metadata_only);
    assert_eq!(head.common.job, Some(job));
    assert!(
        !carry(&mut index),
        "an unfinished census can revisit the old key"
    );

    let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
    tail_source::seed_full_job_template(&index, &candidate, &[], &mut acc).unwrap();
    acc.observe_job(ARCHIVE_JOB_TASK);
    acc.finish_job_template(Some(&context(7)));
    assert_eq!(acc.job_template, Some(JobState::NoId));
}

#[test]
fn same_object_archive_rename_with_job_and_owed_debt_defers_and_holds_owner() {
    use crate::snapshots::upload::freshness_debt::tests::seed_archive_whole_unread;

    let (c, session, mut index, original) = archive_with_terminal_job();
    let candidate = codex_file_join::header_candidate(
        c.sessions.clone(),
        original.clone(),
        &fs::metadata(&original).unwrap(),
    );
    codex_file_join::stage_independent_inventory(&index, &[candidate], MAIN).unwrap();
    index.save(session.path()).unwrap();
    seed_archive_whole_unread(&index, &original);
    index.save(session.path()).unwrap();
    let from = local_index_key(&original);
    let progress = serde_json::to_value(&index.files[&from]).unwrap();
    let before = state_v2::load_head(&index, &from, REVISION)
        .unwrap()
        .unwrap();
    assert!(before.metadata_only);
    assert!(before.common.job.is_some());
    assert_eq!(before.table[&state_v2::Collection::Revisions].pages, 1);

    let archived = c.archived.join(original.file_name().unwrap());
    fs::rename(&original, &archived).unwrap();
    let to = local_index_key(&archived);
    assert!(codex_rollout_carry::physical_matches(
        &before,
        &fs::metadata(&archived).unwrap()
    ));
    index.traversal = None;
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &c.roots(),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    index
        .traversal
        .as_mut()
        .unwrap()
        .codex_rollout_paths
        .insert(to.clone());
    let (deferred, held) = index.prepare_codex_carries(None);
    assert_eq!(deferred, BTreeSet::from([to.clone()]));
    assert_eq!(held, BTreeSet::from([MAIN.to_owned()]));
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .observed_index_keys
        .contains(&from));
    assert_eq!(serde_json::to_value(&index.files[&from]).unwrap(), progress);
    assert!(!index.files.contains_key(&to));
    assert!(state_v2::load_head(&index, &to, REVISION)
        .unwrap()
        .is_none());
    let after = state_v2::load_head(&index, &from, REVISION)
        .unwrap()
        .unwrap();
    assert_eq!(after.common, before.common);
    assert!(after.table == before.table);
}

/// [regress] A provider archive moves a rollout to another path, keeping its
/// old mtime. The walk that lists the moved file counts it only after its path
/// carry, so in that same walk it owes what its predecessor owed: an ACKed file
/// nothing, an unACKed one once, from its first change. A carry that fails
/// leaves the moved file owed.
#[test]
fn archived_rollout_owes_its_carried_debt_in_the_same_walk() {
    const CONTEXT: &str = "g7-carry-context";
    for (acked, carried) in [(true, true), (false, true), (true, false)] {
        crate::snapshots::money_freshness::restart_for_test();
        let c = Corpus::new();
        c.write(MAIN, Some("a"));
        let original = c.path(MAIN);
        File::options()
            .write(true)
            .open(&original)
            .unwrap()
            .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(9 * 3600))
            .unwrap();
        let (session, prior) = StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &c.scratch.join("state"),
        );
        let cache = Arc::new(sampled_scan::SharedCache::default());
        // One ordinary pass, ACKed or saved unACKed: its walk's debt.
        let pass = |mut index: ScanIndex| {
            index.activate_file_upload_context(SnapshotSource::Codex, CONTEXT.into());
            e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
            let previous = index.clone();
            let (mut working, scan, _, _, logs) = page(&c, index, cache.clone());
            let index = if acked {
                working
                    .checkpoint_with_captured_posts(&scan, &previous, "accept")
                    .0
            } else {
                working.save(session.path()).unwrap();
                ScanIndex::load(session.path()).unwrap()
            };
            let debt = logs
                .iter()
                .rev()
                .find(|row| row["stage"] == "freshness_alarm" && row["counts"]["basis"] == "walk")
                .expect("the pass ends a walk")["counts"]["debt"]
                .clone();
            (index, debt)
        };
        let (index, _) = pass(prior);
        let (mut index, before) = pass(index);
        let owed_before = u64::from(!acked);
        assert_eq!(before["outstanding_files"], owed_before, "{before}");
        assert_eq!(before["over_6h_files"], owed_before, "{before}");
        let archived = c.archived.join(original.file_name().unwrap());
        fs::rename(&original, &archived).unwrap();
        let (old_key, new_key) = (local_index_key(&original), local_index_key(&archived));
        if !carried {
            // Destination custody refuses the carry.
            index.confirmed_empty_files.insert(new_key.clone());
        }
        let (index, after) = pass(index);
        let label = format!("acked={acked} carried={carried}\nbefore={before}\nafter={after}");
        if carried {
            assert!(!index.files.contains_key(&old_key), "{label}");
            assert!(index.files.contains_key(&new_key), "{label}");
        }
        let owed = u64::from(!acked || !carried);
        assert_eq!(after["outstanding_files"], owed, "{label}");
        assert_eq!(after["over_6h_files"], owed, "{label}");
        drop(session);
    }
}

/// [regress] Fail toward reading: an archive replaced after its read by a
/// grown object (another stamp and size) is identified and read again, and
/// its new money posts once, equal to a cold run. Asserted after the decoder
/// lock is released.
#[test]
fn replaced_archive_after_its_read_is_identified_and_read() {
    const CONTEXT: &str = "archive-replaced-context";
    let (first, replaced, grown_len, cold_route, replaced_route) = {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::snapshots::money_freshness::restart_for_test();
        let c = Corpus::new();
        let compressed = c.archived.join(format!("rollout-{MAIN}.jsonl.zst"));
        let first_body = rollout(MAIN, Some("a"));
        fs::write(
            &compressed,
            zstd::stream::encode_all(&first_body[..], 1).unwrap(),
        )
        .unwrap();
        let (session, prior) = StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &c.scratch.join("state"),
        );
        let process = Arc::new(sampled_scan::SharedCache::default());
        let (index, _, first) = observed_pass(&c, &compressed, prior, CONTEXT, &process);
        let grown = [first_body, turn(3).into_bytes()].concat();
        let replacement = c.scratch.join("replacement.jsonl.zst");
        fs::write(
            &replacement,
            zstd::stream::encode_all(&grown[..], 1).unwrap(),
        )
        .unwrap();
        fs::rename(&replacement, &compressed).unwrap();
        let (_, replaced_route, replaced) =
            observed_pass(&c, &compressed, index, CONTEXT, &process);
        let (cold_index, cold, _, _, _) = page(
            &c,
            ScanIndex::default(),
            Arc::new(sampled_scan::SharedCache::default()),
        );
        let cold_route = emitted(&cold_index, &cold);
        drop(session);
        (
            first,
            replaced,
            grown.len() as u64,
            cold_route,
            replaced_route,
        )
    };
    let facts = format!("first: {first:?}\nreplaced: {replaced:?}");
    assert!(first.zst_decoded_bytes > 0 && first.posts == 1, "{facts}");
    assert!(!replaced.stamp_matches, "{facts}");
    assert!(replaced.identity_samples > 0, "re-identified\n{facts}");
    assert!(
        replaced.zst_decoded_bytes >= grown_len && replaced.consumed > 0,
        "read again\n{facts}"
    );
    assert_eq!(replaced.snapshots, 1, "{facts}");
    assert_eq!(replaced.posts, 1, "{facts}");
    money_oracle::assert_equivalent(&cold_route, &replaced_route);
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

/// Named creator slots for both accounts, so rows carry account tags.
fn named_creator_slots() -> [(String, String, usize); 2] {
    let hash = |kind: &str, account: &str| {
        let value = if kind == "account" {
            "user"
        } else {
            "workspace"
        };
        ottto_core::billing_identity_hash("openai", kind, &format!("synthetic-{value}-{account}"))
            .unwrap()
    };
    ["a", "b"].map(|account| {
        (
            hash("account", account),
            hash("workspace", account),
            crate::codex_scan_diagnostics::CREATOR_NAMED,
        )
    })
}

/// MAIN and OTHER on two accounts, SIDE a side call and GAP an evidence gap.
fn four_session_corpus() -> Corpus {
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("b"));
    c.write(GAP, None);
    c
}

/// One unobserved page on a fresh cache, checkpointed as accepted. Returns
/// the store, the page, its posts and the bytes it consumed.
fn accepted_page(
    roots: &[PathBuf],
    index: ScanIndex,
    limit: usize,
    slots: &[(String, String, usize)],
) -> (ScanIndex, SourceScanResult, Vec<Vec<u8>>, u64) {
    let before = index.clone();
    let (working, scan, _, consumed, _) =
        page_observed_with_limit(roots, index, Arc::default(), limit, slots, |_| {});
    let (index, posts) = working.checkpoint_with_captured_posts(&scan, &before, "accept");
    (index, scan, posts, consumed)
}

/// The Codex inventory hold the checkpoint still owes, if any.
fn inventory_hold_of(
    index: &ScanIndex,
) -> Option<crate::snapshots::discovery::traversal::state::CodexInventoryHold> {
    index
        .traversal
        .as_ref()
        .and_then(|t| t.residue.codex_inventory_hold.clone())
}

/// No unhealthy retry is armed.
fn retry_unarmed(index: &ScanIndex) -> bool {
    index.traversal.as_ref().map_or(true, |t| {
        t.unhealthy_retry_attempt == 0 && t.unhealthy_retry_not_before_unix_seconds.is_none()
    })
}

/// Makes the bounded unhealthy retry due now.
fn retry_due(index: &mut ScanIndex) {
    index
        .traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds = Some(0);
}

/// [money] A page held only because its header inventory was incomplete
/// owes its candidates to the hold and adds no unreadable or ownership count.
/// The hold keeps the generation red while it owes them. Its release catches
/// them up with cold-equal money and reads what an unheld page reads:
/// - "ram"/"restart": the held page drained discovery, so that generation is
///   red and bounded; the hold survives the durable checkpoint, and the
///   release leaves the generation healthy with no further walk.
/// - "spans": the held page is not the drain page; no retry is ever armed and
///   the generation completes and retires.
/// - "unlisted": a held file the roster no longer lists stays owed after the
///   release, durably and red, until the bounded retry's fresh walk
///   rediscovers it and catches it up.
/// - "pre-fix": a store an older release wrote mid-hold, synthetic counts
///   included, ends one red generation, then catches up without subtracting
///   them.
#[test]
fn inventory_held_page_catches_up_and_leaves_the_generation_healthy() {
    const NEW: &str = "019e5a00-0000-7000-8000-00000000000e";
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slots = named_creator_slots();
    let healthy = |index: &ScanIndex| index.traversal.as_ref().map_or(true, |t| !t.has_errors());
    let changed = [MAIN, OTHER, NEW];
    let mut control_reads = None;
    for arm in ["control", "ram", "restart", "spans", "unlisted", "pre-fix"] {
        let limit = if arm == "spans" { 2 } else { 100 };
        let c = four_session_corpus();
        let (session, prior) = c.publish();
        let (mut index, first, posts, _) = accepted_page(&c.roots(), prior, 100, &slots);
        let accepted = route(&index, &first, posts);
        // A mid-session account switch, a side call, an evidence gap and a
        // never-accepted rollout.
        append(&c.path(MAIN), &(turn(3) + &header(MAIN, Some("switched"))));
        append(&c.path(OTHER), &turn(3));
        c.write(NEW, Some("a"));
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let (_, cold, _, _, _) = page_observed_with_limit(
            &c.roots(),
            ScanIndex::default(),
            Arc::default(),
            100,
            &slots,
            |_| {},
        );
        assert!(
            cold.snapshots
                .iter()
                .flat_map(|item| &item.model_usage)
                .any(|row| row.account_identifier_hash.is_some()),
            "tagged positive control"
        );
        let cold_of = |index: &ScanIndex, scan: &SourceScanResult| {
            let mut page = cold.clone();
            page.snapshots.retain(|item| {
                scan.snapshots
                    .iter()
                    .any(|own| own.source_session_id == item.source_session_id)
            });
            emitted(index, &page)
        };
        let keys = changed.map(|id| local_index_key(&c.path(id)));
        let before = index.clone();
        let mut injected = arm == "control";
        let (working, held, delivered, consumed, _) =
            page_observed_with_limit(&c.roots(), index, Arc::default(), limit, &slots, |scan| {
                if let Some(inventory) = scan.codex_join_inventory.as_mut().filter(|_| !injected) {
                    inventory.complete = false;
                    injected = true;
                }
            });
        assert!(injected, "{arm}");
        if arm == "control" {
            let (index, posts) = working.checkpoint_with_captured_posts(&held, &before, "accept");
            for id in changed {
                assert!(held
                    .snapshots
                    .iter()
                    .any(|item| item.source_session_id == id));
            }
            money_oracle::assert_equivalent(&cold_of(&index, &held), &route(&index, &held, posts));
            assert!(
                healthy(&index),
                "an unheld page leaves the generation healthy"
            );
            control_reads = Some((held.scanned_file_count, consumed));
            drop(session);
            continue;
        }
        assert!(held.snapshots.is_empty(), "{arm}: {:?}", held.snapshots);
        assert!(
            delivered.0.lock().unwrap().is_empty(),
            "{arm}: no body read"
        );
        assert!(!held.census_complete);
        assert_eq!(
            held.unreadable_path_count, 0,
            "{arm}: no synthetic unreadable"
        );
        assert_eq!(
            held.ownership_incomplete_file_count, 0,
            "{arm}: no synthetic ownership"
        );
        let (mut index, posts) = working.checkpoint_with_captured_posts(&held, &before, "accept");
        assert!(posts.is_empty());
        {
            // Recorded before the preparation yield: every held candidate is
            // owed, and none is residue.
            let traversal = index.traversal.as_ref().expect("the held generation stays");
            let hold = inventory_hold_of(&index).expect("the held candidates are owed");
            let owed = keys
                .iter()
                .filter(|key| hold.owed.contains(*key))
                .collect::<Vec<_>>();
            for key in &keys {
                assert!(!traversal.residue.index_keys.contains(key), "{arm}: {key}");
            }
            assert!(traversal.has_errors() && !traversal.has_unsettled_residue());
            if arm == "spans" {
                // Two held; the third waits in the queue, so discovery is
                // not done and no retry is armed.
                assert_eq!(owed.len(), 2, "{arm}: {:?}", hold.owed);
                assert!(traversal.pending_candidates.iter().any(|candidate| {
                    keys.contains(&local_index_key(&candidate.path))
                        && !hold.owed.contains(&local_index_key(&candidate.path))
                }));
                assert!(
                    retry_unarmed(&index),
                    "{arm}: no retry armed by a held page"
                );
            } else {
                assert_eq!(owed.len(), 3, "{arm}: {:?}", hold.owed);
                // The held page drained discovery: red and bounded.
                assert!(traversal.unhealthy_retry_not_before_unix_seconds.is_some());
            }
        }
        for key in &keys[..2] {
            assert_eq!(
                index.files[key].last_upload_body_witness,
                before.files[key].last_upload_body_witness,
                "{arm}: a held accepted witness is unchanged"
            );
        }
        assert!(index
            .files
            .get(&keys[2])
            .is_none_or(|entry| entry.last_upload_body_witness.is_none()));
        let mut held_route = emitted(&index, &held);
        held_route.accepted = accepted.accepted.clone();
        let mut cold_held = cold.clone();
        cold_held
            .snapshots
            .retain(|item| changed.contains(&item.source_session_id.as_str()));
        money_oracle::assert_held_set(
            &changed,
            &accepted,
            &held_route,
            &emitted(&index, &cold_held),
        );
        match arm {
            "restart" => {
                let hold = inventory_hold_of(&index);
                index = ScanIndex::load(session.path()).unwrap();
                assert_eq!(
                    inventory_hold_of(&index),
                    hold,
                    "the durable checkpoint keeps the hold"
                );
            }
            "unlisted" => {
                // The roster loses the new file; it still exists.
                let traversal = index.traversal.as_mut().unwrap();
                assert!(traversal.codex_rollout_paths.remove(&keys[2]));
                index = session.save_reload(&mut index);
            }
            "pre-fix" => {
                // What an older release folded for the same held page.
                let traversal = index.traversal.as_mut().unwrap();
                let owed = traversal
                    .residue
                    .codex_inventory_hold
                    .as_ref()
                    .unwrap()
                    .owed
                    .clone();
                traversal.counts.ownership_incomplete_file_count += owed.len();
                traversal
                    .counts
                    .causes
                    .add(ownership::INVENTORY, owed.len());
                traversal
                    .counts
                    .record_unreadable(UnreadableCause::AliasParser, 1);
                traversal.residue.index_keys.extend(owed);
                index = session.save_reload(&mut index);
            }
            _ => {}
        }
        // Release and catch up, page by page.
        let mut caught = BTreeSet::new();
        let mut reads = (0, 0);
        let mut last_accepted = None;
        for _ in 0..8 {
            let (next, page, posts, consumed) = accepted_page(&c.roots(), index, limit, &slots);
            index = next;
            reads = (reads.0 + page.scanned_file_count, reads.1 + consumed);
            if !page.snapshots.is_empty() {
                let caught_up = route(&index, &page, posts);
                money_oracle::assert_equivalent(&cold_of(&index, &page), &caught_up);
                caught.extend(
                    page.snapshots
                        .iter()
                        .map(|item| item.source_session_id.clone()),
                );
                last_accepted = Some(caught_up);
            }
            if arm == "spans" {
                assert!(retry_unarmed(&index), "{arm}: a release never arms a retry");
            }
            if arm != "spans" || index.traversal.is_none() {
                break;
            }
        }
        if arm == "unlisted" {
            // Released but unlisted: owed, durable and red until the retry.
            assert_eq!(
                caught,
                BTreeSet::from([MAIN.to_string(), OTHER.to_string()])
            );
            let hold = inventory_hold_of(&index).expect("the unlisted file stays owed");
            assert_eq!(hold.owed, BTreeSet::from([keys[2].clone()]));
            assert!(hold.outside_roster.contains_key(&keys[2]));
            assert!(!healthy(&index));
            let reloaded = ScanIndex::load(session.path()).unwrap();
            assert_eq!(inventory_hold_of(&reloaded), Some(hold));
            assert!(!healthy(&reloaded));
            retry_due(&mut index);
            let (next, rewalk, posts, _) = accepted_page(&c.roots(), index, limit, &slots);
            index = next;
            assert_eq!(
                rewalk
                    .snapshots
                    .iter()
                    .map(|item| item.source_session_id.as_str())
                    .collect::<Vec<_>>(),
                vec![NEW],
                "the fresh walk rediscovers only the owed file"
            );
            let caught_up = route(&index, &rewalk, posts);
            money_oracle::assert_equivalent(&cold_of(&index, &rewalk), &caught_up);
            caught.insert(NEW.to_string());
            last_accepted = Some(caught_up);
        }
        assert_eq!(
            caught,
            changed
                .iter()
                .map(|id| id.to_string())
                .collect::<BTreeSet<_>>(),
            "{arm}: every held session caught up"
        );
        assert!(inventory_hold_of(&index).is_none());
        if arm == "pre-fix" {
            // Forward-only: the old counts stay until the bounded re-walk.
            let traversal = index.traversal.as_ref().expect("one red generation");
            assert!(traversal.has_errors());
            assert!(traversal.counts.unreadable_path_count > 0);
            retry_due(&mut index);
            let before = index.clone();
            let (working, rewalk, _, _, _) =
                page_observed_with_limit(&c.roots(), index, Arc::default(), limit, &slots, |_| {});
            assert!(rewalk.snapshots.is_empty(), "the re-walk re-emits nothing");
            let (next, posts) = working.checkpoint_with_captured_posts(&rewalk, &before, "accept");
            assert!(posts.is_empty());
            index = next;
        } else if arm != "unlisted" {
            assert_eq!(
                Some(reads),
                control_reads,
                "{arm}: the release reads what an unheld page reads"
            );
        }
        assert!(healthy(&index), "{arm}: the generation is healthy");
        if arm == "spans" {
            assert!(index.traversal.is_none(), "{arm}: the generation retired");
        }
        assert_quiet(&c, index, &last_accepted.expect("a caught-up page"));
        drop(session);
    }
}

/// [money] Two refused first records hold a page. Repairing one releases the
/// hold, but the other still refuses: it counts again as a real unreadable,
/// is held again and keeps the generation open and red. Once it is repaired
/// too, every held session catches up cold-equal.
#[test]
fn a_remaining_refused_header_stays_red_after_another_releases_the_hold() {
    const BAD_A: &str = "019e5a00-0000-7000-8000-0000000000a1";
    const BAD_B: &str = "019e5a00-0000-7000-8000-0000000000b1";
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slots = named_creator_slots();
    let c = four_session_corpus();
    let (session, prior) = c.publish();
    let page = |index: ScanIndex| accepted_page(&c.roots(), index, 100, &slots);
    let (mut index, _, _, _) = page(prior);
    let refused = |index: &ScanIndex| {
        inventory_hold_of(index).map(|hold| {
            hold.refused_headers
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        })
    };
    let [bad_a, bad_b] = [BAD_A, BAD_B].map(|id| c.path(id));
    fs::write(&bad_a, "not a header\n").unwrap();
    fs::write(&bad_b, "not a header\n").unwrap();
    append(&c.path(MAIN), &turn(3));
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let (index, held, posts, _) = page(index);
    assert!(held.snapshots.is_empty() && posts.is_empty());
    assert_eq!(held.unreadable_path_count, 2, "two real refusals");
    assert_eq!(held.ownership_incomplete_file_count, 0);
    assert_eq!(
        refused(&index),
        Some(BTreeSet::from([
            local_index_key(&bad_a),
            local_index_key(&bad_b)
        ]))
    );
    // One witness moves: the hold releases, and the other refusal holds the
    // page again.
    fs::write(&bad_a, rollout(BAD_A, Some("a"))).unwrap();
    let (index, still, posts, _) = page(index);
    assert!(still.snapshots.is_empty() && posts.is_empty());
    // Generation totals: the two earlier refusals plus the remaining one.
    assert_eq!(
        still.unreadable_path_count, 3,
        "the remaining refusal counts"
    );
    assert_eq!(still.ownership_incomplete_file_count, 0);
    assert_eq!(
        refused(&index),
        Some(BTreeSet::from([local_index_key(&bad_b)]))
    );
    let traversal = index.traversal.as_ref().expect("the generation stays open");
    assert!(traversal.has_errors());
    assert_eq!(traversal.counts.terminal_ownership_incomplete_file_count, 0);
    fs::write(&bad_b, rollout(BAD_B, Some("b"))).unwrap();
    let (index, recovered, posts, _) = page(index);
    let mut ids = recovered
        .snapshots
        .iter()
        .map(|item| item.source_session_id.as_str())
        .collect::<Vec<_>>();
    ids.sort_unstable();
    let mut expected = [MAIN, BAD_A, BAD_B];
    expected.sort_unstable();
    assert_eq!(ids, expected, "every held session catches up");
    assert!(refused(&index).is_none());
    let (_, mut cold, _, _, _) = page_observed_with_limit(
        &c.roots(),
        ScanIndex::default(),
        Arc::default(),
        100,
        &slots,
        |_| {},
    );
    cold.snapshots
        .retain(|item| ids.contains(&item.source_session_id.as_str()));
    money_oracle::assert_equivalent(&emitted(&index, &cold), &route(&index, &recovered, posts));
    // The repaired headers do not erase this generation's real failures.
    assert_eq!(
        index
            .traversal
            .as_ref()
            .unwrap()
            .counts
            .unreadable_path_count,
        3
    );
    drop(session);
}

/// [money] A real held page, with no seam: a watcher-hinted rollout created
/// beside a symlink is selected, but the retained roster refresh refuses the
/// moved directory, so the roster cannot list it and the inventory is
/// incomplete. (A pending census-member directory cannot hold a page: while
/// one is pending the page selects nothing.) In the next generation's census
/// the page holds every candidate: the new rollout, the whole unchanged
/// joined group of a selected member and an accepted rollout whose file
/// regressed behind its accepted extent. It adds no synthetic count, arms no
/// retry, emits no body and keeps the accepted witness through a durable
/// restart. A later page holds a second new rollout while the first debt is
/// still owed: the hold owes their union. Once the symlink is gone and the
/// regressed file is restored and grown, the roster lists both rollouts, the
/// hold releases, every session catches up cold-equal and the generation
/// retires. Read bound, measured at the transcript reader for joined members
/// too: after the restart each checkpointed group member's census visit
/// consumes no byte and starts no first read, while the first generation's
/// read of the group is non-zero on the same counters.
#[test]
fn unlisted_hinted_rollout_holds_a_real_page_until_the_roster_lists_it() {
    use crate::snapshots::codex_file_join::tests::member;
    const GROUP: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const BEHIND: &str = "019e5a00-0000-7000-8000-0000000000d7";
    const QUEUED: [&str; 3] = [
        "019e5a00-0000-7000-8000-0000000000f1",
        "019e5a00-0000-7000-8000-0000000000f2",
        "019e5a00-0000-7000-8000-0000000000f3",
    ];
    const NEW1: &str = "019e5a00-0000-7000-8000-0000000000e1";
    const NEW2: &str = "019e5a00-0000-7000-8000-0000000000e2";
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let slots = named_creator_slots();
    let lines = |rows: &[Value]| {
        rows.iter()
            .map(|row| row.to_string() + "\n")
            .collect::<String>()
    };
    // A joined session emits one item per member file under one fingerprint;
    // the upload sends the first as its representative.
    let unique = |mut scan: SourceScanResult| {
        let mut seen = BTreeSet::new();
        scan.snapshots
            .retain(|item| seen.insert(item.snapshot_fingerprint.clone()));
        scan
    };
    let c = Corpus::new();
    let roots = c.roots();
    // A page's FirstRead events: one per file job that is new to the index,
    // a joined group's job included.
    let first_reads = |logs: &[Value]| {
        logs.iter()
            .filter(|row| row["stage"] == "native_collection_page")
            .map(|row| row["counts"]["first_read_files"].as_u64().unwrap_or(0))
            .sum::<u64>()
    };
    // Each page also returns (bytes consumed at the transcript reader, which
    // joined members' reads pass through too, FirstRead events).
    let step = |index: ScanIndex, limit: usize, hints: &[PathBuf]| {
        let before = index.clone();
        let (working, scan, delivered, consumed, logs) =
            page_observed_hinted(&roots, index, Arc::default(), limit, &slots, hints, |_| {});
        let (index, posts) = working.checkpoint_with_captured_posts(&scan, &before, "accept");
        let scan = unique(scan);
        let routed = route(&index, &scan, posts);
        let reads = delivered.0.lock().unwrap().clone();
        let measured = (consumed, first_reads(&logs));
        (index, scan, routed, reads, before, measured)
    };
    let ids = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .map(|item| item.source_session_id.clone())
            .collect::<BTreeSet<_>>()
    };
    let key = |path: &Path| local_index_key(path);
    // Census order: the accepted rollout, a two-file joined session, then a
    // queued census that outlasts every held page.
    let behind = c.path(BEHIND);
    let group = ["zgroup-a.jsonl", "zgroup-b.jsonl"].map(|name| c.sessions.join(name));
    let behind_accepted = [rollout(BEHIND, Some("a")), turn(3).into_bytes()].concat();
    fs::write(&behind, &behind_accepted).unwrap();
    fs::write(&group[0], lines(&member(GROUP, "r-a", 100, 100))).unwrap();
    fs::write(&group[1], lines(&member(GROUP, "r-b", 200, 300))).unwrap();
    for (number, id) in QUEUED.iter().enumerate() {
        let path = c.sessions.join(format!("zz-{number}.jsonl"));
        fs::write(path, rollout(id, Some("b"))).unwrap();
    }
    let (session, prior) = c.publish();
    let queued_paths = (0..QUEUED.len())
        .map(|n| c.sessions.join(format!("zz-{n}.jsonl")))
        .collect::<Vec<_>>();
    let size = |path: &Path| fs::metadata(path).unwrap().len();
    let rollout_bytes = size(&behind) + queued_paths.iter().map(|path| size(path)).sum::<u64>();
    // Positive control on the same member bytes alone: the counters see the
    // joined group's first read.
    let alone = Corpus::new();
    fs::write(
        alone.sessions.join("zgroup-a.jsonl"),
        lines(&member(GROUP, "r-a", 100, 100)),
    )
    .unwrap();
    fs::write(
        alone.sessions.join("zgroup-b.jsonl"),
        lines(&member(GROUP, "r-b", 200, 300)),
    )
    .unwrap();
    let (_, solo, _, solo_bytes, solo_logs) = page_observed_hinted(
        &alone.roots(),
        ScanIndex::default(),
        Arc::default(),
        100,
        &slots,
        &[],
        |_| {},
    );
    assert_eq!(ids(&unique(solo)), BTreeSet::from([GROUP.to_string()]));
    assert!(
        solo_bytes > 0 && first_reads(&solo_logs) >= 1,
        "the group's first read is observed: {solo_bytes} bytes, {solo_logs:?}"
    );
    // The first generation reads and accepts everything, then retires. It
    // reads each new file once, so its bytes past the four rollouts and its
    // fifth FirstRead are the joined group's.
    let (mut index, first, accepted, _, _, mut measured) = step(prior, 100, &[]);
    let mut everyone = QUEUED.map(String::from).to_vec();
    everyone.extend([GROUP, BEHIND].map(String::from));
    assert_eq!(ids(&first), everyone.into_iter().collect::<BTreeSet<_>>());
    assert!(accepted.accepted.contains_key(GROUP) && accepted.accepted.contains_key(BEHIND));
    for _ in 0..10 {
        if index.traversal.is_none() {
            break;
        }
        let (next, _, _, _, _, more) = step(index, 100, &[]);
        index = next;
        measured = (measured.0 + more.0, measured.1 + more.1);
    }
    assert!(index.traversal.is_none(), "the first generation retired");
    assert!(
        measured.0 > rollout_bytes && measured.1 >= 5,
        "the first generation reads the group: {measured:?}, rollouts {rollout_bytes} bytes"
    );
    let kb = key(&behind);
    let witness = |index: &ScanIndex| {
        index
            .files
            .get(&kb)
            .and_then(|entry| entry.last_upload_body_witness.clone())
    };
    let accepted_witness = witness(&index);
    assert!(accepted_witness.is_some());
    // The next generation walks everything into its census; its first page
    // revisits the unchanged accepted rollout.
    let (index, walked, _, _, _, _) = step(index, 1, &[]);
    assert!(walked.snapshots.is_empty(), "{:?}", walked.snapshots);
    let census = |index: &ScanIndex| {
        index
            .traversal
            .as_ref()
            .expect("the census is open")
            .pending_candidates
            .iter()
            .map(|candidate| key(&candidate.path))
            .collect::<BTreeSet<_>>()
    };
    assert!(census(&index).contains(&key(&group[0])) && !census(&index).contains(&kb));
    // The older revision: a strict prefix of the accepted bytes, behind the
    // indexed extent the accepted body was read to.
    let older = rollout(BEHIND, Some("a"));
    assert!(behind_accepted.starts_with(&older) && older.len() < behind_accepted.len());
    fs::write(&behind, &older).unwrap();
    assert!(fs::metadata(&behind).unwrap().len() < index.files[&kb].size_bytes);
    c.write(NEW1, Some("a"));
    let link = c.sessions.join("held-link");
    std::os::unix::fs::symlink(c.scratch.join("absent"), &link).unwrap();
    // The fresh page: both hinted files, then census fill (the group).
    crate::snapshots::state_v2::release_collection_page_limit_for_test(&index);
    let (held_index, held, held_route, reads, before, _) =
        step(index, 3, &[c.path(NEW1), behind.clone()]);
    assert!(held.snapshots.is_empty(), "{:?}", held.snapshots);
    assert!(reads.is_empty(), "the held page reads no transcript");
    let (causes, _) = held.causes.summary(0);
    assert_eq!(causes[ownership::INVENTORY], 0);
    let walk = |index: &ScanIndex| index.traversal.clone().expect("the generation stays open");
    let assert_held_page = |before: &ScanIndex, after: &ScanIndex, owed: &BTreeSet<String>| {
        let (was, now) = (walk(before), walk(after));
        assert_eq!(
            (
                now.counts.unreadable_path_count,
                now.counts.ownership_incomplete_file_count
            ),
            (
                was.counts.unreadable_path_count,
                was.counts.ownership_incomplete_file_count
            ),
            "no synthetic count"
        );
        assert_eq!(now.residue.index_keys, was.residue.index_keys);
        assert!(
            !now.pending_directories.iter().any(|d| d.census_member),
            "no census directory is pending"
        );
        let hold = now
            .residue
            .codex_inventory_hold
            .clone()
            .expect("the held page is owed");
        assert_eq!(&hold.owed, owed);
        assert!(!hold.awaiting_directories && hold.refused_headers.is_empty());
        assert!(now.has_errors() && !now.has_unsettled_residue());
        assert!(
            !now.pending_candidates.is_empty(),
            "not the drain page: the census still waits"
        );
        assert!(retry_unarmed(after), "a held page arms no retry");
        hold
    };
    let mut owed = BTreeSet::from([key(&c.path(NEW1)), kb.clone()]);
    owed.extend(group.iter().map(|path| key(path)));
    let hold = assert_held_page(&before, &held_index, &owed);
    assert_eq!(
        hold.outside_roster.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([key(&c.path(NEW1))])
    );
    assert_eq!(witness(&held_index), accepted_witness);
    // A durable restart from the committed checkpoint keeps the hold and the
    // accepted witness.
    let mut held_index = held_index;
    let index = session.save_reload(&mut held_index);
    assert_eq!(inventory_hold_of(&index), Some(hold.clone()));
    assert_eq!(witness(&index), accepted_witness);
    let restarted = index.clone();
    // From here on, a page whose census visits only unchanged files (the
    // checkpointed group's members, the queued rollouts) must consume no byte
    // and start no first read, and every group member must be so visited.
    let group_keys = group.iter().map(|path| key(path)).collect::<BTreeSet<_>>();
    let mut unchanged = group_keys.clone();
    unchanged.extend(queued_paths.iter().map(|path| key(path)));
    let queue = |index: &ScanIndex| {
        index.traversal.as_ref().map_or_else(BTreeSet::new, |t| {
            t.pending_candidates
                .iter()
                .map(|candidate| key(&candidate.path))
                .collect::<BTreeSet<_>>()
        })
    };
    let mut unread = BTreeSet::new();
    let mut zero_read = |before: &ScanIndex, after: &ScanIndex, measured: (u64, u64)| {
        let visited = queue(before)
            .difference(&queue(after))
            .cloned()
            .collect::<BTreeSet<_>>();
        let members = visited
            .intersection(&group_keys)
            .cloned()
            .collect::<BTreeSet<_>>();
        if !members.is_empty() && visited.is_subset(&unchanged) {
            assert_eq!(
                measured,
                (0, 0),
                "{visited:?}: (consumed bytes, first reads)"
            );
            unread.extend(members);
        }
    };
    // An ordinary census page: the debt is unmoved, so nothing releases.
    let (index, quiet, _, _, before, measured) = step(index, 1, &[]);
    zero_read(&before, &index, measured);
    assert!(quiet.snapshots.is_empty(), "{:?}", quiet.snapshots);
    assert_eq!(inventory_hold_of(&index), Some(hold));
    // A second new rollout holds the next fresh page; the earlier debt,
    // unselected and partly outside the roster, is still owed with it.
    c.write(NEW2, Some("b"));
    let (index, rehold, _, _, before, measured) = step(index, 1, &[c.path(NEW2)]);
    zero_read(&before, &index, measured);
    assert!(rehold.snapshots.is_empty(), "{:?}", rehold.snapshots);
    owed.insert(key(&c.path(NEW2)));
    let hold = assert_held_page(&before, &index, &owed);
    assert_eq!(
        hold.outside_roster.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([key(&c.path(NEW1)), key(&c.path(NEW2))])
    );
    assert_eq!(witness(&index), accepted_witness);
    // Restored and grown past the accepted extent; the roster can list again.
    fs::write(
        &behind,
        [behind_accepted.clone(), turn(4).into_bytes()].concat(),
    )
    .unwrap();
    fs::remove_file(&link).unwrap();
    let mut index = index;
    let mut caught = BTreeSet::new();
    let mut pages = Vec::new();
    for _ in 0..30 {
        let (next, scan, routed, _, before, measured) = step(index, 1, &[]);
        zero_read(&before, &next, measured);
        index = next;
        assert!(
            inventory_hold_of(&index).is_none(),
            "the listed debt is released"
        );
        assert!(retry_unarmed(&index), "a release arms no retry");
        caught.extend(ids(&scan));
        if !scan.snapshots.is_empty() {
            pages.push((index.clone(), scan, routed));
        }
        if index.traversal.is_none() {
            break;
        }
    }
    assert!(index.traversal.is_none(), "the generation retired");
    assert_eq!(
        caught,
        [BEHIND, NEW1, NEW2]
            .map(String::from)
            .into_iter()
            .collect::<BTreeSet<_>>(),
        "every changed held session catches up"
    );
    let (_, cold, _, _, _) = page_observed_with_limit(
        &roots,
        ScanIndex::default(),
        Arc::default(),
        100,
        &slots,
        |_| {},
    );
    let cold = unique(cold);
    for (index, scan, routed) in &pages {
        let mut page_cold = cold.clone();
        page_cold
            .snapshots
            .retain(|item| ids(scan).contains(&item.source_session_id));
        money_oracle::assert_equivalent(&emitted(index, &page_cold), routed);
    }
    // The held page: no body for any held entity, the regressed one included,
    // and the accepted bodies and witnesses stand.
    let cold_of = |held: &[&str]| {
        let mut page = cold.clone();
        page.snapshots
            .retain(|item| held.contains(&item.source_session_id.as_str()));
        emitted(&restarted, &page)
    };
    let held_ids = [NEW1, GROUP, BEHIND];
    let mut held_route = held_route;
    held_route.accepted = accepted.accepted.clone();
    money_oracle::assert_no_smaller_reemit(
        BEHIND,
        &accepted,
        &held_route,
        &cold_of(&[BEHIND]),
        true,
    );
    money_oracle::assert_held_set(&held_ids, &accepted, &held_route, &cold_of(&held_ids));
    // Read bound: after the restart, each unchanged, checkpointed member of
    // the held group was visited on a page that read nothing.
    assert_eq!(unread, group_keys, "every group member's visit is measured");
    drop(session);
}

/// [regress] Header decoder refusal holds its filename owner, while ordinary
/// siblings publish exact money; funding the next attempt reaches the same EOF.
#[test]
fn unfunded_compressed_header_isolates_filename_owner_and_recovers() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let seed = ScanIndex::default();
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("a"));
    c.write(GAP, None);
    append(&c.path(MAIN), &(turn(3) + &header(MAIN, Some("switched"))));
    let compressed = c.path(MAIN).with_extension("jsonl.zst");
    fs::write(
        &compressed,
        zstd::stream::encode_all(&fs::read(c.path(MAIN)).unwrap()[..], 1).unwrap(),
    )
    .unwrap();
    fs::remove_file(c.path(MAIN)).unwrap();
    let (cold_index, cold, _, _, _) = page(
        &c,
        seed.clone(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    assert_eq!(cold.snapshots.len(), 4);
    let (session, prior) =
        StateV2ColdSession::publish(Source::Codex, &seed, &c.scratch.join("state"));
    // Ordinary part of the former incomplete-inventory hint fixture: no
    // body escapes the failed generation, and a new generation can recover.
    let mut injected = false;
    let (mut hinted, incomplete, delivery, _, _) = page_observed(
        &c,
        prior.clone(),
        Arc::new(sampled_scan::SharedCache::default()),
        |scan| {
            if !injected {
                scan.codex_join_inventory.as_mut().unwrap().complete = false;
                injected = true;
            }
        },
    );
    assert!(injected);
    assert!(incomplete.snapshots.is_empty());
    assert!(!incomplete.census_complete);
    assert!(
        delivery.0.lock().unwrap().is_empty(),
        "no body read on incomplete membership"
    );
    hinted.traversal = None;
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let occupied = OpenedInput::funded(File::open(&compressed).unwrap(), &cache)
        .unwrap()
        .unwrap();
    let (working, refused, _, _, logs) = page(&c, hinted, cache.clone());
    assert!(refused
        .snapshots
        .iter()
        .all(|item| item.source_session_id != MAIN));
    assert_eq!(
        refused.unreadable_path_count, 0,
        "resource refusal is not unreadable"
    );
    assert!(refused.ownership_incomplete_file_count > 0);
    assert!(
        serde_json::to_value(&refused.causes).unwrap()["contributions"][ownership::INVENTORY]
            .as_u64()
            .unwrap()
            > 0
    );
    assert_eq!(full_decodes(&logs), 0);
    let pending = working
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .find(|pending| pending.path == compressed)
        .expect("ordinary retry stays queued");
    assert!(pending.census_member);
    let mut cold_plain = cold.clone();
    cold_plain
        .snapshots
        .retain(|item| item.source_session_id != MAIN);
    let key = local_index_key(&compressed);
    let mut plain_cold_index = cold_index.clone();
    plain_cold_index.files.remove(&key);
    let mut plain_working = working.clone();
    plain_working.files.remove(&key);
    money_oracle::assert_equivalent(
        &emitted(&plain_cold_index, &cold_plain),
        &emitted(&plain_working, &refused),
    );
    let (index, posts) = working.checkpoint_with_captured_posts(&refused, &prior, "accept");
    assert_eq!(posts.len(), 1);
    occupied.close();
    assert_eq!(cache.cursor_reserved(), 0);
    // Reuse an ordinary funded header, then count only the body Full below.
    let mut directories = codex_file_join::DirectoryCensus::new();
    for root in c.roots() {
        directories.observe(&root, &fs::metadata(&root).unwrap());
    }
    let mut headers = codex_file_join::HeaderInventory::new(
        &c.roots(),
        &BTreeSet::from([local_index_key(&compressed)]),
        Some(&directories),
    );
    while !headers.step_encoded(&CodexTitleMetadata::default(), Some(&cache)) {}
    assert!(headers.complete);
    let before = index.clone();
    let mut raced_plain_append = false;
    let (working, funded, _, _, logs) = page_observed(&c, index, cache.clone(), |scan| {
        if scan.codex_join_prepared && !raced_plain_append {
            append(&c.path(OTHER), "{}\n");
            raced_plain_append = true;
        }
    });
    assert!(
        raced_plain_append,
        "ordinary plain append races the inventory boundary"
    );
    assert_eq!(
        full_decodes(&logs),
        1,
        "one funded body Full, no retry grant"
    );
    assert_eq!(funded.snapshots.len(), 1);
    assert!(
        working.files[&local_index_key(&compressed)].codex_counting_v2,
        "a funded Codex read uses V2"
    );
    let mut cold_main = cold;
    cold_main
        .snapshots
        .retain(|item| item.source_session_id == MAIN);
    let mut main_cold_index = cold_index.clone();
    main_cold_index.files.retain(|path, _| *path == key);
    let mut main_working = working.clone();
    main_working.files.retain(|path, _| *path == key);
    money_oracle::assert_equivalent(
        &emitted(&main_cold_index, &cold_main),
        &emitted(&main_working, &funded),
    );
    let (index, posts) = working.checkpoint_with_captured_posts(&funded, &before, "accept");
    assert_eq!(posts.len(), 1);
    assert_eq!(cache.cursor_reserved(), 0);
    // The deliberately raced plain append still needs its ordinary read;
    // this is not the unchanged carry/restart case exercised above.
    let before = index.clone();
    let (working, followup, _, _, _) = page(&c, index, cache);
    assert!(
        followup.snapshots.is_empty(),
        "the non-usage append creates no new money body"
    );
    let (_, posts) = working.checkpoint_with_captured_posts(&followup, &before, "accept");
    assert!(posts.is_empty(), "the raced append has no upload");
    drop(session);
}

/// [regress] An unchanged compressed member never groups a different-stem
/// plaintext rollout into a Strict hold or reads its compressed bytes again.
#[test]
fn different_stem_compressed_member_keeps_plain_singleton_publication() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("b"));
    c.write(GAP, None);
    let compressed = c.path(MAIN).with_extension("jsonl.zst");

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
    let (index, posts) = working.checkpoint_with_captured_posts(&first, &prior, "accept");
    assert_eq!(posts.len(), 1);
    // The observed provider compression path carries its durable physical
    // stamp. A generic first read alone does not promise header reuse.
    fs::write(
        &compressed,
        zstd::stream::encode_all(&fs::read(c.path(MAIN)).unwrap()[..], 1).unwrap(),
    )
    .unwrap();
    fs::remove_file(c.path(MAIN)).unwrap();
    let (_, carried_scan, carried_delivery, carried_bytes, carried_logs) =
        page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert!(carried_scan.snapshots.is_empty());
    assert!(carried_delivery.0.lock().unwrap().is_empty());
    assert_eq!(carried_bytes, 0);
    assert_eq!(full_decodes(&carried_logs), 0);
    let mut index = ScanIndex::load(session.path()).unwrap();
    let compressed_key = local_index_key(&compressed);
    let carried = serde_json::to_value(&index.files[&compressed_key]).unwrap();
    let plain = c
        .sessions
        .join(format!("rollout-2026-10-08T09-00-00-{MAIN}.jsonl"));
    fs::write(&plain, rollout(MAIN, Some("a"))).unwrap();
    append(&plain, &turn(3));
    e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
    let before = index.clone();
    let decoders = codex_zst_refusal_tests::activity().0;
    let (working, scan, _, _, logs) =
        page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
    assert_eq!(full_decodes(&logs), 0);
    assert_eq!(
        codex_zst_refusal_tests::activity().0,
        decoders,
        "unchanged compressed bytes are not read"
    );
    assert_eq!(
        serde_json::to_value(&working.files[&compressed_key]).unwrap(),
        carried
    );
    assert_eq!(scan.snapshots.len(), 1);
    assert_eq!(scan.snapshots[0].source_session_id, MAIN);
    let parked = c.scratch.join("compressed-cold-control");
    fs::rename(&compressed, &parked).unwrap();
    let (cold_index, mut cold, _, _, _) = page(
        &c,
        ScanIndex::default(),
        Arc::new(sampled_scan::SharedCache::default()),
    );
    fs::rename(&parked, &compressed).unwrap();
    cold.snapshots.retain(|item| item.source_session_id == MAIN);
    let (index, posts) = working.checkpoint_with_captured_posts(&scan, &before, "accept");
    assert_eq!(posts.len(), 1, "only the new plaintext usage publishes");
    assert_eq!(
        serde_json::to_value(&index.files[&compressed_key]).unwrap(),
        carried
    );
    let plain_key = local_index_key(&plain);
    let mut cold_index = cold_index;
    cold_index.files.retain(|path, _| *path == plain_key);
    let mut published_index = index;
    published_index.files.retain(|path, _| *path == plain_key);
    money_oracle::assert_equivalent(
        &emitted(&cold_index, &cold),
        &route(&published_index, &scan, posts),
    );
    drop(session);
}

/// [regress] A shed partial save commits no Tail head for a file whose entry
/// it does not keep, so the next page reads that file: a new rollout Full, an
/// appended one by Tail from its kept head. [money] Two accounts, a side call,
/// an evidence gap and (appended) a mid-session switch: the owed page's bodies
/// and placement equal a cold Full's. The appended Claude row is
/// `shed_save_keeps_an_appended_turn_owed_once`.
#[test]
fn shed_save_commits_heads_only_for_kept_entries() {
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for appended in [false, true] {
        let c = Corpus::new();
        let ids = [MAIN, OTHER, SIDE, GAP];
        c.write(MAIN, Some("a"));
        c.write(OTHER, Some("b"));
        // A native spawned side session under B, and an evidence gap.
        c.write(SIDE, Some("b"));
        c.write(GAP, None);
        let keys = ids.map(|id| local_index_key(&c.path(id)));
        let (_session, prior) = StateV2ColdSession::publish(
            Source::Codex,
            &ScanIndex::default(),
            &c.scratch.join("state"),
        );
        let page_on =
            |index: ScanIndex| page(&c, index, Arc::new(sampled_scan::SharedCache::default()));
        // A metadata-only head (an inventory observation) is not a read's
        // continuation and stays by design, as `codex_physical_matches` skips it.
        let heads = |index: &ScanIndex| {
            keys.iter()
                .map(|key| {
                    state_v2::load_head(index, key, REVISION)
                        .unwrap()
                        .filter(|head| !head.metadata_only)
                        .map(|head| head.body)
                })
                .collect::<Vec<_>>()
        };
        let mut before = prior;
        // How the owed page must read each file: a new one Full from 0, an
        // appended one by Tail from its committed end.
        let mut reads = vec![(DeliveryMode::Full, 0); ids.len()];
        if appended {
            let (working, first, ..) = page_on(before.clone());
            before = working
                .checkpoint_with_captured_posts(&first, &before, "accept")
                .0;
            for (read, id) in reads.iter_mut().zip(ids) {
                *read = (DeliveryMode::Tail, fs::metadata(c.path(id)).unwrap().len());
                append(&c.path(id), &turn(3));
            }
            // A mid-session switch: a contradicting creator.
            append(&c.path(MAIN), &header(MAIN, Some("switched")));
            e2_pipeline_scan_fixture::age_listing_for_test(&mut before);
        }
        let kept = heads(&before);
        assert!(kept.iter().all(|head| head.is_some() == appended));
        let (working, shed, ..) = page_on(before.clone());
        assert_eq!(shed.snapshots.len(), ids.len());
        let (mut index, _) = working.checkpoint_with_captured_posts(&shed, &before, "shed");
        assert_eq!(
            heads(&index),
            kept,
            "the shed save keeps each committed head"
        );
        e2_pipeline_scan_fixture::age_listing_for_test(&mut index);
        let before = index.clone();
        let (working, owed, delivery, ..) = page_on(index);
        assert_eq!(
            owed.snapshots.len(),
            ids.len(),
            "the next page reads every file"
        );
        // The read mode: a Full re-read of an appended file fails here.
        let mut delivered = delivery.0.lock().unwrap().clone();
        for read in reads {
            let at = delivered
                .iter()
                .position(|got| *got == read)
                .unwrap_or_else(|| panic!("missing read {read:?} in {delivered:?}"));
            delivered.remove(at);
        }
        assert!(delivered.is_empty(), "extra reads: {delivered:?}");
        let (index, posts) = working.checkpoint_with_captured_posts(&owed, &before, "accept");
        let (_, cold, ..) = page_on(ScanIndex::default());
        let cold = emitted(&index, &cold);
        assert_ne!(
            cold.snapshots[MAIN]["session_account_evidence"],
            cold.snapshots[OTHER]["session_account_evidence"],
            "two placements"
        );
        assert!(
            cold.snapshots[OTHER]["session_account_evidence"].is_object(),
            "tagged positive control"
        );
        assert!(
            cold.snapshots[GAP]["session_account_evidence"].is_null(),
            "evidence gap"
        );
        money_oracle::assert_equivalent(&cold, &route(&index, &owed, posts));
    }
}

/// [money] A paged fresh-plus-fill route equals cold Full across accounts,
/// a switch, a spawned side call and an evidence gap; restart reads no body.
#[test]
fn spare_fresh_page_capacity_preserves_money_and_quiet_restart() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // Codex creator conflicts are a negative control, not request windows.
    // Reuse the shared supported switch/side-call/gap and accepted-share
    // positive control; the native route below proves Codex slot row tags.
    let placement = money_oracle::placement_tests::placement_fixture();
    let mut placement_route = placement.clone();
    placement_route.mode = Mode::Ram;
    money_oracle::assert_equivalent(&placement, &placement_route);
    let mut moved = placement_route.clone();
    moved.snapshots.get_mut("main").unwrap()["model_usage"][0]["identity_parts"][0]
        ["account_identifier_hash"] = json!("b".repeat(64));
    assert!(
        std::panic::catch_unwind(|| money_oracle::assert_placement_equivalent(&placement, &moved))
            .is_err()
    );
    let _lock = DECODER_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    append(&c.path(MAIN), &header(MAIN, Some("switched")));
    append(&c.path(MAIN), &turn(3));
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("b"));
    c.write(GAP, None);
    for n in 1..=3 {
        c.write(
            &format!("019e5a00-0000-7000-8000-00000000000{n}"),
            Some(if n == 1 { "a" } else { "b" }),
        );
    }
    let hash = |kind: &str, account: &str| {
        let prefix = if kind == "account" {
            "user"
        } else {
            "workspace"
        };
        ottto_core::billing_identity_hash("openai", kind, &format!("synthetic-{prefix}-{account}"))
            .unwrap()
    };
    let slots = ["a", "b"].map(|account| {
        (
            hash("account", account),
            hash("workspace", account),
            crate::codex_scan_diagnostics::CREATOR_NAMED,
        )
    });
    let (cold_index, cold_scan, ..) = page_observed_with_limit(
        &c.roots(),
        ScanIndex::default(),
        Arc::default(),
        100,
        &slots,
        |_| {},
    );
    assert_eq!(cold_scan.snapshots.len(), 7);
    let (session, mut index) = StateV2ColdSession::publish(
        Source::Codex,
        &ScanIndex::default(),
        &c.scratch.join("state"),
    );
    ensure_bounded_traversal(
        SnapshotSource::Codex,
        &c.roots(),
        &mut index,
        NOW,
        BACKFILL_WINDOW_DAYS,
    );
    advance_bounded_directory_traversal(
        SnapshotSource::Codex,
        &mut index,
        BACKFILL_WINDOW_DAYS,
        None,
    );
    for candidate in &mut index.traversal.as_mut().unwrap().pending_candidates {
        candidate.watcher_hint = candidate.path == c.path(MAIN);
    }
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut scans = Vec::new();
    let mut consumed_sets = Vec::new();
    for fresh in [true, false] {
        let before = index.clone();
        let (working, scan, ..) =
            page_observed_with_limit(&c.roots(), index, cache.clone(), 4, &slots, |selected| {
                if !selected.codex_join_prepared {
                    assert_eq!(
                        selected
                            .index
                            .traversal
                            .as_ref()
                            .unwrap()
                            .codex_freshness_yield,
                        fresh
                    );
                    assert_eq!(selected.selected_flags.len(), if fresh { 4 } else { 3 });
                    if fresh {
                        assert_eq!(
                            selected.identified_candidates.front().unwrap().path,
                            c.path(MAIN)
                        );
                    }
                }
            });
        consumed_sets.push(
            scan.snapshots
                .iter()
                .map(|item| item.source_session_id.clone())
                .collect::<BTreeSet<_>>(),
        );
        index = working
            .checkpoint_with_captured_posts(&scan, &before, "accept")
            .0;
        scans.push(scan);
    }
    assert!(consumed_sets[0].is_disjoint(&consumed_sets[1]));
    let mut drained = scans.remove(0);
    drained.snapshots.extend(scans.remove(0).snapshots);
    drained.snapshots.sort_by_key(|item| {
        cold_scan
            .snapshots
            .iter()
            .position(|cold| cold.source_session_id == item.source_session_id)
            .unwrap()
    });
    let cold = emitted(&cold_index, &cold_scan);
    let paged = emitted(&index, &drained);
    assert_ne!(
        cold.snapshots[MAIN]["session_account_evidence"],
        cold.snapshots[OTHER]["session_account_evidence"]
    );
    let account_a = "019e5a00-0000-7000-8000-000000000001";
    assert!(cold.snapshots[account_a]["session_account_evidence"].is_object());
    assert!(cold.snapshots[OTHER]["session_account_evidence"].is_object());
    assert_ne!(
        cold.snapshots[account_a]["session_account_evidence"],
        cold.snapshots[OTHER]["session_account_evidence"],
        "two tagged accounts"
    );
    assert!(cold.snapshots[GAP]["session_account_evidence"].is_null());
    for route in [&cold_scan, &drained] {
        for item in &route.snapshots {
            let expected = match item.source_session_id.as_str() {
                MAIN | GAP => None,
                id if id == account_a => Some(hash("account", "a")),
                _ => Some(hash("account", "b")),
            };
            assert!(!item.model_usage.is_empty());
            for row in item.model_usage.iter().chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter()),
            ) {
                assert_eq!(
                    row.account_identifier_hash, expected,
                    "native Codex row placement"
                );
            }
        }
    }
    // Codex uses saved per-session bindings; the request-share ledger in
    // the shared switch control is Claude-specific. Compare the real Codex
    // bindings and exact accepted fingerprints instead of fabricating shares.
    let bindings = serde_json::to_value(&index.session_account_bindings).unwrap();
    assert_eq!(
        bindings,
        serde_json::to_value(&cold_index.session_account_bindings).unwrap()
    );
    assert!(drained.snapshots.iter().all(|item| index
        .accepted_snapshot_fingerprints
        .contains(&item.snapshot_fingerprint)));
    money_oracle::assert_equivalent(&cold, &paged);
    let mut wrong = paged.clone();
    wrong.snapshots.get_mut(OTHER).unwrap()["model_usage"][0]["account_identifier_hash"] =
        json!(hash("account", "a"));
    assert!(
        std::panic::catch_unwind(|| money_oracle::assert_placement_equivalent(&cold, &wrong))
            .is_err()
    );
    let index = ScanIndex::load(session.path()).unwrap();
    assert_eq!(
        bindings,
        serde_json::to_value(&index.session_account_bindings).unwrap()
    );
    assert_quiet(&c, index, &paged);
}

/// [money] The first-import page total moves only which page reads a file.
/// One corpus (two accounts, a mid-session switch, a spawned side call, an
/// evidence gap and tagged rows, plus small sessions: two exactly at the
/// singleton threshold, one a byte above it) drains under scaled limits on
/// four routes: ordinary pages, first-import pages, the crossing (two
/// first-import pages, a restart from the durable store, then ordinary
/// pages) and the resume (two ordinary pages saved as an older process
/// would, a restart from the durable store, then first-import pages). Each
/// route posts every body once, its exact ACK ledger covers
/// them, and its bodies equal cold Full in totals and placement (swapped
/// accounts fail the comparator). The first-import route takes fewer pages;
/// the threshold-exact files stay singletons and the threshold+1 file is
/// cursor work on every route. A quiet restart reads no byte and a later
/// append re-emits no smaller body.
#[test]
fn first_import_page_total_moves_pages_not_money() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    // A failure is caught inside the guard and resumed after it is dropped,
    // so it never poisons the decoder lock for other tests.
    let outcome = {
        let _lock = DECODER_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::panic::catch_unwind(first_import_page_total_rows)
    };
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn first_import_page_total_rows() {
    const LATER_PASS: &str = "2026-10-07T13:00:00Z";
    let c = Corpus::new();
    c.write(MAIN, Some("a"));
    append(&c.path(MAIN), &header(MAIN, Some("switched")));
    append(&c.path(MAIN), &turn(3));
    c.write(OTHER, Some("b"));
    c.write(SIDE, Some("b"));
    c.write(GAP, None);
    let small = |n: u32| format!("019e5a00-0000-7000-8000-0000000001{n:02x}");
    let sized = |id: &str, account: &str, last: u64| {
        fs::write(c.path(id), header(id, Some(account)) + &turn(1) + &turn(last)).unwrap();
    };
    let (exact_a, exact_b, above) = (small(1), small(2), small(3));
    sized(&exact_a, "a", 10);
    sized(&exact_b, "b", 10);
    sized(&above, "a", 20);
    let fillers = (4..=6).map(small).collect::<Vec<_>>();
    for (n, id) in fillers.iter().enumerate() {
        c.write(id, Some(if n % 2 == 0 { "a" } else { "b" }));
    }
    let len = |id: &str| fs::metadata(c.path(id)).unwrap().len();
    let threshold = len(&exact_a);
    assert_eq!(len(&exact_b), threshold, "two reads exactly at the threshold");
    assert_eq!(len(&above), threshold + 1, "one a byte above it");
    let ids = [MAIN, OTHER, SIDE, GAP]
        .map(str::to_owned)
        .into_iter()
        .chain([exact_a.clone(), exact_b.clone(), above.clone()])
        .chain(fillers.iter().cloned())
        .collect::<Vec<_>>();
    let cursor_files = ids.iter().filter(|id| len(id) > threshold).count() as u64;
    assert!(ids.len() as u64 - cursor_files >= 5, "a small-file tail");
    let account = |id: &str| match id {
        MAIN | GAP => None,
        OTHER | SIDE => Some("b"),
        id if id == exact_b || id == fillers[1] => Some("b"),
        _ => Some("a"),
    };
    let hash = |kind: &str, account: &str| {
        let prefix = if kind == "account" {
            "user"
        } else {
            "workspace"
        };
        ottto_core::billing_identity_hash("openai", kind, &format!("synthetic-{prefix}-{account}"))
            .unwrap()
    };
    let slots = named_creator_slots();
    let (cold_index, cold_scan, ..) = page_observed_with_limit(
        &c.roots(),
        ScanIndex::default(),
        Arc::default(),
        100,
        &slots,
        |_| {},
    );
    assert_eq!(cold_scan.snapshots.len(), ids.len());
    let cold = emitted(&cold_index, &cold_scan);
    let position = |id: &str| {
        cold_scan
            .snapshots
            .iter()
            .position(|item| item.source_session_id == id)
            .unwrap()
    };
    let mut page_counts = BTreeMap::new();
    // (route, switch page, upgraded). Not upgraded: the first `switch` pages
    // read the first-import total and the rest the ordinary one (MAX: every
    // page). Upgraded: the first `switch` pages are ordinary, as saved by a
    // process without the larger total, and the rest resume at it. The
    // first-import route runs last: its later append grows the shared corpus.
    for (arm, switch, upgraded) in [
        ("ordinary", 0, false),
        ("crossing", 2, false),
        ("resume", 2, true),
        ("first-import", usize::MAX, false),
    ] {
        assert_eq!(len(&exact_a), threshold, "{arm}: the corpus cold read");
        let store = crate::test_scratch::ScratchDir::canonical(&format!("first-import-{arm}"));
        let dir = fs::canonicalize(store.as_ref()).unwrap().join("state");
        crate::test_scratch::create_private_dir(&dir).unwrap();
        let (session, index) =
            StateV2ColdSession::publish(Source::Codex, &ScanIndex::default(), &dir);
        let (index, mut scans, posts, pages, started) =
            crate::snapshots::with_test_limits_for_test(1 << 20, threshold, 64, || {
                let mut index = index;
                let mut cache = Arc::new(sampled_scan::SharedCache::default());
                let (mut scans, mut posts, mut started) = (Vec::new(), Vec::new(), 0);
                let mut emitted_ids = BTreeMap::<String, usize>::new();
                let mut pages = 0;
                while emitted_ids.len() < ids.len() {
                    pages += 1;
                    assert!(pages <= 48, "{arm}: the corpus drains: {emitted_ids:?}");
                    if switch == 2 && pages == 3 {
                        // A restart between pages: the durable store, a new
                        // process cache, and the flag prepare sets again.
                        // Resumed, the progress saved at the ordinary total
                        // continues at the first-import total.
                        started += cache.counters_for_test().jobs_started;
                        index = ScanIndex::load(session.path()).unwrap();
                        assert!(!index.first_import_pending, "{arm}: never saved");
                        cache = Arc::default();
                    }
                    let first_import = if upgraded {
                        pages > switch
                    } else {
                        pages <= switch
                    };
                    index.first_import_pending = first_import;
                    let before = index.clone();
                    let (working, scan, ..) = page_observed_with_limit(
                        &c.roots(),
                        index,
                        cache.clone(),
                        100,
                        &slots,
                        |page| assert_eq!(page.codex_page.first_import(), first_import, "{arm}"),
                    );
                    let (next, page_posts) =
                        working.checkpoint_with_captured_posts(&scan, &before, "accept");
                    index = next;
                    posts.extend(page_posts);
                    for item in &scan.snapshots {
                        *emitted_ids
                            .entry(item.source_session_id.clone())
                            .or_default() += 1;
                    }
                    scans.push(scan);
                }
                assert!(
                    emitted_ids.values().all(|count| *count == 1),
                    "{arm}: every session emitted once: {emitted_ids:?}"
                );
                started += cache.counters_for_test().jobs_started;
                (index, scans, posts, pages, started)
            });
        page_counts.insert(arm, pages);
        if !matches!(arm, "crossing" | "resume") {
            assert_eq!(
                started, cursor_files,
                "{arm}: only the files above the threshold are cursor work"
            );
        }
        let mut drained = scans.remove(0);
        for scan in scans {
            drained.snapshots.extend(scan.snapshots);
        }
        drained
            .snapshots
            .sort_by_key(|item| position(&item.source_session_id));
        // The actual POSTs carry every body once, each exactly ACKed.
        let actual = route(&index, &drained, posts);
        assert_eq!(actual.accepted.len(), ids.len(), "{arm}: exact ACK ledger");
        let mut paged = emitted(&index, &drained);
        paged.accepted = actual.accepted.clone();
        money_oracle::assert_equivalent(&cold, &paged);
        assert_eq!(
            serde_json::to_value(&index.session_account_bindings).unwrap(),
            serde_json::to_value(&cold_index.session_account_bindings).unwrap(),
            "{arm}: saved session bindings"
        );
        for item in &drained.snapshots {
            let expected = account(&item.source_session_id).map(|name| hash("account", name));
            assert!(!item.model_usage.is_empty(), "{arm}");
            for row in item.model_usage.iter().chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| bucket.model_usage.iter()),
            ) {
                assert_eq!(row.account_identifier_hash, expected, "{arm}: row placement");
            }
        }
        let mut wrong = paged.clone();
        wrong.snapshots.get_mut(OTHER).unwrap()["model_usage"][0]["account_identifier_hash"] =
            json!(hash("account", "a"));
        assert!(
            std::panic::catch_unwind(|| money_oracle::assert_placement_equivalent(&cold, &wrong))
                .is_err(),
            "{arm}: the comparator sees a swapped account"
        );
        if arm != "first-import" {
            continue;
        }
        // A quiet restart while Codex still imports: no byte, no body.
        let mut restored = ScanIndex::load(session.path()).unwrap();
        restored.first_import_pending = true;
        let (restored, _) = assert_quiet(&c, restored, &paged);
        // A later append: the Tail re-emits no smaller body than cold Full.
        append(&c.path(&exact_a), &turn(3));
        let mut index = restored;
        let mut grown = None;
        for _ in 0..8 {
            index.first_import_pending = true;
            let before = index.clone();
            let (working, scan, ..) = page_observed_hinted_at(
                &c.roots(),
                index,
                Arc::default(),
                100,
                &slots,
                &[c.path(&exact_a)],
                LATER_PASS,
                |_| {},
            );
            index = working
                .checkpoint_with_captured_posts(&scan, &before, "accept")
                .0;
            assert!(
                scan.snapshots
                    .iter()
                    .all(|item| item.source_session_id == exact_a),
                "only the grown session"
            );
            if !scan.snapshots.is_empty() {
                grown = Some(scan);
                break;
            }
        }
        let after = grown.expect("the append is read");
        assert_eq!(after.snapshots.len(), 1, "one Tail body");
        let (_, mut cold_after, ..) = page_observed_at(
            &c.roots(),
            ScanIndex::default(),
            Arc::default(),
            100,
            &slots,
            LATER_PASS,
            |_| {},
        );
        cold_after
            .snapshots
            .retain(|item| item.source_session_id == exact_a);
        money_oracle::assert_no_smaller_reemit(
            &exact_a,
            &paged,
            &emitted(&index, &after),
            &emitted(&index, &cold_after),
            false,
        );
    }
    assert!(
        page_counts["first-import"] < page_counts["ordinary"],
        "{page_counts:?}"
    );
}

mod sidecar_reuse_transition {
    use super::*;
    include!("../sources/codex/sidecar/reuse_transition.rs");
}

mod removed_root_transition {
    use super::*;
    include!("../discovery/removed_root_transition.rs");
}
