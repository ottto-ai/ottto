// Compare emitted upload envelopes; inspect pre-finalization candidates only to
// prove ledger no-ops. All inputs are synthetic. Dispatch overlays this harness.
use super::*;
use serde_json::Value;

fn supported(name: &str) -> bool {
    if !crate::heap_layout_bound::layout_supported() {
        println!("MONEY_EQUIVALENCE {name} UNEXECUTED: native retained layout unavailable");
        return false;
    }
    true
}

fn corpus(name: &str) -> Corpus {
    // A shared absolute root gives base and candidate identical input paths.
    // No PID, wall clock or random IDs; raw within-build bodies stay exact.
    let base = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| test_dir("money-equivalence"))
        .join(name);
    if base.exists() {
        std::fs::remove_dir_all(&base).unwrap();
    }
    let root = base.join("projects");
    let support = base.join("support");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::create_dir_all(support.join("snapshots")).unwrap();
    std::fs::write(
        support.join("snapshots/claude_code-reemission-exclusions.txt"),
        "# synthetic\n",
    )
    .unwrap();
    Corpus {
        base,
        root,
        support,
        births: BTreeMap::new(),
    }
}

// Pin physical input clocks rather than deleting volatile fields from uploads.
fn input_clock(path: &Path) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_793_084_400))
        .unwrap();
}

/// Save the exact synthetic JSONL inputs, separately from emitted bodies.
/// CI compares these too: a generator drift cannot masquerade as reader drift.
fn save_inputs(c: &Corpus) {
    fn walk(base: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(base, &path, files);
            } else if path.extension().is_some_and(|e| e == "jsonl") {
                files.insert(
                    path.strip_prefix(base)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                    std::fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(&c.base, &c.base, &mut files);
    assert!(!files.is_empty());
    if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
        std::fs::create_dir_all(&out).unwrap();
        let path = PathBuf::from(out)
            .join(c.base.file_name().unwrap())
            .with_extension("inputs");
        let mut saved = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        writeln!(saved, "{}", serde_json::to_string(&files).unwrap()).unwrap();
    }
}

// Retain the actual emitted items: SnapshotItem intentionally has no wire
// deserializer, and production hashes must be recomputed from production types.
struct ReceiptBody {
    raw: Vec<u8>,
    source: SnapshotSource,
    items: Vec<SnapshotItem>,
}

impl ReceiptBody {
    fn cross_build(&self) -> Vec<u8> {
        let envelope = |bytes: &[u8]| {
            let mut wire: Value = serde_json::from_slice(bytes).unwrap();
            assert_eq!(wire["source"], self.source.api_slug());
            for snapshot in wire["snapshots"].as_array_mut().unwrap() {
                let item = self
                    .items
                    .iter()
                    .find(|item| snapshot["snapshot_fingerprint"] == item.snapshot_fingerprint)
                    .expect("wire snapshot must have its emitted production item");
                let raw = snapshot.clone();
                let mut raw_item = raw.as_object().unwrap().clone();
                raw_item.remove("semantic_envelope").unwrap();
                assert_eq!(Value::Object(raw_item), serde_json::to_value(item).unwrap());
                // These fixtures upload with this exact policy. Check the wire
                // before using it rather than silently assuming a default.
                let policy = SnapshotUploadPolicy::default();
                assert_eq!(
                    raw["semantic_envelope"],
                    serde_json::to_value(crate::snapshots::snapshot_semantic_envelope(
                        self.source,
                        item,
                        policy,
                    ))
                    .unwrap(),
                );
                let mut cross_item = item.clone();
                cross_item.source_file_fingerprint = Some("physical-identity:excluded".into());
                snapshot["source_file_fingerprint"] = json!(cross_item.source_file_fingerprint);
                // Calls the same revision v1/v2 functions as real wire emission.
                snapshot["semantic_envelope"] = serde_json::to_value(
                    crate::snapshots::snapshot_semantic_envelope(self.source, &cross_item, policy),
                )
                .unwrap();
                assert_cross_build_scope(&raw, snapshot);
            }
            canonical(&wire)
        };
        if self.source == SnapshotSource::Pi && self.items.is_empty() {
            assert_eq!(self.raw, b"[]", "quarantine emits no envelope");
            self.raw.clone()
        } else if self.source == SnapshotSource::ClaudeCode {
            // Claude's real uploader returns a sequence of encoded envelopes.
            let batches: Vec<Vec<u8>> = serde_json::from_slice(&self.raw).unwrap();
            canonical(
                &batches
                    .iter()
                    .map(|body| envelope(body))
                    .collect::<Vec<_>>(),
            )
        } else {
            envelope(&self.raw)
        }
    }
}

fn assert_cross_build_scope(raw: &Value, cross: &Value) {
    let mut restored = cross.clone();
    // Assert existing paths: normalization must never add/delete fields or
    // permit any other component, content hash, money or ordering drift.
    for path in [
        "/source_file_fingerprint",
        "/semantic_envelope/revision_hash",
        "/semantic_envelope/revision_v2_hash",
    ] {
        *restored
            .pointer_mut(path)
            .expect("existing cross-build path") =
            raw.pointer(path).expect("existing raw path").clone();
    }
    assert_eq!(
        &restored, raw,
        "cross-build body changed outside identity paths"
    );
}

fn receipt(name: &str, bodies: &[ReceiptBody]) {
    assert!(!bodies.is_empty(), "zero emitted bodies is no proof");
    let bytes = serde_json::to_vec(&bodies.iter().map(|b| &b.raw).collect::<Vec<_>>()).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let cross = serde_json::to_vec(
        &bodies
            .iter()
            .map(ReceiptBody::cross_build)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let cross_digest = format!("{:x}", Sha256::digest(&cross));
    if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
        let out = PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(format!("{name}.json")), &bytes).unwrap();
        std::fs::write(out.join(format!("{name}.sha256")), &digest).unwrap();
        std::fs::write(out.join(format!("{name}.cross-build.json")), &cross).unwrap();
        std::fs::write(
            out.join(format!("{name}.cross-build.sha256")),
            &cross_digest,
        )
        .unwrap();
    }
    println!(
        "MONEY_EQUIVALENCE {name} VERIFIED bytes={} sha256={digest} cross_build_sha256={cross_digest}",
        bytes.len()
    );
}

/// The disk arm's state directory (#806): the committed scan index and,
/// beside it, the real durable store, under a test-held single-writer lock
/// (#801). Every arm loads the SAME committed index from here. It is not an
/// ancestor of the corpus support dir, so the RAM and cold arms hold no
/// state-directory writer, exactly as before.
struct Disk {
    dir: PathBuf,
    index: PathBuf,
}
impl Disk {
    fn new(c: &Corpus) -> Self {
        let dir = c.base.join("durable-state");
        std::fs::create_dir_all(&dir).unwrap();
        crate::locked_state_dir::test_locks::hold(&dir);
        Self {
            index: dir.join("scan-index.json"),
            dir,
        }
    }
    fn begin(&self, owner: &E2ScanFixture, source: SnapshotSource) {
        owner.begin_durable(source, &self.dir, &self.index);
    }
    /// A new owner: a restarted process with an empty RAM cache, whose pass
    /// begins on the store as the daemon's does.
    fn owner(&self, source: SnapshotSource) -> E2ScanFixture {
        let owner = E2ScanFixture::default();
        self.begin(&owner, source);
        owner
    }
    /// The daemon's commit: save the index, then the production post-save
    /// record write and GC for this owner. Returns the index as the next
    /// process loads it.
    fn commit(
        &self,
        cache: &crate::snapshots::sampled_scan::SharedCache,
        source: SnapshotSource,
        index: &mut ScanIndex,
    ) -> ScanIndex {
        index.save(&self.index).unwrap();
        crate::snapshots::durable_after_save_and_retire(
            cache,
            &self.dir,
            source,
            index,
            &self.index,
        );
        ScanIndex::load(&self.index).unwrap()
    }
    fn records(&self) -> usize {
        std::fs::read_dir(crate::durable_tail_store::store_dir_for_index(&self.index))
            .map_or(0, |entries| entries.count())
    }
    /// Every record file's bytes, generation stamp included.
    fn record_bytes(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        std::fs::read_dir(crate::durable_tail_store::store_dir_for_index(&self.index))
            .unwrap()
            .map(|entry| {
                let path = entry.unwrap().path();
                let bytes = std::fs::read(&path).unwrap();
                (path, bytes)
            })
            .collect()
    }
}

/// This owner's restore counters: (attempts, restored, ineligible classes).
fn durable_restores(
    cache: &crate::snapshots::sampled_scan::SharedCache,
    source: SnapshotSource,
) -> (u64, u64, BTreeMap<&'static str, u64>) {
    let (counters, _) = cache
        .durable_counters(source)
        .expect("the owner began a durable pass");
    (
        counters.restore_attempts,
        counters.restored,
        counters.ineligible,
    )
}

/// The warm owner reads Full and commits; its saved index is every arm's
/// prior, and its records are the disk arm's restore source.
fn warm_claude(c: &Corpus, disk: &Disk) -> (E2ScanFixture, ScanIndex) {
    let scanner = E2ScanFixture::default();
    disk.begin(&scanner, SnapshotSource::ClaudeCode);
    let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
    warm.enrich(c);
    warm.finish();
    let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
    assert!(disk.records() > 0, "the warm owner persists its records");
    (scanner, prior)
}

/// Three arms over the SAME prior index and physical files: the retained
/// RAM owner, a cold Full, and the disk arm (a new owner that restores the
/// last commit's records from the real store, then Tails).
fn compare_claude(
    c: &Corpus,
    retained: &E2ScanFixture,
    disk: &Disk,
    prior: ScanIndex,
    mode: (usize, usize, usize),
) -> ReceiptBody {
    let restart = disk.owner(SnapshotSource::ClaudeCode);
    compare_claude_pages(
        c,
        claude_pages(
            c,
            retained,
            &restart,
            [prior.clone(), prior.clone(), prior],
            mode,
            mode,
        ),
    )
}

fn claude_pages(
    c: &Corpus,
    retained: &E2ScanFixture,
    restart: &E2ScanFixture,
    [tail_prior, full_prior, disk_prior]: [ScanIndex; 3],
    mode: (usize, usize, usize),
    disk_mode: (usize, usize, usize),
) -> [Page; 3] {
    save_inputs(c);
    let tail = c.raw(retained, tail_prior, 100, true, &[]);
    assert_eq!(
        tail.modes, mode,
        "must exercise the named retained acquisition"
    );
    let full = c.raw(&E2ScanFixture::default(), full_prior, 100, true, &[]);
    assert_eq!(
        full.modes.1 + full.modes.2,
        0,
        "cold arm cannot reuse a reduction"
    );
    let disk = c.raw(restart, disk_prior, 100, true, &[]);
    assert_eq!(
        disk.modes, disk_mode,
        "disk arm must exercise the named restored acquisition"
    );
    assert_eq!(
        durable_restores(&disk.cache, SnapshotSource::ClaudeCode).1,
        (disk_mode.1 + disk_mode.2) as u64,
        "every reused disk-arm copy comes from the durable store"
    );
    [tail, full, disk]
}

fn finish_claude_pages(c: &Corpus, pages: &mut [Page; 3]) {
    for page in pages {
        page.enrich(c); // attach, side calls, identity reconcile and emission
        page.finish(); // policy/body witnesses/holds, as in the real pipeline
    }
}

fn compare_claude_pages(c: &Corpus, mut pages: [Page; 3]) -> ReceiptBody {
    finish_claude_pages(c, &mut pages);
    compare_claude_uploads(&pages)
}

fn compare_claude_uploads(pages: &[Page; 3]) -> ReceiptBody {
    let [tail, full, disk] = pages;
    let (a, wire_a, _) = upload(&tail.scan.snapshots, &mut e2_progress(), ack);
    let (b, wire_b, _) = upload(&full.scan.snapshots, &mut e2_progress(), ack);
    let (d, wire_d, _) = upload(&disk.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(a.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(b.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(d.unwrap(), ResumableUploadResult::Completed);
    assert!(!wire_a.is_empty(), "fixture must reach real upload");
    assert_eq!(wire_a, wire_b, "emitted full envelopes differ");
    assert_eq!(
        wire_d, wire_b,
        "disk-restored envelopes differ from cold Full"
    );
    assert_eq!(
        wire_d, wire_a,
        "disk-restored envelopes differ from the RAM arm"
    );
    assert_eq!(disk.scan.snapshots.len(), full.scan.snapshots.len());
    for ((a, b), d) in tail
        .scan
        .snapshots
        .iter()
        .zip(&full.scan.snapshots)
        .zip(&disk.scan.snapshots)
    {
        assert_eq!(
            snapshot_upload_body_witness(a),
            snapshot_upload_body_witness(b)
        );
        assert_eq!(
            snapshot_upload_body_witness(d),
            snapshot_upload_body_witness(b)
        );
    }
    assert_eq!(
        Sha256::digest(canonical(&wire_a)),
        Sha256::digest(canonical(&wire_b))
    );
    assert_eq!(
        Sha256::digest(canonical(&wire_d)),
        Sha256::digest(canonical(&wire_b))
    );
    ReceiptBody {
        raw: canonical(&wire_a),
        source: SnapshotSource::ClaudeCode,
        items: tail.scan.snapshots.clone(),
    }
}

fn claude_case(name: &str) {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let mut c = corpus(name);
        if name == "side_owner_directory_unlisted" {
            let hidden = c
                .root
                .join("unlisted")
                .join(ROOT)
                .join("subagents/agent-unlisted.jsonl");
            std::fs::create_dir_all(hidden.parent().unwrap()).unwrap();
            std::fs::write(&hidden, line(ROOT, "hidden-owner", AT, 20)).unwrap();
            input_clock(&hidden);
            // A real owner file exists, but its directory is outside this
            // page's listed root. Trace ownership must not invent its body.
            c.root = c.root.join("listed");
            std::fs::create_dir_all(&c.root).unwrap();
        }
        let path = c.root(ROOT, &line(ROOT, "r1", AT, 10));
        if name == "side_owner" {
            let agent = c.agent(0, &line(ROOT, "agent", AT, 20));
            input_clock(&agent);
        }
        input_clock(&path);
        if name == "failed_then_healthy_telemetry" {
            // A distinct finalized baseline keeps the failed estimate from
            // being suppressed as an unchanged body before real upload.
            c.evidence(&[api("r1", 10, 100)], &[]);
        }
        let disk = Disk::new(&c);
        let (scanner, prior) = warm_claude(&c, &disk);
        let mut mode = (0, 1, 0);
        match name {
            "progressive_response" => append(&path, &line(ROOT, "r1", AT, 30)),
            "duplicate_request_ids" => append(
                &path,
                &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", AT, 20)),
            ),
            "resolver_conflict" => append(
                &path,
                &line(ROOT, "r1", AT, 10).replace("claude-haiku-4-5", "claude-sonnet-4-5"),
            ),
            "quiet_sidecar_growth" => {
                c.evidence(&[api("r1", 10, 100), api("late-side", 5, 50)], &[]);
                mode = (0, 0, 1);
            }
            "side_owner" => {
                c.evidence(
                    &[
                        api("r1", 10, 100),
                        api("agent", 20, 200),
                        api("side", 5, 50),
                    ],
                    &[trace("side", "000")],
                );
                mode = (0, 0, 2);
            }
            "side_without_owner" | "side_owner_directory_unlisted" => {
                let traces = if name == "side_owner_directory_unlisted" {
                    vec![trace("side", "unlisted")]
                } else {
                    vec![]
                };
                c.evidence(&[api("r1", 10, 100), api("side", 5, 50)], &traces);
                mode = (0, 0, 1);
            }
            "failed_then_healthy_telemetry" => {
                // Incomplete telemetry on a live session publishes a token-only
                // estimate; healthy telemetry later replaces its money fields.
                let bad = c
                    .support
                    .join("local-otel/claude-code-effort")
                    .join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes())));
                std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
                std::fs::write(&bad, "{broken-json\n").unwrap();
                // Preserve the failed phase's unpaired API-sidecar input.
                let trace = c
                    .support
                    .join("local-otel/claude-code-trace-ownership")
                    .join(format!("{:x}.jsonl", Sha256::digest(ROOT.as_bytes())));
                std::fs::remove_file(trace).unwrap();
                let health = crate::claude_local_otel::load_claude_api_request_evidence_report(
                    &c.support,
                    [ROOT.to_owned()],
                )
                .health;
                assert_eq!(health.malformed_lines, 1);
                assert!(
                    !health.is_complete(),
                    "failed telemetry decode must be witnessed"
                );
                fn counts(item: &SnapshotItem) -> [u64; 8] {
                    [
                        item.request_count,
                        item.input_tokens,
                        item.output_tokens,
                        item.cache_read_tokens,
                        item.cache_creation_5m_tokens,
                        item.cache_creation_1h_tokens,
                        item.unattributed_total_tokens,
                        item.reasoning_output_tokens,
                    ]
                }
                let finish_phase = |pages: &mut [Page; 3], complete: bool| {
                    for page in pages {
                        assert_eq!(page.scan.snapshots.len(), 1, "must scan the live session");
                        page.enrich(&c);
                        assert!(
                            page.disposition
                                .quarantined_fingerprints(&page.scan.snapshots)
                                .is_empty(),
                            "live estimates must not be request-owned quarantined"
                        );
                        page.finish();
                        literal(page);
                        assert_eq!(page.scan.snapshots.len(), 1);
                        let item = &page.scan.snapshots[0];
                        assert_eq!(item.source_session_id, ROOT);
                        assert_eq!(counts(item), [1, 10, 10, 3, 5, 2, 0, 0]);
                        assert_eq!(item.telemetry_owned_complete, Some(complete));
                        let expected_cost = complete.then_some("0.0001");
                        if complete {
                            let cost = item.cost.as_ref().expect("reported item cost");
                            assert_eq!(cost.total_cost_usd.as_deref(), expected_cost);
                            assert_eq!(cost.evidence_source, "claude_code_api_request");
                            assert!(cost.input_cost_usd.is_none());
                            assert!(cost.output_cost_usd.is_none());
                            assert!(cost.cache_read_cost_usd.is_none());
                            assert!(cost.cache_creation_cost_usd.is_none());
                        } else {
                            assert!(item.cost.is_none(), "unpriced estimate is never $0");
                        }
                        assert_eq!(item.model_usage.len(), 1);
                        assert_eq!(item.usage_buckets.len(), 1);
                        assert_eq!(item.usage_buckets[0].model_usage.len(), 1);
                        for row in item.model_usage.iter().chain(
                            item.usage_buckets
                                .iter()
                                .flat_map(|bucket| &bucket.model_usage),
                        ) {
                            assert_eq!(
                                [
                                    row.request_count,
                                    row.input_tokens,
                                    row.output_tokens,
                                    row.cache_read_tokens,
                                    row.cache_creation_5m_tokens,
                                    row.cache_creation_1h_tokens,
                                    row.unattributed_total_tokens,
                                    row.reasoning_output_tokens
                                ],
                                counts(item),
                            );
                            assert_eq!(row.cost_usd.as_deref(), expected_cost);
                            assert!(row.input_cost_usd.is_none());
                            assert!(row.output_cost_usd.is_none());
                            assert!(row.cache_read_cost_usd.is_none());
                            assert!(row.cache_creation_cost_usd.is_none());
                            assert_eq!(
                                row.selector_context
                                    .get("request_usage_origin")
                                    .map(String::as_str),
                                complete.then_some("telemetry_matched"),
                            );
                        }
                    }
                };
                let mut failed = claude_pages(
                    &c,
                    &scanner,
                    &disk.owner(SnapshotSource::ClaudeCode),
                    [prior.clone(), prior.clone(), prior],
                    (0, 0, 1),
                    (0, 0, 1),
                );
                finish_phase(&mut failed, false);
                let failed_wire = compare_claude_uploads(&failed);
                let failed_items = failed.each_ref().map(|page| page.scan.snapshots[0].clone());
                // Continue each arm from its own finished failed-step index.
                // The retained scanner survives; the Full scanner is fresh.
                // The disk arm's owner commits its failed step, and another
                // new owner restores that record, not the warm page's.
                let [tail_failed, full_failed, mut disk_failed] = failed;
                let disk_prior = disk.commit(
                    &disk_failed.cache,
                    SnapshotSource::ClaudeCode,
                    &mut disk_failed.index,
                );
                c.evidence(&[api("r1", 10, 100)], &[]);
                let mut healthy = claude_pages(
                    &c,
                    &scanner,
                    &disk.owner(SnapshotSource::ClaudeCode),
                    [tail_failed.index, full_failed.index, disk_prior],
                    (0, 0, 1),
                    (0, 0, 1),
                );
                finish_phase(&mut healthy, true);
                let healthy_wire = compare_claude_uploads(&healthy);
                for (before, after) in failed_items.iter().zip(&healthy) {
                    let after = &after.scan.snapshots[0];
                    assert_eq!(counts(before), counts(after), "replacement conserves usage");
                    assert_ne!(before.cost, after.cost);
                    assert_ne!(
                        before.telemetry_owned_complete,
                        after.telemetry_owned_complete
                    );
                    assert_ne!(
                        before.model_usage[0]
                            .selector_context
                            .get("request_usage_origin"),
                        after.model_usage[0]
                            .selector_context
                            .get("request_usage_origin"),
                    );
                }
                assert_ne!(
                    failed_wire.raw, healthy_wire.raw,
                    "reported money replaces the estimate"
                );
                receipt(name, &[failed_wire, healthy_wire]);
                return;
            }
            _ => unreachable!(),
        }
        if mode.1 > 0 {
            input_clock(&path);
        }
        receipt(name, &[compare_claude(&c, &scanner, &disk, prior, mode)]);
    });
}

macro_rules! claude_tests {
    ($($name:ident),+ $(,)?) => { $(#[test] fn $name() { claude_case(stringify!($name)); })+ };
}
claude_tests!(
    progressive_response,
    duplicate_request_ids,
    resolver_conflict,
    quiet_sidecar_growth,
    side_owner,
    side_without_owner,
    side_owner_directory_unlisted,
    failed_then_healthy_telemetry
);

fn codex_rows(turn: &str, tokens: u64) -> String {
    let usage = json!({"input_tokens":tokens,"cached_input_tokens":0,"output_tokens":2,"reasoning_output_tokens":0,"total_tokens":tokens+2});
    [
        json!({"type":"event_msg","timestamp":"2026-10-27T07:00:01Z","payload":{"type":"task_started","turn_id":turn}}),
        json!({"type":"token_usage_record","timestamp":"2026-10-27T07:00:02Z","payload":{"thread_id":ROOT,"turn_id":turn,"response_id":turn,"usage":usage,"thread_token_usage":usage}}),
        json!({"type":"event_msg","timestamp":"2026-10-27T07:00:03Z","payload":{"type":"token_count","info":{"model":"gpt-5.2","last_token_usage":usage,"total_token_usage":usage}}}),
        json!({"type":"event_msg","timestamp":"2026-10-27T07:00:04Z","payload":{"type":"task_complete","turn_id":turn}}),
    ].iter().map(|v| v.to_string()+"\n").collect()
}

fn other_page(
    c: &Corpus,
    scanner: &E2ScanFixture,
    source: SnapshotSource,
    prior: ScanIndex,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    other_page_observing_raw(c, scanner, source, prior, |_| {})
}

fn other_page_observing_raw(
    c: &Corpus,
    scanner: &E2ScanFixture,
    source: SnapshotSource,
    prior: ScanIndex,
    before_finalize: impl FnOnce(&[SnapshotItem]),
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let (mut index, mut scan, modes) = scanner.scan_other(
        source,
        std::slice::from_ref(&c.root),
        &c.support,
        prior,
        true,
    );
    index.bind_session_accounts(source, "e2-synthetic-machine", &mut scan.snapshots, &[]);
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
    before_finalize(&scan.snapshots);
    finalize_scan_after_policy(source, &mut scan, &mut index);
    scan.finish_codex_capture_boundary(&mut index);
    (index, scan, modes)
}
fn other_wire(source: SnapshotSource, scan: &SourceScanResult) -> Vec<u8> {
    assert!(!scan.snapshots.is_empty());
    let mut wire = request(&scan.snapshots);
    wire.source = source.api_slug().into();
    validate_snapshot_batch_request(&wire).unwrap();
    canonical(&wire)
}
fn codex_case(legacy: bool) {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let name = if legacy {
        "codex_legacy_acked_sticky"
    } else {
        "codex_v2_sticky"
    };
    if !supported(name) {
        return;
    }
    let c = corpus(name);
    let disk = Disk::new(&c);
    let path = c.root.join("rollout.jsonl");
    let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z","payload":{"id":ROOT,"timestamp":"2026-10-27T07:00:00Z"}}).to_string()+"\n";
    std::fs::write(&path, header + &codex_rows("turn-a", 10)).unwrap();
    input_clock(&path);
    let scanner = E2ScanFixture::default();
    let source = SnapshotSource::Codex;
    disk.begin(&scanner, source);
    let mut prior = {
        let _cutover = crate::snapshots::TestCutover::set(if legacy { i64::MAX } else { 0 });
        let (mut index, scan, _) = other_page(&c, &scanner, source, ScanIndex::default());
        let accepted = scan
            .snapshots
            .iter()
            .map(|s| s.snapshot_fingerprint.clone())
            .collect();
        index.record_accepted_snapshot_fingerprints(&accepted);
        assert!(!index.files.is_empty());
        assert!(index.files.values().all(|e| e.codex_counting_v2 != legacy));
        // Records bind the counting view, cutover included: this binary
        // commits under its own cutover, as its daemon does after the save.
        disk.commit(&scanner.cache, source, &mut index)
    };
    append(&path, &codex_rows("turn-b", 30));
    input_clock(&path);
    let _cutover = crate::snapshots::TestCutover::set(0);
    if legacy {
        // The old binary's cutover differs, so its RAM reduction cannot be
        // reused. Warm the upgraded binary from the actual Legacy ACK facts,
        // then exercise its next page's retained Tail under that same rule.
        let (mut upgraded, scan, modes) = other_page(&c, &scanner, source, prior);
        assert_eq!(modes, (1, 0, 0));
        assert!(!scan.snapshots.is_empty());
        assert!(upgraded.files.values().all(|e| !e.codex_counting_v2));
        // Its commit writes the Legacy-ACKed record the disk arm restores:
        // a dated header a fresh read would count as V2 (#806 r8 cond. 2).
        prior = disk.commit(&scanner.cache, source, &mut upgraded);
        append(&path, &codex_rows("turn-c", 40));
        input_clock(&path);
    }
    save_inputs(&c);
    let (tail_index, tail, modes) = other_page(&c, &scanner, source, prior.clone());
    assert_eq!(modes, (0, 1, 0), "must reuse retained Codex reduction");
    let (_, full, modes) = other_page(&c, &E2ScanFixture::default(), source, prior.clone());
    assert_eq!(modes, (1, 0, 0));
    // Disk arm (#806): a new owner restores the last commit's record from
    // the real store and Tails, never flipping the counting choice.
    let restart = disk.owner(source);
    let (disk_index, restored, modes) = other_page(&c, &restart, source, prior);
    assert_eq!(modes, (0, 1, 0), "must restore the Codex record, then Tail");
    assert_eq!(durable_restores(&restart.cache, source).1, 1);
    assert!(tail_index
        .files
        .values()
        .all(|e| e.codex_counting_v2 != legacy));
    assert!(
        disk_index
            .files
            .values()
            .all(|e| e.codex_counting_v2 != legacy),
        "restore never flips the counting choice"
    );
    let (a, b) = (other_wire(source, &tail), other_wire(source, &full));
    let d = other_wire(source, &restored);
    assert_eq!(a, b);
    assert_eq!(d, b, "disk-restored envelope differs from cold Full");
    assert_eq!(d, a, "disk-restored envelope differs from the RAM arm");
    assert_eq!(Sha256::digest(&a), Sha256::digest(&b));
    assert_eq!(Sha256::digest(&d), Sha256::digest(&b));
    receipt(
        name,
        &[ReceiptBody {
            raw: a,
            source,
            items: tail.snapshots.clone(),
        }],
    );
}
#[test]
fn codex_v2_sticky() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    codex_case(false);
}
#[test]
fn codex_legacy_acked_sticky() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    codex_case(true);
}

/// Disk-only lifecycle fixtures (#806). scripts/money_equivalence.py counts
/// exactly the cross-build receipts above, so these print a distinct line and
/// write no receipt; the job still runs them and fails on any assertion.
fn disk_verified(name: &str, bodies: &[ReceiptBody], restored: u64) {
    let raw = serde_json::to_vec(&bodies.iter().map(|b| &b.raw).collect::<Vec<_>>()).unwrap();
    // The same physical-identity guard as the cross-build receipts.
    let cross = serde_json::to_vec(
        &bodies
            .iter()
            .map(ReceiptBody::cross_build)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    println!(
        "MONEY_EQUIVALENCE_DISK {name} VERIFIED pages={} restored={restored} sha256={:x} cross_build_sha256={:x}",
        bodies.len(),
        Sha256::digest(&raw),
        Sha256::digest(&cross)
    );
}

/// One root session with a first response, read Full and committed by its
/// warm owner. Returns the corpus, its transcript, the RAM owner and prior.
fn disk_corpus(name: &str) -> (Corpus, Disk, PathBuf, E2ScanFixture, ScanIndex) {
    let mut c = corpus(name);
    let path = c.root(ROOT, &line(ROOT, "r1", AT, 10));
    input_clock(&path);
    let disk = Disk::new(&c);
    let (scanner, prior) = warm_claude(&c, &disk);
    (c, disk, path, scanner, prior)
}

fn grow(path: &Path, request: &str, tokens: u64) {
    append(path, &line(ROOT, request, AT, tokens));
    input_clock(path);
}

/// A restart between every page: each page's disk arm is a new owner that
/// restores the record its predecessor committed (the warm page's, then a
/// restored-and-Tailed owner's) and must emit the RAM owner's and a cold
/// Full's bodies. Each arm continues from its own finished index.
#[test]
fn restart_between_pages() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let name = "restart_between_pages";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let (c, disk, path, scanner, prior) = disk_corpus(name);
        let mut priors = [prior.clone(), prior.clone(), prior];
        let mut bodies = Vec::new();
        for (request, tokens) in [("r2", 20), ("r3", 30)] {
            grow(&path, request, tokens);
            let restart = disk.owner(SnapshotSource::ClaudeCode);
            let mut pages = claude_pages(&c, &scanner, &restart, priors, (0, 1, 0), (0, 1, 0));
            finish_claude_pages(&c, &mut pages);
            bodies.push(compare_claude_uploads(&pages));
            let [tail, full, mut disk_page] = pages;
            let next = disk.commit(
                &disk_page.cache,
                SnapshotSource::ClaudeCode,
                &mut disk_page.index,
            );
            priors = [tail.index, full.index, next];
        }
        assert_ne!(bodies[0].raw, bodies[1].raw, "the second page adds money");
        disk_verified(name, &bodies, 2);
    });
}

/// An upgraded binary that changes no record binding (codec, allowlist,
/// scope, body-witness revision, money rule) restores the older binary's
/// record. The older owner's next pass sees the file unchanged and commits
/// again without rewriting its unchanged record, so the record's generation
/// stamp is older than the committed index. The upgraded owner (a new
/// process) must still restore it and Tail the growth. Every commit follows
/// a real pass, as in the daemon. A real cross-binary upgrade is not
/// buildable in one test binary.
#[test]
fn upgrade_without_semantic_revision() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let name = "upgrade_without_semantic_revision";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let (c, disk, path, scanner, prior) = disk_corpus(name);
        let written = disk.record_bytes();
        assert_eq!(written.len(), 1);
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut quiet = c.raw(&scanner, prior.clone(), 100, true, &[]);
        assert_eq!(
            quiet.modes.0 + quiet.modes.1,
            0,
            "the older owner's file is unchanged: no read"
        );
        quiet.enrich(&c);
        quiet.finish();
        let committed = disk.commit(&quiet.cache, SnapshotSource::ClaudeCode, &mut quiet.index);
        assert!(committed.generation > prior.generation);
        assert_eq!(
            disk.record_bytes(),
            written,
            "an unchanged record keeps its older generation stamp"
        );
        grow(&path, "r2", 20);
        let upgraded = disk.owner(SnapshotSource::ClaudeCode);
        let pages = claude_pages(
            &c,
            &scanner,
            &upgraded,
            [committed.clone(), committed.clone(), committed],
            (0, 1, 0),
            (0, 1, 0),
        );
        disk_verified(name, &[compare_claude_pages(&c, pages)], 1);
    });
}

/// A downgraded binary without the store (main before #806) reads the grown
/// file Full and commits a newer entry, leaving the newer binary's record on
/// disk. On re-upgrade that record no longer binds the committed entry: the
/// new owner must refuse it and read Full, never restore the pre-downgrade
/// reduction. Its own commit then restores again on the next restart.
#[test]
fn downgrade_then_reupgrade() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    let name = "downgrade_then_reupgrade";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let (c, disk, path, _, prior) = disk_corpus(name);
        let downgraded = E2ScanFixture::default();
        grow(&path, "r2", 20);
        let mut down = c.raw(&downgraded, prior, 100, true, &[]);
        assert_eq!(down.modes, (1, 0, 0), "the downgraded binary has no copy");
        down.enrich(&c);
        down.finish();
        down.index.save(&disk.index).unwrap(); // writes no record
        let committed = ScanIndex::load(&disk.index).unwrap();
        assert_eq!(disk.records(), 1, "the downgrade leaves the newer record");
        grow(&path, "r3", 30);
        let reupgraded = disk.owner(SnapshotSource::ClaudeCode);
        let mut pages = claude_pages(
            &c,
            &downgraded,
            &reupgraded,
            [committed.clone(), committed.clone(), committed],
            (0, 1, 0),
            (1, 0, 0),
        );
        let (attempts, _, ineligible) =
            durable_restores(&reupgraded.cache, SnapshotSource::ClaudeCode);
        assert_eq!(attempts, 1);
        assert_eq!(ineligible, BTreeMap::from([("entry_changed", 1)]));
        finish_claude_pages(&c, &mut pages);
        let refused = compare_claude_uploads(&pages);
        let [tail, full, mut disk_page] = pages;
        let next = disk.commit(
            &disk_page.cache,
            SnapshotSource::ClaudeCode,
            &mut disk_page.index,
        );
        grow(&path, "r4", 40);
        let restart = disk.owner(SnapshotSource::ClaudeCode);
        let pages = claude_pages(
            &c,
            &downgraded,
            &restart,
            [tail.index, full.index, next],
            (0, 1, 0),
            (0, 1, 0),
        );
        let restored = compare_claude_pages(&c, pages);
        disk_verified(name, &[refused, restored], 1);
    });
}

// These names are executable backlog, not simulated disk restores or family
// commits. Do not remove an ignore until its stated production feature exists.
macro_rules! pending {
    ($name:ident, $reason:literal) => {
        #[test]
        #[ignore = $reason]
        fn $name() {
            panic!($reason);
        }
    };
}
pending!(
    twin_branch_copy,
    "E3: family commit vector not on main; forced family Full cannot prove retained equality"
);
pending!(
    twin_resume_copy,
    "E3: family commit vector not on main; forced family Full cannot prove retained equality"
);
pending!(
    twin_moved_file,
    "E1/E3: path-move restore and family commit vector not on main"
);
pending!(
    twin_one_member_grows,
    "E3: family commit vector not on main"
);
pending!(
    twin_stale_or_queued_holder,
    "E3: all-or-held family commit vector not on main"
);
pending!(
    twin_mixed_accounts,
    "E3: family commit vector with per-member account evidence not on main"
);

// Pi uses the same scanner and committed index; durable Pi is unsupported.
// Its lines intentionally contain only synthetic text and identifiers.
fn pi_json(value: Value) -> String {
    value.to_string() + "\n"
}

fn pi_header(id: &str, version: u64, parent: Option<&str>) -> String {
    pi_json(json!({"type":"session", "version":version, "id":id,
        "timestamp":"2026-10-27T06:00:00Z", "cwd":"/synthetic/pi-work",
        "parentSession":parent}))
}

fn pi_turn(shape: &str, response: Option<&str>, input: u64, at: &str) -> Value {
    let mut value = json!({"type":shape, "id":"a0000001", "parentId":"a0000000",
        "timestamp":"2026-10-27T07:00:01Z", "message":{
            "role":"assistant", "provider":"openai", "model":"gpt-5.4",
            "api":"openai-responses", "timestamp":at, "thinkingLevel":"low",
            "stopReason":"stop", "content":[{"type":"text","text":"Synthetic answer."}],
            "usage":{"input":input,"output":2,"cacheRead":3,"cacheWrite":4,
                "totalTokens":input+9,"cost":{"total":0.001}}}});
    if let Some(response) = response {
        value["message"]["responseId"] = json!(response);
    }
    value
}

fn pi_seed() -> String {
    pi_header("synthetic-pi-session", 3, None)
        + &pi_json(
            json!({"type":"model_change","id":"a0000000","parentId":null,
            "timestamp":"2026-10-27T06:00:00Z","provider":"openai","modelId":"gpt-5.4"}),
        )
        + &pi_json(json!({"type":"thinking_level_change","id":"a0000002",
            "parentId":"a0000000","thinkingLevel":"low","timestamp":"2026-10-27T06:00:00Z"}))
        + &pi_json(
            json!({"type":"message","id":"a0000003","parentId":"a0000002",
            "message":{"role":"system","content":"Synthetic system instruction. ".repeat(250),
                "timestamp":1793080800000u64}}),
        )
        + &pi_json(
            json!({"type":"message","id":"a0000004","parentId":"a0000003",
            "message":{"role":"user","content":[{"type":"text","text":"Synthetic first prompt."}],
                "timestamp":1793080800000u64}}),
        )
        + &pi_json(pi_turn(
            "message",
            Some("seed-response"),
            10,
            "2026-10-27T06:00:01Z",
        ))
}

struct PiProof {
    sampled: bool,
    durable: bool,
    bodies: Vec<ReceiptBody>,
}

impl PiProof {
    fn capture(&mut self, scan: &SourceScanResult) {
        self.bodies.push(ReceiptBody {
            raw: if scan.snapshots.is_empty() {
                b"[]".to_vec()
            } else {
                other_wire(SnapshotSource::Pi, scan)
            },
            source: SnapshotSource::Pi,
            items: scan.snapshots.clone(),
        });
    }

    fn finish(self, c: &Corpus, disk: &Disk) {
        let name = c.base.file_name().unwrap().to_str().unwrap();
        receipt(name, &self.bodies);
        if self.durable {
            assert!(disk.records() > 0, "native Pi receipt must survive");
            println!("MONEY_EQUIVALENCE_PI_CAPABILITY {name} SUPPORTED");
            println!("MONEY_EQUIVALENCE_DISK {name} VERIFIED");
        } else {
            assert_eq!(disk.records(), 0, "base has no durable Pi receipt");
            println!("MONEY_EQUIVALENCE_PI_CAPABILITY {name} UNSUPPORTED");
            println!("MONEY_EQUIVALENCE_DISK {name} UNSUPPORTED");
        }
    }
}

fn pi_disk_corpus(
    name: &str,
    initial: &str,
) -> (Corpus, Disk, PathBuf, E2ScanFixture, ScanIndex, PiProof) {
    let c = corpus(name);
    let path = c.root.join("session.jsonl");
    std::fs::write(&path, initial).unwrap();
    input_clock(&path);
    let disk = Disk::new(&c);
    let scanner = disk.owner(SnapshotSource::Pi);
    let (mut index, scan, modes) =
        other_page(&c, &scanner, SnapshotSource::Pi, ScanIndex::default());
    // The copied harness runs on main too: only head admits Pi to RAM.
    let sampled = match std::env::var("OTTTO_MONEY_EQUIVALENCE_PI_RAM_EXPECTED").as_deref() {
        Ok("0") => false,
        Ok("1") | Err(_) => true,
        Ok(other) => panic!("invalid Pi RAM expectation: {other}"),
    };
    assert_eq!(
        modes,
        if sampled { (1, 0, 0) } else { (0, 0, 0) },
        "head must exercise sampled Pi; base must exercise cold Full"
    );
    assert!(!scan.snapshots.is_empty());
    let prior = disk.commit(&scanner.cache, SnapshotSource::Pi, &mut index);
    let durable = disk.records() > 0;
    let mut proof = PiProof {
        sampled,
        durable,
        bodies: Vec::new(),
    };
    proof.capture(&scan);
    (c, disk, path, scanner, prior, proof)
}

fn pi_grow(path: &Path, value: Value) {
    append(path, &pi_json(value));
    input_clock(path);
}

#[derive(Clone, Copy, Debug)]
enum PiLedgerStep {
    Emit(u64, u64),
    Noop(u64, u64),
    ConflictDrop(u64, u64),
}

impl PiLedgerStep {
    fn totals(self) -> (u64, u64) {
        match self {
            Self::Emit(requests, input)
            | Self::Noop(requests, input)
            | Self::ConflictDrop(requests, input) => (requests, input),
        }
    }
}

fn pi_ledger_totals(items: &[SnapshotItem]) -> (u64, u64) {
    assert_eq!(items.len(), 1, "ledger fixture has one cumulative session");
    (
        items.iter().map(|s| s.request_count).sum(),
        items.iter().map(|s| s.input_tokens).sum(),
    )
}

struct PiLedgerCheck<'a> {
    step: PiLedgerStep,
    accepted: &'a [SnapshotItem],
}

impl PiLedgerCheck<'_> {
    fn page(
        &self,
        c: &Corpus,
        scanner: &E2ScanFixture,
        prior: ScanIndex,
    ) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
        let previous_files = prior.files.clone();
        let previous_entities = prior.file_snapshot_fingerprints.clone();
        let mut candidates = Vec::new();
        let (index, scan, modes) =
            other_page_observing_raw(c, scanner, SnapshotSource::Pi, prior, |items| {
                candidates = items.to_vec();
            });
        match self.step {
            PiLedgerStep::Emit(..) => {
                assert_eq!(pi_ledger_totals(&scan.snapshots), self.step.totals());
                assert_eq!(scan.semantic_noop_count, 0);
                assert_eq!(scan.dropped_usage_record_count, 0);
            }
            PiLedgerStep::Noop(..) | PiLedgerStep::ConflictDrop(..) => {
                assert!(scan.snapshots.is_empty());
                assert_eq!(pi_ledger_totals(self.accepted), self.step.totals());
                assert_eq!(index.files.len(), 1);
                assert_eq!(previous_files.len(), 1);
                for (key, before) in &previous_files {
                    let after = &index.files[key];
                    assert!(before.last_snapshot_fingerprint.is_some());
                    assert!(before.last_upload_body_witness.is_some());
                    assert_eq!(
                        after.last_snapshot_fingerprint,
                        before.last_snapshot_fingerprint
                    );
                    assert_eq!(
                        after.last_upload_body_witness,
                        before.last_upload_body_witness
                    );
                    match self.step {
                        PiLedgerStep::Noop(..) => {
                            assert_eq!(scan.semantic_noop_count, 1);
                            assert_eq!(scan.dropped_usage_record_count, 0);
                            assert_eq!(pi_ledger_totals(&candidates), self.step.totals());
                            let candidate = &candidates[0];
                            let accepted = &self.accepted[0];
                            // The copy precedes finalization's fingerprint
                            // recomputation and suppression of the candidate.
                            assert_eq!(
                                (
                                    crate::snapshots::snapshot_fingerprint(
                                        SnapshotSource::Pi,
                                        candidate
                                    ),
                                    snapshot_upload_body_witness(candidate),
                                ),
                                (
                                    accepted.snapshot_fingerprint.clone(),
                                    snapshot_upload_body_witness(accepted),
                                ),
                            );
                            assert!(after.size_bytes > before.size_bytes);
                        }
                        PiLedgerStep::ConflictDrop(..) => {
                            assert_eq!(scan.semantic_noop_count, 0);
                            assert_eq!(scan.dropped_usage_record_count, 1);
                            // The incomplete parse must not advance the file
                            // checkpoint: the resolving append remains retryable.
                            assert_eq!(
                                serde_json::to_value(after).unwrap(),
                                serde_json::to_value(before).unwrap()
                            );
                        }
                        PiLedgerStep::Emit(..) => unreachable!(),
                    }
                }
                assert_eq!(index.file_snapshot_fingerprints, previous_entities);
            }
        }
        (index, scan, modes)
    }
}

// Return each arm's own finished index, so a later page cannot borrow another
// arm's settlement. Quarantined files have no emitted body; compare their
// disposition and retryability instead of inventing a successful upload.
#[allow(clippy::too_many_arguments)]
fn pi_pages(
    proof: &mut PiProof,
    c: &Corpus,
    retained: &E2ScanFixture,
    restart: &E2ScanFixture,
    priors: [ScanIndex; 3],
    ram_mode: (usize, usize, usize),
    disk_mode: (usize, usize, usize),
    restores: u64,
) -> ([ScanIndex; 3], SourceScanResult) {
    pi_pages_checked(
        proof, c, retained, restart, priors, ram_mode, disk_mode, restores, None,
    )
}

#[allow(clippy::too_many_arguments)]
fn pi_pages_checked(
    proof: &mut PiProof,
    c: &Corpus,
    retained: &E2ScanFixture,
    restart: &E2ScanFixture,
    priors: [ScanIndex; 3],
    ram_mode: (usize, usize, usize),
    disk_mode: (usize, usize, usize),
    restores: u64,
    ledger: Option<&PiLedgerCheck<'_>>,
) -> ([ScanIndex; 3], SourceScanResult) {
    save_inputs(c);
    let page = |scanner: &E2ScanFixture, prior| match ledger {
        Some(check) => check.page(c, scanner, prior),
        None => other_page(c, scanner, SnapshotSource::Pi, prior),
    };
    let [tail_prior, full_prior, disk_prior] = priors;
    let (tail_index, tail, mode) = page(retained, tail_prior);
    assert_eq!(
        mode,
        if proof.sampled { ram_mode } else { (0, 0, 0) },
        "Pi retained acquisition"
    );
    let (full_index, full, mode) = page(&E2ScanFixture::default(), full_prior);
    assert_eq!(mode.1 + mode.2, 0, "cold Pi cannot reuse a reduction");
    let (disk_index, restored, mode) = page(restart, disk_prior);
    assert_eq!(
        mode,
        if proof.durable {
            disk_mode
        } else if proof.sampled {
            (disk_mode.0 + disk_mode.1, 0, disk_mode.2)
        } else {
            (0, 0, 0)
        },
        "Pi disk acquisition"
    );
    if proof.durable {
        assert_eq!(
            restart
                .cache
                .durable_counters(SnapshotSource::Pi)
                .unwrap()
                .0
                .restored,
            restores,
            "actual Pi disk restores"
        );
    } else {
        assert!(restart.cache.durable_counters(SnapshotSource::Pi).is_none());
    }
    for scan in [&tail, &restored] {
        assert_eq!(
            scan.dropped_usage_record_count,
            full.dropped_usage_record_count
        );
        assert_eq!(scan.census_complete, full.census_complete);
        assert_eq!(scan.snapshots.len(), full.snapshots.len());
    }
    if !full.snapshots.is_empty() {
        let expected = other_wire(SnapshotSource::Pi, &full);
        assert_eq!(
            other_wire(SnapshotSource::Pi, &tail),
            expected,
            "Pi RAM Tail != Full"
        );
        assert_eq!(
            other_wire(SnapshotSource::Pi, &restored),
            expected,
            "Pi disk restore != Full"
        );
        for (a, b) in restored.snapshots.iter().zip(&full.snapshots) {
            assert_eq!(
                snapshot_upload_body_witness(a),
                snapshot_upload_body_witness(b)
            );
        }
    } else {
        assert_eq!(tail_index.files.len(), full_index.files.len());
        assert_eq!(disk_index.files.len(), full_index.files.len());
    }
    proof.capture(&full);
    ([tail_index, full_index, disk_index], full)
}

fn pi_splits(name: &str, prefix: &str, suffix: Vec<Value>, requests: u64) -> SourceScanResult {
    let (c, disk, path, scanner, prior, mut proof) = pi_disk_corpus(name, prefix);
    let mut priors = [prior.clone(), prior.clone(), prior];
    let mut last = None;
    for value in suffix {
        pi_grow(&path, value);
        let restart = disk.owner(SnapshotSource::Pi);
        let ([tail, full, mut restored], scan) = pi_pages(
            &mut proof,
            &c,
            &scanner,
            &restart,
            priors,
            (0, 1, 0),
            (0, 1, 0),
            1,
        );
        let next = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
        priors = [tail, full, next];
        last = Some(scan);
    }
    let scan = last.expect("fixture must cross a seal");
    assert_eq!(
        scan.snapshots.iter().map(|s| s.request_count).sum::<u64>(),
        requests,
        "{name}"
    );
    proof.finish(&c, &disk);
    scan
}

fn pi_ledger_splits(
    name: &str,
    prefix: &str,
    initial: PiLedgerStep,
    suffix: Vec<(Value, PiLedgerStep)>,
    final_totals: (u64, u64),
) {
    let (c, disk, path, scanner, prior, mut proof) = pi_disk_corpus(name, prefix);
    assert!(matches!(initial, PiLedgerStep::Emit(..)));
    let mut accepted = proof.bodies[0].items.clone();
    assert_eq!(pi_ledger_totals(&accepted), initial.totals());
    // The shared initial prefix is accepted by all three arms. Check cold and
    // recordless restart against the retained arm's actual captured body too.
    for initial_scanner in [E2ScanFixture::default(), disk.owner(SnapshotSource::Pi)] {
        let (_, scan, _) = PiLedgerCheck {
            step: initial,
            accepted: &[],
        }
        .page(&c, &initial_scanner, ScanIndex::default());
        assert_eq!(other_wire(SnapshotSource::Pi, &scan), proof.bodies[0].raw);
    }
    let mut priors = [prior.clone(), prior.clone(), prior];
    let mut ram_mode = (0, 1, 0);
    for (value, step) in suffix {
        pi_grow(&path, value);
        let restart = disk.owner(SnapshotSource::Pi);
        let ([tail, full, mut restored], scan) = pi_pages_checked(
            &mut proof,
            &c,
            &scanner,
            &restart,
            priors,
            ram_mode,
            (0, 1, 0),
            1,
            Some(&PiLedgerCheck {
                step,
                accepted: &accepted,
            }),
        );
        if matches!(step, PiLedgerStep::Emit(..)) {
            accepted = scan.snapshots;
        }
        let next = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
        priors = [tail, full, next];
        // A conflict consumes the retained reduction without reinserting it.
        // The NEXT append must therefore acquire Full, not Tail.
        ram_mode = if matches!(step, PiLedgerStep::ConflictDrop(..)) {
            (1, 0, 0)
        } else {
            (0, 1, 0)
        };
    }
    assert_eq!(pi_ledger_totals(&accepted), final_totals, "{name}");
    proof.finish(&c, &disk);
}

#[test]
fn pi() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi") {
        return;
    }
    // P1: every appended line boundary, including model/thinking changes,
    // the large system message, and the user/assistant flush boundary.
    let lines: Vec<Value> = pi_seed()
        .lines()
        .map(|s| serde_json::from_str(s).unwrap())
        .collect();
    let scan = pi_splits(
        "pi_plain_session",
        &pi_seed(),
        lines.into_iter().skip(1).collect(),
        2,
    );
    assert_eq!(scan.snapshots[0].input_tokens, 20);
}

#[test]
fn pi_tool_turn() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_tool_turn") {
        return;
    }
    let mut tool = pi_turn("message", Some("tool-response"), 20, "2026-10-27T06:01:00Z");
    tool["message"]["stopReason"] = json!("toolUse");
    tool["message"]["content"] = json!([{"type":"toolCall","id":"synthetic-call",
        "name":"read","arguments":{"path":"synthetic.txt"}}]);
    pi_splits(
        "pi_tool_turn",
        &pi_seed(),
        vec![
            tool,
            json!({"type":"message","id":"a0000005","parentId":"a0000001",
            "timestamp":"2026-10-27T06:01:01Z", "message":{"role":"toolResult",
            "toolCallId":"synthetic-call","toolName":"read","isError":false,
            "content":[{"type":"text","text":"Synthetic tool result."}],"timestamp":1793080861000u64}}),
            pi_turn("message", Some("after-tool"), 30, "2026-10-27T06:02:00Z"),
        ],
        3,
    );
}

#[test]
fn pi_summary_usage() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_summary_usage") {
        return;
    }
    for kind in ["compaction", "branch_summary"] {
        let summary = json!({"type":kind,"id":"b0000001","parentId":"a0000001",
            "timestamp":"2026-10-27T07:00:01Z", "summary":"Synthetic branch checkpoint.",
            "firstKeptEntryId":"a0000004","tokensBefore":8000,
            "usage":{"input":20,"output":5,"cost":{"total":0.002}},
            "details":{"systemPrompt":"Synthetic checkpoint. ".repeat(320)}});
        let scan = pi_splits(
            &format!("pi_{kind}"),
            &pi_seed(),
            vec![
                summary,
                pi_turn("message", Some("after-summary"), 30, "2026-10-27T07:01:00Z"),
            ],
            3,
        );
        let item = &scan.snapshots[0];
        assert_eq!((item.input_tokens, item.output_tokens), (60, 9));
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.004")
        );
        let hour = item
            .usage_buckets
            .iter()
            .find(|b| b.bucket_start == "2026-10-27T07:00:00Z")
            .unwrap();
        let summary = hour
            .model_usage
            .iter()
            .find(|r| r.model_provider.is_none())
            .unwrap();
        assert_eq!(
            (&*summary.model, summary.input_tokens, summary.request_count),
            ("gpt-5.4", 20, 1)
        );
    }
}

#[test]
fn pi_usage_entry_kinds() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_usage_entry_kinds") {
        return;
    }
    let entries = ["cache_warm", "synthetic_future_kind"]
        .into_iter()
        .map(|kind| {
            json!({"type":"usage","id":"c0000001","parentId":"a0000001","kind":kind,
            "timestamp":"2026-10-27T07:00:01Z", "provider":"google", "model":"gemini-2.5-flash",
            "usage":{"input":20,"output":5,"cost":{"total":0.002}}})
        })
        .collect();
    let scan = pi_splits("pi_usage_entry_kinds", &pi_seed(), entries, 3);
    let row = scan.snapshots[0]
        .model_usage
        .iter()
        .find(|r| r.model == "gemini-2.5-flash")
        .unwrap();
    assert_eq!(row.model_provider.as_deref(), Some("google"));
    assert_eq!((row.request_count, row.input_tokens), (2, 40));
}

#[test]
fn pi_ledger_seal_boundaries() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_ledger_seal_boundaries") {
        return;
    }
    use PiLedgerStep::{ConflictDrop, Emit, Noop};
    let message = pi_turn(
        "message",
        Some("synthetic-reused"),
        20,
        "2026-10-27T06:01:00Z",
    );
    let mut end = message.clone();
    end["type"] = json!("message_end");
    // SOURCE duplicate on both sides of the seal; count > 1 must survive.
    let prefix = pi_seed() + &pi_json(message.clone()) + &pi_json(message.clone());
    pi_ledger_splits(
        "pi_ledger_count_above_one",
        &prefix,
        Emit(3, 50),
        vec![
            (end.clone(), Noop(3, 50)),
            (end.clone(), Noop(3, 50)),
            (message.clone(), Emit(4, 70)),
            (end.clone(), Noop(4, 70)),
        ],
        (4, 70),
    );
    // SOURCE paired_digests is nonempty at commit, before another exact pair.
    pi_ledger_splits(
        "pi_ledger_paired_digest",
        &(pi_seed() + &pi_json(message.clone()) + &pi_json(end.clone())),
        Emit(2, 30),
        vec![(message.clone(), Emit(3, 50)), (end.clone(), Noop(3, 50))],
        (3, 50),
    );
    // Reused-id pairing temporarily conflicts until both digests have paired.
    let mut later = pi_turn(
        "message",
        Some("synthetic-reused"),
        30,
        "2026-10-27T06:02:00Z",
    );
    let prefix = pi_seed() + &pi_json(message.clone()) + &pi_json(later.clone());
    later["type"] = json!("message_end");
    pi_ledger_splits(
        "pi_ledger_reused_id",
        &prefix,
        Emit(3, 60),
        vec![(later, ConflictDrop(3, 60)), (end.clone(), Noop(3, 60))],
        (3, 60),
    );
    pi_ledger_splits(
        "pi_ledger_reverse_pair",
        &(pi_seed() + &pi_json(end)),
        Emit(2, 30),
        vec![(message, Noop(2, 30))],
        (2, 30),
    );
}

#[test]
fn pi_divergent_pair_quarantine() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_divergent_pair_quarantine") {
        return;
    }
    for paired in [false, true] {
        let message = pi_turn(
            "message",
            Some("synthetic-conflict"),
            20,
            "2026-10-27T06:01:00Z",
        );
        let mut end = message.clone();
        end["type"] = json!("message_end");
        let mut prefix = pi_seed() + &pi_json(message);
        if paired {
            prefix += &pi_json(end.clone());
        }
        end["message"]["usage"]["input"] = json!(99);
        let scan = pi_splits(
            if paired {
                "pi_conflict_after_pair"
            } else {
                "pi_conflict"
            },
            &prefix,
            vec![end],
            0,
        );
        assert!(scan.snapshots.is_empty());
        assert_eq!(scan.dropped_usage_record_count, 1);
    }
}

fn pi_usage_case(name: &str) {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported(name) {
        return;
    }
    let (response, input, repeats, requests, tokens) = match name {
        "pi_no_response_id" => (None, 20, 2, 4, 70),
        "pi_error_zero_requests" => (Some("synthetic-error"), 0, 1, 1, 10),
        _ => panic!("unknown Pi usage row: {name}"),
    };
    let mut prefix = pi_seed();
    let mut turn = pi_turn("message", response, input, "2026-10-27T06:01:00Z");
    if response.is_none() {
        turn["message"]["provider"] = json!("google");
        turn["message"]["model"] = json!("gemini-2.5-flash");
        prefix += &pi_json(turn.clone());
    } else {
        turn["message"]["stopReason"] = json!("error");
        turn["message"]["errorMessage"] = json!("Synthetic provider error.");
        turn["message"]["usage"] = json!({"input":0,"output":0,"cacheRead":0,"cacheWrite":0,
            "totalTokens":0,"cost":{"total":0}});
    }
    let scan = pi_splits(name, &prefix, vec![turn; repeats], requests);
    assert_eq!(scan.snapshots[0].input_tokens, tokens, "{name}");
}

/// [money] Missing response IDs must retain every billable occurrence.
#[test]
fn pi_no_response_id() {
    pi_usage_case("pi_no_response_id");
}

#[test]
fn pi_selector_across_seal() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_selector_across_seal") {
        return;
    }
    let scan = pi_splits(
        "pi_selector_across_seal",
        &pi_seed(),
        vec![
            json!({"type":"custom","id":"d0000001","parentId":"a0000001",
            "customType":"ottto-selector","timestamp":"2026-10-27T06:01:00Z",
            "data":{"selector_context":{"service_tier":"flex","batch_mode":true,"context_bucket":"long"}}}),
            pi_turn(
                "message",
                Some("selector-response"),
                20,
                "2026-10-27T06:02:00Z",
            ),
        ],
        2,
    );
    let row = scan.snapshots[0]
        .model_usage
        .iter()
        .find(|r| r.input_tokens == 20)
        .unwrap();
    assert_eq!(
        row.selector_context.get("service_tier").map(String::as_str),
        Some("flex")
    );
    assert_eq!(
        row.selector_context.get("batch_mode").map(String::as_str),
        Some("true")
    );
}

#[test]
fn pi_time_and_invalid_evidence() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_time_and_invalid_evidence") {
        return;
    }
    let scan = pi_splits(
        "pi_provider_hour_and_late_time",
        &pi_seed(),
        vec![
            pi_turn(
                "message",
                Some("boundary-response"),
                20,
                "2026-10-27T06:59:59Z",
            ),
            pi_turn("message", Some("late-response"), 30, "2026-10-27T05:59:59Z"),
        ],
        3,
    );
    assert_eq!(
        scan.snapshots[0]
            .usage_buckets
            .iter()
            .map(|b| b.bucket_start.as_str())
            .collect::<Vec<_>>(),
        ["2026-10-27T05:00:00Z", "2026-10-27T06:00:00Z"]
    );
    let mut bad_cost = pi_turn("message", Some("bad-cost"), 20, "2026-10-27T06:01:00Z");
    bad_cost["message"]["usage"]["cost"] = json!({"total":null,"input":"invalid","output":-1});
    let scan = pi_splits("pi_invalid_cost", &pi_seed(), vec![bad_cost], 2);
    assert!(scan.snapshots[0].cost.is_none());
    let bad_time = pi_turn("message", Some("bad-time"), 20, "synthetic-invalid-time");
    let scan = pi_splits("pi_invalid_time", &pi_seed(), vec![bad_time], 0);
    assert_eq!(scan.dropped_usage_record_count, 1);
    let huge = pi_turn(
        "message",
        Some("overflow-response"),
        u64::MAX - 9,
        "2026-10-27T06:01:00Z",
    );
    let scan = pi_splits("pi_usage_overflow", &pi_seed(), vec![huge], 0);
    assert_eq!(scan.dropped_usage_record_count, 1);
}

/// [money] A zero-usage error must not add a billable request.
#[test]
fn pi_error_zero_requests() {
    pi_usage_case("pi_error_zero_requests");
}

/// [money] Pinned residual: copied lines timestamped at or after the fork header stay counted.
#[test]
fn pi_cli_fork_preserves_double_count() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_cli_fork_preserves_double_count") {
        return;
    }
    // M-2 will change these request/input totals when inherited usage is skipped.
    const EXPECTED_FORK_TOTALS: (u64, u64) = (3, 40);
    let (c, disk, path, scanner, prior, mut proof) =
        pi_disk_corpus("pi_cli_fork_preserves_double_count", &pi_seed());
    let fork = c.root.join("fork.jsonl");
    let copied = pi_seed()
        .lines()
        .skip(1)
        .map(|s| s.to_owned() + "\n")
        .collect::<String>();
    let mut header: Value = serde_json::from_str(&pi_header(
        "synthetic-fork-session",
        3,
        Some("synthetic-parent.jsonl"),
    ))
    .unwrap();
    header["timestamp"] = json!("2026-10-27T07:00:00Z");
    std::fs::write(&fork, pi_json(header) + &copied).unwrap();
    input_clock(&fork);
    pi_grow(
        &path,
        pi_turn("message", Some("parent-growth"), 20, "2026-10-27T06:02:00Z"),
    );
    let restart = disk.owner(SnapshotSource::Pi);
    let (_, scan) = pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        [prior.clone(), prior.clone(), prior],
        (1, 1, 0),
        (1, 1, 0),
        1,
    );
    assert_eq!(scan.snapshots.len(), 2);
    assert_eq!(
        (
            scan.snapshots.iter().map(|s| s.request_count).sum::<u64>(),
            scan.snapshots.iter().map(|s| s.input_tokens).sum::<u64>(),
        ),
        EXPECTED_FORK_TOTALS
    );
    proof.finish(&c, &disk);
}

fn pi_lifecycle_case(name: &str) {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported(name) {
        return;
    }
    let (rewrite, downgrade, turns): (bool, bool, &[(&str, u64, &str)]) = match name {
        "pi_upgrade_without_semantic_revision" => (
            false,
            false,
            &[("upgrade-growth", 20, "2026-10-27T06:01:00Z")],
        ),
        "pi_downgrade_then_reupgrade" => (
            false,
            true,
            &[
                ("reupgrade-growth", 30, "2026-10-27T06:02:00Z"),
                ("next-restart", 40, "2026-10-27T06:03:00Z"),
            ],
        ),
        "pi_version_rewrite_after_tail" => (
            true,
            false,
            &[
                ("before-migration", 20, "2026-10-27T06:01:00Z"),
                ("after-migration", 30, "2026-10-27T06:02:00Z"),
            ],
        ),
        _ => panic!("unknown Pi lifecycle row: {name}"),
    };
    let initial = if rewrite {
        pi_seed().replacen("\"version\":3", "\"version\":1", 1)
    } else {
        pi_seed()
    };
    let (c, disk, path, mut scanner, prior, mut proof) = pi_disk_corpus(name, &initial);
    let mut priors = if downgrade {
        drop(scanner);
        scanner = E2ScanFixture::default();
        pi_grow(
            &path,
            pi_turn(
                "message",
                Some("downgrade-growth"),
                20,
                "2026-10-27T06:01:00Z",
            ),
        );
        let (mut down, scan, mode) = other_page(&c, &scanner, SnapshotSource::Pi, prior);
        assert_eq!(
            mode,
            if proof.sampled { (1, 0, 0) } else { (0, 0, 0) },
            "{name}"
        );
        proof.capture(&scan);
        down.save(&disk.index).unwrap();
        let committed = ScanIndex::load(&disk.index).unwrap();
        assert_eq!(disk.records(), usize::from(proof.durable), "{name}");
        [committed.clone(), committed.clone(), committed]
    } else if rewrite {
        [prior.clone(), prior.clone(), prior]
    } else {
        disk.begin(&scanner, SnapshotSource::Pi);
        let (mut quiet, _, mode) = other_page(&c, &scanner, SnapshotSource::Pi, prior.clone());
        assert_eq!(mode.0 + mode.1, 0, "{name}");
        let committed = disk.commit(&scanner.cache, SnapshotSource::Pi, &mut quiet);
        assert!(committed.generation > prior.generation, "{name}");
        [committed.clone(), committed.clone(), committed]
    };
    for (step, &(response, input, at)) in turns.iter().enumerate() {
        let turn = pi_turn("message", Some(response), input, at);
        let migrating = rewrite && step == 1;
        if migrating {
            let mut migrated = std::fs::read_to_string(&path).unwrap().replacen(
                "\"version\":1",
                "\"version\":3",
                1,
            );
            migrated += &pi_json(turn);
            let before = std::fs::metadata(&path).unwrap();
            std::fs::write(&path, migrated).unwrap();
            input_clock(&path);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(
                    before.ino(),
                    std::fs::metadata(&path).unwrap().ino(),
                    "{name}"
                );
            }
            assert!(
                std::fs::metadata(&path).unwrap().len() > before.len(),
                "{name}"
            );
        } else {
            pi_grow(&path, turn);
        }
        let restart = disk.owner(SnapshotSource::Pi);
        let ram_mode = if migrating { (1, 0, 0) } else { (0, 1, 0) };
        let (disk_mode, restores) = if migrating {
            ((1, 0, 0), 0)
        } else {
            ((0, 1, 0), 1)
        };
        let ([tail, full, mut restored], scan) = pi_pages(
            &mut proof, &c, &scanner, &restart, priors, ram_mode, disk_mode, restores,
        );
        if migrating {
            assert_eq!(scan.snapshots[0].request_count, 3, "{name}");
        }
        if step + 1 == turns.len() {
            break;
        }
        let next = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
        priors = [tail, full, next];
    }
    proof.finish(&c, &disk);
}

/// [money] A version rewrite after Tail must reacquire Full without double billing.
#[test]
fn pi_version_rewrite_after_tail() {
    pi_lifecycle_case("pi_version_rewrite_after_tail");
}

#[test]
fn pi_restart_between_pages() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_restart_between_pages") {
        return;
    }
    pi_splits(
        "pi_restart_between_pages",
        &pi_seed(),
        vec![
            pi_turn("message", Some("restart-one"), 20, "2026-10-27T06:01:00Z"),
            pi_turn("message", Some("restart-two"), 30, "2026-10-27T06:02:00Z"),
        ],
        3,
    );
}

/// [money] An index-only upgrade must preserve emitted usage across restart.
#[test]
fn pi_upgrade_without_semantic_revision() {
    pi_lifecycle_case("pi_upgrade_without_semantic_revision");
}

/// [money] Downgrade and reupgrade must preserve each arm's committed usage.
#[test]
fn pi_downgrade_then_reupgrade() {
    pi_lifecycle_case("pi_downgrade_then_reupgrade");
}

#[cfg(unix)]
#[test]
fn pi_acquisition_metadata_changes() {
    let _restart_restore = crate::snapshots::RestartRestoreForTest::enabled();
    if !supported("pi_acquisition_metadata_changes") {
        return;
    }
    use std::os::unix::fs::PermissionsExt;
    let (c, disk, path, scanner, prior, mut proof) =
        pi_disk_corpus("pi_acquisition_metadata_changes", &pi_seed());
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    let permissions = std::fs::metadata(&path).unwrap().permissions().mode();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(permissions ^ 0o100)).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        modified
    );
    let restart = disk.owner(SnapshotSource::Pi);
    let ([tail, full, mut restored], _) = pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        [prior.clone(), prior.clone(), prior],
        (0, 0, 0),
        (0, 0, 0),
        0,
    );
    let next = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(modified + std::time::Duration::from_secs(2))
        .unwrap();
    let restart = disk.owner(SnapshotSource::Pi);
    let ([tail, full, mut restored], _) = pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        [tail, full, next],
        (1, 0, 0),
        (1, 0, 0),
        0,
    );
    let next = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
    pi_grow(
        &path,
        pi_turn(
            "message",
            Some("metadata-growth"),
            20,
            "2026-10-27T06:01:00Z",
        ),
    );
    let restart = disk.owner(SnapshotSource::Pi);
    pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        [tail, full, next],
        (0, 1, 0),
        (0, 1, 0),
        1,
    );
    proof.finish(&c, &disk);
}
