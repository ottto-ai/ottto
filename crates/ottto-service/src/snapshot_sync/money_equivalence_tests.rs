// Compare emitted upload envelopes, never pre-finalization reductions. All input
// files are synthetic. The dispatch overlays only this test harness on the base.
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
        if self.source == SnapshotSource::ClaudeCode {
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
    let (mut index, mut scan, modes) = scanner.scan_other(
        source,
        std::slice::from_ref(&c.root),
        &c.support,
        prior,
        true,
    );
    index.bind_session_accounts(source, "e2-synthetic-machine", &mut scan.snapshots, &[]);
    apply_upload_policy(source, &mut scan.snapshots, SnapshotUploadPolicy::default());
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
    codex_case(false);
}
#[test]
fn codex_legacy_acked_sticky() {
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
pending!(
    pi,
    "E1 design D1: Pi explicitly remains Full-on-change; no retained Pi reduction on main"
);

mod state_v2_money_tests {
    include!("state_v2_money_tests.rs");
}
