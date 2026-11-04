// Emitted-body fixtures over Claude's Tail route and the other sources' RAM
// path. CI's money-equivalence job runs each build's own harness under the
// enclosing module name, which preserves the cross-build test and receipt
// catalog.
use super::*;
use serde_json::Value;

fn supported(name: &str) -> bool {
    if !crate::heap_layout_bound::layout_supported() {
        println!("MONEY_EQUIVALENCE {name} UNEXECUTED: native retained layout unavailable");
        return false;
    }
    true
}

pub(super) fn corpus(name: &str) -> Corpus {
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
pub(super) fn input_clock(path: &Path) {
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
pub(super) struct ReceiptBody {
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
    receipt_with_output(
        name,
        bodies,
        "OTTTO_MONEY_EQUIVALENCE_OUTPUT",
        "MONEY_EQUIVALENCE",
    );
}

pub(super) fn receipt_with_output(
    name: &str,
    bodies: &[ReceiptBody],
    output_env: &str,
    marker: &str,
) {
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
    if let Some(out) = std::env::var_os(output_env) {
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
        "{marker} {name} VERIFIED bytes={} sha256={digest} cross_build_sha256={cross_digest}",
        bytes.len()
    );
}

/// One restart owner's committed state: the state database of the source
/// under test with a Tail codec (Claude by default), or the other sources'
/// saved index, under a test-held single-writer lock. The codec source's
/// retained and restart arms read the same committed heads; the cold arm owns
/// an empty route. Only the restart arm's page commits.
struct Disk {
    dir: PathBuf,
    index: PathBuf,
    route: PathBuf,
    source: SnapshotSource,
}
impl Disk {
    fn new(c: &Corpus) -> Self {
        Self::with_route(c, SnapshotSource::ClaudeCode)
    }
    /// `source`'s state database route; every other source saves its index.
    fn with_route(c: &Corpus, source: SnapshotSource) -> Self {
        use crate::snapshots::scan_index_persistence::Source;
        let base = c.base.canonicalize().unwrap();
        let dir = base.join("durable-state");
        std::fs::create_dir_all(&dir).unwrap();
        crate::locked_state_dir::test_locks::hold(&dir);
        let persisted = match source {
            SnapshotSource::ClaudeCode => Source::Claude,
            SnapshotSource::Codex => Source::Codex,
            SnapshotSource::Pi => Source::Pi,
        };
        let (session, _) =
            crate::snapshots::StateV2ColdSession::publish(persisted, &ScanIndex::default(), &dir);
        let route = session.path().to_owned();
        // The database outlives the session handle; the corpus owns the dir.
        std::mem::forget(session);
        E2ScanFixture::register_route_for_test(&route);
        Self {
            index: dir.join("scan-index.json"),
            dir,
            route,
            source,
        }
    }
    fn path(&self, source: SnapshotSource) -> &Path {
        if source == self.source {
            &self.route
        } else {
            &self.index
        }
    }
    fn begin(&self, owner: &E2ScanFixture, source: SnapshotSource) {
        owner.begin_pass(source, &self.dir, self.path(source));
        if source == self.source {
            owner.on_committed_route(&self.route);
        }
    }
    /// A new owner: a restarted process with an empty RAM cache, whose pass
    /// begins as the daemon's does.
    fn owner(&mut self, source: SnapshotSource) -> E2ScanFixture {
        let owner = E2ScanFixture::default();
        self.begin(&owner, source);
        owner
    }
    /// The daemon's commit: save the index, then the post-save reconcile for
    /// this owner. Returns the index as the next process loads it.
    fn commit(
        &self,
        cache: &crate::snapshots::sampled_scan::SharedCache,
        source: SnapshotSource,
        index: &mut ScanIndex,
    ) -> ScanIndex {
        let path = self.path(source);
        index.save(path).unwrap();
        crate::snapshots::after_source_save(cache, &self.dir, source, index, path);
        ScanIndex::load(path).unwrap()
    }
}

/// The page's bodies reach the destination and their exact ACKs land in its
/// index, as the service does before it saves. Without them the next read owes
/// the upload context and is Full.
fn accept_page(page: &mut Page) {
    let mut progress = e2_progress();
    assert_eq!(
        upload(&page.scan.snapshots, &mut progress, ack).0.unwrap(),
        ResumableUploadResult::Completed
    );
    page.index
        .record_accepted_snapshot_fingerprints(&progress.accepted_fingerprints);
    crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
        &mut page.index,
        &page.scan.snapshots,
        &progress.fresh_context_body_acks,
    );
}

/// The warm owner's first page, Full, accepted and committed.
fn warm_claude(c: &Corpus, disk: &Disk) -> (E2ScanFixture, ScanIndex) {
    warm_claude_page(c, disk, true)
}

/// The warm owner's first page, Full and committed but never delivered: its
/// files hold no receipt and owe their upload-context proof.
fn warm_claude_undelivered(c: &Corpus, disk: &Disk) -> (E2ScanFixture, ScanIndex) {
    warm_claude_page(c, disk, false)
}

fn warm_claude_page(c: &Corpus, disk: &Disk, delivered: bool) -> (E2ScanFixture, ScanIndex) {
    let scanner = E2ScanFixture::default();
    disk.begin(&scanner, SnapshotSource::ClaudeCode);
    let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
    warm.enrich(c);
    warm.finish();
    if delivered {
        accept_page(&mut warm);
    }
    let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
    (scanner, prior)
}

/// Three arms over the SAME prior index and physical files: the warm owner, a
/// cold Full, and a new owner, both continuing from the committed Tail heads.
fn compare_claude(
    c: &Corpus,
    retained: &E2ScanFixture,
    disk: &mut Disk,
    prior: ScanIndex,
    mode: (usize, usize, usize),
) -> ReceiptBody {
    let restart = disk.owner(SnapshotSource::ClaudeCode);
    let mut pages = claude_pages(
        c,
        retained,
        &restart,
        [prior.clone(), prior.clone(), prior],
        mode,
    );
    finish_claude_pages(c, &mut pages);
    compare_claude_uploads(&pages)
}

fn claude_pages(
    c: &Corpus,
    retained: &E2ScanFixture,
    restart: &E2ScanFixture,
    [tail_prior, full_prior, disk_prior]: [ScanIndex; 3],
    mode: (usize, usize, usize),
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
        disk.modes, mode,
        "a new owner continues from the same committed heads"
    );
    [tail, full, disk]
}

pub(super) fn finish_claude_pages(c: &Corpus, pages: &mut [Page; 3]) {
    for page in pages {
        page.enrich(c); // attach, side calls, identity reconcile and emission
        page.finish(); // policy/body witnesses/holds, as in the real pipeline
    }
}

fn compare_claude_pages(c: &Corpus, mut pages: [Page; 3]) -> ReceiptBody {
    finish_claude_pages(c, &mut pages);
    compare_claude_uploads(&pages)
}

pub(super) fn compare_claude_uploads(pages: &[Page; 3]) -> ReceiptBody {
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
        let (c, path) = claude_corpus(name);
        if name == "failed_then_healthy_telemetry" {
            // A distinct finalized baseline keeps the failed estimate from
            // being suppressed as an unchanged body before real upload.
            c.evidence(&[api("r1", 10, 100)], &[]);
        }
        let mut disk = Disk::new(&c);
        let (scanner, prior) = warm_claude(&c, &disk);
        let mode = match name {
            "quiet_sidecar_growth" => {
                c.evidence(&[api("r1", 10, 100), api("late-side", 5, 50)], &[]);
                (0, 0, 1)
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
                    for page in pages.iter_mut() {
                        assert_eq!(page.scan.snapshots.len(), 1, "must scan the live session");
                        page.enrich(&c);
                        assert!(
                            page.disposition
                                .quarantined_fingerprints(&page.scan.snapshots)
                                .is_empty(),
                            "live estimates must not be request-owned quarantined"
                        );
                        page.finish();
                    }
                    for page in pages.iter() {
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
                let failed_owner = disk.owner(SnapshotSource::ClaudeCode);
                let mut failed = claude_pages(
                    &c,
                    &scanner,
                    &failed_owner,
                    [prior.clone(), prior.clone(), prior],
                    (0, 0, 1),
                );
                finish_phase(&mut failed, false);
                let failed_wire = compare_claude_uploads(&failed);
                let failed_items = failed.each_ref().map(|page| page.scan.snapshots[0].clone());
                // The Full arm continues from its own finished index; the new
                // owner commits its failed step, and both Tail arms continue
                // from that commit.
                let [_, full_failed, mut disk_failed] = failed;
                accept_page(&mut disk_failed);
                let disk_prior = disk.commit(
                    &disk_failed.cache,
                    SnapshotSource::ClaudeCode,
                    &mut disk_failed.index,
                );
                c.evidence(&[api("r1", 10, 100)], &[]);
                let healthy_owner = disk.owner(SnapshotSource::ClaudeCode);
                let mut healthy = claude_pages(
                    &c,
                    &scanner,
                    &healthy_owner,
                    [disk_prior.clone(), full_failed.index, disk_prior],
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
            _ => claude_change(&c, &path, name),
        };
        if mode.1 > 0 {
            input_clock(&path);
        }
        receipt(
            name,
            &[compare_claude(&c, &scanner, &mut disk, prior, mode)],
        );
    });
}

/// A row's corpus before its warm page: the root transcript (returned) and
/// any owner file the row needs. Shared with the state-v2 cold rows.
pub(super) fn claude_corpus(name: &str) -> (Corpus, PathBuf) {
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
    (c, path)
}

/// The row's change after its warm page; returns the retained acquisition
/// mode it exercises. Shared with the state-v2 cold rows.
pub(super) fn claude_change(c: &Corpus, path: &Path, name: &str) -> (usize, usize, usize) {
    match name {
        "progressive_response" => append(path, &line(ROOT, "r1", AT, 30)),
        "duplicate_request_ids" => append(
            path,
            &(line(ROOT, "r1", AT, 10) + &line(ROOT, "r2", AT, 20)),
        ),
        "resolver_conflict" => append(
            path,
            &line(ROOT, "r1", AT, 10).replace("claude-haiku-4-5", "claude-sonnet-4-5"),
        ),
        "side_owner" => {
            c.evidence(
                &[
                    api("r1", 10, 100),
                    api("agent", 20, 200),
                    api("side", 5, 50),
                ],
                &[trace("side", "000")],
            );
            return (0, 0, 2);
        }
        "side_without_owner" | "side_owner_directory_unlisted" => {
            let traces = if name == "side_owner_directory_unlisted" {
                vec![trace("side", "unlisted")]
            } else {
                vec![]
            };
            c.evidence(&[api("r1", 10, 100), api("side", 5, 50)], &traces);
            return (0, 0, 1);
        }
        _ => unreachable!(),
    }
    (0, 1, 0)
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
    // A codec source's page continues from its owner's route, as Claude's do.
    let prior = crate::snapshots::e2_pipeline_scan_fixture::route_for_test(
        source,
        Some(scanner.cache.as_ref()),
        prior,
    );
    other_page_with_slots(c, scanner, source, prior, &[], before_finalize)
}

/// A page that reads a fixture route's graph unrouted: it stages no Tail, as
/// a build without the source's codec.
fn other_page_unrouted(
    c: &Corpus,
    scanner: &E2ScanFixture,
    source: SnapshotSource,
    prior: ScanIndex,
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let prior = crate::snapshots::e2_pipeline_scan_fixture::route_for_test(source, None, prior);
    let page = other_page_with_slots(c, scanner, source, prior, &[], |_| {});
    assert!(
        crate::snapshots::e2_pipeline_scan_fixture::route_of(&page.0).is_none(),
        "a downgrade fixture must stage no Tail on a route",
    );
    page
}

/// [`other_page_observing_raw`], binding accounts with these registered Codex
/// slots as the daemon's sync does.
fn other_page_with_slots(
    c: &Corpus,
    scanner: &E2ScanFixture,
    source: SnapshotSource,
    prior: ScanIndex,
    slots: &[(String, String, usize)],
    before_finalize: impl FnOnce(&[SnapshotItem]),
) -> (ScanIndex, SourceScanResult, (usize, usize, usize)) {
    let (mut index, mut scan, modes) = scanner.scan_other(
        source,
        std::slice::from_ref(&c.root),
        &c.support,
        prior,
        true,
    );
    index.bind_session_accounts_with_mixed(
        source,
        "e2-synthetic-machine",
        &mut scan.snapshots,
        &[],
        (slots, &mut [0; 9]),
        &Default::default(),
    );
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
fn codex_case(legacy: bool, content: bool) {
    let name = match (legacy, content) {
        (true, false) => "codex_legacy_acked_sticky",
        (false, false) => "codex_v2_sticky",
        (true, true) => "codex_content_legacy",
        (false, true) => "codex_content_v2",
    };
    if !supported(name) {
        return;
    }
    let c = corpus(name);
    // Codex continues from its state database route, as Claude does.
    let mut disk = Disk::with_route(&c, SnapshotSource::Codex);
    let path = c.root.join("rollout.jsonl");
    let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z","payload":{"id":ROOT,"timestamp":"2026-10-27T07:00:00Z"}}).to_string()+"\n";
    let content_prefix = if content {
        [
            json!({"type":"turn_context","timestamp":"2026-10-27T07:00:00Z",
                "payload":{"turn_id":"turn-a","cwd":"/synthetic/codex","model":"gpt-5.2"}}),
            json!({"type":"event_msg","timestamp":"2026-10-27T07:00:00Z",
                "payload":{"type":"user_message","message":"Synthetic content-only replay prompt"}}),
        ].iter().map(|line| line.to_string()+"\n").collect::<String>()
    } else {
        String::new()
    };
    std::fs::write(&path, header + &content_prefix + &codex_rows("turn-a", 10)).unwrap();
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
        disk.commit(&scanner.cache, source, &mut index)
    };
    append(&path, &codex_rows("turn-b", 30));
    input_clock(&path);
    let _cutover = crate::snapshots::TestCutover::set(0);
    if legacy {
        // The old binary's cutover differs, so its committed head cannot be
        // reused. Warm the upgraded binary from the actual Legacy ACK facts,
        // then exercise its next page's routed Tail under that same rule.
        let (mut upgraded, scan, modes) = other_page(&c, &scanner, source, prior);
        assert_eq!(modes, (1, 0, 0));
        assert!(!scan.snapshots.is_empty());
        assert!(upgraded.files.values().all(|e| !e.codex_counting_v2));
        prior = disk.commit(&scanner.cache, source, &mut upgraded);
        append(&path, &codex_rows("turn-c", 40));
        input_clock(&path);
    }
    let restart = disk.owner(source);
    save_inputs(&c);
    let (tail_index, tail, modes) = other_page(&c, &scanner, source, prior.clone());
    assert_eq!(modes, (0, 1, 0), "must continue from the Codex route head");
    let (_, full, modes) = other_page(&c, &E2ScanFixture::default(), source, prior.clone());
    assert_eq!(modes, (1, 0, 0));
    // S2b: a new owner continues from the same committed Codex heads.
    let (_, restored, modes) = other_page(&c, &restart, source, prior);
    assert_eq!(
        modes,
        (0, 1, 0),
        "a restarted Codex owner continues from the same committed heads"
    );
    assert!(tail_index
        .files
        .values()
        .all(|e| e.codex_counting_v2 != legacy));
    let (a, b) = (other_wire(source, &tail), other_wire(source, &full));
    let d = other_wire(source, &restored);
    assert_eq!(a, b);
    assert_eq!(d, b, "restarted envelope differs from cold Full");
    assert_eq!(d, a, "restarted envelope differs from the RAM arm");
    assert_eq!(Sha256::digest(&a), Sha256::digest(&b));
    assert_eq!(Sha256::digest(&d), Sha256::digest(&b));
    // The existing cross-build exporter has a fixed receipt catalog. This
    // additional same-build content fence proof emits no catalog entry.
    if content {
        return;
    }
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
    codex_case(false, false);
}
#[test]
fn codex_legacy_acked_sticky() {
    codex_case(true, false);
}

/// [money] Content-only Legacy/V2 replay preserves the emitted body and never
/// adds the restored prefix twice; a cold Full is the independent body oracle.
#[test]
fn codex_content_only_caller_matches_cold_full() {
    for legacy in [false, true] {
        codex_case(legacy, true);
    }
}

/// [money] An indexed sibling transcript deleted after a committed page is
/// retired through its directory's complete read and secure absence proof.
/// The live file's next page emits the same envelope through its retained
/// Tail, a cold Full and a restarted owner. Pi retires the sibling in every
/// arm; Codex protection may keep it, identically in every arm. The live
/// entry stays. Same-build proof only: no receipt.
#[test]
fn deleted_sibling_retires_without_changing_live_money() {
    const SIBLING: &str = "5b1b1b1b-0000-4000-8000-00000000c0de";
    for source in [SnapshotSource::Codex, SnapshotSource::Pi] {
        let name = format!("deleted_sibling_{}", source.api_slug());
        if !supported(&name) {
            return;
        }
        let _cutover = crate::snapshots::TestCutover::set(0);
        let c = corpus(&name);
        let mut disk = Disk::with_route(&c, source);
        let (live, sibling) = (c.root.join("live.jsonl"), c.root.join("sibling.jsonl"));
        let header = |id: &str| {
            json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z",
                "payload":{"id":id,"timestamp":"2026-10-27T07:00:00Z"}})
            .to_string()
                + "\n"
        };
        let (scanner, live_body, sibling_body, growth) = if source == SnapshotSource::Codex {
            (
                E2ScanFixture::default(),
                header(ROOT) + &codex_rows("turn-a", 10),
                header(SIBLING) + &codex_rows("turn-s", 5).replace(ROOT, SIBLING),
                codex_rows("turn-b", 30),
            )
        } else {
            (
                disk.owner(source),
                pi_seed(),
                pi_seed().replacen("synthetic-pi-session", "synthetic-pi-sibling", 1),
                pi_json(pi_turn(
                    "message",
                    Some("sibling-growth"),
                    20,
                    "2026-10-27T06:01:00Z",
                )),
            )
        };
        for (path, body) in [(&live, &live_body), (&sibling, &sibling_body)] {
            std::fs::write(path, body).unwrap();
            input_clock(path);
        }
        if source == SnapshotSource::Codex {
            disk.begin(&scanner, source);
        }
        let (mut index, scan, _) = other_page(&c, &scanner, source, ScanIndex::default());
        assert!(!scan.snapshots.is_empty(), "{source:?}");
        let key = |path: &Path| path.to_string_lossy().into_owned();
        assert!(index.files.contains_key(&key(&sibling)), "{source:?}");
        let prior = disk.commit(&scanner.cache, source, &mut index);
        std::fs::remove_file(&sibling).unwrap();
        append(&live, &growth);
        input_clock(&live);
        let restart = disk.owner(source);
        let (tail_index, tail, _) = other_page(&c, &scanner, source, prior.clone());
        let (full_index, full, _) =
            other_page(&c, &E2ScanFixture::default(), source, prior.clone());
        let (restored_index, restored, _) = other_page(&c, &restart, source, prior);
        let wire = other_wire(source, &full);
        assert_eq!(other_wire(source, &tail), wire, "{source:?}: Tail");
        assert_eq!(other_wire(source, &restored), wire, "{source:?}: restart");
        // Codex protection may keep the sibling's custody; every route agrees.
        let custody = |index: &ScanIndex| index.files.contains_key(&key(&sibling));
        for index in [&tail_index, &full_index, &restored_index] {
            assert!(index.files.contains_key(&key(&live)), "{source:?}");
            assert_eq!(custody(index), custody(&full_index), "{source:?}");
            assert!(
                source == SnapshotSource::Codex || !custody(index),
                "{source:?}"
            );
        }
    }
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

pub(super) fn grow(path: &Path, request: &str, tokens: u64) {
    append(path, &line(ROOT, request, AT, tokens));
    input_clock(path);
}

/// A restart between every page: each page's new owner continues from the Tail
/// heads its predecessor committed and must emit a cold Full's bodies.
#[test]
fn restart_between_pages() {
    let name = "restart_between_pages";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let (c, mut disk, path, scanner, prior) = disk_corpus(name);
        let mut priors = [prior.clone(), prior.clone(), prior];
        let mut bodies = Vec::new();
        for (request, tokens) in [("r2", 20), ("r3", 30)] {
            grow(&path, request, tokens);
            let restart = disk.owner(SnapshotSource::ClaudeCode);
            let mut pages = claude_pages(&c, &scanner, &restart, priors, (0, 1, 0));
            finish_claude_pages(&c, &mut pages);
            bodies.push(compare_claude_uploads(&pages));
            let [_, _, mut disk_page] = pages;
            accept_page(&mut disk_page);
            let next = disk.commit(
                &disk_page.cache,
                SnapshotSource::ClaudeCode,
                &mut disk_page.index,
            );
            // The cold arm reads the same committed prior: its own unACKed
            // lineage, republished on a new route, holds a growth claim bound
            // to the old one.
            priors = [next.clone(), next.clone(), next];
        }
        assert_ne!(bodies[0].raw, bodies[1].raw, "the second page adds money");
        disk_verified(name, &bodies, 2);
    });
}

/// An upgraded binary that changes no head binding continues the older
/// binary's head. The older owner's next pass sees the file unchanged and
/// commits again without rewriting that head, so the head is older than the
/// committed index. The upgraded owner (a new process) must still load it and
/// Tail the growth. A real cross-binary upgrade is not buildable in one test
/// binary.
#[test]
fn upgrade_without_semantic_revision() {
    let name = "upgrade_without_semantic_revision";
    if !supported(name) {
        return;
    }
    with_e2(|| {
        let (c, mut disk, path, scanner, prior) = disk_corpus(name);
        disk.begin(&scanner, SnapshotSource::ClaudeCode);
        let mut quiet = c.raw(&scanner, prior.clone(), 100, true, &[]);
        assert_eq!(
            quiet.modes.0 + quiet.modes.1,
            0,
            "the older owner's file is unchanged: no read"
        );
        quiet.enrich(&c);
        quiet.finish();
        accept_page(&mut quiet);
        let committed = disk.commit(&quiet.cache, SnapshotSource::ClaudeCode, &mut quiet.index);
        assert!(committed.generation > prior.generation);
        grow(&path, "r2", 20);
        let upgraded = disk.owner(SnapshotSource::ClaudeCode);
        let pages = claude_pages(
            &c,
            &scanner,
            &upgraded,
            [committed.clone(), committed.clone(), committed],
            (0, 1, 0),
        );
        disk_verified(name, &[compare_claude_pages(&c, pages)], 1);
    });
}

// These names are executable backlog, not simulated disk restores or family
// commits. Do not remove an ignore until its stated production feature exists.
macro_rules! pending {
    ($name:ident, $reason:literal) => {
        /// [money] codex admission branches preserve emitted totals.
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

// Pi uses the same scanner, committed index and durable store as the others.
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

    /// Same-build proof only: the cross-build receipt catalog has no Pi rows,
    /// so this checks the identity scope, emitting nothing.
    fn finish(self) {
        assert!(!self.bodies.is_empty(), "zero emitted bodies is no proof");
        for body in &self.bodies {
            body.cross_build();
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
    let mut disk = Disk::with_route(&c, SnapshotSource::Pi);
    let scanner = disk.owner(SnapshotSource::Pi);
    let (mut index, scan, modes) =
        other_page(&c, &scanner, SnapshotSource::Pi, ScanIndex::default());
    assert_eq!(modes, (1, 0, 0), "head must exercise sampled Pi");
    assert!(!scan.snapshots.is_empty());
    let prior = disk.commit(&scanner.cache, SnapshotSource::Pi, &mut index);
    let mut proof = PiProof {
        sampled: true,
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

#[track_caller]
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

/// One Pi page's expectations: the retained and disk acquisition modes, the
/// and an optional ledger check on every arm.
struct PiPageExpect<'a> {
    ram_mode: (usize, usize, usize),
    disk_mode: (usize, usize, usize),
    ledger: Option<&'a PiLedgerCheck<'a>>,
}

impl PiPageExpect<'_> {
    fn modes(ram_mode: (usize, usize, usize), disk_mode: (usize, usize, usize)) -> Self {
        Self {
            ram_mode,
            disk_mode,
            ledger: None,
        }
    }
}

// Every arm reads from the same committed `prior`: Pi keeps no RAM reduction
// on its Tail route, so the retained owner continues from the committed heads
// too, and the arms differ only in what they recompute from that one saved
// graph. Returns the restart arm's index, which callers commit.
// Quarantined files have no emitted body; compare their disposition and
// retryability instead of inventing a successful upload.
fn pi_pages(
    proof: &mut PiProof,
    c: &Corpus,
    retained: &E2ScanFixture,
    restart: &E2ScanFixture,
    prior: ScanIndex,
    expect: PiPageExpect<'_>,
) -> (ScanIndex, SourceScanResult) {
    let PiPageExpect {
        ram_mode,
        disk_mode,
        ledger,
    } = expect;
    save_inputs(c);
    let page = |scanner: &E2ScanFixture, prior| match ledger {
        Some(check) => check.page(c, scanner, prior),
        None => other_page(c, scanner, SnapshotSource::Pi, prior),
    };
    let (tail_index, tail, mode) = page(retained, prior.clone());
    assert_eq!(
        mode,
        if proof.sampled { ram_mode } else { (0, 0, 0) },
        "Pi retained acquisition"
    );
    let (full_index, full, mode) = page(&E2ScanFixture::default(), prior.clone());
    assert_eq!(mode.1 + mode.2, 0, "cold Pi cannot reuse a reduction");
    let (disk_index, restored, mode) = page(restart, prior);
    // A new owner continues from the same committed Tail heads.
    assert_eq!(
        mode,
        if proof.sampled { disk_mode } else { (0, 0, 0) },
        "Pi restarted acquisition"
    );
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
            "Pi restarted owner != Full"
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
    (disk_index, full)
}

macro_rules! pi_row {
    ($name:expr) => {
        if !supported($name) {
            return;
        }
    };
}

fn pi_splits(name: &str, prefix: &str, suffix: Vec<Value>, requests: u64) -> SourceScanResult {
    let (c, mut disk, path, scanner, mut prior, mut proof) = pi_disk_corpus(name, prefix);
    let mut last = None;
    for value in suffix {
        pi_grow(&path, value);
        let restart = disk.owner(SnapshotSource::Pi);
        let (mut restored, scan) = pi_pages(
            &mut proof,
            &c,
            &scanner,
            &restart,
            prior.clone(),
            PiPageExpect::modes((0, 1, 0), (0, 1, 0)),
        );
        prior = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
        last = Some(scan);
    }
    let scan = last.expect("fixture must cross a seal");
    assert_eq!(
        scan.snapshots.iter().map(|s| s.request_count).sum::<u64>(),
        requests,
        "{name}"
    );
    proof.finish();
    scan
}

fn pi_ledger_splits(
    name: &str,
    prefix: &str,
    initial: PiLedgerStep,
    suffix: Vec<(Value, PiLedgerStep)>,
    final_totals: (u64, u64),
) {
    let (c, mut disk, path, scanner, mut prior, mut proof) = pi_disk_corpus(name, prefix);
    assert!(matches!(initial, PiLedgerStep::Emit(..)));
    let mut accepted = proof.bodies[0].items.clone();
    assert_eq!(pi_ledger_totals(&accepted), initial.totals());
    // The shared initial prefix is accepted by all three arms. Check a cold
    // Full against the retained arm's actual captured body too. A restarted
    // owner continues from the committed graph, never a default one: with no
    // head it is this cold Full, and pi_pages restarts it on every step.
    let (_, scan, _) = PiLedgerCheck {
        step: initial,
        accepted: &[],
    }
    .page(&c, &E2ScanFixture::default(), ScanIndex::default());
    assert_eq!(other_wire(SnapshotSource::Pi, &scan), proof.bodies[0].raw);
    // pi_pages compares the replayed suffix's emitted wire to cold Full. A
    // dropped conflict keeps its predecessor head: the next read Tails from it.
    for (value, step) in suffix {
        pi_grow(&path, value);
        let restart = disk.owner(SnapshotSource::Pi);
        let (mut restored, scan) = pi_pages(
            &mut proof,
            &c,
            &scanner,
            &restart,
            prior.clone(),
            PiPageExpect {
                ledger: Some(&PiLedgerCheck {
                    step,
                    accepted: &accepted,
                }),
                ..PiPageExpect::modes((0, 1, 0), (0, 1, 0))
            },
        );
        if matches!(step, PiLedgerStep::Emit(..)) {
            accepted = scan.snapshots;
        }
        prior = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
    }
    assert_eq!(pi_ledger_totals(&accepted), final_totals, "{name}");
    proof.finish();
}

/// [money] A plain Pi session split at every line boundary emits cold Full's
/// money from the RAM Tail and the disk restore.
#[test]
fn pi() {
    pi_row!("pi");
    // Every appended line boundary, including model/thinking changes,
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

/// [money] A tool call, its result and the next turn split across pages emit
/// cold Full's money on every route.
#[test]
fn pi_tool_turn() {
    pi_row!("pi_tool_turn");
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

/// [money] Compaction and branch-summary usage counts once, in its own hour and
/// model row, on every route.
#[test]
fn pi_summary_usage() {
    pi_row!("pi_summary_usage");
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

/// [money] Standalone usage entries of a known and an unknown kind count under
/// their provider on every route.
#[test]
fn pi_usage_entry_kinds() {
    pi_row!("pi_usage_entry_kinds");
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

/// [money] The usage dedup ledger keeps counts, pairs and conflicts across every
/// restore seal.
#[test]
fn pi_ledger_seal_boundaries() {
    pi_row!("pi_ledger_seal_boundaries");
    use PiLedgerStep::{ConflictDrop, Emit, Noop};
    let message = pi_turn(
        "message",
        Some("synthetic-reused"),
        20,
        "2026-10-27T06:01:00Z",
    );
    let mut end = message.clone();
    end["type"] = json!("message_end");
    // A duplicate on both sides of the seal; count > 1 must survive.
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
    // paired_digests is nonempty at commit, before another exact pair.
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

/// [money] A message_end whose usage diverges from its message drops that usage
/// on every route, before or after a pair.
#[test]
fn pi_divergent_pair_quarantine() {
    pi_row!("pi_divergent_pair_quarantine");
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
    pi_row!(name);
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

/// [money] A selector recorded before the seal applies to the usage after it on
/// every route.
#[test]
fn pi_selector_across_seal() {
    pi_row!("pi_selector_across_seal");
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

/// [money] Hour buckets, late times, invalid cost or time and overflowing usage
/// resolve as in cold Full on every route.
#[test]
fn pi_time_and_invalid_evidence() {
    pi_row!("pi_time_and_invalid_evidence");
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
    let scan = pi_splits("pi_usage_overflow", &pi_seed(), vec![huge], 1);
    assert_eq!(scan.snapshots[0].input_tokens, 10);
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
    pi_row!("pi_cli_fork_preserves_double_count");
    // The fork rule skips only copies stamped before the fork header; these copies are
    // stamped at or after it, so they stay counted.
    const EXPECTED_FORK_TOTALS: (u64, u64) = (3, 40);
    let (c, mut disk, path, scanner, prior, mut proof) =
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
        prior,
        PiPageExpect::modes((1, 1, 0), (1, 1, 0)),
    );
    assert_eq!(scan.snapshots.len(), 2);
    assert_eq!(
        (
            scan.snapshots.iter().map(|s| s.request_count).sum::<u64>(),
            scan.snapshots.iter().map(|s| s.input_tokens).sum::<u64>(),
        ),
        EXPECTED_FORK_TOTALS
    );
    proof.finish();
}

fn pi_lifecycle_case(name: &str) {
    pi_row!(name);
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
    let (c, mut disk, path, mut scanner, prior, mut proof) = pi_disk_corpus(name, &initial);
    let mut prior = if downgrade {
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
        // The older build has no Pi codec: it reads the growth Full, stages
        // no Tail and commits its index on the same route, so the committed
        // heads stay those of the first page.
        let (mut down, scan, mode) =
            other_page_unrouted(&c, &scanner, SnapshotSource::Pi, prior.clone());
        assert_eq!(
            mode,
            if proof.sampled { (1, 0, 0) } else { (0, 0, 0) },
            "{name}"
        );
        proof.capture(&scan);
        crate::snapshots::e2_pipeline_scan_fixture::onto_route_for_test(&mut down, &prior);
        let committed = disk.commit(&scanner.cache, SnapshotSource::Pi, &mut down);
        // The reupgraded build is a new process on the committed route.
        scanner = disk.owner(SnapshotSource::Pi);
        committed
    } else if rewrite {
        prior.clone()
    } else {
        disk.begin(&scanner, SnapshotSource::Pi);
        let (mut quiet, _, mode) = other_page(&c, &scanner, SnapshotSource::Pi, prior.clone());
        assert_eq!(mode.0 + mode.1, 0, "{name}");
        let committed = disk.commit(&scanner.cache, SnapshotSource::Pi, &mut quiet);
        assert!(committed.generation > prior.generation, "{name}");
        committed
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
        let disk_mode = if migrating { (1, 0, 0) } else { (0, 1, 0) };
        let (mut restored, scan) = pi_pages(
            &mut proof,
            &c,
            &scanner,
            &restart,
            prior.clone(),
            PiPageExpect::modes(ram_mode, disk_mode),
        );
        if migrating {
            assert_eq!(scan.snapshots[0].request_count, 3, "{name}");
        }
        if step + 1 == turns.len() {
            break;
        }
        prior = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
    }
    proof.finish();
}

/// [money] A version rewrite after Tail must reacquire Full without double billing.
#[test]
fn pi_version_rewrite_after_tail() {
    pi_lifecycle_case("pi_version_rewrite_after_tail");
}

/// [money] A restart between pages restores the previous page's record and
/// emits cold Full's money.
#[test]
fn pi_restart_between_pages() {
    pi_row!("pi_restart_between_pages");
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
/// [money] A mode-only change reads nothing, an mtime-only change reads Full,
/// and later growth restores and Tails, each equal to cold Full.
#[test]
fn pi_acquisition_metadata_changes() {
    pi_row!("pi_acquisition_metadata_changes");
    use std::os::unix::fs::PermissionsExt;
    let (c, mut disk, path, scanner, prior, mut proof) =
        pi_disk_corpus("pi_acquisition_metadata_changes", &pi_seed());
    let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
    let permissions = std::fs::metadata(&path).unwrap().permissions().mode();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(permissions ^ 0o100)).unwrap();
    assert_eq!(
        std::fs::metadata(&path).unwrap().modified().unwrap(),
        modified
    );
    let restart = disk.owner(SnapshotSource::Pi);
    let (mut restored, _) = pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        prior,
        PiPageExpect::modes((0, 0, 0), (0, 0, 0)),
    );
    let next = disk.commit(&restart.cache, SnapshotSource::Pi, &mut restored);
    std::fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(modified + std::time::Duration::from_secs(2))
        .unwrap();
    let restart = disk.owner(SnapshotSource::Pi);
    let (mut restored, _) = pi_pages(
        &mut proof,
        &c,
        &scanner,
        &restart,
        next,
        PiPageExpect::modes((1, 0, 0), (1, 0, 0)),
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
        next,
        PiPageExpect::modes((0, 1, 0), (0, 1, 0)),
    );
    proof.finish();
}

/// [money] Admission branches omitted by the native-authority sticky fixture. Check
/// real scanner output against explicit additive totals, without a frozen parser.
#[test]
fn codex_admission_branches_preserve_emitted_totals() {
    if !supported("codex_admission_branches") {
        return;
    }
    let usage = |n: u64| {
        json!({"input_tokens":n,"cached_input_tokens":0,
        "output_tokens":0,"reasoning_output_tokens":0,"total_tokens":n})
    };
    let ui = |id: u64, last: Option<u64>, total: u64| {
        let mut row = json!({"type":"event_msg","timestamp":"2026-10-27T07:00:02Z",
            "fixture_line":id,"payload":{"type":"token_count","info":{
                "model":"gpt-5.2","total_token_usage":usage(total)}}});
        if let Some(last) = last {
            row["payload"]["info"]["last_token_usage"] = usage(last);
        }
        row
    };
    let event = |kind: &str, turn: &str| {
        json!({"type":"event_msg",
        "timestamp":"2026-10-27T07:00:01Z","payload":{"type":kind,"turn_id":turn}})
    };
    let start = || event("task_started", "a");
    let close = || event("task_complete", "a");
    let mut fallback = ui(1, Some(1), 1);
    fallback["payload"]["info"]
        .as_object_mut()
        .unwrap()
        .remove("model");
    let mut dropped = ui(1, Some(1), 1);
    dropped["timestamp"] = json!("invalid");
    let mut explicit = ui(1, Some(1), 1);
    explicit["payload"]["info"]["last_token_usage"]["request_count"] = json!(3);
    explicit["payload"]["info"]["total_token_usage"]["request_count"] = json!(3);
    let mut overflow = vec![start()];
    overflow.extend((1..=66).map(|i| {
        let mut row = ui(i, Some(1), i);
        row["payload"]["info"]["model"] = json!(format!("fixture-model-{i}"));
        row
    }));
    overflow.push(close());
    let repeated = ui(2, Some(1), 1);
    for (name, legacy, lines, expected) in [
        (
            "unbound",
            false,
            vec![fallback.clone(), repeated.clone(), repeated],
            2,
        ),
        (
            "base-reset-zero-repeat",
            false,
            vec![
                start(),
                ui(1, None, 5),
                ui(2, None, 7),
                ui(3, None, 2),
                ui(4, Some(0), 2),
                ui(5, Some(1), 3),
                ui(6, Some(1), 3),
                close(),
            ],
            3,
        ),
        (
            "legacy-reset",
            true,
            vec![
                ui(1, None, 5),
                ui(2, None, 7),
                ui(3, None, 2),
                ui(4, Some(0), 2),
                ui(5, Some(1), 3),
                ui(5, Some(1), 3),
            ],
            10,
        ),
        (
            "closure-mismatch",
            false,
            vec![
                start(),
                ui(1, Some(1), 1),
                event("task_started", "b"),
                ui(2, Some(1), 2),
                event("task_complete", "other"),
            ],
            2,
        ),
        (
            "dropped-staging",
            false,
            vec![start(), dropped, ui(2, Some(1), 2), close()],
            1,
        ),
        ("pending-overflow", false, overflow, 66),
        ("model-fallback", true, vec![fallback, ui(2, Some(1), 2)], 2),
        (
            "explicit-request-count",
            false,
            vec![start(), explicit, close()],
            1,
        ),
        (
            "invalid-closure",
            false,
            vec![
                close(),
                event("task_complete", ""),
                event("task_complete", &"x".repeat(129)),
                start(),
                ui(1, Some(1), 1),
                event("task_complete", ""),
                close(),
            ],
            1,
        ),
    ] {
        let c = corpus(&format!("codex-admission-{name}"));
        let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z",
            "payload":{"id":ROOT,"timestamp":"2026-10-27T07:00:00Z"}});
        let prefix = header.to_string() + "\n";
        let text = std::iter::once(header)
            .chain(lines)
            .map(|v| v.to_string() + "\n")
            .collect::<String>();
        let path = c.root.join("rollout.jsonl");
        if name == "dropped-staging" {
            // Invalid records are isolated after a genuine disk restore and
            // Tail, as well as from RAM and a cold byte-zero read.
            let source = SnapshotSource::Codex;
            let _cutover = crate::snapshots::TestCutover::set(0);
            let mut disk = Disk::with_route(&c, source);
            let scanner = E2ScanFixture::default();
            disk.begin(&scanner, source);
            std::fs::write(&path, prefix + &codex_rows("seed", 1)).unwrap();
            input_clock(&path);
            let (mut prior, seed, modes) = other_page(&c, &scanner, source, ScanIndex::default());
            assert_eq!(modes, (1, 0, 0));
            assert!(!seed.snapshots.is_empty());
            prior.record_accepted_snapshot_fingerprints(
                &seed
                    .snapshots
                    .iter()
                    .map(|s| s.snapshot_fingerprint.clone())
                    .collect(),
            );
            let prior = disk.commit(&scanner.cache, source, &mut prior);
            append(&path, text.split_once('\n').unwrap().1);
            input_clock(&path);
            let restart = disk.owner(source);
            let arms = [
                other_page(&c, &scanner, source, prior.clone()),
                other_page(&c, &E2ScanFixture::default(), source, prior.clone()),
                other_page(&c, &restart, source, prior.clone()),
            ];
            assert_eq!(arms[0].2, (0, 1, 0));
            assert_eq!(arms[1].2, (1, 0, 0));
            // The restarted owner continues from the same committed Codex head.
            assert_eq!(arms[2].2, (0, 1, 0));
            for (_, scan, _) in &arms {
                assert_eq!(scan.dropped_usage_record_count, 1);
                assert_eq!(scan.recognized_usage_drop_count, 1);
                assert_eq!(scan.snapshots.len(), 1);
                assert_eq!(
                    scan.snapshots[0].input_tokens, 2,
                    "seed plus the valid staging sibling, never the invalid record"
                );
                assert!(!other_wire(source, scan).is_empty());
            }
            let emitted = |scan: &SourceScanResult| serde_json::to_vec(&scan.snapshots).unwrap();
            assert_eq!(emitted(&arms[0].1), emitted(&arms[1].1));
            assert_eq!(emitted(&arms[2].1), emitted(&arms[1].1));
            continue;
        }
        std::fs::write(&path, text).unwrap();
        input_clock(&path);
        let _cutover = crate::snapshots::TestCutover::set(if legacy { i64::MAX } else { 0 });
        let (_, scan, _) = other_page(
            &c,
            &E2ScanFixture::default(),
            SnapshotSource::Codex,
            ScanIndex::default(),
        );
        assert_eq!(
            scan.snapshots.iter().map(|s| s.input_tokens).sum::<u64>(),
            expected,
            "{name}"
        );
        if name == "explicit-request-count" {
            assert_eq!(
                scan.snapshots.iter().map(|s| s.request_count).sum::<u64>(),
                3
            );
        }
        let wire = other_wire(SnapshotSource::Codex, &scan);
        assert!(!wire.is_empty(), "{name}: emitted body must validate");
    }
}

/// [money] Rename-before-ACK restart reconstructs exactly the cold complete body.
#[test]
fn native_successor_rename_before_ack_cold_reopen_preserves_money() {
    successor_cold_reopen(None);
}

/// [money] Refused/not-stored successor remains unacknowledged across cold reopen.
#[test]
fn refused_or_not_stored_successor_cold_reopen_preserves_money() {
    for disposition in ["refused", "not_stored"] {
        successor_cold_reopen(Some(disposition));
    }
}

fn successor_cold_reopen(disposition: Option<&str>) {
    if !supported("successor-cold-reopen") {
        return;
    }
    with_e2(|| {
        let (c, mut disk, path, warm, prior) = disk_corpus(&format!(
            "successor-cold-reopen-{}",
            disposition.unwrap_or("before-ack")
        ));
        let progress_path = disk.dir.join("upload-progress.json");
        let mut progress = e2_progress();
        let mut accepted = c.raw(
            &E2ScanFixture::default(),
            ScanIndex::default(),
            100,
            true,
            &[],
        );
        accepted.enrich(&c);
        accepted.finish();
        assert_eq!(
            upload(&accepted.scan.snapshots, &mut progress, ack)
                .0
                .unwrap(),
            ResumableUploadResult::Completed
        );
        progress.save(&progress_path).unwrap(); // Existing receipts precede successor rename.
        let accepted_fingerprints = progress.accepted_fingerprints.clone();
        // Reuse these outcomes with a B2 loss-bearing successor.
        append(&path, "{broken\n");
        grow(&path, "next", 20);
        let mut successor = c.raw(&warm, prior.clone(), 100, true, &[]);
        successor.enrich(&c);
        successor.finish();
        let fulls = successor.modes.0;
        assert_eq!(successor.scan.malformed_json_line_count, 1);
        if let Some(disposition) = disposition {
            let _result = upload(&successor.scan.snapshots, &mut progress, |batch| {
                let mut response = ack(batch)?;
                if disposition == "not_stored" {
                    response.unchanged_entities = std::mem::take(&mut response.accepted_entities);
                    for entity in &mut response.unchanged_entities {
                        entity.unchanged_basis = Some("usage_identical".into());
                    }
                } else {
                    response.rejected_entities = std::mem::take(&mut response.accepted_entities)
                        .into_iter()
                        .map(|entity| crate::snapshot_client::SnapshotEntityRejection {
                            source_session_id: entity.source_session_id,
                            snapshot_fingerprint: entity.snapshot_fingerprint,
                            occurrence_count: entity.occurrence_count,
                            reason: "usage_accounting_authority_downgrade".into(),
                            detail: "synthetic refusal".into(),
                            permanent: true,
                        })
                        .collect();
                    response.accepted = 0;
                    response.sessions_reconciled = 0;
                }
                Ok(response)
            });
            progress.save(&progress_path).unwrap();
        }
        // Lose acquisition memory without saving its new index or ACK. Keep
        // the committed heads, original index and durable upload progress.
        drop(successor);
        drop(warm);
        let reloaded = SnapshotUploadProgress::load(
            &progress_path,
            &format!("{:064x}", 99),
            snapshot_quarantine_witness(SnapshotSource::ClaudeCode),
        )
        .unwrap();
        assert_eq!(reloaded.accepted_fingerprints, accepted_fingerprints);
        let reopened = disk.owner(SnapshotSource::ClaudeCode);
        let mut actual = c.raw(&reopened, prior.clone(), 100, true, &[]);
        let mut cold = c.raw(&E2ScanFixture::default(), prior, 100, true, &[]);
        actual.enrich(&c);
        actual.finish();
        cold.enrich(&c);
        cold.finish();
        assert!(fulls + actual.modes.0 <= 1);
        assert!(!actual.scan.snapshots.is_empty());
        assert_eq!(actual.scan.malformed_json_line_count, 1);
        assert_eq!(
            serde_json::to_value(&actual.index).unwrap()["terminal_jsonl_dispositions"],
            serde_json::to_value(&cold.index).unwrap()["terminal_jsonl_dispositions"]
        );
        let (a, actual_wire, _) = upload(&actual.scan.snapshots, &mut e2_progress(), ack);
        let (b, cold_wire, _) = upload(&cold.scan.snapshots, &mut e2_progress(), ack);
        assert_eq!(a.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(b.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(
            actual_wire, cold_wire,
            "complete money and identity bodies survive cold reopen"
        );
    });
}

/// Invoked by the existing challenge fixture: exercise the same emitted-body
/// oracle with real account evidence, without adding a second test/receipt name.
pub(in crate::snapshot_sync) fn assert_head_conflict_account_placement() {
    assert!(
        crate::heap_layout_bound::layout_supported(),
        "placement oracle must execute"
    );
    with_e2(|| {
        let mut c = corpus("head-conflict-account-placement");
        let org_a = "11111111-1111-4111-8111-111111111111";
        let org_b = "22222222-2222-4222-8222-222222222222";
        let marker = |org: &str| {
            json!({"type":"attachment","sessionId":ROOT,
            "attachment":{"type":"credential_org","organizationUuid":org}})
            .to_string()
                + "\n"
        };
        let path = c.root(ROOT, &(marker(org_a) + &line(ROOT, "r1", AT, 10)));
        input_clock(&path);
        c.evidence(&[api("r1", 10, 100)], &[]);
        let disk = Disk::new(&c);
        let retained = E2ScanFixture::capturing_identity();
        disk.begin(&retained, SnapshotSource::ClaudeCode);
        let mut warm = c.raw(&retained, ScanIndex::default(), 100, true, &[]);
        warm.enrich(&c);
        warm.finish();
        accept_page(&mut warm);
        let prior = disk.commit(&warm.cache, SnapshotSource::ClaudeCode, &mut warm.index);
        let switch = json!({"type":"attachment","sessionId":ROOT,
            "attachment":{"type":"session_context","context":{}}})
        .to_string()
            + "\n";
        append(
            &path,
            &(switch + &marker(org_b) + &line(ROOT, "r2", "2026-08-02T07:00:20Z", 20)),
        );
        c.evidence(&[api("r1", 10, 100), api("r2", 20, 200)], &[]);
        input_clock(&path);
        let restart = E2ScanFixture::capturing_identity();
        disk.begin(&restart, SnapshotSource::ClaudeCode);
        let cold = E2ScanFixture::capturing_identity();
        let restarted = c.raw(&restart, prior.clone(), 100, true, &[]);
        let mut pages = [
            c.raw(&retained, prior.clone(), 100, true, &[]),
            c.raw(&cold, prior, 100, true, &[]),
            restarted,
        ];
        assert_eq!(pages[0].modes, (0, 1, 0), "warm owner Tail");
        assert_eq!(pages[1].modes, (1, 0, 0), "cold Full");
        assert_eq!(pages[2].modes, (0, 1, 0), "new owner Tail");
        finish_claude_pages(&c, &mut pages);
        let receipt = compare_claude_uploads(&pages);
        let a = ottto_core::billing_identity_hash("anthropic", "organization", org_a).unwrap();
        let b = ottto_core::billing_identity_hash("anthropic", "organization", org_b).unwrap();
        let item = receipt
            .items
            .iter()
            .find(|item| item.source_session_id == ROOT)
            .unwrap();
        assert_eq!((item.request_count, item.input_tokens), (2, 30));
        assert_eq!(
            item.cost.as_ref().unwrap().total_cost_usd.as_deref(),
            Some("0.0003")
        );
        let mut placement = Vec::new();
        for row in &item.model_usage {
            let row = serde_json::to_value(row).unwrap();
            let parts = row.get("identity_parts").and_then(Value::as_array);
            let parts = parts.map_or(std::slice::from_ref(&row), Vec::as_slice);
            for part in parts {
                let evidence =
                    &item.request_evidence[part["evidence_ref"].as_u64().unwrap() as usize];
                placement.push((
                    evidence.provider_workspace_hash.clone().unwrap(),
                    part["request_count"].as_u64().unwrap(),
                    part["input_tokens"].as_u64().unwrap(),
                    part["cost_usd"].as_str().unwrap().to_string(),
                ));
            }
        }
        placement.sort();
        let mut expected = vec![
            (a, 1, 10, "0.0001".to_string()),
            (b, 1, 20, "0.0002".to_string()),
        ];
        expected.sort();
        assert_eq!(
            placement, expected,
            "non-vacuous totals AND account placement across all three arms"
        );
        println!("HEAD_CONFLICT_MONEY_ORACLE VERIFIED arms=cold_full,ram_tail,restored_tail accounts=2 requests=2 input_tokens=30 cost_usd=0.0003");
    });
}

/// A `/branch` session: a copied parent line (`forkedFrom`) proves the owned
/// start, so the e2 body has strict posture and carries its cache patch.
fn forked_root(c: &mut Corpus) -> PathBuf {
    let mut copied: Value = serde_json::from_str(line(ROOT, "r0", AT, 5).trim()).unwrap();
    copied["forkedFrom"] = serde_json::json!({
        "sessionId": "3338a80a-f36e-4cbc-a5bb-50fc66430ba5", "messageUuid": "m-0"});
    let path = c.root(
        ROOT,
        &(copied.to_string() + "\n" + &line(ROOT, "r1", AT, 10)),
    );
    input_clock(&path);
    path
}

/// The production network projection: base head and cache patch per the ledger.
fn under_cas(items: &[SnapshotItem], progress: &SnapshotUploadProgress) -> Vec<SnapshotItem> {
    let mut items = items.to_vec();
    for item in &mut items {
        prepare_snapshot_cache_for_upload(item, progress, true, false, &BTreeSet::new());
    }
    items
}

/// The server's CAS check refuses ROOT's stale base and mints `challenge`;
/// every other entity is accepted.
fn refuse_root(
    batch: &[SnapshotItem],
    challenge: &str,
) -> Result<crate::snapshot_client::SnapshotBatchResponse> {
    let mut response = ack(batch)?;
    for mut reference in std::mem::take(&mut response.accepted_entities) {
        if reference.source_session_id != ROOT {
            response.accepted_entities.push(reference);
            continue;
        }
        response.accepted -= 1;
        response.sessions_reconciled -= 1;
        reference.head_etag = None;
        reference.body_witness_version = None;
        reference.body_witness_digest = None;
        reference.head_challenge = Some(challenge.to_owned());
        response.conflict_entities.push(reference);
    }
    response.bind_conflict_rescans(&request(batch));
    Ok(response)
}

/// Three arms over one prior: the warm owner, a cold Full, and a new owner
/// whose Tail load hits are counted.
fn arms(c: &Corpus, warm: &E2ScanFixture, disk: &mut Disk, prior: &ScanIndex) -> ([Page; 3], u64) {
    let hits = || {
        crate::snapshots::e2_pipeline_scan_fixture::tail_counter_for_test("tail_db_loads", "hit")
    };
    let restart = disk.owner(SnapshotSource::ClaudeCode);
    let tail = c.raw(warm, prior.clone(), 100, true, &[]);
    let full = c.raw(&E2ScanFixture::default(), prior.clone(), 100, true, &[]);
    let before = hits();
    let disk = c.raw(&restart, prior.clone(), 100, true, &[]);
    let disk_hits = hits() - before;
    assert_eq!(full.modes.1 + full.modes.2, 0, "cold arm reads Full");
    ([tail, full, disk], disk_hits)
}

/// The owed answer rides exactly ROOT's outgoing body.
fn answers(page: &Page, progress: &SnapshotUploadProgress, challenge: &str) {
    let mut sent = under_cas(&page.scan.snapshots, progress);
    let now = current_unix_seconds();
    assert_eq!(attach_head_conflict_answers(&mut sent, progress, now), 1);
    let root = sent.iter().find(|item| item.source_session_id == ROOT);
    let answer = root.and_then(|item| item.cache_conflict_answer.clone());
    assert_eq!(answer.map(|(c, _)| c), Some(challenge.to_owned()));
}

/// [money] SOURCE Addendum 7 (Q2) GOLDEN, conflict then append. A head-CAS
/// conflict with a challenge is recorded on a production-shaped Claude body.
/// While the answer is owed (the ledger's challenge mirrored into the scan
/// index, as each prepare does), no read continues from stored state: (a) a
/// 0-new-byte late-evidence selection and (b) an append read a native Full,
/// with no saved-head hit, equal to the cold Full, and that Full carries the
/// answer. The append's Full holds the route's six-hour growth claim, so a
/// second owner on the same route defers.
#[test]
fn conflict_then_append() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    with_e2(|| {
        let mut c = corpus("conflict_then_append");
        let path = forked_root(&mut c);
        c.evidence(&[api("r1", 10, 100)], &[]);
        let mut disk = Disk::new(&c);
        let warm = E2ScanFixture::default();
        disk.begin(&warm, SnapshotSource::ClaudeCode);
        let mut progress = e2_progress();
        let key = cache_session_key(ROOT);
        let challenge = "c".repeat(64);

        let mut first = c.raw(&warm, ScanIndex::default(), 100, true, &[]);
        first.enrich(&c);
        first.finish();
        let sent = under_cas(&first.scan.snapshots, &progress);
        assert!(sent.iter().any(|item| item.cache_observations.is_some()));
        let (result, _, _) = upload(&sent, &mut progress, ack);
        assert_eq!(result.unwrap(), ResumableUploadResult::Completed);
        settle_index_after_upload(&mut first.index, &first.committed, &progress);
        accept_upload_context_acks_for_test(
            &mut first.index,
            &first.scan.snapshots,
            &progress.fresh_context_body_acks,
        );
        let prior = disk.commit(&first.cache, SnapshotSource::ClaudeCode, &mut first.index);
        assert_eq!(
            progress.accepted_cache_heads.get(&key),
            Some(&"e".repeat(64))
        );

        // An append on the stale base: the server refuses it with a challenge.
        append(&path, &line(ROOT, "r2", AT, 20));
        input_clock(&path);
        c.evidence(&[api("r1", 10, 100), api("r2", 20, 200)], &[]);
        let mut refused = c.raw(&warm, prior, 100, true, &[]);
        assert_eq!(
            refused.modes,
            (0, 1, 0),
            "the refused body is a Tail append"
        );
        refused.enrich(&c);
        refused.finish();
        let sent = under_cas(&refused.scan.snapshots, &progress);
        let (result, _, _) = upload(&sent, &mut progress, |batch| refuse_root(batch, &challenge));
        assert!(matches!(
            result.unwrap(),
            ResumableUploadResult::Deferred { .. }
        ));
        assert_eq!(progress.head_conflict_challenges[&key].challenge, challenge);
        let fingerprint = &sent.iter().find(|i| i.source_session_id == ROOT).unwrap();
        let fingerprint = fingerprint.snapshot_fingerprint.clone();
        assert_eq!(
            progress.quarantined_fingerprints[&fingerprint].disposition,
            SnapshotQuarantineDisposition::RetryPending
        );
        settle_index_after_upload(&mut refused.index, &refused.committed, &progress);
        let mut prior = disk.commit(
            &refused.cache,
            SnapshotSource::ClaudeCode,
            &mut refused.index,
        );
        assert!(prior
            .quarantined_snapshot_fingerprints
            .contains_key(&fingerprint));
        prior.activate_head_conflict_sessions(
            progress.head_conflict_challenges.keys().cloned().collect(),
        );

        // (a) 0 new bytes, late evidence: no arm re-folds; the answer is a Full.
        let late = [
            api("r1", 10, 100),
            api("r2", 20, 200),
            api("late-side", 5, 50),
        ];
        c.evidence(&late, &[]);
        let (mut pages, _) = arms(&c, &warm, &mut disk, &prior);
        assert_eq!(pages[0].modes, (1, 0, 0), "the RAM arm never re-folds");
        assert_eq!(pages[2].modes, (1, 0, 0), "the restored arm never re-folds");
        finish_claude_pages(&c, &mut pages);
        compare_claude_uploads(&pages);
        answers(&pages[2], &progress, &challenge);

        // (b) An append of the conflicted session reads Full and answers.
        append(&path, &line(ROOT, "r3", AT, 30));
        input_clock(&path);
        c.evidence(
            &[
                api("r1", 10, 100),
                api("r2", 20, 200),
                api("late-side", 5, 50),
                api("r3", 30, 300),
            ],
            &[],
        );
        let (mut pages, disk_hits) = arms(&c, &warm, &mut disk, &prior);
        assert_eq!(pages[0].modes, (1, 0, 0), "the RAM arm reads Full");
        assert_eq!(disk_hits, 0, "an owed answer never continues the head");
        // A grown file read Full takes the route's durable six-hour growth
        // claim. The RAM arm took it on the shared route, so the new owner's
        // growth Full of the same key defers and sends nothing.
        assert_eq!(pages[2].modes, (0, 0, 0), "the new owner defers");
        finish_claude_pages(&c, &mut pages);
        assert!(pages[2]
            .scan
            .snapshots
            .iter()
            .all(|item| item.source_session_id != ROOT));
        let (a, wire_a, _) = upload(&pages[0].scan.snapshots, &mut e2_progress(), ack);
        let (b, wire_b, _) = upload(&pages[1].scan.snapshots, &mut e2_progress(), ack);
        assert_eq!(a.unwrap(), ResumableUploadResult::Completed);
        assert_eq!(b.unwrap(), ResumableUploadResult::Completed);
        assert!(!wire_a.is_empty(), "fixture must reach real upload");
        assert_eq!(wire_a, wire_b, "the RAM arm's Full equals the cold Full");
        answers(&pages[0], &progress, &challenge);
    });
}
