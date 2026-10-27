// Compare emitted upload envelopes, never pre-finalization reductions. All input
// files are synthetic. The dispatch overlays only this test harness on the base.
use super::*;

fn supported(name: &str) -> bool {
    if !crate::heap_layout_bound::layout_supported() {
        println!("MONEY_EQUIVALENCE {name} UNEXECUTED: native retained layout unavailable");
        return false;
    }
    true
}

fn corpus(name: &str) -> Corpus {
    // A shared absolute root gives base and candidate identical input paths.
    // No PID, wall clock, random IDs or body-field normalization is allowed.
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

fn receipt(name: &str, bodies: &[Vec<u8>]) {
    assert!(!bodies.is_empty(), "zero emitted bodies is no proof");
    let bytes = serde_json::to_vec(bodies).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    if let Some(out) = std::env::var_os("OTTTO_MONEY_EQUIVALENCE_OUTPUT") {
        let out = PathBuf::from(out);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(format!("{name}.json")), &bytes).unwrap();
        std::fs::write(out.join(format!("{name}.sha256")), &digest).unwrap();
    }
    println!(
        "MONEY_EQUIVALENCE {name} VERIFIED bytes={} sha256={digest}",
        bytes.len()
    );
}

/// A third arm can supply its restored scanner/index here when durable restore
/// lands. The two existing arms consume the SAME index and physical files.
fn compare_claude(
    c: &Corpus,
    retained: &E2ScanFixture,
    prior: ScanIndex,
    mode: (usize, usize, usize),
) -> Vec<u8> {
    compare_claude_pages(c, claude_pages(c, retained, [prior.clone(), prior], mode))
}

fn claude_pages(
    c: &Corpus,
    retained: &E2ScanFixture,
    [tail_prior, full_prior]: [ScanIndex; 2],
    mode: (usize, usize, usize),
) -> [Page; 2] {
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
    [tail, full]
}

fn compare_claude_pages(c: &Corpus, [mut tail, mut full]: [Page; 2]) -> Vec<u8> {
    for page in [&mut tail, &mut full] {
        page.enrich(c); // attach, side calls, identity reconcile and emission
        page.finish(); // policy/body witnesses/holds, as in the real pipeline
    }
    compare_claude_uploads(&tail, &full)
}

fn compare_claude_uploads(tail: &Page, full: &Page) -> Vec<u8> {
    let (a, wire_a, _) = upload(&tail.scan.snapshots, &mut e2_progress(), ack);
    let (b, wire_b, _) = upload(&full.scan.snapshots, &mut e2_progress(), ack);
    assert_eq!(a.unwrap(), ResumableUploadResult::Completed);
    assert_eq!(b.unwrap(), ResumableUploadResult::Completed);
    assert!(!wire_a.is_empty(), "fixture must reach real upload");
    assert_eq!(wire_a, wire_b, "emitted full envelopes differ");
    for (a, b) in tail.scan.snapshots.iter().zip(&full.scan.snapshots) {
        assert_eq!(
            snapshot_upload_body_witness(a),
            snapshot_upload_body_witness(b)
        );
    }
    assert_eq!(
        Sha256::digest(canonical(&wire_a)),
        Sha256::digest(canonical(&wire_b))
    );
    canonical(&wire_a)
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
        let scanner = E2ScanFixture::default();
        let mut warm = c.raw(&scanner, ScanIndex::default(), 100, true, &[]);
        warm.enrich(&c);
        warm.finish();
        let prior = c.reload(&mut warm.index);
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
                let finish_phase = |pages: &mut [Page; 2], complete: bool| {
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
                let mut failed = claude_pages(&c, &scanner, [prior.clone(), prior], (0, 0, 1));
                finish_phase(&mut failed, false);
                let failed_wire = compare_claude_uploads(&failed[0], &failed[1]);
                let failed_items = failed.each_ref().map(|page| page.scan.snapshots[0].clone());
                // Continue each arm from its own finished failed-step index.
                // The retained scanner survives; the Full scanner is fresh.
                let [tail_failed, full_failed] = failed;
                c.evidence(&[api("r1", 10, 100)], &[]);
                let mut healthy = claude_pages(
                    &c,
                    &scanner,
                    [tail_failed.index, full_failed.index],
                    (0, 0, 1),
                );
                finish_phase(&mut healthy, true);
                let healthy_wire = compare_claude_uploads(&healthy[0], &healthy[1]);
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
                    failed_wire, healthy_wire,
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
        receipt(name, &[compare_claude(&c, &scanner, prior, mode)]);
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
    let path = c.root.join("rollout.jsonl");
    let header = json!({"type":"session_meta","timestamp":"2026-10-27T07:00:00Z","payload":{"id":ROOT,"timestamp":"2026-10-27T07:00:00Z"}}).to_string()+"\n";
    std::fs::write(&path, header + &codex_rows("turn-a", 10)).unwrap();
    input_clock(&path);
    let scanner = E2ScanFixture::default();
    let source = SnapshotSource::Codex;
    let mut index = {
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
        index
    };
    let mut prior = c.reload(&mut index);
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
        prior = c.reload(&mut upgraded);
        append(&path, &codex_rows("turn-c", 40));
        input_clock(&path);
    }
    save_inputs(&c);
    let (tail_index, tail, modes) = other_page(&c, &scanner, source, prior.clone());
    assert_eq!(modes, (0, 1, 0), "must reuse retained Codex reduction");
    let (_, full, modes) = other_page(&c, &E2ScanFixture::default(), source, prior);
    assert_eq!(modes, (1, 0, 0));
    assert!(tail_index
        .files
        .values()
        .all(|e| e.codex_counting_v2 != legacy));
    let (a, b) = (other_wire(source, &tail), other_wire(source, &full));
    assert_eq!(a, b);
    assert_eq!(Sha256::digest(&a), Sha256::digest(&b));
    receipt(name, &[a]);
}
#[test]
fn codex_v2_sticky() {
    codex_case(false);
}
#[test]
fn codex_legacy_acked_sticky() {
    codex_case(true);
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
    restart_between_pages,
    "E1/#806: no durable reduction restore on main; a fresh cache reads Full"
);
pending!(
    upgrade_without_semantic_revision,
    "E1/#806: no durable codec/semantic migration on main"
);
pending!(
    downgrade_then_reupgrade,
    "E1/#806: no durable generation-bound restore on main"
);
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
