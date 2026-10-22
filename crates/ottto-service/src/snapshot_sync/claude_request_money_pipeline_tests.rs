// P1 per-request Claude money, shadow only, through the real caller: the
// `PipelineFixture` page stages run `apply_claude_local_evidence_to_scan`,
// which runs the shadow. The shadow changes no page decision and no live
// item; its B1 rows (grain, family, coverage) are internally consistent; its
// refusal and reader-failure paths never fail a page and never claim
// coverage. Fixtures are synthetic.

use super::*;
use crate::snapshots::claude_request_money as money;

/// A transcript whose only response copies `req_1_1` of the second session.
const MONEY_PIPELINE_COPY: &str = "f6666666-6666-4666-8666-666666666666";
const MONEY_PIPELINE_SIDE_CALL: &str = "req_side_call";
/// The page fixture's response: input 10, output 10.
const MONEY_PIPELINE_RESPONSE_TOKENS: u64 = 20;
/// The side call's row: input 5, output 5.
const MONEY_PIPELINE_SIDE_CALL_TOKENS: u64 = 10;

/// The deliberate differences between the shadow body and the live (SI)
/// body. Everything else must be equal.
const MONEY_DELIBERATE_DIFFERENCES: [&str; 2] = [
    "copied requests leave the copy",
    "side calls appear on the unproven path",
];

const MONEY_PIPELINE_CYCLE: PipelineCycle<'static> = PipelineCycle {
    upload_context: "upload-context-1",
    replay_generation: "replay-generation-1",
    proven_owner_session: Some(PIPELINE_HELD_SESSION),
    first_page_upload: PipelineUpload::Accept,
    historical_replay: false,
};

#[derive(Clone, Copy)]
struct MoneyCorpus {
    shadow: bool,
    /// The copied-request transcript and the API rows (with one side call).
    copies_and_rows: bool,
    /// The copy's root has a directory where its API sidecar should be.
    broken_sidecar: bool,
}

struct MoneyPipelineArm {
    facts: Vec<serde_json::Value>,
    /// Non-ledger census records: relative key -> request hashes.
    census: BTreeMap<String, Vec<u64>>,
    lines: Vec<serde_json::Value>,
    /// Every JSONL row (grain, family and coverage).
    rows: Vec<serde_json::Value>,
}

impl MoneyPipelineArm {
    fn of(&self, kind: &str) -> Vec<&serde_json::Value> {
        self.rows.iter().filter(|row| row["row"] == kind).collect()
    }
}

fn money_api_line(session: &str, request: &str, sequence: u64, tokens: u64) -> String {
    let mut row = crate::claude_local_otel::ClaudeLocalOtelEvidence {
        capture_revision: "claude_api_request:v2".into(),
        session_id: session.into(),
        request_id: request.into(),
        client_request_id: format!("client-{request}"),
        observed_at: format!("2026-08-02T07:00:{:02}Z", 10 + sequence),
        model: "claude-haiku-4-5".into(),
        effort: "high".into(),
        query_source: "user".into(),
        speed: "fast".into(),
        app_version: "2.1.226".into(),
        event_sequence: Some(sequence + 1),
        cost_usd_micros: Some(100),
        input_tokens: tokens / 2,
        output_tokens: tokens / 2,
        request_count: 1,
        ..Default::default()
    };
    row.fingerprint = format!(
        "sha256:{:x}",
        Sha256::digest(serde_json::to_vec(&row).expect("serialize row"))
    );
    serde_json::to_string(&row).expect("serialize row") + "\n"
}

fn money_sidecar_path(support: &Path, session: &str) -> PathBuf {
    support
        .join(crate::claude_local_otel::STORE_DIR)
        .join(format!("{:x}.jsonl", Sha256::digest(session.as_bytes())))
}

fn money_write_corpus(fixture: &PipelineFixture, corpus: MoneyCorpus) {
    if corpus.copies_and_rows {
        std::fs::write(
            fixture.root.join(format!("{MONEY_PIPELINE_COPY}.jsonl")),
            pipeline_transcript_line(MONEY_PIPELINE_COPY, "req_1_1", 7),
        )
        .expect("write copied-request transcript");
        for (number, session) in PIPELINE_SESSIONS.iter().enumerate() {
            let path = money_sidecar_path(&fixture.support, session);
            std::fs::create_dir_all(path.parent().expect("store dir")).expect("create store");
            let mut lines = money_api_line(
                session,
                &format!("req_{number}_1"),
                0,
                MONEY_PIPELINE_RESPONSE_TOKENS,
            );
            if number == 1 {
                lines.push_str(&money_api_line(
                    session,
                    MONEY_PIPELINE_SIDE_CALL,
                    1,
                    MONEY_PIPELINE_SIDE_CALL_TOKENS,
                ));
            }
            std::fs::write(path, lines).expect("write API sidecar");
        }
    }
    if corpus.broken_sidecar {
        std::fs::create_dir_all(money_sidecar_path(&fixture.support, MONEY_PIPELINE_COPY))
            .expect("directory in place of a sidecar");
    }
}

fn money_jsonl_rows(support: &Path) -> Vec<serde_json::Value> {
    let Ok(entries) = std::fs::read_dir(support.join("diagnostics")) else {
        return Vec::new();
    };
    let mut paths = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("claude-request-money-shadow-"))
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths
        .iter()
        .flat_map(|path| {
            std::fs::read_to_string(path)
                .expect("read shadow JSONL")
                .lines()
                .map(|line| serde_json::from_str(line).expect("JSONL row"))
                .collect::<Vec<_>>()
        })
        .collect()
}

fn money_census(fixture: &PipelineFixture, index: &ScanIndex) -> BTreeMap<String, Vec<u64>> {
    let canonical = std::fs::canonicalize(&fixture.base).unwrap_or_default();
    index
        .claude_request_census_for_test()
        .records()
        .filter(|(key, _)| !crate::snapshots::claude_request_census::is_ledger_key(key))
        .map(|(key, record)| {
            let relative = Path::new(key)
                .strip_prefix(&fixture.base)
                .or_else(|_| Path::new(key).strip_prefix(&canonical))
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| key.clone());
            (relative, record.request_hashes().to_vec())
        })
        .collect()
}

/// One arm: a baseline traversal, then an append and a second traversal.
fn money_pipeline_arm(name: &str, corpus: MoneyCorpus) -> MoneyPipelineArm {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new(name);
    money_write_corpus(&fixture, corpus);
    if corpus.shadow {
        money::enable_shadow_for_test(&fixture.support);
    }
    let _ = money::take_shadow_lines_for_test();
    let mut facts = Vec::new();
    let mut last = None;
    for hour in [8, 9] {
        if hour == 9 {
            fixture.append(PIPELINE_SESSIONS[2], "req_2_2");
        }
        for page in fixture.traversal(hour, &MONEY_PIPELINE_CYCLE) {
            facts.push(census_parity_page_facts(&fixture, &page));
            last = Some(page.index);
        }
    }
    // The shadow's rows are written by its writer, after each page.
    money::store::flush();
    MoneyPipelineArm {
        facts,
        census: money_census(&fixture, &last.expect("pages")),
        lines: money::take_shadow_lines_for_test(),
        rows: money_jsonl_rows(&fixture.support),
    }
}

fn money_totals(row: &serde_json::Value, part: &str) -> (u64, u64) {
    let totals = &row[part];
    (
        totals["tokens"].as_u64().unwrap_or(0),
        totals["requests"].as_u64().unwrap_or(0),
    )
}

fn money_count(lines: &[serde_json::Value], name: &str) -> u64 {
    lines
        .iter()
        .map(|line| line["counts"][name].as_u64().expect("count"))
        .sum()
}

fn money_grain_tokens(side: &serde_json::Value) -> i128 {
    [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "unattributed_total_tokens",
    ]
    .iter()
    .map(|name| i128::from(side[*name].as_u64().expect("token component")))
    .sum()
}

/// The B1 reader's view: every family row's new minus old equals the sum of
/// its snapshot's grain rows (new minus old), in tokens and in requests, so
/// one reader prices the window from the grains alone. Ids are hashed.
fn money_assert_rows_consistent(arm: &MoneyPipelineArm) {
    let families = arm.of("family");
    assert!(!families.is_empty(), "the shadow writes family rows");
    let mut built = 0;
    for family in &families {
        assert_eq!(family["counting"], "claude_request_counting:v1", "{family}");
        assert_eq!(family["v"], 2, "{family}");
        assert_eq!(family["family"].as_str().map(str::len), Some(16), "{family}");
        let (old_tokens, old_requests) = money_totals(family, "old");
        let (new_tokens, new_requests) = money_totals(family, "new");
        assert_eq!(
            family["net_token_change"].as_i64(),
            Some(new_tokens as i64 - old_tokens as i64),
            "{family}"
        );
        assert!(
            family["removed_change"].is_null()
                == family["removed_change_unavailable"].is_string(),
            "{family}"
        );
        if family["category"] == "unbuilt" {
            assert_eq!(family["coverage_complete"], false, "{family}");
            continue;
        }
        built += 1;
        let (tokens, requests) = arm
            .of("grain")
            .iter()
            .filter(|grain| {
                grain["family"] == family["family"] && grain["snapshot"] == family["snapshot"]
            })
            .fold((0_i128, 0_i128), |sum, grain| {
                (
                    sum.0 + money_grain_tokens(&grain["new"]) - money_grain_tokens(&grain["old"]),
                    sum.1 + i128::from(grain["new"]["requests"].as_u64().unwrap())
                        - i128::from(grain["old"]["requests"].as_u64().unwrap()),
                )
            });
        assert_eq!(
            (tokens, requests),
            (
                i128::from(new_tokens) - i128::from(old_tokens),
                i128::from(new_requests) - i128::from(old_requests)
            ),
            "grains explain the family: {family}"
        );
    }
    assert!(built > 0, "the builder builds ordinary families: {:?}", arm.rows);
    for grain in arm.of("grain") {
        assert_eq!(grain["session"].as_str().map(str::len), Some(16), "{grain}");
        assert!(grain["hour"].as_str().is_some_and(|hour| hour.ends_with(":00:00Z")), "{grain}");
        assert!(grain["selector"].is_object(), "{grain}");
        assert!(grain["category"].is_string(), "{grain}");
    }
    assert!(!arm.of("coverage").is_empty(), "every day has a coverage row");
    assert_eq!(money_count(&arm.lines, "certificate_mismatch"), 0);
    // Hashed ids only.
    let joined = arm
        .rows
        .iter()
        .map(serde_json::Value::to_string)
        .collect::<String>();
    for raw in PIPELINE_SESSIONS
        .iter()
        .chain([&MONEY_PIPELINE_COPY])
        .copied()
        .chain(["req_1_1", MONEY_PIPELINE_SIDE_CALL])
    {
        assert!(!joined.contains(raw), "raw id {raw} in the JSONL");
    }
}

/// Zero behavior change through the real caller: with identical sidecars
/// and transcripts, the page facts (bodies, uploads, holds, settlement,
/// census decisions) and the non-ledger census records are identical with
/// the shadow on and off. The shadow's only writes are its own ledger
/// records, its log line and its JSONL.
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_shadow_changes_no_page_decision_through_the_real_caller() {
    let corpus = MoneyCorpus {
        shadow: false,
        copies_and_rows: true,
        broken_sidecar: false,
    };
    let off = money_pipeline_arm("money-shadow-off", corpus);
    let on = money_pipeline_arm(
        "money-shadow-on",
        MoneyCorpus {
            shadow: true,
            ..corpus
        },
    );
    assert_eq!(on.facts, off.facts, "the shadow changes no page decision");
    assert_eq!(on.census, off.census, "nor any D1 record");
    assert!(off.lines.is_empty() && off.rows.is_empty());
    assert!(!on.lines.is_empty(), "every Claude page logs one line");
    for line in &on.lines {
        assert_eq!(line["counting"], "claude_request_counting:v1");
        assert_eq!(line["counts"]["refused_budget"], 0, "{line}");
        assert!(line["ledger"]["census_serialized_bytes"].is_u64(), "{line}");
        assert!(line["scope"]["lost"].is_u64(), "{line}");
    }
    money_assert_rows_consistent(&on);
    // The copy is removed from the copy's family: the source family's API
    // row proves the owner, so the copy leaves and the money stays once.
    assert!(
        money_count(&on.lines, "units_removed") >= 1,
        "{:?}",
        on.lines
    );
    let copy_family = money::hashed_id_for_test(MONEY_PIPELINE_COPY);
    let copy_row = on
        .of("family")
        .into_iter()
        .rfind(|row| row["family"] == copy_family.as_str())
        .expect("the copy's family row");
    assert_eq!(
        money_totals(copy_row, "removed"),
        (MONEY_PIPELINE_RESPONSE_TOKENS, 1),
        "{copy_row}"
    );
    assert_eq!(money_totals(copy_row, "new").0, 0, "{copy_row}");
    assert!(on.of("grain").iter().any(|grain| {
        grain["family"] == copy_family.as_str() && grain["category"] == "copies_removed"
    }));
    // A matched transcript unit keeps its own reported cost: an own-cost
    // grain whose new side carries the row's cost_usd.
    assert!(
        money_count(&on.lines, "units_matched") >= 1,
        "{:?}",
        on.lines
    );
    assert!(on.of("grain").iter().any(|grain| {
        grain["category"] == "own_cost"
            && grain["request_usage_origin"] == "telemetry_matched"
            && grain["new"]["cost_usd"] == "0.000100"
    }));
    // The proven side call keeps its own cost, once.
    assert!(
        money_count(&on.lines, "side_calls") >= 1,
        "the telemetry-only request is a side call: {:?}",
        on.lines
    );
    let side_calls = on
        .of("grain")
        .into_iter()
        .filter(|grain| grain["category"] == "side_call_added")
        .collect::<Vec<_>>();
    let latest = side_calls
        .iter()
        .map(|grain| grain["snapshot"].as_u64().unwrap())
        .max();
    let latest = side_calls
        .iter()
        .filter(|grain| grain["snapshot"].as_u64() == latest)
        .collect::<Vec<_>>();
    assert_eq!(latest.len(), 1, "{side_calls:?}");
    assert_eq!(latest[0]["request_usage_origin"], "telemetry_reported");
    assert_eq!(latest[0]["new"]["cost_usd"], "0.000100");
    assert_eq!(latest[0]["new"]["requests"], 1);
    assert_eq!(money::reserved_for_test(), 0, "admission is released");
}

/// Finding 8: arming the shadow changes no live item and no live
/// reservation. The same corpus scanned unarmed and armed yields identical
/// items whose completed heap bound is identical (so every live reservation
/// boundary, tight or not, admits or refuses them identically); the capture
/// is held in its own budget outside the items and freed by the shadow.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_capture_never_enters_live_items_or_reservations() {
    let fixture = PipelineFixture::new("money-shadow-zero-live");
    money_write_corpus(
        &fixture,
        MoneyCorpus {
            shadow: true,
            copies_and_rows: true,
            broken_sidecar: false,
        },
    );
    let scan = |index: &mut ScanIndex| {
        crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.root),
            index,
            "2026-08-02T08:00:00Z",
            183,
            16,
            true,
        )
        .expect("scan synthetic Claude root")
    };
    let baseline_reserved = money::capture::capture_reserved();
    let mut unarmed_index = ScanIndex::default();
    let unarmed = scan(&mut unarmed_index);
    assert_eq!(money::capture::capture_reserved(), baseline_reserved);
    money::enable_shadow_for_test(&fixture.support);
    let mut armed_index = ScanIndex::default();
    let armed = scan(&mut armed_index);
    assert!(
        money::capture::capture_reserved() > baseline_reserved,
        "the armed parse captured, in its own budget"
    );
    assert_eq!(armed.snapshots.len(), unarmed.snapshots.len());
    for (armed, unarmed) in armed.snapshots.iter().zip(&unarmed.snapshots) {
        assert_eq!(
            serde_json::to_value(armed).unwrap(),
            serde_json::to_value(unarmed).unwrap()
        );
        let exact = crate::heap_layout_bound::completed_bound(unarmed, usize::MAX);
        assert_eq!(
            crate::heap_layout_bound::completed_bound(armed, usize::MAX),
            exact
        );
        if let Some(exact) = exact {
            for limit in [exact, exact - 1] {
                assert_eq!(
                    crate::heap_layout_bound::completed_bound(armed, limit),
                    crate::heap_layout_bound::completed_bound(unarmed, limit),
                    "at the tight boundary {limit}"
                );
            }
        }
    }
    assert_eq!(armed.census_complete, unarmed.census_complete);
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    money::shadow_page_at(
        &fixture.support,
        &armed.snapshots,
        &armed_index,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        armed.census_complete,
        response + 3600,
    );
    // The page's batch is released by its writer.
    money::store::flush();
    // Every page item's capture was taken (freed); drop any parse of this
    // scope no item carried, then the capture budget is back to baseline.
    money::capture::purge_scope_for_test(&fixture.support);
    assert_eq!(money::capture::capture_reserved(), baseline_reserved);
    assert_eq!(money::reserved_for_test(), 0);

    // Sol R4-3: the kill switch stops capture too. The page that sees it
    // drops the waiting captures, and a parse while it is off captures
    // nothing; once it is gone the next page turns capture back on.
    let off = fixture.support.join("claude-request-money-shadow.off");
    let page = || {
        money::shadow_page(
            &fixture.support,
            &armed.snapshots,
            &armed_index,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            armed.census_complete,
        );
        money::store::flush();
    };
    std::fs::write(&off, b"").unwrap();
    let _ = scan(&mut ScanIndex::default());
    assert!(money::capture::capture_reserved() > baseline_reserved);
    // The off pages run on the real clock (the fixture's rows are older and
    // the writer's retention may drop them): count the rows since then.
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let off_rows = || {
        money_jsonl_rows(&fixture.support)
            .into_iter()
            .filter(|row| row["row"] == "coverage")
            .filter(|row| row["observed_unix"].as_u64().is_some_and(|at| at >= since))
            .collect::<Vec<_>>()
    };
    page();
    assert_eq!(
        money::capture::capture_reserved(),
        baseline_reserved,
        "the page that sees the switch drops the waiting captures"
    );
    // StateMissing B: the day's first off page writes one false coverage
    // row, so the part of the day the shadow skipped never reads complete.
    let rows = off_rows();
    assert_eq!(rows.len(), 1, "one row for the off day: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["row"], "coverage", "{row}");
    assert_eq!(row["coverage_complete"], false, "{row}");
    assert_eq!(row["refused"], true, "{row}");
    let _ = scan(&mut ScanIndex::default());
    assert_eq!(
        money::capture::capture_reserved(),
        baseline_reserved,
        "a parse while the shadow is off captures nothing"
    );
    page();
    assert_eq!(off_rows().len(), 1, "later off pages of the day write nothing");
    std::fs::remove_file(&off).unwrap();
    page();
    let _ = scan(&mut ScanIndex::default());
    assert!(money::capture::capture_reserved() > baseline_reserved);
    money::capture::purge_scope_for_test(&fixture.support);
    assert_eq!(money::capture::capture_reserved(), baseline_reserved);
    assert_eq!(money::reserved_for_test(), 0);
    let _ = money::take_shadow_lines_for_test();
}

fn money_scan(fixture: &PipelineFixture) -> crate::snapshots::SourceScanResult {
    crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.root),
        &mut ScanIndex::default(),
        "2026-08-02T08:00:00Z",
        183,
        16,
        true,
    )
    .expect("scan synthetic Claude root")
}

/// StateMissing r3: a kill switch present when the process starts stops
/// capture before any page has seen it (the cycle seeds it before its
/// first parse), and a panic inside the capture ends in the shadow: the
/// latch is set, the capture is dropped and the live parse is unchanged.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_capture_stops_at_start_and_contains_its_panics() {
    let corpus = MoneyCorpus {
        shadow: true,
        copies_and_rows: true,
        broken_sidecar: false,
    };
    let baseline_reserved = money::capture::capture_reserved();
    let fixture = PipelineFixture::new("money-shadow-capture-start-off");
    money_write_corpus(&fixture, corpus);
    std::fs::write(fixture.support.join("claude-request-money-shadow.off"), b"").unwrap();
    money::enable_shadow_for_test(&fixture.support);
    money::seed_shadow_off(&fixture.support);
    let _ = money_scan(&fixture);
    assert_eq!(
        money::capture::capture_reserved(),
        baseline_reserved,
        "the first parse with the switch present captures nothing"
    );
    money::disable_shadow_for_test(&fixture.support);

    let fixture = PipelineFixture::new("money-shadow-capture-panic");
    money_write_corpus(&fixture, corpus);
    let unarmed = money_scan(&fixture);
    money::enable_shadow_for_test(&fixture.support);
    money::capture::set_panic_for_test(true);
    let armed = money_scan(&fixture);
    money::capture::set_panic_for_test(false);
    // Reads and clears the latch the capture panic set.
    let (panicked, _) = money::guarded_for_test(|| {});
    money::disable_shadow_for_test(&fixture.support);
    assert!(panicked, "the capture panic set the shadow's latch");
    assert_eq!(
        money::capture::capture_reserved(),
        baseline_reserved,
        "the panicked capture was dropped, never deposited"
    );
    assert_eq!(armed.snapshots.len(), unarmed.snapshots.len());
    for (armed, unarmed) in armed.snapshots.iter().zip(&unarmed.snapshots) {
        assert_eq!(
            serde_json::to_value(armed).unwrap(),
            serde_json::to_value(unarmed).unwrap()
        );
    }
    assert_eq!(armed.census_complete, unarmed.census_complete);
}

/// Sol R5-2: the rows a page hands to the writer are admitted at what they
/// own. A 64 KiB model on a copied response is charged in full on the grain
/// that carries it (a flat share per grain would not); when that admission
/// does not fit, the page is refused (a false coverage row, no memo moves)
/// and every byte is refunded.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_batch_admits_long_models_in_full() {
    const LONG: usize = 64 * 1024;
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let long_model = format!("claude-haiku-4-5-{}", "x".repeat(LONG));
    // Fixture names of one length: the grain keys hold their paths.
    let page = |name: &str, model: &str, hold: usize| {
        let fixture = PipelineFixture::new(name);
        money_write_corpus(
            &fixture,
            MoneyCorpus {
                shadow: true,
                copies_and_rows: true,
                broken_sidecar: false,
            },
        );
        std::fs::write(
            fixture.root.join(format!("{MONEY_PIPELINE_COPY}.jsonl")),
            pipeline_transcript_line(MONEY_PIPELINE_COPY, "req_1_1", 7)
                .replace("claude-haiku-4-5", model),
        )
        .unwrap();
        money::enable_shadow_for_test(&fixture.support);
        let mut index = ScanIndex::default();
        let scan = crate::snapshots::scan_source_roots_with_test_limit(
            SnapshotSource::ClaudeCode,
            std::slice::from_ref(&fixture.root),
            &mut index,
            "2026-08-02T08:00:00Z",
            183,
            16,
            true,
        )
        .expect("scan synthetic Claude root");
        let held = (hold > 0).then(|| money::ShadowReservation::admit(hold).expect("hold"));
        let counts = money::shadow_page_at(
            &fixture.support,
            &scan.snapshots,
            &index,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            scan.census_complete,
            response + 3600,
        );
        drop(held);
        money::store::flush();
        money::capture::purge_scope_for_test(&fixture.support);
        money::disable_shadow_for_test(&fixture.support);
        assert_eq!(money::reserved_for_test(), 0, "every admission is refunded");
        (counts, money_jsonl_rows(&fixture.support))
    };
    let (short, _) = page("money-shadow-model-1", "claude-haiku-4-5", 0);
    let (long, rows) = page("money-shadow-model-2", &long_model, 0);
    assert_eq!(short.refused_budget, 0, "{short:?}");
    assert_eq!(long.refused_budget, 0, "{long:?}");
    assert!(
        rows.iter()
            .any(|row| row["row"] == "grain" && row["model"].as_str() == Some(long_model.as_str())),
        "the long model reaches a grain: {rows:?}"
    );
    assert!(
        long.admitted_peak_bytes >= short.admitted_peak_bytes + LONG as u64,
        "the long model is charged: {} vs {}",
        long.admitted_peak_bytes,
        short.admitted_peak_bytes
    );
    let hold = money::SHADOW_MEMORY_CEILING_BYTES - long.admitted_peak_bytes as usize + 1;
    let (refused, rows) = page("money-shadow-model-3", &long_model, hold);
    assert_eq!(refused.refused_budget, 1, "{refused:?}");
    assert_eq!(refused.coverage_complete, 0, "{refused:?}");
    assert!(rows.iter().all(|row| row["row"] == "coverage"), "{rows:?}");
    assert!(rows.iter().any(|row| row["refused"] == true), "{rows:?}");
}

/// A sidecar that cannot be read (a directory in its place) never fails the
/// page or changes it, and its family is never complete: a reader failure is
/// not "no rows".
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_shadow_reader_failure_is_never_complete_and_changes_nothing() {
    let corpus = MoneyCorpus {
        shadow: false,
        copies_and_rows: true,
        broken_sidecar: true,
    };
    let off = money_pipeline_arm("money-shadow-reader-off", corpus);
    let on = money_pipeline_arm(
        "money-shadow-reader-on",
        MoneyCorpus {
            shadow: true,
            ..corpus
        },
    );
    assert_eq!(on.facts, off.facts);
    assert_eq!(on.census, off.census);
    assert!(
        money_count(&on.lines, "rows_unavailable_roots") >= 1,
        "{:?}",
        on.lines
    );
    let copy_family = money::hashed_id_for_test(MONEY_PIPELINE_COPY);
    let copy_rows = on
        .of("family")
        .into_iter()
        .filter(|row| row["family"] == copy_family.as_str())
        .collect::<Vec<_>>();
    assert!(!copy_rows.is_empty());
    assert!(copy_rows
        .iter()
        .all(|row| row["coverage_complete"] == false));
    assert!(on
        .of("coverage")
        .iter()
        .all(|row| row["coverage_complete"] == false));
    money_assert_rows_consistent(&on);
}

/// Admission refusal: with the shadow's whole memory ceiling held, every page
/// logs one refused line, writes no family or grain row, marks the day
/// incomplete, and changes nothing.
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_shadow_refusal_logs_and_changes_nothing() {
    let corpus = MoneyCorpus {
        shadow: false,
        copies_and_rows: true,
        broken_sidecar: false,
    };
    let off = money_pipeline_arm("money-shadow-refused-off", corpus);
    let held = money::ShadowReservation::admit(
        money::SHADOW_MEMORY_CEILING_BYTES - money::reserved_for_test(),
    )
    .expect("hold the whole ceiling");
    let on = money_pipeline_arm(
        "money-shadow-refused-on",
        MoneyCorpus {
            shadow: true,
            ..corpus
        },
    );
    drop(held);
    assert_eq!(money::reserved_for_test(), 0);
    assert_eq!(on.facts, off.facts);
    assert_eq!(on.census, off.census);
    assert!(!on.lines.is_empty());
    assert!(on
        .lines
        .iter()
        .all(|line| line["counts"]["refused_budget"] == 1 && line["counts"]["families"] == 0));
    assert!(on.of("family").is_empty() && on.of("grain").is_empty());
    let coverage = on.of("coverage");
    assert!(!coverage.is_empty());
    assert!(coverage
        .iter()
        .all(|row| row["coverage_complete"] == false && row["refused"] == true));
}

/// One armed scan of a fresh fixture, for direct `shadow_page_at` calls.
fn money_armed_scan(name: &str) -> (PipelineFixture, ScanIndex, crate::snapshots::SourceScanResult) {
    let fixture = PipelineFixture::new(name);
    money::enable_shadow_for_test(&fixture.support);
    let mut index = ScanIndex::default();
    let scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.root),
        &mut index,
        "2026-08-02T08:00:00Z",
        183,
        16,
        true,
    )
    .expect("scan synthetic Claude root");
    (fixture, index, scan)
}

/// Immature units (younger than the maturity window) are neither counted nor
/// removed and their live slices leave the new body as `immature`; at a
/// later clock the same corpus counts them all and equals the live body.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_holds_immature_units_until_they_mature() {
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let none = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let no_trace = crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default();
    let units = PIPELINE_SESSIONS.len() as u64;
    let (fixture, index, scan) = money_armed_scan("money-shadow-immature");
    let young = money::shadow_page_at(
        &fixture.support,
        &scan.snapshots,
        &index,
        &none,
        &no_trace,
        scan.census_complete,
        response + 30,
    );
    assert_eq!(young.units_immature, units, "{young:?}");
    assert_eq!(young.units_counted, 0, "{young:?}");
    assert_eq!(
        young.tokens_immature,
        units * MONEY_PIPELINE_RESPONSE_TOKENS
    );
    assert_eq!(young.tokens_new, young.tokens_old - young.tokens_immature, "{young:?}");
    let (fixture, index, scan) = money_armed_scan("money-shadow-mature");
    let mature = money::shadow_page_at(
        &fixture.support,
        &scan.snapshots,
        &index,
        &none,
        &no_trace,
        scan.census_complete,
        response + 3600,
    );
    assert_eq!(mature.units_immature, 0, "{mature:?}");
    assert_eq!(mature.units_counted, units, "{mature:?}");
    assert_eq!(mature.units_undecided, 0, "{mature:?}");
    assert_eq!(mature.tokens_new, mature.tokens_old, "{mature:?}");
    assert_eq!(mature.families_equal, mature.families, "{mature:?}");
    money::store::flush();
    assert_eq!(money::reserved_for_test(), 0);
}

/// Finding 2: the removal delta is bound to the previous complete body of
/// the same union; with no previous body it is unavailable, never zero.
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_shadow_removed_change_is_bound_to_the_previous_body() {
    let on = money_pipeline_arm(
        "money-shadow-removed-change",
        MoneyCorpus {
            shadow: true,
            copies_and_rows: true,
            broken_sidecar: false,
        },
    );
    let copy_family = money::hashed_id_for_test(MONEY_PIPELINE_COPY);
    let rows = on
        .of("family")
        .into_iter()
        .filter(|row| row["family"] == copy_family.as_str())
        .collect::<Vec<_>>();
    assert!(!rows.is_empty());
    let first = rows[0];
    if first["coverage_complete"] == true {
        assert!(first["removed_change"].is_null(), "{first}");
        assert_eq!(first["removed_change_unavailable"], "no_previous_body");
    }
    for row in rows.iter().skip(1) {
        if row["coverage_complete"] == true && !row["removed_change"].is_null() {
            assert_eq!(row["removed_change_basis"], "previous_shadow", "{row}");
            assert_eq!(row["removed_change"]["requests"], 0, "{row}");
            assert_eq!(row["removed_change"]["tokens"], 0, "{row}");
        }
    }
    assert!(money_count(&on.lines, "removed_change_available")
        + money_count(&on.lines, "removed_change_unavailable")
        >= rows.len() as u64);
}

/// The latest snapshot's grains of each family row.
fn money_latest_grains(arm: &MoneyPipelineArm) -> Vec<&serde_json::Value> {
    let mut latest = BTreeMap::<String, u64>::new();
    for family in arm.of("family") {
        let snapshot = family["snapshot"].as_u64().unwrap();
        let slot = latest
            .entry(family["family"].as_str().unwrap().to_owned())
            .or_default();
        *slot = (*slot).max(snapshot);
    }
    arm.of("grain")
        .into_iter()
        .filter(|grain| {
            latest.get(grain["family"].as_str().unwrap()) == grain["snapshot"].as_u64().as_ref()
        })
        .collect()
}

/// SI parity: on a corpus with no copied request and no side call, the shadow
/// body equals the live body except units it holds on unknown debt (or
/// defers as immature). With them, only the deliberate differences appear,
/// each in its own family and by its exact amount.
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_shadow_matches_the_live_body_except_the_deliberate_differences() {
    let undecided = ["held", "immature"];
    let plain = money_pipeline_arm(
        "money-shadow-parity-plain",
        MoneyCorpus {
            shadow: true,
            copies_and_rows: false,
            broken_sidecar: false,
        },
    );
    money_assert_rows_consistent(&plain);
    for grain in plain.of("grain") {
        assert!(
            undecided.contains(&grain["category"].as_str().unwrap()),
            "an undeclared difference: {grain}"
        );
    }
    for row in plain
        .of("family")
        .into_iter()
        .filter(|row| row["category"] != "unbuilt")
        .filter(|row| money_totals(row, "held").1 == 0 && money_totals(row, "immature").1 == 0)
    {
        assert_eq!(row["category"], "equal", "{row}");
        assert_eq!(money_totals(row, "new"), money_totals(row, "old"), "{row}");
    }
    assert_eq!(money_count(&plain.lines, "side_calls"), 0);
    assert_eq!(money_count(&plain.lines, "units_removed"), 0);

    let differing = money_pipeline_arm(
        "money-shadow-parity-differing",
        MoneyCorpus {
            shadow: true,
            copies_and_rows: true,
            broken_sidecar: false,
        },
    );
    money_assert_rows_consistent(&differing);
    let copy_family = money::hashed_id_for_test(MONEY_PIPELINE_COPY);
    let side_family = money::hashed_id_for_test(PIPELINE_SESSIONS[1]);
    let mut copies = 0_i128;
    let mut side_calls = 0_i128;
    for grain in money_latest_grains(&differing) {
        let change = money_grain_tokens(&grain["new"]) - money_grain_tokens(&grain["old"]);
        match grain["category"].as_str().unwrap() {
            // MONEY_DELIBERATE_DIFFERENCES[0]
            "copies_removed" => {
                assert_eq!(grain["family"], copy_family.as_str(), "{grain}");
                copies += change;
            }
            // MONEY_DELIBERATE_DIFFERENCES[1]
            "side_call_added" => {
                assert_eq!(grain["family"], side_family.as_str(), "{grain}");
                side_calls += change;
            }
            // A matched unit's own money: same tokens.
            "own_cost" => assert_eq!(change, 0, "{grain}"),
            category if undecided.contains(&category) => {}
            _ => panic!("an undeclared difference: {grain}"),
        }
    }
    assert_eq!(copies, -i128::from(MONEY_PIPELINE_RESPONSE_TOKENS));
    assert_eq!(side_calls, i128::from(MONEY_PIPELINE_SIDE_CALL_TOKENS));
    assert_eq!(MONEY_DELIBERATE_DIFFERENCES.len(), 2);
}

/// AutoReview 5: when the JSONL cannot be written, no family memo moves
/// (the reader never received those rows, so they are no removal basis).
/// The writer reports the failure to the next page, which withholds the
/// memos (one per complete body: only a complete body is a basis).
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_memos_move_only_with_published_rows() {
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let (fixture, index, scan) = money_armed_scan("money-shadow-unpublished");
    std::fs::write(fixture.support.join("diagnostics"), b"not a directory").unwrap();
    let page = || {
        let counts = money::shadow_page_at(
            &fixture.support,
            &scan.snapshots,
            &index,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            scan.census_complete,
            response + 3600,
        );
        money::store::flush();
        counts
    };
    let first = page();
    assert!(first.families > 0, "{first:?}");
    assert!(first.jsonl_queued > 0, "{first:?}");
    let second = page();
    assert!(second.jsonl_failed >= 1, "{second:?}");
    assert_eq!(
        second.family_memos_withheld, first.families_coverage_complete,
        "{second:?}"
    );
    // An unwritten body is no removal basis: never a delta.
    assert_eq!(second.removed_change_available, 0, "{second:?}");
    let memos = money::store::with_ledger_for_test(&fixture.support, |ledger| {
        ledger
            .census()
            .records_with_prefix(crate::snapshots::claude_request_census::FAMILY_KEY_PREFIX)
            .count()
    });
    assert_eq!(memos, Some(0));
    assert_eq!(money::reserved_for_test(), 0);
}

/// Sol R3-3 / R3-6: every page writes its families' rows (no writer-side
/// "unchanged" skip: the reader keeps each family's latest rows by
/// `snapshot`, so X, Y, X ends at X whatever the writer's timing) and its
/// own coverage row; a page whose batch never reached its file (a full
/// outbox) owes its day a false coverage row, written with the next batch.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_writes_every_page_and_owes_coverage_for_lost_batches() {
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let (fixture, index, scan) = money_armed_scan("money-shadow-every-page");
    let page = |now| {
        let counts = money::shadow_page_at(
            &fixture.support,
            &scan.snapshots,
            &index,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            scan.census_complete,
            now,
        );
        money::store::flush();
        counts
    };
    let first = page(response + 3600);
    let second = page(response + 3601);
    assert!(first.families > 0, "{first:?}");
    let rows = money_jsonl_rows(&fixture.support);
    let of = |kind: &str| {
        rows.iter()
            .filter(|row| row["row"] == kind)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        of("family").len() as u64,
        first.families + second.families,
        "the same rows twice are written twice"
    );
    assert_eq!(of("coverage").len(), 2, "one coverage row per page");
    let snapshots = of("family")
        .iter()
        .map(|row| row["snapshot"].as_u64().unwrap())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(snapshots.len(), 2, "each page is its own snapshot");

    // A dropped batch (as a full outbox drops it) owes its day a false row:
    // latched in memory (no file I/O on the page's thread), and written by
    // the writer's next batch.
    money::owe_coverage_for_test(&fixture.support, response + 3602, false);
    assert_eq!(money_owed_markers(&fixture.support), 0);
    page(response + 3603);
    let rows = money_jsonl_rows(&fixture.support);
    let owed = rows
        .iter()
        .filter(|row| row["row"] == "coverage" && row["dropped"] == true)
        .collect::<Vec<_>>();
    assert_eq!(owed.len(), 1, "{owed:?}");
    assert_eq!(owed[0]["coverage_complete"], false);
    assert_eq!(owed[0]["observed_unix"], response + 3602);
    assert_eq!(
        rows.iter()
            .filter(|row| row["row"] == "coverage" && row["dropped"] == false)
            .count(),
        3
    );
    // A debt of a failed write survives a restart (Sol R3-6: its marker).
    money::owe_coverage_for_test(&fixture.support, response + 3604, true);
    money::forget_owed_coverage_for_test(&fixture.support);
    assert_eq!(money_owed_markers(&fixture.support), 1);
    page(response + 3605);
    assert_eq!(money_owed_markers(&fixture.support), 0, "a written debt is settled");
    let owed = money_jsonl_rows(&fixture.support)
        .into_iter()
        .filter(|row| row["row"] == "coverage" && row["dropped"] == true)
        .map(|row| row["observed_unix"].as_u64().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(owed, [response + 3602, response + 3604]);
    assert_eq!(money::reserved_for_test(), 0);
}

/// Owed-coverage markers in the support directory's diagnostics.
fn money_owed_markers(support: &Path) -> usize {
    std::fs::read_dir(support.join("diagnostics"))
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".owed"))
                .count()
        })
        .unwrap_or(0)
}

/// Sol R4-1: a seal is only a seal once its false row is on disk. A day
/// filled with true rows whose file cannot be written owes its false row
/// (kept across a restart), and when the file can be written again the next
/// batch seals the day with it; then the day takes nothing more.
#[cfg(unix)]
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_seal_needs_its_false_row() {
    use std::os::unix::fs::PermissionsExt;
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let (fixture, index, scan) = money_armed_scan("money-shadow-failed-seal");
    let page = |now| {
        let counts = money::shadow_page_at(
            &fixture.support,
            &scan.snapshots,
            &index,
            &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
            &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
            scan.census_complete,
            now,
        );
        money::store::flush();
        counts
    };
    page(response + 3600);
    let day = std::fs::read_dir(fixture.support.join("diagnostics"))
        .unwrap()
        .flatten()
        .map(|entry| entry.path())
        .find(|path| path.extension().is_some_and(|extension| extension == "jsonl"))
        .expect("the day's file");
    // Fill the day with true rows to just under its room.
    let filler = serde_json::json!({"row": "coverage", "v": 2, "coverage_complete": true})
        .to_string()
        + "\n";
    let size = std::fs::metadata(&day).unwrap().len();
    let fill = (money::jsonl_room_for_test() - size - 64) / filler.len() as u64;
    let mut file = std::fs::OpenOptions::new().append(true).open(&day).unwrap();
    file.write_all(filler.repeat(fill as usize).as_bytes()).unwrap();
    drop(file);
    let false_rows = |rows: &[serde_json::Value]| {
        rows.iter()
            .filter(|row| row["row"] == "coverage" && row["coverage_complete"] == false)
            .count()
    };
    let before = false_rows(&money_jsonl_rows(&fixture.support));
    std::fs::set_permissions(&day, std::fs::Permissions::from_mode(0o444)).unwrap();
    if std::fs::OpenOptions::new().append(true).open(&day).is_ok() {
        // Permissions do not bind this user: nothing to show.
        std::fs::set_permissions(&day, std::fs::Permissions::from_mode(0o644)).unwrap();
        return;
    }
    let unwritten = std::fs::read(&day).unwrap();
    page(response + 3601);
    assert_eq!(std::fs::read(&day).unwrap(), unwritten, "nothing reached the file");
    assert_eq!(money_owed_markers(&fixture.support), 1, "the false row is owed");
    // A restart, then the file can be written again.
    money::forget_owed_coverage_for_test(&fixture.support);
    std::fs::set_permissions(&day, std::fs::Permissions::from_mode(0o644)).unwrap();
    let failed = page(response + 3602);
    assert!(failed.jsonl_failed >= 1, "{failed:?}");
    let rows = money_jsonl_rows(&fixture.support);
    assert!(false_rows(&rows) > before, "the seal's false row is on disk");
    assert!(rows
        .iter()
        .any(|row| row["row"] == "coverage" && row["truncated"] == true));
    assert_eq!(money_owed_markers(&fixture.support), 0);
    let sealed = std::fs::read(&day).unwrap();
    let after = page(response + 3603);
    assert_eq!(after.jsonl_sealed, 1, "{after:?}");
    assert_eq!(std::fs::read(&day).unwrap(), sealed, "a sealed day takes nothing more");
    assert_eq!(money::reserved_for_test(), 0);
}

/// Sol R4-2: rows are serialized by the writer, and a page that is late at
/// the hand-off publishes only a refused coverage row: no family, grain or
/// memo of its families.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_late_page_publishes_only_refused_coverage() {
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let (fixture, index, scan) = money_armed_scan("money-shadow-late-hand-off");
    money::set_page_fault_for_test(money::PageFault::LateAtHandOff);
    let counts = money::shadow_page_at(
        &fixture.support,
        &scan.snapshots,
        &index,
        &crate::claude_local_otel::ClaudeLocalOtelLoadReport::default(),
        &crate::claude_local_otel::ClaudeTraceOwnershipLoadReport::default(),
        scan.census_complete,
        response + 3600,
    );
    money::set_page_fault_for_test(money::PageFault::None);
    money::store::flush();
    assert!(counts.families > 0, "{counts:?}");
    assert_eq!(counts.refused_deadline, 1, "{counts:?}");
    assert_eq!(counts.coverage_complete, 0, "{counts:?}");
    let rows = money_jsonl_rows(&fixture.support);
    assert!(rows.iter().all(|row| row["row"] == "coverage"), "{rows:?}");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["refused"], true);
    assert_eq!(rows[0]["coverage_complete"], false);
    let memos = money::store::with_ledger_for_test(&fixture.support, |ledger| {
        ledger
            .census()
            .records_with_prefix(crate::snapshots::claude_request_census::FAMILY_KEY_PREFIX)
            .count()
    });
    assert_eq!(memos, Some(0));
    assert_eq!(money::reserved_for_test(), 0);
}

/// Finding 8, whole cycle: from one saved state (a populated ledger saved
/// to disk and reloaded), the same cycle run unarmed, armed, and armed with
/// every ledger save failing saves the same index bytes at every page and
/// makes the same page decisions. The shadow holds the index immutably and
/// keeps its ledger in its own store, so the index and every live allowance
/// derived from it are the same armed or not.
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_armed_cycle_saves_the_baseline_index() {
    let _source_manifests = SourceManifestTestGuard::new();
    let fixture = PipelineFixture::new("money-shadow-whole-cycle");
    money_write_corpus(
        &fixture,
        MoneyCorpus {
            shadow: true,
            copies_and_rows: true,
            broken_sidecar: false,
        },
    );
    // Populate the ledger with an armed cycle, then save it and forget it.
    money::enable_shadow_for_test(&fixture.support);
    fixture.traversal(8, &MONEY_PIPELINE_CYCLE);
    money::store::forget_for_test(&fixture.support);
    let ledger_dir = fixture.support.join(money::store::LEDGER_DIR);
    assert!(ledger_dir.join("meta.json").is_file(), "the ledger was saved");
    fixture.append(PIPELINE_SESSIONS[2], "req_2_2");
    let saved = money_files(&fixture.base);
    let cycle = |armed: bool, ledger_fails: bool| {
        money_restore_files(&fixture.base, &saved);
        money::store::forget_for_test(&fixture.support);
        if armed {
            money::enable_shadow_for_test(&fixture.support);
        } else {
            money::disable_shadow_for_test(&fixture.support);
        }
        if ledger_fails {
            for name in std::fs::read_dir(&ledger_dir).unwrap().flatten() {
                let staged = name.path().with_extension("json.tmp");
                std::fs::create_dir_all(staged.join("blocked")).unwrap();
            }
        }
        let _ = money::take_shadow_lines_for_test();
        let pages = fixture.traversal(9, &MONEY_PIPELINE_CYCLE);
        money::store::flush();
        let lines = money::take_shadow_lines_for_test();
        let pages = pages
            .iter()
            .map(|page| {
                (
                    census_parity_page_facts(&fixture, page),
                    serde_json::to_vec(&page.index).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        (pages, std::fs::read(&fixture.index_path).unwrap(), lines)
    };
    let (baseline, baseline_index, quiet) = cycle(false, false);
    assert!(quiet.is_empty());
    let (armed, armed_index, lines) = cycle(true, false);
    assert_eq!(armed.len(), baseline.len());
    for (number, (armed, baseline)) in armed.iter().zip(&baseline).enumerate() {
        assert_eq!(armed.0, baseline.0, "page {number}: the same decisions");
        assert!(armed.1 == baseline.1, "page {number}: the same index bytes");
    }
    assert!(armed_index == baseline_index, "the same saved index");
    // The armed cycle ran on the reloaded ledger.
    assert_eq!(lines[0]["counts"]["ledger_loading"], 1, "{}", lines[0]);
    assert!(
        lines
            .iter()
            .any(|line| line["ledger"]["telemetry_records"].as_u64() > Some(0)),
        "{lines:?}"
    );
    let (failing, failing_index, lines) = cycle(true, true);
    assert_eq!(failing.len(), baseline.len());
    for (number, (failing, baseline)) in failing.iter().zip(&baseline).enumerate() {
        assert_eq!(failing.0, baseline.0, "page {number}: the same decisions");
        assert!(failing.1 == baseline.1, "page {number}: the same index bytes");
    }
    assert!(failing_index == baseline_index, "the same saved index");
    assert!(!lines.is_empty());
    assert_eq!(money::reserved_for_test(), 0);
}

/// Every file under `dir`: relative path -> bytes.
fn money_files(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        for entry in std::fs::read_dir(&next).unwrap().flatten() {
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                pending.push(path);
            } else {
                let relative = path.strip_prefix(dir).unwrap().to_path_buf();
                files.insert(relative, std::fs::read(&path).unwrap());
            }
        }
    }
    files
}

/// Put `dir`'s files back to `saved`: a changed file is rewritten in place
/// (its identity kept), a new one removed, a missing one recreated.
fn money_restore_files(dir: &Path, saved: &BTreeMap<PathBuf, Vec<u8>>) {
    let now = money_files(dir);
    for (relative, bytes) in &now {
        match saved.get(relative) {
            Some(old) if old == bytes => {}
            Some(old) => std::fs::write(dir.join(relative), old).unwrap(),
            None => std::fs::remove_file(dir.join(relative)).unwrap(),
        }
    }
    for (relative, bytes) in saved {
        if !now.contains_key(relative) {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
    }
}

// P2 literal bodies go through the production resumable upload/ACK loop.
// Typed synthetic bodies avoid live provider state while preserving every
// ownership byte whose downgrade/stripping would invalidate the contract.
fn p2a_wire_body(id: u64) -> serde_json::Value {
    serde_json::json!({
        "source_session_id":format!("session-{id}"),
        "snapshot_fingerprint":format!("{id:064x}"),
        "usage_accounting_contract":"claude_request_owned_usage:v1",
        "removed_request_count":1,
        "removed_usage":{"input_tokens":11,"output_tokens":2,"cache_read_tokens":3,
            "cache_creation_5m_tokens":5,"cache_creation_1h_tokens":7,
            "unattributed_total_tokens":0,"reasoning_output_tokens":0},
        "telemetry_owned_complete":true,
        "input_tokens":13,"output_tokens":2,"request_count":1,
        "usage_buckets":[{"bucket_start":"2026-08-02T08:00:00Z","model_usage":[{
            "model":"claude-haiku-4-5","input_tokens":13,"output_tokens":2,"request_count":1,
            "selector_context":{"request_usage_origin":"telemetry_matched"},
            "selector_sources":{"request_usage_origin":"claude_api_request"},"cost_usd":"0.000100"}]}]
    })
}
fn p2a_fp(item: &serde_json::Value) -> &str {
    item["snapshot_fingerprint"].as_str().unwrap()
}
fn p2a_witness(item: &serde_json::Value) -> String {
    format!("{:x}", Sha256::digest(serde_json::to_vec(item).unwrap()))
}

#[test]
#[serial(client_report)]
fn p2a_literal_503_resends_byte_identical_after_progress_restart() {
    let scratch = crate::test_scratch::ScratchDir::new("p2a-literal-503");
    let path = scratch.join("progress.json");
    let scope = unique_poison_scope();
    let items = vec![p2a_wire_body(1), p2a_wire_body(2)];
    let original = serde_json::to_vec(&items).unwrap();
    let mut progress = test_upload_progress();
    let namespace = progress.destination_namespace_hash.clone();
    let mut accepted = 0;
    let mut first = Vec::new();
    let result = upload_resumable_batches_with_body_witness(
        &items,
        &scope,
        &mut progress,
        &mut accepted,
        p2a_fp,
        p2a_witness,
        |batch| {
            first = serde_json::to_vec(&batch).unwrap();
            Err(anyhow::Error::new(UploadShed {
                request_owned_route_unavailable: true,
                status: 503,
                retry_after: Some(Duration::from_secs(60)),
            }))
        },
        |progress| progress.save(&path),
    )
    .unwrap();
    assert!(matches!(result, ResumableUploadResult::Shed { .. }));
    assert_eq!(accepted, 0);
    assert!(progress.accepted_fingerprints.is_empty());
    assert!(progress.permanent_rejections.is_empty());
    // A shed request does not require a checkpoint write, so save the unchanged
    // state as orderly shutdown would, then reload the actual progress codec.
    progress.save(&path).unwrap();
    let mut progress = SnapshotUploadProgress::load(
        &path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    let mut retried = Vec::new();
    upload_resumable_batches_with_body_witness(
        &items,
        &scope,
        &mut progress,
        &mut accepted,
        p2a_fp,
        p2a_witness,
        |batch| {
            retried = serde_json::to_vec(&batch).unwrap();
            Ok(accepted_batch(batch.len()))
        },
        |progress| progress.save(&path),
    )
    .unwrap();
    assert_eq!(first, original);
    assert_eq!(
        retried, original,
        "503 cannot strip the literal, removals or origin"
    );
    assert_eq!(accepted, 2);
    assert_eq!(progress.accepted_fingerprints.len(), 2);
}

#[test]
#[serial(client_report)]
fn p2a_literal_422_is_persisted_retry_debt_without_bisect_or_poison() {
    use crate::client_report::{observe, reset_for_test, ClientReportReason};
    reset_for_test();
    let scratch = crate::test_scratch::ScratchDir::new("p2a-literal-422");
    let path = scratch.join("progress.json");
    let scope = unique_poison_scope();
    let items = vec![p2a_wire_body(1), p2a_wire_body(2)];
    let mut progress = test_upload_progress();
    let namespace = progress.destination_namespace_hash.clone();
    let mut accepted = 0;
    let mut attempts = 0;
    let result=upload_resumable_batches_with_body_witness(&items,&scope,&mut progress,&mut accepted,
        p2a_fp,p2a_witness,|batch| {
            attempts+=1; assert_eq!(serde_json::to_vec(&batch).unwrap(),serde_json::to_vec(&items).unwrap());
            Err(anyhow::Error::new(BatchRejected {status:422,body_excerpt:Some(
                r#"{"errors":[{"loc":["body","snapshots",0,"usage_accounting_contract"],"type":"literal_error"}]}"#.into())}))
        },|progress|progress.save(&path)).unwrap();
    assert!(
        matches!(result,ResumableUploadResult::Shed {retry_after:Some(delay)} if delay==Duration::from_secs(1800))
    );
    assert_eq!(
        attempts, 1,
        "literal skew must be classified before singleton poison isolation"
    );
    assert_eq!(accepted, 0);
    assert!(progress.accepted_fingerprints.is_empty());
    assert!(progress.permanent_rejections.is_empty());
    assert_eq!(observe().quantity(ClientReportReason::Poisoned), 0);
    assert!(counted_poison_fingerprints_for_test(&scope).is_empty());
    let loaded = SnapshotUploadProgress::load(
        &path,
        &namespace,
        snapshot_quarantine_witness(SnapshotSource::Codex),
    )
    .unwrap();
    assert_eq!(loaded.quarantined_fingerprints.len(), items.len());
    for item in &items {
        let debt = &loaded.quarantined_fingerprints[p2a_fp(item)];
        assert_eq!(debt.version_skew_attempts, 1);
        assert_eq!(
            debt.upload_body_witness.as_deref(),
            Some(p2a_witness(item).as_str())
        );
    }
    reset_for_test();
}

#[test]
#[serial(client_report)]
fn p2a_restart_at_each_ack_save_boundary_replays_exact_body_until_durable_ack() {
    // 0: before request; 1: server accepted but ACK lost; 2: ACK received but
    // local save failed; 3: ACK durably saved. An ACK lost in transit and one
    // lost to a failed local save must both replay. A durable ACK must not.
    for boundary in 0..4 {
        let scratch = crate::test_scratch::ScratchDir::new("p2a-ack-boundary");
        let path = scratch.join("progress.json");
        let scope = unique_poison_scope();
        let items = vec![p2a_wire_body(1)];
        let original = serde_json::to_vec(&items).unwrap();
        let mut progress = test_upload_progress();
        let namespace = progress.destination_namespace_hash.clone();
        progress.save(&path).unwrap();
        let mut accepted = 0;
        if boundary > 0 {
            let outcome = upload_resumable_batches_with_body_witness(
                &items,
                &scope,
                &mut progress,
                &mut accepted,
                p2a_fp,
                p2a_witness,
                |batch| {
                    assert_eq!(serde_json::to_vec(&batch).unwrap(), original);
                    if boundary == 1 {
                        Err(anyhow!("synthetic lost ACK"))
                    } else {
                        Ok(accepted_batch(batch.len()))
                    }
                },
                |progress| {
                    if boundary == 2 {
                        Err(anyhow!("synthetic failed ACK save"))
                    } else {
                        progress.save(&path)
                    }
                },
            );
            assert_eq!(outcome.is_ok(), boundary == 3);
        }
        let mut progress = SnapshotUploadProgress::load(
            &path,
            &namespace,
            snapshot_quarantine_witness(SnapshotSource::Codex),
        )
        .unwrap();
        let mut calls = 0;
        upload_resumable_batches_with_body_witness(
            &items,
            &scope,
            &mut progress,
            &mut accepted,
            p2a_fp,
            p2a_witness,
            |batch| {
                calls += 1;
                assert_eq!(serde_json::to_vec(&batch).unwrap(), original);
                Ok(accepted_batch(batch.len()))
            },
            |progress| progress.save(&path),
        )
        .unwrap();
        assert_eq!(calls, usize::from(boundary != 3), "boundary {boundary}");
        assert!(progress.contains_body(p2a_fp(&items[0]), &p2a_witness(&items[0])));
    }
}

#[test]
#[serial(client_report)]
fn p2a_old_v1_head_is_replaced_by_literal_and_exact_ack_is_not_old_settlement() {
    let scope = unique_poison_scope();
    let literal = p2a_wire_body(1);
    let mut old = literal.clone();
    old["usage_accounting_contract"] = serde_json::json!("session_exclusive_reported_usage:v1");
    old["snapshot_fingerprint"] = serde_json::json!(format!("{:064x}", 3));
    for key in [
        "removed_request_count",
        "removed_usage",
        "telemetry_owned_complete",
    ] {
        old.as_object_mut().unwrap().remove(key);
    }
    old["input_tokens"] = serde_json::json!(24);
    old["request_count"] = serde_json::json!(2);
    let mut progress = test_upload_progress();
    let mut accepted = 0;
    upload_resumable_batches_with_body_witness(
        &[old.clone()],
        &scope,
        &mut progress,
        &mut accepted,
        p2a_fp,
        p2a_witness,
        |batch| Ok(accepted_batch(batch.len())),
        |_| Ok(()),
    )
    .unwrap();
    let mut offered = Vec::new();
    upload_resumable_batches_with_body_witness(
        std::slice::from_ref(&literal),
        &scope,
        &mut progress,
        &mut accepted,
        p2a_fp,
        p2a_witness,
        |batch| {
            offered = batch;
            Ok(accepted_batch(1))
        },
        |_| Ok(()),
    )
    .unwrap();
    assert_eq!(offered, vec![literal.clone()]);
    assert_eq!(accepted, 2);
    assert_eq!(
        literal["request_count"].as_u64().unwrap()
            + literal["removed_request_count"].as_u64().unwrap(),
        old["request_count"].as_u64().unwrap()
    );
    assert_eq!(
        literal["input_tokens"].as_u64().unwrap()
            + literal["removed_usage"]["input_tokens"].as_u64().unwrap(),
        old["input_tokens"].as_u64().unwrap()
    );
    assert!(progress.contains_body(p2a_fp(&literal), &p2a_witness(&literal)));
}

#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn p2a_whole_file_copy_same_session_emits_one_union_with_mac_wide_distinct_ids() {
    let fixture = PipelineFixture::new("p2a-whole-file-union");
    money::enable_shadow_for_test(&fixture.support);
    let original = fixture.root.join(format!("{}.jsonl", PIPELINE_SESSIONS[1]));
    let duplicate = fixture.root.join(format!("{MONEY_PIPELINE_COPY}.jsonl"));
    std::fs::copy(&original, &duplicate).unwrap(); // preserve the content session id
    let mut index = ScanIndex::default();
    let mut scan = crate::snapshots::scan_source_roots_with_test_limit(
        SnapshotSource::ClaudeCode,
        std::slice::from_ref(&fixture.root),
        &mut index,
        "2026-08-02T09:00:00Z",
        183,
        16,
        true,
    )
    .unwrap();
    std::fs::create_dir_all(fixture.support.join("snapshots")).unwrap();
    std::fs::write(fixture.support.join("snapshots/claude_code-reemission-exclusions.txt"), b"").unwrap();
    index.load_claude_reemission_exclusions(&fixture.support);
    money::store::reload_for_test(&fixture.support);
    // The normal page builds from actual multi-file membership, not a test
    // supplied union key. This intentionally pins the unfinished P2 union seam.
    let held = money::live_page(
        &fixture.support,
        &mut scan.snapshots,
        &index,
        &Default::default(),
        &Default::default(),
        true,
        None,
        &mut BTreeMap::new(),
    );
    money::store::flush();
    money::disable_shadow_for_test(&fixture.support);
    assert!(
        held.is_empty(),
        "a whole-file duplicate must have a buildable union: {held:?}"
    );
    let mut sessions = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut requests = 0;
    for item in &scan.snapshots {
        assert!(
            sessions.insert(item.source_session_id.clone()),
            "one upload per logical session"
        );
        assert_eq!(
            item.usage_accounting_contract.as_deref(),
            Some(money::REQUEST_OWNED_CONTRACT)
        );
        assert_eq!(item.removed_request_count, Some(0));
        assert_eq!(item.request_count, 1, "per session union total");
        assert_eq!(
            item.usage_buckets
                .iter()
                .flat_map(|b| &b.model_usage)
                .map(|r| r.request_count)
                .sum::<u64>(),
            1,
            "per hour union total"
        );
        requests += item.request_count;
        for id in &item.claude_usage_request_ids {
            assert!(ids.insert(id.clone()), "Mac-wide distinct request");
        }
    }
    assert_eq!(requests, PIPELINE_SESSIONS.len() as u64);
    assert_eq!(ids.len(), PIPELINE_SESSIONS.len());
}
