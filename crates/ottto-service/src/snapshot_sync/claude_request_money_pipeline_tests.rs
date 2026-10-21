// P1 per-request Claude money, shadow only, through the real caller: the
// `PipelineFixture` page stages run `apply_claude_local_evidence_to_scan`,
// which runs the shadow. The shadow changes no page decision; its family rows
// conserve the live totals; its refusal and reader-failure paths never fail a
// page. Fixtures are synthetic.

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
    rows: Vec<serde_json::Value>,
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

/// Every built family conserves the live totals: old + reported side calls =
/// new + removed + held + immature, in tokens and in requests.
fn money_assert_conserved(arm: &MoneyPipelineArm) {
    assert!(!arm.rows.is_empty(), "the shadow writes family rows");
    let mut built = 0;
    for row in &arm.rows {
        assert_eq!(row["counting"], "claude_request_counting:v1", "{row}");
        assert_eq!(row["family"].as_str().map(str::len), Some(16), "{row}");
        let (old_tokens, old_requests) = money_totals(row, "old");
        let (new_tokens, new_requests) = money_totals(row, "new");
        assert_eq!(
            row["removed_change"].as_i64(),
            Some(new_tokens as i64 - old_tokens as i64),
            "{row}"
        );
        if row["category"] == "unbuilt" {
            assert_eq!(row["coverage_complete"].as_bool(), Some(false), "{row}");
            continue;
        }
        built += 1;
        let reported = &row["by_origin"]["telemetry_reported"];
        let (reported_tokens, reported_requests) = (
            reported["tokens"].as_u64().unwrap_or(0),
            reported["requests"].as_u64().unwrap_or(0),
        );
        let parts = ["removed", "held", "immature"]
            .iter()
            .map(|part| money_totals(row, part))
            .fold((new_tokens, new_requests), |sum, part| {
                (sum.0 + part.0, sum.1 + part.1)
            });
        assert_eq!(
            (
                old_tokens + reported_tokens,
                old_requests + reported_requests
            ),
            parts,
            "conservation: {row}"
        );
    }
    assert!(
        built > 0,
        "the builder builds ordinary families: {:?}",
        arm.rows
    );
    assert_eq!(money_count(&arm.lines, "certificate_mismatch"), 0);
    assert_eq!(
        money_count(&arm.lines, "residue_tokens"),
        0,
        "{:?}",
        arm.lines
    );
}

/// Zero behavior change through the real caller: with identical sidecars
/// and transcripts, the page facts (bodies, uploads, holds, settlement,
/// census decisions) and the non-ledger census records are identical with
/// the shadow on and off. The shadow's only writes are its own `otel:`
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
        assert!(line["ledger"]["transcript_u_known"].is_u64(), "{line}");
    }
    money_assert_conserved(&on);
    // The copy is removed from the copy's family: the source family's API
    // row proves the owner, so the copy leaves and the money stays once.
    assert!(
        money_count(&on.lines, "units_removed") >= 1,
        "{:?}",
        on.lines
    );
    let copy_family = money::hashed_id_for_test(MONEY_PIPELINE_COPY);
    let copy_row = on
        .rows
        .iter()
        .find(|row| row["family"] == copy_family.as_str())
        .expect("the copy's family row");
    assert_eq!(
        money_totals(copy_row, "removed"),
        (MONEY_PIPELINE_RESPONSE_TOKENS, 1),
        "{copy_row}"
    );
    assert_eq!(money_totals(copy_row, "new").0, 0, "{copy_row}");
    // A matched row is a witness of its transcript unit (Sol N1): it adds
    // no unit, so the matched units are among the counted ones.
    assert!(
        money_count(&on.lines, "units_matched") >= 1,
        "{:?}",
        on.lines
    );
    assert!(
        money_count(&on.lines, "units_matched") + money_count(&on.lines, "units_matched_unpriced")
            <= money_count(&on.lines, "units_counted")
    );
    assert!(
        money_count(&on.lines, "side_calls") >= 1,
        "the telemetry-only request is a side call: {:?}",
        on.lines
    );
    // The JSONL carries hashed ids only.
    let joined = on
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
    assert_eq!(money::reserved_for_test(), 0, "admission is released");
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
        .rows
        .iter()
        .filter(|row| row["family"] == copy_family.as_str())
        .collect::<Vec<_>>();
    assert!(!copy_rows.is_empty());
    assert!(copy_rows
        .iter()
        .all(|row| row["coverage_complete"] == false));
    money_assert_conserved(&on);
}

/// Admission refusal: with the shadow's whole memory ceiling held, every page
/// logs one refused line, writes no family row, and changes nothing.
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
    assert!(on.rows.is_empty(), "a refused page writes no family row");
}

/// Immature units (younger than the maturity window) are neither counted nor
/// removed; at a later clock the same page counts them. Both conserve.
#[test]
#[serial(claude_request_money_shadow)]
fn money_shadow_holds_immature_units_until_they_mature() {
    let fixture = PipelineFixture::new("money-shadow-immature");
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
    let response = census_pipeline_window("2026-08-02T07:00:00Z");
    let report = crate::claude_local_otel::ClaudeLocalOtelLoadReport::default();
    let young = money::shadow_page_at(
        &fixture.support,
        &scan.snapshots,
        &mut index,
        &report,
        scan.census_complete,
        response + 30,
    );
    let units = PIPELINE_SESSIONS.len() as u64;
    assert_eq!(young.units_immature, units, "{young:?}");
    assert_eq!(young.units_counted, 0, "{young:?}");
    assert_eq!(
        young.tokens_immature,
        units * MONEY_PIPELINE_RESPONSE_TOKENS
    );
    assert_eq!(young.tokens_new, 0, "{young:?}");
    assert_eq!(
        young.tokens_old,
        young.tokens_new + young.tokens_removed + young.tokens_held + young.tokens_immature
    );
    let mature = money::shadow_page_at(
        &fixture.support,
        &scan.snapshots,
        &mut index,
        &report,
        scan.census_complete,
        response + 3600,
    );
    assert_eq!(mature.units_immature, 0, "{mature:?}");
    assert_eq!(
        mature.units_counted
            + mature.units_removed
            + mature.units_undecided
            + mature.units_two_owner,
        units,
        "{mature:?}"
    );
    assert_eq!(
        mature.tokens_old,
        mature.tokens_new + mature.tokens_removed + mature.tokens_held + mature.tokens_immature
    );
    assert_eq!(money::reserved_for_test(), 0);
}

/// SI parity: on a corpus with no copied request and no side call, the shadow
/// body equals the live body for every built family. With them, only the
/// deliberate differences appear, each in its own family and by its exact
/// amount.
#[test]
#[serial(source_manifests)]
#[serial(claude_request_money_shadow)]
fn money_shadow_matches_the_live_body_except_the_deliberate_differences() {
    let plain = money_pipeline_arm(
        "money-shadow-parity-plain",
        MoneyCorpus {
            shadow: true,
            copies_and_rows: false,
            broken_sidecar: false,
        },
    );
    money_assert_conserved(&plain);
    for row in plain.rows.iter().filter(|row| row["category"] != "unbuilt") {
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
    money_assert_conserved(&differing);
    let copy_family = money::hashed_id_for_test(MONEY_PIPELINE_COPY);
    let side_family = money::hashed_id_for_test(PIPELINE_SESSIONS[1]);
    for row in differing
        .rows
        .iter()
        .filter(|row| row["category"] != "unbuilt")
    {
        let (old, _) = money_totals(row, "old");
        let (new, _) = money_totals(row, "new");
        if row["family"] == copy_family.as_str() {
            // MONEY_DELIBERATE_DIFFERENCES[0]
            assert_eq!(old - new, MONEY_PIPELINE_RESPONSE_TOKENS, "{row}");
        } else if row["family"] == side_family.as_str() && new != old {
            // MONEY_DELIBERATE_DIFFERENCES[1], unless the live body already
            // carries reported usage (then it is counted, not added).
            assert_eq!(new - old, MONEY_PIPELINE_SIDE_CALL_TOKENS, "{row}");
        } else {
            assert_eq!(new, old, "an undeclared difference: {row}");
        }
    }
    assert_eq!(MONEY_DELIBERATE_DIFFERENCES.len(), 2);
}
