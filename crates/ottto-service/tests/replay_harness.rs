//! Synthetic child-process checks. Never reads provider state or starts serve.
#![cfg(all(unix, feature = "replay-harness"))]
use serde_json::{json, Value};
use std::fs;
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Output};

const CANARY: &str = "synthetic-private-content-canary";
const SESSION: &str = "synthetic-private-session-canary";
struct Fixture {
    base: PathBuf,
    clone: PathBuf,
    support: PathBuf,
    root: PathBuf,
    key: PathBuf,
    collected_at: String,
}
impl Fixture {
    fn new() -> Self {
        let base = std::env::temp_dir().join(format!(
            "replay-{}-{}",
            std::process::id(),
            ottto_core::generate_control_token().unwrap()
        ));
        let clone = base.join("clone");
        let support = base.join("scratch");
        let root = clone.join("claude/project");
        let key = base.join("shared-key");
        for dir in [&base, &clone, &support, &root] {
            fs::create_dir_all(dir).unwrap();
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(&key, [42; 32]).unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let collected_at = time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        let fixture = Self {
            base,
            clone,
            support,
            root,
            key,
            collected_at,
        };
        fixture.manifest(json!({"claude":[fixture.clone.join("claude")], "codex":[], "pi":[]}));
        fixture.append(1, 10);
        fixture
    }
    fn manifest(&self, value: Value) {
        fs::write(self.clone.join("roots.json"), value.to_string()).unwrap();
    }
    fn append(&self, n: u64, tokens: u64) {
        let now = &self.collected_at;
        let row = json!({"type":"assistant", "sessionId":SESSION, "uuid":format!("u{n}"), "requestId":format!("req{n}"), "timestamp":now,
            "cwd":self.base.join(CANARY), "message":{"id":format!("msg{n}"), "model":"claude-sonnet-4-6", "role":"assistant", "content":[{"type":"text","text":CANARY}], "usage":{"input_tokens":tokens,"output_tokens":2}}});
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.root.join(format!("{SESSION}.jsonl")))
            .unwrap();
        writeln!(file, "{row}").unwrap();
    }
    fn command(&self, pass: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ottto-service"));
        command
            .args(["replay-harness", "--support-dir"])
            .arg(&self.support)
            .arg("--roots-manifest")
            .arg(self.clone.join("roots.json"))
            .args(["--pass", pass, "--out"])
            .arg(self.support.join(format!("{pass}.jsonl")))
            .arg("--blinding-key-file")
            .arg(&self.key)
            .arg("--collected-at")
            .arg(&self.collected_at)
            .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &self.support)
            .env("OTTTO_SERVICE_SECRET_FALLBACK_DIR", &self.support)
            .env_remove("OTTTO_API_BASE_URL");
        command
    }
    fn run(&self, pass: &str) -> Vec<Value> {
        let output = self.command(pass).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.assert_private(&output);
        self.rows(pass)
    }
    fn assert_private(&self, output: &Output) {
        for text in [
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ] {
            for forbidden in [CANARY, SESSION, self.base.to_str().unwrap()] {
                assert!(!text.contains(forbidden), "raw output: {text}");
            }
        }
    }
    fn rows(&self, pass: &str) -> Vec<Value> {
        let text = fs::read_to_string(self.support.join(format!("{pass}.jsonl"))).unwrap();
        for forbidden in [CANARY, SESSION, self.base.to_str().unwrap()] {
            assert!(!text.contains(forbidden), "raw JSONL");
        }
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
    fn refused(&self, mut command: Command) {
        let output = command.output().unwrap();
        self.assert_refused(&output);
    }
    fn assert_refused(&self, output: &Output) {
        assert_eq!(
            output.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        self.assert_private(output);
        assert!(!self.support.join(".replay-harness").exists());
        assert!(!self.support.join("P0.jsonl").exists());
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Retain synthetic scratch and print its aggregate-only records.
            // In CI the filesystem disappears with the runner; the log remains.
            eprintln!("retaining failed synthetic replay fixture; aggregate diagnostics follow");
            if let Ok(entries) = fs::read_dir(&self.support) {
                for entry in entries.flatten() {
                    if entry.path().extension().is_some_and(|ext| ext == "jsonl") {
                        if let Ok(text) = fs::read_to_string(entry.path()) {
                            eprintln!("replay aggregate diagnostics:\n{text}");
                        }
                    }
                }
            }
            return;
        }
        fs::remove_dir_all(&self.base).unwrap();
    }
}
fn totals(rows: &[Value]) -> &Value {
    rows.iter()
        .find(|row| row["kind"] == "pass_totals")
        .expect("completed pass")
}
fn session(rows: &[Value]) -> &Value {
    rows.iter()
        .rev()
        .find(|row| row["kind"] == "session")
        .expect("emitted session")
}

const PLATFORM_QUALIFICATION: &str = "platform: durable retention unsupported on this layout; restore is qualified on macOS by the native durable_tail/#865 fixtures in normal macOS CI";

#[derive(Clone, Debug)]
struct RetentionWitness {
    bound_refused: u64,
    insert_admitted: u64,
    other_refusals: u64,
}
#[derive(Clone, Debug)]
struct PlatformDiagnostics {
    layout_supported: bool,
    records_after_p0: u64,
    p0: RetentionWitness,
    page: RetentionWitness,
    full: u64,
    tail: u64,
    full_causes: Value,
    restore_outcome: Value,
}
impl PlatformDiagnostics {
    fn validate_p0(&self) -> Result<(), &'static str> {
        if self.p0.other_refusals != 0 {
            return Err("P0 non-layout refusal");
        }
        if self.layout_supported {
            if self.records_after_p0 == 0 {
                return Err("supported layout requires durable P0 records");
            }
        } else if self.records_after_p0 != 0
            || self.p0.bound_refused == 0
            || self.p0.insert_admitted != 0
        {
            return Err("unsupported layout requires zero records and a real P0 layout witness");
        }
        Ok(())
    }

    fn validate_growth(&self) -> Result<(), &'static str> {
        self.validate_p0()?;
        if self.page.other_refusals != 0 {
            return Err("growth non-layout refusal");
        }
        if self.layout_supported {
            if self.full != 0 || self.tail == 0 || self.full_causes != json!({}) {
                return Err("supported layout requires Full0/Tail>=1/no cause");
            }
            if self.restore_outcome.get("miss").is_some() {
                return Err("supported layout must not miss a durable restore");
            }
        } else {
            // This one-file fixture must account for its one Full precisely.
            // state_missing is never accepted without BOTH actual witnesses.
            if self.full > 1 {
                return Err("unsupported one-file growth exceeds Full bound");
            }
            if self.full != 1
                || self.full_causes != json!({"state_missing":1})
                || self.restore_outcome != json!({"miss":{"missing":1}})
                || self.page.bound_refused == 0
                || self.page.insert_admitted != 0
            {
                return Err("unsupported layout requires exact state_missing/miss:missing and layout witness");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CounterClass {
    LayoutWitness,
    NonLayoutFailure,
    Observation,
}

// Exhaustive cache_lifecycle.rs::counters! registry. Citations below are
// relative to src/ and describe the emitter, not a guess from the key's name.
// Only retention_bound_refused can witness the real layout gate; the existing
// PlatformDiagnostics gate still requires the real layout_supported=false.
const LIFECYCLE_COUNTERS: &[(&str, CounterClass)] = &[
    // transcript_cache.rs::take: destructively acquired an existing entry.
    ("take_hit", CounterClass::Observation),
    // transcript_cache.rs::take: no resident entry; no historical cause claimed.
    ("take_absent", CounterClass::Observation),
    // snapshots/sampled_scan.rs::SharedCache::take: retained lock poisoned.
    ("take_poisoned_lock", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::admit_at_rank: candidate remains admitted.
    ("insert_admitted", CounterClass::Observation),
    // transcript_cache.rs::admit_at_rank: live reservation exceeds byte limit.
    (
        "insert_live_reservation_refused",
        CounterClass::NonLayoutFailure,
    ),
    // transcript_cache.rs::admit_at_rank: clock overflow clears cache/refuses.
    ("insert_clock_reset", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::admit_at_rank: count-disabled OR layout; ambiguous,
    // so this is not an accepted substitute for the retention layout witness.
    (
        "insert_disabled_or_layout_refused",
        CounterClass::NonLayoutFailure,
    ),
    // transcript_cache.rs::admit_at_rank: retained/entry bound not admitted.
    ("insert_entry_bound_refused", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::admit_at_rank: state has no frozen-charge support.
    (
        "insert_frozen_charge_refused",
        CounterClass::NonLayoutFailure,
    ),
    // transcript_cache.rs::admit_at_rank: key cannot fit the entry allowance.
    ("insert_key_bound_refused", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::admit_at_rank: candidate itself lost victim ordering.
    ("insert_self_evicted", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::admit_at_rank: no victim can satisfy admission.
    ("insert_no_victim_refused", CounterClass::NonLayoutFailure),
    // snapshots/sampled_scan.rs::SharedCache::insert_admitted: retained lock poisoned.
    ("insert_poisoned_lock", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::admit_at_rank: capacity victim action; not refusal.
    ("insert_entries_evicted", CounterClass::Observation),
    // transcript_cache.rs::admit_at_rank: Claude/Codex victims of a Pi
    // insertion, a subset of insert_entries_evicted.
    ("cache_evicted_by_pi_claude_code", CounterClass::Observation),
    ("cache_evicted_by_pi_codex", CounterClass::Observation),
    // transcript_cache.rs::evict_until: cursor reservation victim action.
    (
        "cursor_reservation_entries_evicted",
        CounterClass::Observation,
    ),
    // transcript_cache.rs::evict_until: copy-refusal victim action only.
    ("copy_refusal_entries_evicted", CounterClass::Observation),
    // transcript_cache.rs::evict_until: bytes of released victims.
    ("copy_refusal_bytes_released", CounterClass::Observation),
    // snapshots/sampled_scan.rs::fit_residents: remeasure unknown resident bound.
    ("copy_refusal_remeasured", CounterClass::Observation),
    // snapshots/sampled_scan.rs::fit_residents: residents already fit, no release.
    ("copy_refusal_kept", CounterClass::Observation),
    // snapshots/sampled_scan.rs::release_for_copy_refusal: walk hit visit cap.
    (
        "copy_refusal_walk_visit_limit",
        CounterClass::NonLayoutFailure,
    ),
    // transcript_cache.rs::evict_until: CopyAdmission victim action.
    ("copy_refusal_admission_evicted", CounterClass::Observation),
    // snapshots/sampled_scan.rs::release_for_copy_refusal: unsupported AUDIT
    // METADATA clears cache; distinct from the native heap-layout gate (E1 F1).
    ("clear_metadata_unsupported", CounterClass::NonLayoutFailure),
    // snapshots/sampled_scan.rs::release_for_copy_refusal: conservative native
    // baseline unknown-bound clear; ordinary action, not layout proof itself.
    (
        "clear_full_resident_bound_unknown",
        CounterClass::Observation,
    ),
    // snapshots/sampled_scan.rs::release_for_copy_refusal: no active copy charge.
    ("clear_no_active", CounterClass::Observation),
    // snapshots/sampled_scan.rs::release_for_copy_refusal: other active charge
    // cannot fit/be measured, even after fitting attempts; not the Full baseline.
    ("clear_other_active", CounterClass::NonLayoutFailure),
    // transcript_cache.rs::clear: number of released entries, not clear cause.
    ("clear_entries_released", CounterClass::Observation),
    // snapshots/sampled_scan.rs::SharedCache::clear: retained lock poisoned.
    ("clear_poisoned_lock", CounterClass::NonLayoutFailure),
    // snapshots/sampled_jsonl.rs::retain_reduction: unfinished/failed/lossy parse.
    (
        "retention_incomplete_or_lossy",
        CounterClass::NonLayoutFailure,
    ),
    // snapshots/sampled_jsonl.rs::retain_reduction/retain_after_release:
    // reduction dependencies incompatible with optional retention.
    ("retention_incompatible", CounterClass::NonLayoutFailure),
    // snapshots/sampled_jsonl.rs::retain_reduction/retain_after_release:
    // retention_bound failed; qualified only with real unsupported layout flag.
    ("retention_bound_refused", CounterClass::LayoutWitness),
    // snapshots/sampled_jsonl.rs::record_retention_bound_refusal: Pi subset
    // of retention_bound_refused; never a layout witness on its own.
    ("retention_bound_refused_pi", CounterClass::Observation),
    // snapshots/sampled_jsonl.rs::retain_reduction/retain_after_release: no plan.
    ("retention_no_plan", CounterClass::NonLayoutFailure),
    // snapshots/sampled_jsonl.rs::retain_reduction/retain_after_release:
    // EOF/certificate does not match sealed prefix; copy refused.
    ("retention_unsealed_eof", CounterClass::NonLayoutFailure),
    // snapshots/sampled_jsonl.rs::retain_reduction/retain_after_release:
    // actual reduction clone exceeds its bound.
    (
        "retention_clone_bound_refused",
        CounterClass::NonLayoutFailure,
    ),
    // snapshots.rs native completion: finalization budget/bound refuses copy.
    (
        "retention_finalization_bound_refused",
        CounterClass::NonLayoutFailure,
    ),
    // snapshots/sampled_jsonl.rs::retain_reduction/retain_after_release:
    // completed reduction produced; successful observation, not admission yet.
    ("retention_produced", CounterClass::Observation),
    // snapshots.rs:8833 (apply_claude_reported_usage_*): prefix bodies excluded
    // from family proof census; provenance bookkeeping, not retention refusal.
    ("prefix_excluded_bodies", CounterClass::Observation),
    // snapshots/sampled_audit.rs::complete_native_recomposition: prefix tag cleared.
    ("prefix_tag_clears", CounterClass::Observation),
    // snapshots.rs::apply_pi_line: cost parsing, never a retention decision.
    ("pi_cost_refused_overflow", CounterClass::Observation),
    ("pi_cost_precision_rounded", CounterClass::Observation),
];

// CachePage flattens the registry above and adds these sparse scalars.
const PAGE_ONLY_COUNTERS: &[(&str, CounterClass)] = &[
    // local_resource_diagnostics/claude_reread.rs::cache_capacity_eviction(true):
    // count-pressure victims, not a refusal of the candidate.
    ("insert_count_entries_evicted", CounterClass::Observation),
    // local_resource_diagnostics/claude_reread.rs::cache_capacity_eviction(false):
    // byte-pressure victims, not a refusal of the candidate.
    ("insert_byte_entries_evicted", CounterClass::Observation),
    // local_resource_diagnostics/claude_reread.rs::Reinsertion::drop:
    // destructive hit left without successful readmission.
    ("reinsert_failed", CounterClass::NonLayoutFailure),
];

fn checked_counter_map(
    counts: &Value,
    page: bool,
) -> Result<&serde_json::Map<String, Value>, String> {
    let counts = counts.as_object().ok_or("counter object required")?;
    for (key, count) in counts {
        let class = LIFECYCLE_COUNTERS
            .iter()
            .find(|(name, _)| *name == key)
            .or_else(|| {
                if page {
                    PAGE_ONLY_COUNTERS.iter().find(|(name, _)| *name == key)
                } else {
                    None
                }
            })
            .map(|(_, class)| *class)
            .ok_or_else(|| format!("unclassified lifecycle counter: {key}"))?;
        let count = count
            .as_u64()
            .ok_or_else(|| format!("invalid counter value: {key}"))?;
        if class == CounterClass::NonLayoutFailure && count != 0 {
            return Err(format!("non-layout lifecycle failure: {key}"));
        }
    }
    // Process Counts serializes EVERY registered key, including zeros. Unlike
    // CachePage's sparse map, a missing process key is not an observed zero.
    if !page {
        for (key, _) in LIFECYCLE_COUNTERS {
            if !counts.contains_key(*key) {
                return Err(format!("missing lifecycle counter: {key}"));
            }
        }
    }
    Ok(counts)
}

// The shared restore disposition moved off the process lifecycle registry.
// It remains an observation; it cannot witness or excuse a layout refusal.
const DURABLE_ALARM_OBSERVATIONS: &[(&str, CounterClass)] =
    &[("restored_behind_accepted", CounterClass::Observation)];

fn retention_witness(rows: &[Value]) -> Result<RetentionWitness, String> {
    for row in rows
        .iter()
        .filter(|row| row["record"]["stage"] == "durable_tail_alarm")
    {
        for (key, _) in DURABLE_ALARM_OBSERVATIONS {
            if let Some(outcomes) = row["record"]["counts"].get(key) {
                let outcomes = outcomes.as_object().ok_or("invalid restore observation")?;
                for (outcome, count) in outcomes {
                    if !matches!(outcome.as_str(), "held" | "published") || count.as_u64().is_none()
                    {
                        return Err("invalid restore observation outcome".into());
                    }
                }
            }
        }
    }
    let counts = &rows
        .iter()
        .rev()
        .find(|row| row["record"]["stage"] == "process_retained_cache_lifecycle_totals")
        .ok_or("actual lifecycle witness required")?["record"]["counts"];
    let counts = checked_counter_map(counts, false)?;
    let mut insert_admitted = counts["insert_admitted"]
        .as_u64()
        .ok_or("admission witness required")?;
    for row in rows
        .iter()
        .filter(|row| row["record"]["stage"] == "native_collection_page")
    {
        // CachePage is omitted entirely when empty; null/malformed is not empty.
        if let Some(page) = row["record"]["counts"].get("retained_cache_page_events") {
            let page = checked_counter_map(page, true)?;
            // Sparse omission means zero. Preserve a positive admission in
            // either carrier for the existing unsupported-layout zero gate.
            if let Some(count) = page.get("insert_admitted") {
                insert_admitted =
                    insert_admitted.max(count.as_u64().ok_or("admission count required")?);
            }
        }
    }
    // Overlapping process totals and page deltas are validated independently,
    // never added. Every positive lifecycle failure already returned Err.
    Ok(RetentionWitness {
        bound_refused: counts["retention_bound_refused"]
            .as_u64()
            .ok_or("layout witness required")?,
        insert_admitted,
        other_refusals: 0,
    })
}

fn refusal_count(value: &Value) -> u64 {
    match value {
        Value::Object(map) => map.values().map(refusal_count).sum(),
        Value::Array(values) => values.iter().map(refusal_count).sum(),
        _ => value.as_u64().expect("write refusal count required"),
    }
}

fn p0_diagnostics(rows: &[Value]) -> PlatformDiagnostics {
    let row = rows
        .iter()
        .find(|row| row["kind"] == "durable_after_save_diagnostics")
        .expect("actual P0 store diagnostics required");
    eprintln!("P0 durable_after_save={row}");
    assert_eq!(row["state_lock_held"], true);
    assert_eq!(row["store_initialized"], true);
    assert!(row.as_object().unwrap().contains_key("store_disabled"));
    assert_eq!(row["store_disabled"], Value::Null);
    assert!(matches!(
        row["inventory"].as_str(),
        Some("counted" | "directory_absent")
    ));
    let layout_supported = row["heap_layout_supported"]
        .as_bool()
        .expect("real layout diagnostic required");
    if !layout_supported {
        assert_eq!(row["platform_qualification"], PLATFORM_QUALIFICATION);
        eprintln!("{PLATFORM_QUALIFICATION}");
    }
    let records_after_p0 = row["records_after_save"]
        .as_u64()
        .expect("P0 inventory required");
    assert_eq!(totals(rows)["durable_records_after_save"], records_after_p0);
    let mut witness = retention_witness(rows).expect("classified P0 lifecycle witness");
    for field in [
        "not_persisted",
        "write_unlocked",
        "write_deferred",
        "budget_refused",
        "records_deferred",
        "store_write_skipped",
        "format_hold",
        "t14_rebuild",
        "records_invalidated",
    ] {
        witness.other_refusals += refusal_count(&row["write_counters"][field]);
    }
    PlatformDiagnostics {
        layout_supported,
        records_after_p0,
        p0: witness.clone(),
        page: witness,
        full: 0,
        tail: 0,
        full_causes: json!({}),
        restore_outcome: json!({}),
    }
}

fn growth_diagnostics(p0: &PlatformDiagnostics, rows: &[Value]) -> PlatformDiagnostics {
    let mut pages = rows
        .iter()
        .filter(|row| row["record"]["stage"] == "native_collection_page");
    let row = pages.next().expect("growth page required");
    assert!(
        pages.next().is_none(),
        "single-file fixture expects one page"
    );
    let counts = &row["record"]["counts"];
    let reads = &counts["sampled_acquisition"];
    let mut observed = p0.clone();
    observed.page = retention_witness(rows).expect("classified growth lifecycle witness");
    observed.full = reads["full_selections"]
        .as_u64()
        .expect("page Full count required");
    observed.tail = reads["tail_selections"]
        .as_u64()
        .expect("page Tail count required");
    observed.full_causes = reads["page_events"]["full_reasons"]
        .as_object()
        .expect("actual Full causes required")
        .clone()
        .into();
    observed.restore_outcome = counts["full_causes"]["restore_outcome"]
        .as_object()
        .expect("restore outcome required")
        .clone()
        .into();
    // P3's killed child has no fabricated totals; its completed page is proof.
    if let Some(total) = rows.iter().find(|row| row["kind"] == "pass_totals") {
        assert_eq!(total["full_reads"], observed.full);
        assert_eq!(total["tail_reads"], observed.tail);
    }
    observed
}

fn linux_witness() -> PlatformDiagnostics {
    let witness = RetentionWitness {
        bound_refused: 1,
        insert_admitted: 0,
        other_refusals: 0,
    };
    PlatformDiagnostics {
        layout_supported: false,
        records_after_p0: 0,
        p0: witness.clone(),
        page: witness,
        full: 1,
        tail: 0,
        full_causes: json!({"state_missing":1}),
        restore_outcome: json!({"miss":{"missing":1}}),
    }
}
#[test]
fn platform_gate_accepts_linux_only_with_the_layout_witness() {
    assert!(linux_witness().validate_growth().is_ok());
}
#[test]
fn platform_gate_rejects_a_different_full_cause() {
    let mut d = linux_witness();
    d.full_causes = json!({"audit_due":1});
    assert!(d.validate_growth().is_err());
}
#[test]
fn platform_gate_rejects_records_with_a_restore_miss() {
    let mut d = linux_witness();
    d.records_after_p0 = 1;
    assert!(d.validate_growth().is_err());
    d.layout_supported = true;
    d.full = 0;
    d.tail = 1;
    d.full_causes = json!({});
    assert!(d.validate_growth().is_err());
}

#[test]
fn platform_gate_rejects_non_layout_refusals() {
    let mut d = linux_witness();
    d.page.other_refusals = 1;
    assert!(d.validate_growth().is_err());
    d.page.other_refusals = 0;
    d.p0.other_refusals = 1;
    assert!(d.validate_growth().is_err());
}
#[test]
fn platform_gate_rejects_a_supported_layout_full() {
    let mut d = linux_witness();
    d.layout_supported = true;
    d.records_after_p0 = 1;
    d.tail = 1;
    d.full_causes = json!({});
    d.restore_outcome = json!({"restored":1});
    assert!(d.validate_growth().is_err());
}

#[test]
fn platform_gate_rejects_a_missing_layout_witness() {
    let mut d = linux_witness();
    d.page.bound_refused = 0;
    assert!(d.validate_growth().is_err());
    d.page.bound_refused = 1;
    d.p0.bound_refused = 0;
    assert!(d.validate_growth().is_err());
}
#[test]
fn platform_gate_accepts_supported_layout_restore_and_tail_only() {
    let mut d = linux_witness();
    d.layout_supported = true;
    d.records_after_p0 = 1;
    d.full = 0;
    d.tail = 1;
    d.full_causes = json!({});
    d.restore_outcome = json!({"restored":1});
    assert!(d.validate_growth().is_ok());
}

// No filesystem/process fixture: these exercise the JSON -> witness adapter,
// before PlatformDiagnostics can hide an omitted counter in other_refusals=0.
fn unsupported_lifecycle_rows() -> Vec<Value> {
    let mut counts = serde_json::Map::new();
    for (key, _) in LIFECYCLE_COUNTERS {
        counts.insert((*key).into(), json!(0));
    }
    counts.insert("retention_bound_refused".into(), json!(1));
    counts.insert("take_absent".into(), json!(1));
    counts.insert("copy_refusal_remeasured".into(), json!(2));
    counts.insert("clear_no_active".into(), json!(1));
    vec![
        json!({"kind":"local_resources", "record":{
            "stage":"process_retained_cache_lifecycle_totals", "counts":counts}}),
        json!({"kind":"local_resources", "record":{
            "stage":"native_collection_page", "counts":{
                "retained_cache_page_events":{
                    "retention_bound_refused":1, "take_absent":1,
                    "copy_refusal_remeasured":2, "clear_no_active":1}}}}),
    ]
}

fn extraction_gate(rows: &[Value]) -> Result<(), String> {
    let witness = retention_witness(rows)?;
    let mut diagnostics = linux_witness();
    diagnostics.p0 = witness.clone();
    diagnostics.page = witness;
    diagnostics.validate_growth().map_err(str::to_owned)
}

fn boundary_counts(rows: &mut [Value], page: bool) -> &mut serde_json::Map<String, Value> {
    let counts = if page {
        &mut rows[1]["record"]["counts"]["retained_cache_page_events"]
    } else {
        &mut rows[0]["record"]["counts"]
    };
    counts.as_object_mut().unwrap()
}

#[test]
fn lifecycle_extraction_accepts_valid_unsupported_rows() {
    assert!(extraction_gate(&unsupported_lifecycle_rows()).is_ok());
}

#[test]
fn lifecycle_extraction_rejects_clear_metadata_unsupported() {
    for page in [false, true] {
        let mut rows = unsupported_lifecycle_rows();
        boundary_counts(&mut rows, page).insert("clear_metadata_unsupported".into(), json!(1));
        assert_eq!(
            extraction_gate(&rows).unwrap_err(),
            "non-layout lifecycle failure: clear_metadata_unsupported"
        );
    }
}

#[test]
fn lifecycle_extraction_rejects_every_non_layout_failure() {
    for page in [false, true] {
        let extras = if page { PAGE_ONLY_COUNTERS } else { &[] };
        for (key, class) in LIFECYCLE_COUNTERS.iter().chain(extras) {
            if *class == CounterClass::NonLayoutFailure {
                let mut rows = unsupported_lifecycle_rows();
                boundary_counts(&mut rows, page).insert((*key).into(), json!(1));
                assert_eq!(
                    extraction_gate(&rows).unwrap_err(),
                    format!("non-layout lifecycle failure: {key}"),
                    "page={page}"
                );
            }
        }
    }
}

#[test]
fn lifecycle_extraction_keeps_every_ordinary_observation_neutral() {
    for page in [false, true] {
        let extras = if page { PAGE_ONLY_COUNTERS } else { &[] };
        for (key, class) in LIFECYCLE_COUNTERS.iter().chain(extras) {
            // insert_admitted is an observation, but the existing unsupported
            // layout gate independently requires zero admitted inserts.
            if *class == CounterClass::Observation && *key != "insert_admitted" {
                let mut rows = unsupported_lifecycle_rows();
                boundary_counts(&mut rows, page).insert((*key).into(), json!(1));
                assert!(extraction_gate(&rows).is_ok(), "key={key} page={page}");
            }
        }
    }
}

#[test]
fn lifecycle_extraction_preserves_admission_observations_for_the_gate() {
    for page in [false, true] {
        let mut rows = unsupported_lifecycle_rows();
        boundary_counts(&mut rows, page).insert("insert_admitted".into(), json!(1));
        assert!(
            retention_witness(&rows).is_ok(),
            "admission is an observation"
        );
        assert!(
            extraction_gate(&rows).is_err(),
            "unsupported layout still requires zero admissions"
        );
    }
}

#[test]
fn lifecycle_extraction_rejects_unknown_keys_even_when_zero() {
    for page in [false, true] {
        let mut rows = unsupported_lifecycle_rows();
        boundary_counts(&mut rows, page).insert("unclassified_counter".into(), json!(0));
        assert_eq!(
            extraction_gate(&rows).unwrap_err(),
            "unclassified lifecycle counter: unclassified_counter"
        );
    }
}

#[test]
fn lifecycle_extraction_rejects_missing_malformed_and_wrong_carrier_counts() {
    let mut rows = unsupported_lifecycle_rows();
    boundary_counts(&mut rows, false).remove("take_absent");
    assert_eq!(
        extraction_gate(&rows).unwrap_err(),
        "missing lifecycle counter: take_absent"
    );
    for page in [false, true] {
        let mut rows = unsupported_lifecycle_rows();
        boundary_counts(&mut rows, page).insert("take_absent".into(), Value::Null);
        assert_eq!(
            extraction_gate(&rows).unwrap_err(),
            "invalid counter value: take_absent"
        );
    }
    let mut rows = unsupported_lifecycle_rows();
    boundary_counts(&mut rows, false).insert("reinsert_failed".into(), json!(0));
    assert_eq!(
        extraction_gate(&rows).unwrap_err(),
        "unclassified lifecycle counter: reinsert_failed"
    );
    let mut rows = unsupported_lifecycle_rows();
    rows[1]["record"]["counts"]["retained_cache_page_events"] = Value::Null;
    assert_eq!(
        extraction_gate(&rows).unwrap_err(),
        "counter object required"
    );
}

#[test]
fn lifecycle_classification_covers_core_registry_and_page_schema() {
    // Intentional source-shape tripwire, not a parser implementation. These
    // public definitions enumerate the actual serialized counters. New keys
    // must fail even if zero-valued sparse keys never appear in this fixture.
    let registry = include_str!("../src/local_resource_diagnostics/cache_lifecycle.rs");
    assert_eq!(registry.matches("counters! {").count(), 1);
    let fields = registry
        .split_once("counters! {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    let registered: std::collections::BTreeSet<_> = fields
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("//"))
        .map(|line| {
            line.split_once(':')
                .expect("registry field definition")
                .0
                .trim()
        })
        .collect();
    let classified: std::collections::BTreeSet<_> =
        LIFECYCLE_COUNTERS.iter().map(|(key, _)| *key).collect();
    assert_eq!(
        classified.len(),
        LIFECYCLE_COUNTERS.len(),
        "duplicate classification"
    );
    assert_eq!(
        classified, registered,
        "classify every lifecycle schema change"
    );

    let source = include_str!("../src/local_resource_diagnostics/claude_reread.rs");
    let fields = source
        .split_once("pub(crate) struct CachePage {")
        .unwrap()
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    let mut registered: std::collections::BTreeSet<_> = fields
        .lines()
        .filter_map(|line| line.trim().strip_prefix("pub(crate) "))
        .map(|line| {
            line.split_once(':')
                .expect("page field definition")
                .0
                .trim()
        })
        .collect();
    assert!(
        registered.remove("events"),
        "CachePage must flatten lifecycle events"
    );
    let classified: std::collections::BTreeSet<_> =
        PAGE_ONLY_COUNTERS.iter().map(|(key, _)| *key).collect();
    assert_eq!(
        classified.len(),
        PAGE_ONLY_COUNTERS.len(),
        "duplicate page classification"
    );
    assert_eq!(
        classified, registered,
        "classify every page-only schema change"
    );
}

fn assert_quiet_restart(rows: &[Value]) {
    let counts = totals(rows);
    eprintln!("{} aggregate={counts}", counts["pass"].as_str().unwrap());
    assert_eq!(counts["full_reads"], 0);
    assert_eq!(counts["tail_reads"], 0);
    // Completed native plus guard bytes: also proves zero transcript body bytes.
    assert_eq!(counts["bytes_read"], 0);
    assert!(counts["index_reuse_skips"].as_u64().unwrap() > 0);
    // Null/unavailable never passes as an observed zero, nor does a missing read.
    for field in ["restore_attempts", "records_read", "bytes_read"] {
        assert_eq!(
            counts["durable_store_io"][field], 0,
            "quiet store I/O: {field}"
        );
    }
    assert!(!rows.iter().any(|row| row["kind"] == "session"));
}

#[test]
fn quiet_restart_reuses_index_without_touching_the_store() {
    let f = Fixture::new();
    f.run("P0");
    assert_quiet_restart(&f.run("P1"));
}

#[test]
fn independent_cold_uses_the_same_key_and_all_fifteen_money_fields() {
    // Separate processes, physical files and empty scratch directories. Copy
    // frozen bytes, including their transcript clock and workspace, verbatim.
    let chain = Fixture::new();
    let mut cold = Fixture::new();
    cold.key = chain.key.clone();
    cold.collected_at = chain.collected_at.clone();
    let chain_path = chain.root.join(format!("{SESSION}.jsonl"));
    let cold_path = cold.root.join(format!("{SESSION}.jsonl"));
    fs::copy(&chain_path, &cold_path).unwrap();
    use std::os::unix::fs::MetadataExt;
    assert_ne!(
        fs::metadata(chain_path).unwrap().ino(),
        fs::metadata(cold_path).unwrap().ino()
    );
    assert_eq!(fs::read_dir(&cold.support).unwrap().count(), 0);
    let before = chain.run("P0");
    let independent = cold.run("COLD");
    assert_eq!(totals(&independent)["pass"], "COLD");
    assert!(totals(&independent)["full_reads"].as_u64().unwrap() > 0);
    let before = session(&before);
    let independent = session(&independent);
    for field in [
        "blinded_session_hash",
        "source",
        "token_totals",
        "entity_count",
        "money_oracle",
        "money_oracle_encoding",
        "emitted_body_digest",
    ] {
        assert_eq!(before[field], independent[field], "COLD mismatch: {field}");
    }
    let fields = [
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_5m_tokens",
        "cache_creation_1h_tokens",
        "reasoning_output_tokens",
        "unattributed_total_tokens",
        "request_count",
        "cost",
        "usage_buckets",
        "model_usage",
        "removed_usage",
        "removed_request_count",
        "usage_accounting_contract",
        "telemetry_owned_complete",
    ];
    assert_eq!(
        independent["money_oracle"].as_object().unwrap().len(),
        fields.len()
    );
    for field in fields {
        assert_eq!(
            independent["money_oracle"][field].as_str().unwrap().len(),
            64,
            "missing {field}"
        );
    }
}

#[test]
fn cold_refuses_reused_scratch_without_mutating_it() {
    let f = Fixture::new();
    f.run("P0");
    let index = fs::read(f.support.join("P0.jsonl")).unwrap();
    let output = f.command("COLD").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!f.support.join("COLD.jsonl").exists());
    assert_eq!(fs::read(f.support.join("P0.jsonl")).unwrap(), index);
}

#[test]
fn supplied_key_controls_session_body_and_money_commitments() {
    let first = Fixture::new();
    let mut second = Fixture::new();
    second.collected_at = first.collected_at.clone();
    fs::copy(
        first.root.join(format!("{SESSION}.jsonl")),
        second.root.join(format!("{SESSION}.jsonl")),
    )
    .unwrap();
    fs::write(&second.key, [43; 32]).unwrap();
    let first = first.run("P0");
    let second = second.run("COLD");
    let first = session(&first);
    let second = session(&second);
    assert_eq!(first["token_totals"], second["token_totals"]);
    assert_ne!(
        first["blinded_session_hash"],
        second["blinded_session_hash"]
    );
    assert_ne!(first["emitted_body_digest"], second["emitted_body_digest"]);
    for (field, value) in first["money_oracle"].as_object().unwrap() {
        assert_ne!(
            value, &second["money_oracle"][field],
            "key ignored: {field}"
        );
    }
}

#[test]
fn emitted_collection_clock_remains_in_body_digest() {
    let first = Fixture::new();
    let mut second = Fixture::new();
    fs::copy(
        first.root.join(format!("{SESSION}.jsonl")),
        second.root.join(format!("{SESSION}.jsonl")),
    )
    .unwrap();
    second.key = first.key.clone();
    second.collected_at = (time::OffsetDateTime::parse(
        &first.collected_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
        + time::Duration::seconds(1))
    .format(&time::format_description::well_known::Rfc3339)
    .unwrap();
    let first = first.run("P0");
    let second = second.run("COLD");
    let first = session(&first);
    let second = session(&second);
    assert_eq!(
        first["blinded_session_hash"],
        second["blinded_session_hash"]
    );
    assert_eq!(first["money_oracle"], second["money_oracle"]);
    assert_ne!(first["emitted_body_digest"], second["emitted_body_digest"]);
}

#[test]
fn refuses_invalid_collection_clock_before_scratch_mutation() {
    let mut f = Fixture::new();
    f.collected_at = CANARY.into();
    f.refused(f.command("COLD"));
}

#[test]
fn refuses_missing_public_and_symlinked_blinding_keys() {
    let f = Fixture::new();
    let original = fs::read(&f.key).unwrap();
    fs::remove_file(&f.key).unwrap();
    f.refused(f.command("P0"));
    fs::write(&f.key, original).unwrap();
    fs::set_permissions(&f.key, fs::Permissions::from_mode(0o644)).unwrap();
    f.refused(f.command("P0"));
    let target = f.base.join("key-target");
    fs::rename(&f.key, &target).unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
    symlink(target, &f.key).unwrap();
    f.refused(f.command("P0"));
}

#[cfg(target_os = "linux")]
mod fifo_inputs {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    fn make_fifo(path: &Path) {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a valid NUL-terminated string for this call.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    fn refuse_promptly(f: &Fixture, mut command: Command) {
        let mut child = command
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                // Always kill and reap before failing, including on regression.
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("replay-harness blocked instead of refusing a FIFO input");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        f.assert_refused(&output);
        assert_eq!(output.stderr, b"replay-harness: isolation refused\n");
    }

    #[test]
    fn refuses_fifo_blinding_key_without_blocking() {
        let f = Fixture::new();
        fs::remove_file(&f.key).unwrap();
        make_fifo(&f.key);
        refuse_promptly(&f, f.command("P0"));
    }

    #[test]
    fn refuses_symlink_to_fifo_blinding_key_without_blocking() {
        let f = Fixture::new();
        let target = f.base.join("fifo-target");
        make_fifo(&target);
        fs::remove_file(&f.key).unwrap();
        symlink(target, &f.key).unwrap();
        refuse_promptly(&f, f.command("P0"));
    }
}

#[test]
fn refuses_mismatched_or_missing_scratch_support() {
    let f = Fixture::new();
    let mut command = f.command("P0");
    command.env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &f.clone);
    f.refused(command);
    let mut command = f.command("P0");
    command.env_remove("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR");
    f.refused(command);
}
#[test]
fn refuses_existing_daemon_state() {
    let f = Fixture::new();
    fs::write(f.support.join("account.json"), "{}").unwrap();
    f.refused(f.command("P0"));
}
#[test]
fn refuses_root_outside_clone_and_nested_symlink() {
    let f = Fixture::new();
    f.manifest(json!({"claude":[f.support],"codex":[],"pi":[]}));
    f.refused(f.command("P0"));
    f.manifest(json!({"claude":[f.clone.join("claude")],"codex":[],"pi":[]}));
    symlink(&f.support, f.root.join("escape")).unwrap();
    f.refused(f.command("P0"));
}
#[test]
fn refuses_external_api_and_unowned_loopback() {
    let f = Fixture::new();
    for url in ["https://example.invalid", "http://127.0.0.1:1"] {
        let mut command = f.command("P0");
        command.env("OTTTO_API_BASE_URL", url);
        f.refused(command);
    }
}
#[test]
fn refuses_missing_and_external_secret_fallback() {
    let f = Fixture::new();
    let mut command = f.command("P0");
    command.env_remove("OTTTO_SERVICE_SECRET_FALLBACK_DIR");
    f.refused(command);
    let mut command = f.command("P0");
    command.env("OTTTO_SERVICE_SECRET_FALLBACK_DIR", &f.clone);
    f.refused(command);
}
#[test]
fn synthetic_cold_quiet_growth_kill_and_restart() {
    let f = Fixture::new();
    let cold = f.run("P0");
    let platform = p0_diagnostics(&cold);
    platform.validate_p0().expect("P0 platform premise");
    eprintln!(
        "P0 platform premise PASS; layout_supported={}",
        platform.layout_supported
    );
    assert!(totals(&cold)["full_reads"].as_u64().unwrap() > 0);
    assert_eq!(session(&cold)["entity_count"], 1);
    assert_eq!(
        session(&cold)["blinded_session_hash"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    assert_eq!(
        session(&cold)["emitted_body_digest"]
            .as_str()
            .unwrap()
            .len(),
        64
    );
    let quiet = f.run("P1");
    assert_quiet_restart(&quiet);
    f.append(2, 20);
    let growth = f.run("P2");
    for row in &growth {
        if row["record"]["stage"] == "native_collection_page" {
            let causes = &row["record"]["counts"]["full_causes"];
            eprintln!(
                "P2 full_causes={causes} restore_outcome={}",
                causes["restore_outcome"]
            );
            eprintln!("P2 aggregate_page={}", row["record"]);
        }
    }
    let p2 = growth_diagnostics(&platform, &growth);
    p2.validate_growth()
        .expect("P2 platform-qualified acquisition");
    eprintln!(
        "P2 platform-qualified PASS full={} tail={}",
        p2.full, p2.tail
    );
    assert_eq!(
        session(&cold)["blinded_session_hash"],
        session(&growth)["blinded_session_hash"]
    );
    assert_ne!(
        session(&cold)["emitted_body_digest"],
        session(&growth)["emitted_body_digest"]
    );
    f.append(3, 30);
    let killed = f
        .command("P3")
        .args(["--kill-after-pages", "1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.signal(), Some(libc::SIGKILL));
    let before_restart = f.rows("P3");
    let p3 = growth_diagnostics(&platform, &before_restart);
    p3.validate_growth()
        .expect("P3 completed page platform-qualified acquisition");
    eprintln!(
        "P3 killed-page platform-qualified PASS full={} tail={}",
        p3.full, p3.tail
    );
    assert!(before_restart
        .iter()
        .any(|row| row["kind"] == "page_finished"));
    assert!(!before_restart
        .iter()
        .any(|row| row["kind"] == "pass_totals"));
    assert_eq!(
        session(&growth)["blinded_session_hash"],
        session(&before_restart)["blinded_session_hash"]
    );
    let restart = f.run("P3");
    // P3 output is append-only: keep the killed revision for the oracle, and
    // assert quiet restart against only the newly appended invocation rows.
    assert_eq!(&restart[..before_restart.len()], before_restart.as_slice());
    let restart = &restart[before_restart.len()..];
    assert_quiet_restart(restart);
    eprintln!("P3 restart PASS: quiet index reuse, zero acquisition/store reads");
    assert!(restart.iter().any(|row| row["kind"] == "local_resources"));
    // Independent fresh scratch uses the same production cycle over the final
    // synthetic transcript; cumulative money must equal the restarted chain.
    let mut fresh = Fixture::new();
    fresh.key = f.key.clone();
    fresh.collected_at = f.collected_at.clone();
    fs::copy(
        f.root.join(format!("{SESSION}.jsonl")),
        fresh.root.join(format!("{SESSION}.jsonl")),
    )
    .unwrap();
    let oracle = fresh.run("COLD");
    for field in [
        "blinded_session_hash",
        "source",
        "token_totals",
        "entity_count",
        "money_oracle",
        "money_oracle_encoding",
        "emitted_body_digest",
    ] {
        assert_eq!(
            session(&before_restart)[field],
            session(&oracle)[field],
            "COLD output field {field}"
        );
    }
    eprintln!("P3 chain-to-COLD OUTPUT equality PASS; no Linux restore qualification");
}
#[test]
fn command_is_hidden() {
    let output = Command::new(env!("CARGO_BIN_EXE_ottto-service"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!String::from_utf8(output.stdout)
        .unwrap()
        .contains("replay-harness"));
}

#[test]
fn refuses_live_support_even_with_matching_environment() {
    let f = Fixture::new();
    let home = f.base.join("fake-home");
    let live = home.join("Library/Application Support/Ottto");
    fs::create_dir_all(&live).unwrap();
    fs::set_permissions(&live, fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_ottto-service"))
        .args(["replay-harness", "--support-dir"])
        .arg(&live)
        .arg("--roots-manifest")
        .arg(f.clone.join("roots.json"))
        .args(["--pass", "P0", "--out"])
        .arg(live.join("P0.jsonl"))
        .arg("--blinding-key-file")
        .arg(&f.key)
        .arg("--collected-at")
        .arg(&f.collected_at)
        .env("HOME", &home)
        .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", &live)
        .env("OTTTO_SERVICE_SECRET_FALLBACK_DIR", &live)
        .env_remove("OTTTO_API_BASE_URL")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(fs::read_dir(live).unwrap().count(), 0);
}

#[test]
fn kill_after_first_source_leaves_second_source_for_restart() {
    let f = Fixture::new();
    let pi = f.clone.join("pi");
    fs::create_dir(&pi).unwrap();
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let header = json!({"type":"session", "id":"synthetic-pi-session", "timestamp":now});
    let usage = json!({"type":"message", "message":{"role":"assistant", "model":"gpt-5.4", "provider":"openai", "responseId":"fixture-response", "timestamp":now, "usage":{"input":12,"output":4,"cost":{"total":0.001}}}});
    fs::write(pi.join("synthetic.jsonl"), format!("{header}\n{usage}\n")).unwrap();
    f.manifest(json!({"claude":[f.clone.join("claude")], "codex":[], "pi":[pi]}));
    let killed = f
        .command("P3")
        .args(["--kill-after-pages", "1"])
        .output()
        .unwrap();
    assert_eq!(killed.status.signal(), Some(libc::SIGKILL));
    let partial = f.rows("P3");
    assert_eq!(
        partial
            .iter()
            .filter(|r| r["kind"] == "page_finished")
            .count(),
        1
    );
    assert!(!partial.iter().any(|r| r["source"] == "pi"));
    let resumed = f.run("P3");
    let pi = resumed
        .iter()
        .find(|r| r["kind"] == "session" && r["source"] == "pi")
        .expect("unprocessed source emitted after crash");
    assert_eq!(pi["token_totals"]["input_tokens"], 12);
    assert_eq!(totals(&resumed)["pages"], 2);
    // Pi has no store-counter view; mixed-source totals cannot claim zero I/O.
    assert!(totals(&resumed)["durable_store_io"].is_null());
}

#[test]
fn supplied_hold_back_inventory_is_validated_and_counted() {
    let f = Fixture::new();
    let inventory = f.clone.join("hold-back.json");
    fs::write(
        &inventory,
        json!({"files":[format!("claude/project/{SESSION}.jsonl")]}).to_string(),
    )
    .unwrap();
    let output = f
        .command("P0")
        .arg("--hold-back")
        .arg(inventory)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(f.rows("P0")[0]["held_files"], 1);
}

#[test]
fn refuses_physical_targets_of_live_provider_and_support_symlinks() {
    for provider in [".claude", "Library/Application Support/Ottto"] {
        let f = Fixture::new();
        let home = f.base.join("fake-home");
        let live = home.join(provider);
        fs::create_dir_all(live.parent().unwrap()).unwrap();
        let target = if provider == ".claude" {
            &f.clone
        } else {
            &f.support
        };
        symlink(target, &live).unwrap();
        let mut command = f.command("P0");
        command.env("HOME", &home);
        f.refused(command);
    }
}

#[test]
fn refuses_oversized_marker_and_blinding_key_without_allocating_them() {
    for name in [".replay-harness", "replay-blinding-key"] {
        let f = Fixture::new();
        fs::write(
            f.support.join(".replay-harness"),
            b"ottto isolated replay v1\n",
        )
        .unwrap();
        let path = if name == "replay-blinding-key" {
            f.key.clone()
        } else {
            f.support.join(name)
        };
        let file = fs::File::create(path).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        let output = f.command("P0").output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        f.assert_private(&output);
    }
}

#[test]
fn accepts_driver_supplied_home_and_provider_paths_inside_scratch() {
    let f = Fixture::new();
    // Establish the scratch marker first, so fixture directories can be added
    // without weakening admission of an unrelated nonempty support directory.
    f.run("P0");
    let home = f.support.join("driver-home");
    fs::create_dir(&home).unwrap();
    let output = f
        .command("P1")
        .env("HOME", &home)
        .env("CLAUDE_CONFIG_DIR", home.join(".claude"))
        .env("CODEX_HOME", home.join(".codex"))
        .env("PI_CODING_AGENT_DIR", home.join(".pi/agent"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(totals(&f.rows("P1"))["full_reads"], 0);
}
