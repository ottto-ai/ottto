// Ignored harness: restart restore ON vs OFF on a private copy of local
// transcripts and support state, through this module's fixture pipeline
// (real scan, durable store, enrich/finish, fake ACK). It never starts a
// daemon or a child process and never uploads. Inert unless both
// OTTTO_ON_PROOF_ARM (on|off|cold) and OTTTO_ON_PROOF_DIR are set. Output is
// counts only: never a path, session id or content.
//
// Layout under the copy dir, prepared outside the run: `manifest.tsv` lines
// `<source>\troot|index\t<path relative to run/>`; `t0/` and `t1/` hold two
// clone sets of every root; `run/` holds this arm's working roots and
// `run/support`, a support copy in its production layout (each index stays
// in its namespace dir beside its companion storage and durable store).
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    codex_evidence, money_oracle, native_cold, Mode, RouteResult,
};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

const WARM_CAP: usize = 12;
const GROWTH_PAGES: u64 = 6;

fn report(arm: &str, mut row: Value) {
    row["on_proof"] = json!(true);
    row["arm"] = json!(arm);
    println!("{row}");
}

fn footprint() -> Option<u64> {
    crate::local_resource_diagnostics::state_v2_memory().phys_footprint_bytes
}

/// The 10 ms phys_footprint sampler of the memory-classes harness (#1030).
fn peak<T>(f: impl FnOnce() -> T) -> (T, Option<u64>) {
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            let mut high = footprint();
            while !stop.load(AtomicOrdering::Acquire) {
                std::thread::sleep(std::time::Duration::from_millis(10));
                high = high.max(footprint());
            }
            high
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        stop.store(true, AtomicOrdering::Release);
        let high = sampler.join().expect("sampler failed");
        (
            result.unwrap_or_else(|e| std::panic::resume_unwind(e)),
            high,
        )
    })
}

/// Sums numbers in `add` into `into`, recursively; other values replace.
fn merge(into: &mut Value, add: &Value) {
    match (into, add) {
        (Value::Object(into), Value::Object(add)) => {
            for (key, value) in add {
                merge(into.entry(key.clone()).or_insert(Value::Null), value);
            }
        }
        // A carrier without a measurement (terminal rearm) keeps the counts.
        (_, Value::Null) => {}
        (Value::Number(into), Value::Number(add)) => {
            *into = (into.as_u64().unwrap_or(0) + add.as_u64().unwrap_or(0)).into();
        }
        (into, add) => *into = add.clone(),
    }
}

/// One source: its checkpoint, owner (process) and committed index.
struct Lane {
    source: SnapshotSource,
    roots: Vec<PathBuf>,
    disk: Disk,
    owner: E2ScanFixture,
    index: ScanIndex,
    /// Latest emitted body per entity, and Codex tier state for the oracle.
    bodies: BTreeMap<String, Value>,
    tier_replay: Value,
    /// Passes, then growth Full, Tail, read bytes and appended bytes.
    totals: [u64; 5],
}

impl Lane {
    /// One daemon pass: begin, scan, finish, upload with ACK, commit.
    fn pass(&mut self, c: &Corpus, run: &Path) -> Value {
        let (source, claude) = (self.source, self.source == SnapshotSource::ClaudeCode);
        let scope = crate::transcript_acquisition::Scope("on-proof".into());
        let capture = crate::snapshots::claude_request_identity::captures(source);
        let cache = self.owner.cache.clone();
        let policy = SnapshotUploadPolicy::default();
        crate::snapshots::begin_durable_pass(
            &cache,
            &self.disk.dir,
            source,
            &self.disk.index,
            false,
            &scope,
            capture,
            policy.session_attribution_labels_enabled,
        );
        let (c0, s0) = cache.durable_counters(source).unwrap_or_default();
        let roots: Vec<PathBuf> = self.roots.iter().map(|root| run.join(root)).collect();
        let mut index = std::mem::take(&mut self.index);
        index.activate_effective_upload_body_witness_revision(
            crate::snapshot_sync::effective_upload_body_witness_revision(source),
        );
        if claude {
            index.adopt_effective_upload_body_witness_revision_monotonically();
            index.load_claude_reemission_exclusions(&c.support);
        }
        let (((mut index, scan, wires), records), high) = peak(|| {
            crate::local_resource_diagnostics::capture(|| {
                let committed = claude.then(|| index.clone());
                let owned = crate::snapshots::OwnedSourceScan::new_with_durable_cache(
                    source,
                    &roots,
                    index,
                    // The cycle's real clock, in process (no `date` child).
                    &crate::backfill::now_rfc3339(),
                    crate::snapshot_sync::MAX_SNAPSHOT_STATUS_WINDOW_DAYS,
                    crate::snapshots::MAX_BACKFILL_FILES_PER_SOURCE,
                    false,
                    claude.then_some(c.support.as_path()),
                    &[],
                    false,
                    capture,
                    &[],
                    &cache,
                )
                .with_sampled_acquisition(cache.clone(), scope.clone());
                let (mut index, mut scan, modes, _) = native_cold::scan(owned, usize::MAX);
                if let Some(committed) = committed {
                    let mut page = Page {
                        cache: cache.clone(),
                        committed,
                        index,
                        scan,
                        modes,
                        disposition: Default::default(),
                        released: Default::default(),
                        unhealthy: Default::default(),
                    };
                    page.enrich(c);
                    page.finish();
                    let wires = if page.scan.snapshots.is_empty() {
                        Vec::new()
                    } else {
                        upload(&page.scan.snapshots, &mut e2_progress(), ack).1
                    };
                    return (page.index, page.scan, wires);
                }
                index.bind_session_accounts(
                    source,
                    "e2-synthetic-machine",
                    &mut scan.snapshots,
                    &[],
                );
                apply_upload_policy(source, &mut scan.snapshots, policy);
                finalize_scan_after_policy(source, &mut scan, &mut index);
                scan.finish_codex_capture_boundary(&mut index);
                let wires = scan
                    .snapshots
                    .chunks(crate::snapshot_sync::SNAPSHOT_BATCH_LIMIT)
                    .map(|chunk| {
                        let mut wire = request(chunk);
                        wire.source = source.api_slug().into();
                        validate_snapshot_batch_request(&wire).unwrap();
                        canonical(&wire)
                    })
                    .collect();
                (index, scan, wires)
            })
        });
        // Bodies the fake server ACKed, keyed by entity as the money oracle is.
        let sent: BTreeSet<String> = wires
            .iter()
            .flat_map(|wire| {
                let wire: Value = serde_json::from_slice(wire).unwrap();
                wire["snapshots"].as_array().cloned().unwrap_or_default()
            })
            .filter_map(|item| item["snapshot_fingerprint"].as_str().map(str::to_owned))
            .collect();
        let items: Vec<SnapshotItem> = scan
            .snapshots
            .iter()
            .filter(|item| sent.contains(&item.snapshot_fingerprint))
            .cloned()
            .collect();
        let emitted = items.len();
        self.bodies
            .extend(RouteResult::emitted(Mode::Restart, source, wires, &items).snapshots);
        index.record_accepted_snapshot_fingerprints(&sent);
        self.index = self.disk.commit(&cache, source, &mut index);
        drop(index);
        if source == SnapshotSource::Codex {
            self.tier_replay = codex_evidence(&self.index, &scan)["TierReplay"].take();
        }
        drop(scan);
        let steady = footprint();
        let (c1, s1) = cache.durable_counters(source).unwrap_or_default();
        let mut page = Value::Null;
        for record in &records {
            if record["stage"] == "native_collection_page" && record["source"] == source.api_slug()
            {
                merge(&mut page, &record["counts"]);
            }
        }
        let n = |value: &Value| value.as_u64().unwrap_or(0);
        let read = &page["sampled_acquisition"];
        let events = &read["page_events"];
        let delta = |a: &BTreeMap<&'static str, u64>, b: &BTreeMap<&'static str, u64>| {
            a.iter()
                .map(|(k, v)| (*k, v.saturating_sub(b.get(k).copied().unwrap_or(0))))
                .filter(|(_, v)| *v > 0)
                .collect::<BTreeMap<_, _>>()
        };
        let (ineligible, resource_full) = (
            delta(&c1.ineligible, &c0.ineligible),
            delta(&c1.resource_full, &c0.resource_full),
        );
        let behind = s1.format_hold[7].saturating_sub(s0.format_hold[7]);
        let (native, guard) = (
            n(&read["completed_native_bytes"]),
            n(&read["completed_guard_bytes"]),
        );
        let rederive = c1
            .rederive_head_bytes
            .saturating_sub(c0.rederive_head_bytes);
        let store_read = s1.bytes_read.saturating_sub(s0.bytes_read);
        let outcome = &page["full_causes"]["restore_outcome"];
        json!({
            "source": source.api_slug(),
            "full": n(&read["full_selections"]),
            "tail": n(&read["tail_selections"]),
            "unchanged": n(&read["unchanged_selections"]),
            "full_reasons": events["full_reasons"],
            "full_by_parse_reason": events["full_by_parse_reason"],
            "full_cause": events["full_cause"],
            "restore": {
                "restored": c1.restored.saturating_sub(c0.restored),
                "missing": c1.missing.saturating_sub(c0.missing),
                "behind": behind,
                "refused": c1.refused_record.saturating_sub(c0.refused_record).saturating_sub(behind),
                "entry_changed": ineligible.get("entry_changed").copied().unwrap_or(0),
                "selection_cleared": n(&outcome["miss"]["ineligible.selection_cleared"]),
                "cache_transit": resource_full.get("cache_transit").copied().unwrap_or(0),
                "active_restore_no_room": resource_full.get("active_restore_no_room").copied().unwrap_or(0),
                "page_outcome": outcome,
                "ineligible": ineligible,
                "resource_full": resource_full,
            },
            "read_bytes": native + guard + rederive + store_read,
            "native_bytes": native,
            "guard_bytes": guard,
            "rederive_head_bytes": rederive,
            "store_bytes_read": store_read,
            "store_budget_refused": s1.budget_refused.saturating_sub(s0.budget_refused),
            "memo_evicted": s1.memo_evicted.saturating_sub(s0.memo_evicted),
            "records_on_disk": s1.disk_records,
            "records_written": s1.records_written.saturating_sub(s0.records_written),
            "gc_records_deleted": s1.gc_records_deleted.saturating_sub(s0.gc_records_deleted),
            "not_persisted": delta(&c1.not_persisted, &c0.not_persisted),
            "emitted": emitted,
            "footprint_peak": high,
            "footprint_steady": steady,
        })
    }
}

/// One pass per source; true when every source read nothing (0 Full, 0 Tail).
fn round(
    arm: &str,
    phase: &str,
    pass: u64,
    lanes: &mut [Lane],
    c: &Corpus,
    appended: &[u64],
) -> bool {
    let mut quiet = true;
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut row = lane.pass(c, &c.base);
        let (full, tail) = (row["full"].as_u64().unwrap(), row["tail"].as_u64().unwrap());
        quiet &= full == 0 && tail == 0;
        lane.totals[0] += 1;
        if phase == "growth" {
            let read = row["read_bytes"].as_u64().unwrap();
            for (total, add) in lane.totals[1..]
                .iter_mut()
                .zip([full, tail, read, appended[i]])
            {
                *total += add;
            }
            row["appended_bytes"] = json!(appended[i]);
        }
        row["phase"] = json!(phase);
        row["pass"] = json!(pass);
        report(arm, row);
    }
    quiet
}

/// Latest emitted bodies per source, owner-only; read back by the cold arm.
fn save(dir: &Path, arm: &str, lanes: &[Lane]) {
    let saved: BTreeMap<_, _> = lanes
        .iter()
        .map(|l| {
            (
                l.source.api_slug(),
                json!({"bodies": l.bodies, "tier_replay": l.tier_replay}),
            )
        })
        .collect();
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(dir.join(format!("{arm}.json")))
        .unwrap();
    serde_json::to_writer(file, &saved).unwrap();
}

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        match entry.file_type() {
            Ok(kind) if kind.is_dir() => files(&entry.path(), out),
            Ok(kind) if kind.is_file() => out.push(entry.path()),
            _ => {}
        }
    }
}

fn is_prefix(t0: &Path, t1: &Path) -> bool {
    let (mut a, mut b) = (
        std::fs::File::open(t0).unwrap(),
        std::fs::File::open(t1).unwrap(),
    );
    let (mut x, mut y) = (vec![0; 1 << 20], vec![0; 1 << 20]);
    loop {
        let len = a.read(&mut x).unwrap();
        if len == 0 {
            return true;
        }
        if b.read_exact(&mut y[..len]).is_err() || x[..len] != y[..len] {
            return false;
        }
    }
}

/// T1 minus T0: appendable (T0 is a byte prefix of T1) and new files as
/// (lane, T1 file, run file, first byte, end), and rewritten files.
struct Growth {
    appends: Vec<(usize, PathBuf, PathBuf, u64, u64)>,
    rewritten: Vec<(usize, PathBuf, PathBuf)>,
}
impl Growth {
    fn plan(dir: &Path, arm: &str, lanes: &[Lane]) -> Self {
        let mut growth = Self {
            appends: Vec::new(),
            rewritten: Vec::new(),
        };
        for (i, lane) in lanes.iter().enumerate() {
            let mut counts = [0u64; 4]; // grown, new, rewritten, unchanged
            for root in &lane.roots {
                let mut found = Vec::new();
                files(&dir.join("t1").join(root), &mut found);
                for t1 in found {
                    let relative = t1.strip_prefix(dir.join("t1")).unwrap();
                    let (t0, run) = (
                        dir.join("t0").join(relative),
                        dir.join("run").join(relative),
                    );
                    let end = std::fs::metadata(&t1).unwrap().len();
                    let start = std::fs::metadata(&t0).ok().map(|m| m.len());
                    match start {
                        Some(len) if len == end && is_prefix(&t0, &t1) => counts[3] += 1,
                        Some(len) if len < end && is_prefix(&t0, &t1) => {
                            counts[0] += 1;
                            growth.appends.push((i, t1, run, len, end));
                        }
                        Some(_) => {
                            counts[2] += 1;
                            growth.rewritten.push((i, t1, run));
                        }
                        None => {
                            counts[1] += 1;
                            growth.appends.push((i, t1, run, 0, end));
                        }
                    }
                }
            }
            report(
                arm,
                json!({"phase": "growth_plan", "source": lane.source.api_slug(),
                "grown": counts[0], "new": counts[1], "rewritten": counts[2], "unchanged": counts[3]}),
            );
        }
        growth
    }

    /// Delivers slice `page` of GROWTH_PAGES, cut at line ends; returns the
    /// bytes delivered per lane. Rewritten files are replaced on page 1.
    fn apply(&self, page: u64, lanes: usize) -> Vec<u64> {
        let mut delivered = vec![0; lanes];
        if page == 1 {
            for (i, t1, run) in &self.rewritten {
                delivered[*i] += std::fs::copy(t1, run).unwrap();
            }
        }
        for (i, t1, run, start, end) in &self.appends {
            let have = std::fs::metadata(run).map_or(0, |m| m.len());
            let mut source = std::fs::File::open(t1).unwrap();
            let mut cut = *end;
            if page < GROWTH_PAGES {
                let target = start + (end - start) * page / GROWTH_PAGES;
                source.seek(SeekFrom::Start(target)).unwrap();
                let mut line = Vec::new();
                cut = target
                    + std::io::BufReader::new(&source)
                        .read_until(b'\n', &mut line)
                        .unwrap() as u64;
            }
            if cut <= have {
                continue;
            }
            std::fs::create_dir_all(run.parent().unwrap()).unwrap();
            let mut out = std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .mode(0o600)
                .open(run)
                .unwrap();
            source.seek(SeekFrom::Start(have)).unwrap();
            delivered[*i] += std::io::copy(&mut source.take(cut - have), &mut out).unwrap();
        }
        delivered
    }
}

/// Cold Full over T1 against each saved arm, per source. Panic text (entity
/// ids) stays suppressed; only the verdict and counts print.
fn oracle(dir: &Path, lanes: &[Lane]) {
    for against in ["on", "off"] {
        let Ok(bytes) = std::fs::read(dir.join(format!("{against}.json"))) else {
            continue;
        };
        let saved: Value = serde_json::from_slice(&bytes).unwrap();
        for lane in lanes {
            let slug = lane.source.api_slug();
            // Money fields only: whole bodies also carry each pass's clock.
            let money = |bodies: &BTreeMap<String, Value>| {
                bodies
                    .iter()
                    .map(|(id, b)| {
                        let fields = money_oracle::FIELDS.iter().map(|f| (*f, b[*f].clone()));
                        (id.clone(), fields.collect::<BTreeMap<_, _>>())
                    })
                    .collect::<BTreeMap<_, _>>()
            };
            let route = |mode, bodies: BTreeMap<String, Value>, tier: &Value| {
                let mut route = RouteResult::emitted(mode, lane.source, Vec::new(), &[]);
                route.normalized = json!(money(&bodies));
                if lane.source == SnapshotSource::Codex {
                    // The shape of `codex_evidence`'s token_count, from merged bodies.
                    let tokens = |b: &Value| {
                        ["input_tokens", "output_tokens", "cache_read_tokens"]
                            .into_iter()
                            .chain(["reasoning_output_tokens", "request_count"])
                            .map(|f| b[f].clone())
                            .collect::<Vec<_>>()
                    };
                    route.codex_evidence = json!({"TierReplay": tier, "token_count":
                        bodies.iter().map(|(id, b)| (id.clone(), tokens(b))).collect::<BTreeMap<_, _>>()});
                }
                route.snapshots = bodies;
                route
            };
            let cold = route(Mode::ColdFull, lane.bodies.clone(), &lane.tier_replay);
            let bodies = serde_json::from_value(saved[slug]["bodies"].clone()).unwrap_or_default();
            let other = route(Mode::Restart, bodies, &saved[slug]["tier_replay"]);
            let equivalent = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                money_oracle::assert_equivalent(&cold, &other)
            }))
            .is_ok();
            let entities: BTreeSet<_> = cold
                .snapshots
                .keys()
                .chain(other.snapshots.keys())
                .collect();
            let (a, b) = (money(&cold.snapshots), money(&other.snapshots));
            let differences = entities
                .iter()
                .filter(|id| a.get(**id) != b.get(**id))
                .count();
            report(
                "cold",
                json!({"phase": "oracle", "against": against, "source": slug,
                "entities": entities.len(), "equivalent": equivalent, "differences": differences}),
            );
        }
    }
}

fn run(arm: &str, dir: &Path) {
    let _switch = if arm == "on" {
        crate::snapshots::RestartRestoreForTest::enabled()
    } else {
        crate::snapshots::RestartRestoreForTest::disabled()
    };
    let base = dir.join("run");
    // Never dropped: Corpus's destructor would delete the copy.
    let c = std::mem::ManuallyDrop::new(Corpus {
        support: base.join("support"),
        root: base.clone(),
        base,
        births: BTreeMap::new(),
    });
    let manifest = std::fs::read_to_string(dir.join("manifest.tsv")).unwrap();
    let entries: Vec<Vec<&str>> = manifest.lines().map(|l| l.split('\t').collect()).collect();
    // The daemon's single-writer lock on the support dir covers every index.
    crate::locked_state_dir::test_locks::hold(&c.support);
    let mut lanes = Vec::new();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let pick = |kind: &str| {
            entries
                .iter()
                .filter(|e| e.len() == 3 && e[0] == source.api_slug() && e[1] == kind)
                .map(|e| PathBuf::from(e[2]))
                .collect::<Vec<_>>()
        };
        let Some(index) = pick("index").pop().map(|index| c.base.join(index)) else {
            continue;
        };
        let state = index.parent().unwrap().to_path_buf();
        lanes.push(Lane {
            source,
            roots: pick("root"),
            owner: E2ScanFixture::default(),
            index: ScanIndex::load(&index).unwrap(),
            disk: Disk { dir: state, index },
            bodies: BTreeMap::new(),
            tier_replay: Value::Null,
            totals: [0; 5],
        });
    }
    report(
        arm,
        json!({"phase": "load", "sources": lanes.len(), "footprint_floor": footprint()}),
    );
    let phase = if arm == "cold" { "cold" } else { "warm" };
    for pass in 1..=WARM_CAP as u64 {
        let quiet = round(arm, phase, pass, &mut lanes, &c, &[]);
        save(dir, arm, &lanes);
        if quiet {
            break;
        }
    }
    if arm == "cold" {
        oracle(dir, &lanes);
    } else {
        // A restart: a new owner with an empty cache over the same committed
        // checkpoint and store, which keep their production path and binding.
        let restart = |lanes: &mut [Lane]| {
            for lane in lanes {
                lane.owner = E2ScanFixture::default();
            }
        };
        restart(&mut lanes);
        round(arm, "restart", 1, &mut lanes, &c, &[]);
        let growth = Growth::plan(dir, arm, &lanes);
        for page in 1..=GROWTH_PAGES {
            if page == GROWTH_PAGES.div_ceil(2) + 1 {
                restart(&mut lanes);
            }
            let delivered = growth.apply(page, lanes.len());
            round(arm, "growth", page, &mut lanes, &c, &delivered);
            save(dir, arm, &lanes);
        }
    }
    for lane in &lanes {
        let [passes, full, tail, read, appended] = lane.totals;
        report(
            arm,
            json!({"phase": "totals", "source": lane.source.api_slug(), "passes": passes,
            "growth_full": full, "growth_tail": tail, "growth_read_bytes": read,
            "appended_bytes": appended, "read_over_appended": read as f64 / appended.max(1) as f64,
            "entities": lane.bodies.len()}),
        );
    }
}

/// [behaviour] On-demand ON vs OFF evidence on a private real-data copy;
/// ignored and inert without its env. Run one arm per invocation, alone:
/// --ignored --exact --test-threads=1.
#[test]
#[ignore = "on-demand restart-restore measurement on a private copy"]
fn restart_restore_real_copy() {
    let (Ok(arm), Some(dir)) = (
        std::env::var("OTTTO_ON_PROOF_ARM"),
        std::env::var_os("OTTTO_ON_PROOF_DIR"),
    ) else {
        return;
    };
    if !["on", "off", "cold"].contains(&arm.as_str()) {
        return;
    }
    // Panic text can name paths or entities: print a count instead.
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let result = std::panic::catch_unwind(|| run(&arm, Path::new(&dir)));
    std::panic::set_hook(hook);
    if result.is_err() {
        report(&arm, json!({"failures": 1}));
        panic!("on-proof arm failed");
    }
}
