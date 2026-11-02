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
// `otel-t0/local-otel` and `otel-t1/local-otel` are the telemetry copies taken
// with each root set: warm, restart and growth see T0's, the drain and cold
// see T1's, so a growth page never sees telemetry newer than its transcripts.
use super::*;
use crate::snapshots::sampled_scan::transition_fixture::{
    codex_evidence, money_oracle, native_cold, Mode, RouteResult,
};
use serde_json::{json, Value};
use std::io::{BufRead, Read, Seek, SeekFrom};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

/// Warm and cold run until a pass reads nothing (0 Full, 0 Tail); a fresh
/// index needs its first Full plus the identity contract's one re-read.
const WARM_CAP: usize = 24;
const GROWTH_PAGES: u64 = 6;
/// After the last growth page, passes until one reads nothing, so every
/// grown file is read once more before the oracle (as the next cycles would).
const DRAIN_CAP: u64 = 12;

/// Installs telemetry copy `which` (`t0` or `t1`) as the run's `local-otel`;
/// without that copy the support copy's own telemetry stays. Counts only.
fn telemetry(arm: &str, dir: &Path, support: &Path, which: &str) {
    let from = dir.join(format!("otel-{which}")).join("local-otel");
    let mut found = Vec::new();
    files(&from, &mut found);
    if found.is_empty() {
        report(arm, json!({"phase": "telemetry", "which": "support"}));
        return;
    }
    let to = support.join("local-otel");
    let _ = std::fs::remove_dir_all(&to);
    for file in &found {
        let target = to.join(file.strip_prefix(&from).unwrap());
        std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700)
            .create(target.parent().unwrap())
            .unwrap();
        std::fs::copy(file, &target).unwrap();
    }
    report(
        arm,
        json!({"phase": "telemetry", "which": which, "files": found.len()}),
    );
}

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
    /// Passes, then growth Full, Tail, read bytes and appended bytes, then
    /// drain Full, Tail and read bytes.
    totals: [u64; 8],
}

impl Lane {
    /// One daemon pass: begin, scan, finish, upload with ACK, settle, commit.
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
        let (((mut index, scan, wires, rejected, upload_failed), records), high) = peak(|| {
            crate::local_resource_diagnostics::capture(|| {
                // The page's prior: settlement reads it as production does.
                let committed = index.clone();
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
                if claude {
                    let mut page = Page {
                        cache: cache.clone(),
                        committed,
                        index,
                        scan,
                        modes,
                        disposition: Default::default(),
                        released: Default::default(),
                        unhealthy: Default::default(),
                        stats: Default::default(),
                        // Finish runs before this harness uploads; the exact
                        // ACKs are accepted after settlement, as the service does.
                        delivered: None,
                    };
                    page.enrich(c);
                    let holds = page.finish();
                    let mut progress = e2_progress();
                    let (wires, rejected, failed) = send(&page.scan.snapshots, &mut progress);
                    if failed {
                        // The daemon fails this cycle after a partial
                        // checkpoint; keeping the prior index is stricter
                        // (the next pass retries all of it) and is counted.
                        return (page.committed, page.scan, wires, rejected, true);
                    }
                    // The Completed settlement, then the upload ledger fold.
                    let mut index =
                        settle_completed_upload(page.index, &page.committed, &progress, &holds)
                            .index;
                    settle_index_after_upload(&mut index, &page.committed, &progress);
                    crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
                        &mut index,
                        &page.scan.snapshots,
                        &progress.fresh_context_body_acks,
                    );
                    return (index, page.scan, wires, rejected, failed);
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
                let mut progress = SnapshotUploadProgress::new(
                    format!("{:064x}", 99),
                    snapshot_quarantine_witness(source),
                );
                let mut rejected = 0;
                let wires: Vec<Vec<u8>> = scan
                    .snapshots
                    .chunks(crate::snapshot_sync::SNAPSHOT_BATCH_LIMIT)
                    .filter_map(|chunk| {
                        let mut wire = request(chunk);
                        wire.source = source.api_slug().into();
                        if validate_snapshot_batch_request(&wire).is_err() {
                            rejected += chunk.len();
                            return None;
                        }
                        progress
                            .accepted_fingerprints
                            .extend(chunk.iter().map(|item| item.snapshot_fingerprint.clone()));
                        progress
                            .fresh_context_body_acks
                            .extend(chunk.iter().map(|item| {
                                (
                                    item.snapshot_fingerprint.clone(),
                                    snapshot_upload_body_witness(item),
                                )
                            }));
                        Some(canonical(&wire))
                    })
                    .collect();
                if rejected > 0 {
                    // As above: a failed cycle keeps the prior index.
                    return (committed, scan, wires, rejected, true);
                }
                // Production folds the ACKs into the index after every upload
                // outcome; this clears settled Codex capture facts, without
                // which those files re-parse (`codex_capture`) every pass.
                settle_index_after_upload(&mut index, &committed, &progress);
                crate::snapshots::e2_pipeline_scan_fixture::accept_upload_context_acks_for_test(
                    &mut index,
                    &scan.snapshots,
                    &progress.fresh_context_body_acks,
                );
                (index, scan, wires, rejected, false)
            })
        });
        // Bodies the fake server ACKed, keyed by entity as the money oracle
        // is. Production upload coalesces items that share a fingerprint
        // (first offer wins), so the wire, not the item list, is the emission.
        let wire_items: Vec<Value> = wires
            .iter()
            .flat_map(|wire| {
                let mut wire: Value = serde_json::from_slice(wire).unwrap();
                match wire["snapshots"].take() {
                    Value::Array(items) => items,
                    _ => Vec::new(),
                }
            })
            .collect();
        let sent: BTreeSet<&str> = wire_items
            .iter()
            .filter_map(|item| item["snapshot_fingerprint"].as_str())
            .collect();
        let coalesced = scan
            .snapshots
            .iter()
            .filter(|item| sent.contains(item.snapshot_fingerprint.as_str()))
            .count()
            .saturating_sub(sent.len());
        let mut entities = BTreeSet::new();
        let mut duplicate_entities = 0;
        for item in &wire_items {
            let entity = item["source_session_id"].as_str().unwrap_or_default();
            duplicate_entities += usize::from(!entities.insert(entity.to_owned()));
            self.bodies.insert(entity.to_owned(), item.clone());
        }
        let emitted = wire_items.len();
        drop(wire_items);
        self.index = self.disk.commit(&cache, source, &mut index);
        drop(index);
        if source == SnapshotSource::Codex {
            self.tier_replay = codex_evidence(&self.index, &scan)["TierReplay"].take();
        }
        drop(scan);
        let steady = footprint();
        let (c1, s1) = cache.durable_counters(source).unwrap_or_default();
        let mut page = Value::Null;
        let mut alarms = json!({});
        for record in &records {
            if record["source"] != source.api_slug() {
                continue;
            }
            match record["stage"].as_str() {
                Some("native_collection_page") => merge(&mut page, &record["counts"]),
                // Restore-path alarms, e.g. a restored graph whose prepare
                // was refused (`returned_original_full.<reason>`).
                Some(stage) if stage.starts_with("durable_tail") => merge(
                    alarms
                        .as_object_mut()
                        .unwrap()
                        .entry(stage)
                        .or_insert(Value::Null),
                    &record["counts"],
                ),
                _ => {}
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
            // prepare_started/prepare_failed, including restored graphs.
            "acquisition_admission": read["acquisition_admission"],
            "alarms": alarms,
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
            "coalesced_duplicates": coalesced,
            "duplicate_entities": duplicate_entities,
            "preflight_rejected": rejected,
            "upload_failed": upload_failed,
            "footprint_peak": high,
            "footprint_steady": steady,
        })
    }
}

/// The fixture `upload` through the production resumable uploader and the
/// fake ACK, except that a batch failing wire preflight is refused as the
/// daemon refuses it (an error, counted) instead of panicking the arm.
fn send(
    items: &[SnapshotItem],
    progress: &mut SnapshotUploadProgress,
) -> (Vec<Vec<u8>>, usize, bool) {
    let (mut wires, mut rejected, mut accepted) = (Vec::new(), 0, 0);
    if items.is_empty() {
        return (wires, rejected, false);
    }
    let result = upload_resumable_batches_with_literal_families(
        items,
        &unique_poison_scope(),
        progress,
        &mut accepted,
        |s| s.snapshot_fingerprint.as_str(),
        snapshot_upload_body_witness,
        |s| Some(s.source_session_id.as_str()),
        |_| false,
        crate::snapshots::claude_request_money::request_owned_family_root,
        &mut InplaceRetryBudget::default(),
        |batch| {
            let wire = request(&batch);
            if let Err(reason) = validate_snapshot_batch_request(&wire) {
                rejected += batch.len();
                return Err(anyhow::Error::new(SnapshotBatchPreflightRejected {
                    reason,
                }));
            }
            wires.push(canonical(&wire));
            let owned = batch.iter().map(|s| (*s).clone()).collect::<Vec<_>>();
            let response = ack(&owned)?;
            response.validate_entity_ack(&wire)?;
            Ok(response)
        },
        |_| Ok(()),
    );
    (wires, rejected, result.is_err())
}

/// One pass per source; true when every source read nothing (0 Full, 0 Tail).
fn round(
    arm: &str,
    phase: &str,
    pass: u64,
    lanes: &mut [Lane],
    c: &Corpus,
    appended: &[u64],
    held: &[u64],
) -> bool {
    let mut quiet = true;
    crate::on_proof::next_pass();
    for (i, lane) in lanes.iter_mut().enumerate() {
        let mut row = lane.pass(c, &c.base);
        // Per-class holds/serves and completed-read buckets of this lane pass.
        row["proof"] = crate::on_proof::row();
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
            row["partial_line_bytes_held"] = json!(held[i]);
        } else if phase == "drain" {
            let read = row["read_bytes"].as_u64().unwrap();
            for (total, add) in lane.totals[5..].iter_mut().zip([full, tail, read]) {
                *total += add;
            }
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

/// The end of the last complete line in `[start, cut)`, or `start`: growth
/// never delivers a partial last line, which a writer may still be finishing.
fn line_end(file: &mut std::fs::File, start: u64, cut: u64) -> u64 {
    let mut buf = vec![0; 1 << 16];
    let mut end = cut;
    while end > start {
        let len = (end - start).min(buf.len() as u64);
        file.seek(SeekFrom::Start(end - len)).unwrap();
        file.read_exact(&mut buf[..len as usize]).unwrap();
        if let Some(i) = buf[..len as usize].iter().rposition(|b| *b == b'\n') {
            return end - len + i as u64 + 1;
        }
        end -= len;
    }
    start
}

/// T1 minus T0: appendable (T0 is a byte prefix of T1) and new files as
/// (lane, T1 file, run file, first byte, end), rewritten files, and files
/// T1 no longer has (removed from the run on page 1, as T1 shows them).
struct Growth {
    appends: Vec<(usize, PathBuf, PathBuf, u64, u64)>,
    rewritten: Vec<(usize, PathBuf, PathBuf)>,
    removed: Vec<PathBuf>,
}
impl Growth {
    fn plan(dir: &Path, arm: &str, lanes: &[Lane]) -> Self {
        let mut growth = Self {
            appends: Vec::new(),
            rewritten: Vec::new(),
            removed: Vec::new(),
        };
        for (i, lane) in lanes.iter().enumerate() {
            let mut counts = [0u64; 5]; // grown, new, rewritten, unchanged, removed
            for root in &lane.roots {
                let mut before = Vec::new();
                files(&dir.join("t0").join(root), &mut before);
                for t0 in before {
                    let relative = t0.strip_prefix(dir.join("t0")).unwrap();
                    if !dir.join("t1").join(relative).exists() {
                        counts[4] += 1;
                        growth.removed.push(dir.join("run").join(relative));
                    }
                }
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
                "grown": counts[0], "new": counts[1], "rewritten": counts[2], "unchanged": counts[3],
                "removed": counts[4]}),
            );
        }
        growth
    }

    /// Delivers slice `page` of GROWTH_PAGES, cut at line ends; returns the
    /// bytes delivered per lane, and on the last page the partial-line bytes
    /// held back. Rewritten files are replaced, removed ones deleted, on page 1.
    fn apply(&self, page: u64, lanes: usize) -> (Vec<u64>, Vec<u64>) {
        let (mut delivered, mut held) = (vec![0; lanes], vec![0; lanes]);
        if page == 1 {
            for (i, t1, run) in &self.rewritten {
                delivered[*i] += std::fs::copy(t1, run).unwrap();
            }
            for run in &self.removed {
                std::fs::remove_file(run).unwrap();
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
            // read_until stops at EOF without a newline: cut back to the
            // last complete line, on every page.
            cut = line_end(&mut source, *start, cut);
            if page == GROWTH_PAGES {
                held[*i] += end - cut;
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
        (delivered, held)
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
            // Compare the entities both runs emitted; count the rest.
            let saved_bodies: BTreeMap<String, Value> =
                serde_json::from_value(saved[slug]["bodies"].clone()).unwrap_or_default();
            let common = |from: &BTreeMap<String, Value>, other: &BTreeMap<String, Value>| {
                from.iter()
                    .filter(|(id, _)| other.contains_key(*id))
                    .map(|(id, b)| (id.clone(), b.clone()))
                    .collect::<BTreeMap<_, _>>()
            };
            let only_cold = lane
                .bodies
                .keys()
                .filter(|id| !saved_bodies.contains_key(*id))
                .count();
            let only_arm = saved_bodies
                .keys()
                .filter(|id| !lane.bodies.contains_key(*id))
                .count();
            let cold = route(
                Mode::ColdFull,
                common(&lane.bodies, &saved_bodies),
                &lane.tier_replay,
            );
            let other = route(
                Mode::Restart,
                common(&saved_bodies, &lane.bodies),
                &saved[slug]["tier_replay"],
            );
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
                "entities": entities.len(), "only_cold": only_cold, "only_arm": only_arm,
                "equivalent": equivalent, "differences": differences}),
            );
        }
    }
}

fn run(arm: &str, dir: &Path) {
    crate::on_proof::enable();
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
        // A fresh support copy has no index yet: the daemon's first start.
        std::os::unix::fs::DirBuilderExt::mode(std::fs::DirBuilder::new().recursive(true), 0o700)
            .create(&state)
            .unwrap();
        lanes.push(Lane {
            source,
            roots: pick("root"),
            owner: E2ScanFixture::default(),
            index: ScanIndex::load(&index).unwrap(),
            disk: Disk { dir: state, index },
            bodies: BTreeMap::new(),
            tier_replay: Value::Null,
            totals: [0; 8],
        });
    }
    report(
        arm,
        json!({"phase": "load", "sources": lanes.len(), "footprint_floor": footprint()}),
    );
    telemetry(
        arm,
        dir,
        &c.support,
        if arm == "cold" { "t1" } else { "t0" },
    );
    let phase = if arm == "cold" { "cold" } else { "warm" };
    let mut quiet_at = None;
    for pass in 1..=WARM_CAP as u64 {
        let quiet = round(arm, phase, pass, &mut lanes, &c, &[], &[]);
        save(dir, arm, &lanes);
        if quiet {
            quiet_at = Some(pass);
            break;
        }
    }
    report(
        arm,
        json!({"phase": format!("{phase}_quiet"), "quiet_at_pass": quiet_at, "cap": WARM_CAP}),
    );
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
        round(arm, "restart", 1, &mut lanes, &c, &[], &[]);
        let growth = Growth::plan(dir, arm, &lanes);
        for page in 1..=GROWTH_PAGES {
            if page == GROWTH_PAGES.div_ceil(2) + 1 {
                restart(&mut lanes);
            }
            let (delivered, held) = growth.apply(page, lanes.len());
            round(arm, "growth", page, &mut lanes, &c, &delivered, &held);
            save(dir, arm, &lanes);
        }
        // T1 telemetry now matches the delivered transcripts; drain until a
        // pass reads nothing, so the oracle sees what later cycles converge to.
        telemetry(arm, dir, &c.support, "t1");
        let mut drain_quiet_at = None;
        for pass in 1..=DRAIN_CAP {
            let quiet = round(arm, "drain", pass, &mut lanes, &c, &[], &[]);
            save(dir, arm, &lanes);
            if quiet {
                drain_quiet_at = Some(pass);
                break;
            }
        }
        report(
            arm,
            json!({"phase": "drain_quiet", "drain_quiet_at_pass": drain_quiet_at, "cap": DRAIN_CAP}),
        );
    }
    report(
        arm,
        json!({"phase": "proof_end", "proof": crate::on_proof::end()}),
    );
    for lane in &lanes {
        let [passes, full, tail, read, appended, drain_full, drain_tail, drain_read] = lane.totals;
        report(
            arm,
            json!({"phase": "totals", "source": lane.source.api_slug(), "passes": passes,
            "growth_full": full, "growth_tail": tail, "growth_read_bytes": read,
            "appended_bytes": appended, "read_over_appended": read as f64 / appended.max(1) as f64,
            "drain_full": drain_full, "drain_tail": drain_tail, "drain_read_bytes": drain_read,
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
    // Panic text can name paths or entities: print only the panic site, its
    // last three path components and line (a crate source file), never the
    // payload. The oracle's caught non-equivalence also prints one.
    let hook = std::panic::take_hook();
    let tag = arm.clone();
    std::panic::set_hook(Box::new(move |info| {
        let at = info.location().map(|at| {
            let mut parts: Vec<&str> = at.file().rsplit('/').take(3).collect();
            parts.reverse();
            format!("{}:{}", parts.join("/"), at.line())
        });
        report(&tag, json!({"phase": "panic", "at": at}));
    }));
    let result = std::panic::catch_unwind(|| run(&arm, Path::new(&dir)));
    std::panic::set_hook(hook);
    if result.is_err() {
        report(&arm, json!({"failures": 1}));
        panic!("on-proof arm failed");
    }
}
