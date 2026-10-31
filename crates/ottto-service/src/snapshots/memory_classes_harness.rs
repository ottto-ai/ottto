//! Counts-only, macOS v1 memory measurements on private copies of local state.
use super::*;
use crate::test_scratch::ScratchDir;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};

macro_rules! metric {
    ($source:expr; $value:expr) => { println!("{}", json!({"memory_metric":true,"source":$source,"metric":$value})); };
}
fn heap() -> i64 {
    let mut stats = std::mem::MaybeUninit::<libc::malloc_statistics_t>::zeroed();
    // SAFETY: Darwin writes a malloc_statistics_t into the correctly sized buffer.
    unsafe { libc::malloc_zone_statistics(std::ptr::null_mut(), stats.as_mut_ptr()) };
    unsafe { stats.assume_init() }.size_in_use as i64
}
fn footprint() -> u64 {
    crate::local_resource_diagnostics::memory_harness_current().expect("footprint unavailable")
}
fn point(source: &str, name: &str) -> i64 {
    let bytes = heap();
    metric!(source; json!({"point":name,"heap_bytes":bytes,"footprint_bytes":footprint()}));
    bytes
}
fn peak<T>(f: impl FnOnce() -> T) -> (T, u64) {
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let sampler = scope.spawn(|| {
            let mut high = footprint();
            while !stop.load(AtomicOrdering::Acquire) {
                std::thread::sleep(Duration::from_millis(10));
                high = high.max(footprint());
            }
            high
        });
        // Always stop the scoped sampler, including when the measured operation panics.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
        stop.store(true, AtomicOrdering::Release);
        let high = sampler.join().expect("sampler failed");
        (
            result.unwrap_or_else(|error| std::panic::resume_unwind(error)),
            high,
        )
    })
}
fn freed(source: &str, class: &str, entries: usize, before: i64) -> i64 {
    let bytes = before - heap();
    metric!(source; json!({"class":class,"entries":entries,"freed_bytes":bytes}));
    bytes
}
fn release<T>(value: T) {
    drop(value);
}
fn parts<'a, T: Default + 'a>(
    source: &str,
    class: &str,
    values: impl Iterator<Item = &'a mut T>,
    count: impl Fn(&T) -> usize,
) {
    let before = heap();
    let mut entries = 0;
    for value in values {
        entries += count(value);
        release(std::mem::take(value));
    }
    freed(source, class, entries, before);
}
fn classes(source: &str, index: &mut ScanIndex, graph: i64) {
    let start = heap();
    let mut sum = 0;
    let fresh = ScanIndex::default();
    macro_rules! top {
        ($field:ident; $count:expr; $body:block) => {{
            let entries = $count;
            let before = heap();
            $body
            release(std::mem::replace(&mut index.$field, fresh.$field));
            sum += freed(source, stringify!($field), entries, before);
        }};
    }
    macro_rules! split {
        ($name:expr; $values:expr; $count:expr) => {
            parts(source, $name, $values, $count);
        };
    }
    top!(claude_account_family_pending; index.claude_account_family_pending.len(); {
        let pending = &mut index.claude_account_family_pending;
        split!("account.windows.member_requests"; pending.values_mut().flat_map(|p| &mut p.previous_windows).map(|w| &mut w.member_requests); BTreeMap::len);
        split!("account.windows.members"; pending.values_mut().flat_map(|p| &mut p.previous_windows).map(|w| &mut w.members); BTreeMap::len);
        split!("account.windows.rest"; pending.values_mut().map(|p| &mut p.previous_windows); Vec::len);
        split!("account.current.member_requests"; pending.values_mut().map(|p| &mut p.current.member_requests); BTreeMap::len);
        split!("account.current.members"; pending.values_mut().map(|p| &mut p.current.members); BTreeMap::len);
        split!("account.absent_members"; pending.values_mut().map(|p| &mut p.confirmed_absent_members); BTreeSet::len);
    });
    top!(claude_usage_family_pending; index.claude_usage_family_pending.len(); {
        let pending = &mut index.claude_usage_family_pending;
        split!("usage.occurrences"; pending.values_mut().map(|p| &mut p.member_occurrences); |v| v.values().map(BTreeMap::len).sum());
        split!("usage.request_hashes"; pending.values_mut().map(|p| &mut p.member_request_id_hashes); |v| v.values().map(BTreeSet::len).sum());
    });
    top!(claude_request_census; index.claude_request_census.record_count(); {
        let records = index.claude_request_census.record_count();
        let mut arcs = BTreeMap::<usize, Arc<[u64]>>::new();
        for (_, record) in index.claude_request_census.records() {
            if let Some(arc) = record.shared_request_hashes() {
                arcs.entry(arc.as_ptr() as usize).or_insert(arc);
            }
        }
        let entries = arcs.len();
        metric!(source; json!({"class":"census.hashes","entries":arcs.values().map(|a| a.len()).sum::<usize>(),"arcs":entries}));
        let before = heap();
        drop(std::mem::take(&mut index.claude_request_census));
        freed(source, "census.records_ex_arcs", records, before);
        let before = heap();
        drop(arcs);
        freed(source, "census.hash_arcs", entries, before);
    });
    macro_rules! count {
        (len, $value:expr) => {
            $value.len()
        };
        (option, $value:expr) => {
            usize::from($value.is_some())
        };
        (scalar, $value:expr) => {
            1
        };
        (zero, $value:expr) => {
            0
        };
    }
    // Strings count bytes; scalars count one; runtime structs without entry APIs count zero.
    macro_rules! fields {
        ($kind:ident; $($field:ident),* $(,)?) => {$(top!($field; count!($kind, index.$field); {});)*};
    }
    fields!(len; persistence_unavailable, files, session_account_bindings, terminal_jsonl_dispositions, known_configured_scan_roots, legacy_unresolved_root_file_witnesses);
    fields!(len; codex_state_only_snapshot_fingerprints, codex_state_only_blocked_session_ids, codex_state_only_blocked_by_file, codex_state_only_blocked_unattributed, codex_state_only_blocked_legacy, codex_parent_ownership_refs);
    fields!(len; codex_parent_ownership_ledgers, codex_parent_side_requests, codex_parent_side, codex_parent_prefix_proofs, codex_proof_index_incarnation, codex_proof_index_minted);
    fields!(len; codex_parent_proof_parents_live, claude_desktop_title_files, claude_account_family_witnesses, claude_usage_family_witnesses, claude_usage_authority_quarantine, claude_duplicate_request_owners);
    fields!(len; claude_owned_start_census, claude_account_deferred_holds, confirmed_empty_files, codex_counting_moved_evidence, file_snapshot_fingerprints, snapshot_activity_at);
    fields!(len; accepted_snapshot_fingerprints, quarantined_snapshot_fingerprints, effective_upload_body_witness_revision_excluded_source_files, reason_reoffer_retries, terminal_contract_retries, reason_reoffer_cooldowns);
    fields!(len; accepted_rebuild_incidence, codex_counting_tombstones, codex_counting_evictions);
    fields!(option; persistence_root, persistence_controls, persistence_legacy_recovery, upload_context_fingerprint, codex_parent_proof_cursor, codex_parent_side_cursor);
    fields!(option; claude_duplicate_fence_next_full_rearm_unix_seconds, claude_request_identity_contract, claude_desktop_store_cursor, claude_desktop_store_upper_bound, claude_desktop_census_witness, claude_desktop_store_retry_not_before_unix_seconds);
    fields!(option; resume_after_path, resume_upper_bound_path, resume_census_window_end, traversal, scan_residue_witness, historical_replay_generation);
    fields!(option; completed_context_curve_replay_generation, legacy_settlement_reconcile_after_fingerprint, active_quarantine_witness, active_upload_context_fingerprint, claude_history_cutoff_unix_seconds, accepted_rebuild_pending_since_unix_seconds);
    fields!(option; accepted_rebuild_last_alarm_unix_seconds, upload_ack_retirement_handoff, held_audit_progress, claude_desktop_store_inventory, copy_prefix_base_upload_context);
    fields!(scalar; schema_version, generation, codex_state_only_blocked_attributed, codex_parent_side_generation, codex_parent_proof_wrap_epoch, codex_parent_proof_seq);
    fields!(scalar; claude_retired_family_tombstones_initialized, claude_retired_family_tombstones_uncertain, claude_duplicate_request_witness_overflowed, claude_duplicate_fence_rearm_attempt, claude_request_identity_contract_changed, claude_desktop_store_sweep_had_errors);
    fields!(scalar; claude_desktop_identity_census_complete, claude_desktop_lineage_census_complete, claude_desktop_store_retry_attempt, bounded_sweep_had_unsettled_upload, bounded_sweep_unsettled_causes, context_curve_capability_enabled);
    fields!(scalar; context_curve_replay_epoch, accepted_snapshot_fingerprint_ledger_version, file_upload_context_enabled, active_effective_upload_body_witness_revision, active_effective_upload_body_witness_revision_monotone, claude_history_unverified_in_process);
    fields!(scalar; claude_rebuild_read_load_eligible, claude_history_gate_loaded, claude_history_move_not_full, claude_history_move_released, accepted_incidence_pending_census, copy_unproven_enabled);
    fields!(zero; decode_holds, claude_account_window_retention, withheld_memo, claude_request_census_shadow, claude_retired_family_tombstones, claude_full_rearm_progress);
    fields!(zero; claude_stale_family_carry, mixed_context_view, context_read_counts, claude_reemission_exclusions, retired_reread_guard, codex_counting_evicted_legacy);
    fields!(zero; claude_no_list_policy, claude_history_emission, claude_money_birth_store, claude_copy_removals);
    metric!(source; json!({"point":"class_totals","graph_bytes":graph,"freed_bytes":sum,"residual_bytes":graph-sum,"heap_delta_bytes":start-heap()}));
}
fn measure(source: SnapshotSource, path: &Path, support: &Path) -> Result<()> {
    let label = source.api_slug();
    let floor = point(label, "floor");
    let started = Instant::now();
    let (loaded, load_peak) = peak(|| {
        ScanIndex::load_inner_with_support(path, Some(source), Some(support), SystemTime::now())
    });
    let (mut index, origin) = loaded?;
    anyhow::ensure!(
        matches!(origin, LoadOrigin::Loaded(_)),
        "index was not loaded"
    );
    let graph = point(label, "loaded") - floor;
    metric!(label; json!({"point":"load","graph_bytes":graph,"peak_footprint_bytes":load_peak,"elapsed_ms":started.elapsed().as_millis()}));
    // Save precedes clone so clone retention cannot hide the save's transient peak.
    let before = footprint();
    let started = Instant::now();
    let (saved, high) = peak(|| index.save(path));
    saved?;
    metric!(label; json!({"point":"save","before_footprint_bytes":before,"peak_footprint_bytes":high,"elapsed_ms":started.elapsed().as_millis()}));
    let before = heap();
    let copy = index.clone();
    metric!(label; json!({"point":"clone","heap_bytes":heap()-before}));
    drop(copy);
    point(label, "clone_dropped");
    classes(label, &mut index, graph);
    drop(index);
    point(label, "all_dropped");
    Ok(())
}
fn stable_copy(from: &Path, to: &Path) -> Result<u64> {
    let mut input = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(from)?;
    let before = input.metadata()?;
    anyhow::ensure!(before.is_file(), "regular file required");
    let mut output = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(to)?;
    let bytes = std::io::copy(&mut input, &mut output)?;
    output.set_permissions(fs::Permissions::from_mode(0o600))?;
    let after = fs::symlink_metadata(from)?;
    anyhow::ensure!(
        before.len() == bytes
            && after.is_file()
            && before.dev() == after.dev()
            && before.ino() == after.ino()
            && before.len() == after.len()
            && before.modified()? == after.modified()?,
        "source changed during copy"
    );
    Ok(bytes)
}
fn scratch_bytes(path: &Path) -> Result<u64> {
    let mut bytes = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = entry.file_type()?;
        bytes += if metadata.is_dir() {
            scratch_bytes(&entry.path())?
        } else {
            entry.metadata()?.len()
        };
    }
    Ok(bytes)
}
fn run() -> Result<()> {
    if let Some(path) = std::env::var_os("OTTTO_MEMORY_CHILD_INDEX") {
        let source = match std::env::var("OTTTO_MEMORY_CHILD_SOURCE")?.as_str() {
            "claude_code" => SnapshotSource::ClaudeCode,
            "codex" => SnapshotSource::Codex,
            "pi" => SnapshotSource::Pi,
            _ => anyhow::bail!("unknown source"),
        };
        let support = PathBuf::from(
            std::env::var_os("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR")
                .context("private support required")?,
        );
        let path = PathBuf::from(path).canonicalize()?;
        anyhow::ensure!(
            path.starts_with(support.canonicalize()?)
                && support
                    .canonicalize()?
                    .starts_with(std::env::temp_dir().canonicalize()?)
                && fs::metadata(&support)?.permissions().mode() & 0o777 == 0o700
                && fs::metadata(&path)?.permissions().mode() & 0o777 == 0o600,
            "private index required"
        );
        // This isolated worker also keeps production-created save/lock files owner-only.
        unsafe { libc::umask(0o077) };
        return measure(source, &path, &support);
    }
    let support = std::env::var_os("OTTTO_MEMORY_SUPPORT_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(ottto_core::default_support_dir);
    let destinations = support.join("snapshots/destinations");
    let mut roots = vec![support.join("snapshots")];
    if destinations.is_dir() {
        for entry in fs::read_dir(destinations)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                roots.push(entry.path());
            }
        }
    }
    let mut measured = 0;
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let (index, progress) = crate::snapshot_sync::memory_harness_paths(&support, source);
        for root in &roots {
            let from = root.join(index.file_name().context("index filename required")?);
            if !from.is_file() {
                continue;
            }
            let scratch = ScratchDir::new("ottto-memory-classes");
            let target = scratch.join(root.strip_prefix(&support)?);
            fs::create_dir_all(&target)?;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o700))?;
            let to = target.join(index.file_name().unwrap());
            let result = (|| -> Result<()> {
                let progress_from = root.join(progress.file_name().unwrap());
                let inputs: Vec<_> = [&from, &progress_from]
                    .into_iter()
                    .filter(|p| p.exists())
                    .map(|p| Ok((p, fs::metadata(p)?)))
                    .collect::<Result<_>>()?;
                let mut bytes = stable_copy(&from, &to)?;
                if progress_from.try_exists()? {
                    bytes +=
                        stable_copy(&progress_from, &target.join(progress.file_name().unwrap()))?;
                }
                for (path, before) in inputs {
                    let after = fs::metadata(path)?;
                    anyhow::ensure!(
                        before.len() == after.len() && before.modified()? == after.modified()?,
                        "source changed across copy"
                    );
                }
                let progress_copy = target.join(progress.file_name().unwrap());
                let progress_before = if progress_copy.try_exists()? {
                    Some(fs::read(&progress_copy)?)
                } else {
                    None
                };
                metric!(source.api_slug(); json!({"point":"copied","bytes":bytes}));
                let child = std::process::Command::new(std::env::current_exe()?)
                    .args([
                        "--ignored",
                        "--exact",
                        "snapshots::memory_classes_harness::real_m4_memory_classes",
                        "--nocapture",
                        "--test-threads=1",
                    ])
                    .env("OTTTO_MEMORY_CHILD_INDEX", &to)
                    .env("OTTTO_MEMORY_CHILD_SOURCE", source.api_slug())
                    .env("OTTTO_LOCAL_PLATFORM_SUPPORT_DIR", scratch.as_ref())
                    .output()?;
                // Production loader diagnostics and panic text may contain private paths.
                for line in String::from_utf8_lossy(&child.stdout).lines() {
                    if let Some(value) = line
                        .find('{')
                        .and_then(|at| serde_json::from_str::<Value>(&line[at..]).ok())
                    {
                        if value["memory_metric"] == true {
                            println!("{value}");
                        }
                    }
                }
                anyhow::ensure!(child.status.success(), "measurement child failed");
                if let Some(before) = progress_before {
                    anyhow::ensure!(fs::read(progress_copy)? == before, "progress changed");
                }
                Ok(())
            })();
            let deleted = scratch_bytes(scratch.as_ref())?;
            fs::remove_dir_all(scratch.as_ref())?;
            metric!(source.api_slug(); json!({"point":"cleanup","deleted_bytes":deleted}));
            result?;
            measured += 1;
        }
    }
    anyhow::ensure!(measured > 0, "no local v1 indices found");
    Ok(())
}
/// [behaviour] On-demand memory harness for memory PRs; ignored, needs local
/// Claude/Codex/Pi state; counts only. Set OTTTO_MEMORY_SUPPORT_DIR to a copied
/// support directory; run alone with --ignored --nocapture --test-threads=1.
#[test]
#[ignore = "on-demand local state memory measurement"]
fn real_m4_memory_classes() {
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| println!("{{\"failures\":1}}")));
    let result = std::panic::catch_unwind(run);
    std::panic::set_hook(hook);
    assert!(matches!(result, Ok(Ok(()))), "memory measurement failed");
}
