//! Claude telemetry retention: delete a session's API and trace side files once
//! every transcript of that session is gone. The side files are read only for
//! the session's own transcripts, for transcripts that copied its requests,
//! and for state that still names its root; each of those keeps the pair.
//! Deletion is paused until a pair's delivery is proven (see
//! [`delivery_proven`]): until then every candidate is held and only counted
//! from metadata; no held pair's body is read.
//!
//! Runs after a successful selected save whose upload completed and fully
//! settled (a deferred, rejected, shed or partial upload drops the run), only
//! while the last root walk began in this process and listed every root with
//! no walk issue. Candidates: the roots whose indexed members this pass
//! retired, plus every stored pair once per complete walk (the backlog), so a
//! pair held once is rechecked once per complete walk. Nothing is persisted: a
//! crash between the two unlinks leaves one member, which a later released run
//! deletes.
use super::claude_request_census::held_candidates;
use super::money_freshness::index_current_since_start;
use super::*;
use crate::claude_local_otel::telemetry_stem;
use crate::local_resource_diagnostics::ClaudeTelemetryRetention as Counts;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Keys this pass removed from the index (the retirer's work).
pub(crate) fn removed_index_keys(before: &ScanIndex, after: &ScanIndex) -> BTreeSet<String> {
    before
        .files
        .keys()
        .filter(|key| !after.files.contains_key(*key))
        .cloned()
        .collect()
}

fn root_of(key: &str) -> Option<&str> {
    claude_index_path_member_ref(Path::new(key)).map(|member| member.root)
}

/// The keys the roster's walk listed, less this pass's removed keys.
fn listed_keys<'a>(
    roster: &'a g7_debt::Roster,
    removed: &'a BTreeSet<String>,
) -> impl Iterator<Item = &'a String> {
    roster.listed.keys().filter(|key| !removed.contains(*key))
}

/// `removed`: this pass's removed keys; `named`: sessions this pass's
/// snapshots name as parent or root.
pub(crate) fn retire_claude_telemetry(
    support_dir: &Path,
    index: &ScanIndex,
    scan_roots: &[PathBuf],
    removed: &BTreeSet<String>,
    named: &[String],
) {
    #[cfg(test)]
    RUNS.with(|runs| runs.set(runs.get() + 1));
    let Some((roster, backlog)) = index_current_since_start(SnapshotSource::ClaudeCode) else {
        return;
    };
    let mut listing_fault = 0;
    let mut stems = removed
        .iter()
        .filter_map(|key| root_of(key))
        .map(telemetry_stem)
        .collect::<BTreeSet<_>>();
    if backlog {
        match crate::claude_local_otel::telemetry_stems(support_dir) {
            Ok(all) => stems.extend(all),
            Err(_) => listing_fault = 1,
        }
    }
    let release = delivery_proven(&stems);
    let mut held = Counts::default();
    // Classification only: a listed family member proves a current transcript.
    let listed = listed_keys(&roster, removed)
        .filter_map(|key| root_of(key))
        .map(telemetry_stem)
        .collect::<BTreeSet<_>>();
    for stem in stems.difference(&release) {
        let no_transcript = !listed.contains(stem);
        match crate::claude_local_otel::telemetry_pair_bytes(support_dir, stem) {
            Ok(None) => continue,
            Ok(Some(bytes)) if no_transcript => held.held_no_transcript_bytes += bytes,
            Ok(Some(_)) => {}
            Err(()) => {
                held.read_fault += 1;
                continue;
            }
        }
        held.held_roots += 1;
        held.held_no_transcript_roots += u64::from(no_transcript);
    }
    if held != Counts::default() {
        crate::local_resource_diagnostics::claude_telemetry_retention(held);
    }
    let mut run = if release.is_empty() {
        Counts::default()
    } else {
        retire(
            support_dir,
            index,
            scan_roots,
            removed,
            named,
            &roster,
            release,
        )
    };
    run.read_fault += listing_fault;
    if run != Counts::default() {
        crate::local_resource_diagnostics::claude_telemetry_retention(run);
    }
}

#[cfg(test)]
thread_local! {
    static RUNS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Test seam: how many times the sync loop reached retention on this thread
/// since the last call.
#[cfg(test)]
pub(crate) fn take_runs_for_test() -> u32 {
    RUNS.with(|runs| runs.replace(0))
}

/// The `no_transcript_delivery_hold` seam: the candidates proven delivered, the
/// only ones retention may delete; none today. The change that uploads
/// telemetry-only sessions supplies the proof: a durable per-candidate ACK of
/// the exact body, bound to the destination and the pair's member generations;
/// never page completion, another session's ACK or a global switch.
fn delivery_proven(stems: &BTreeSet<String>) -> BTreeSet<String> {
    let proven = BTreeSet::new();
    #[cfg(test)]
    let proven = if PROVEN.with(std::cell::Cell::get) {
        stems.clone()
    } else {
        proven
    };
    stems.intersection(&proven).cloned().collect()
}

#[cfg(test)]
thread_local! {
    static PROVEN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Test seam: on this thread, treat every candidate as delivered (`true`) or
/// none, as today (`false`), to exercise the pipeline a proof releases into.
/// Delete when the delivery proof lands.
#[cfg(test)]
pub(crate) fn prove_delivery_for_test(proven: bool) {
    PROVEN.with(|cell| cell.set(proven));
}

/// One run over `stems`: every stem with a member is retired, held or a fault.
fn retire(
    support_dir: &Path,
    index: &ScanIndex,
    scan_roots: &[PathBuf],
    removed: &BTreeSet<String>,
    named: &[String],
    roster: &g7_debt::Roster,
    stems: BTreeSet<String>,
) -> Counts {
    let mut run = Counts::default();
    let Some(protected) = protected_stems(index, scan_roots, removed, named, roster) else {
        run.held_roots = stems.len() as u64;
        return run;
    };
    // A pair written after the roster's walk began is kept.
    let fence = i64::try_from(roster.started_at_ms / 1000).unwrap_or(i64::MAX);
    let mut candidates = Vec::new();
    for stem in stems {
        if protected.contains(&stem) {
            run.held_roots += 1;
            continue;
        }
        match crate::claude_local_otel::read_telemetry_pair(support_dir, &stem) {
            Err(()) => run.read_fault += 1,
            Ok(None) => {}
            Ok(Some(pair)) if pair.last_write >= fence => run.held_roots += 1,
            Ok(Some(pair)) => candidates.push((stem, pair)),
        }
    }
    let copied = copied_candidates(index, removed, roster, &candidates);
    let mut unlinked = false;
    for ((stem, pair), copied) in candidates.iter().zip(copied) {
        if copied {
            run.held_roots += 1;
            run.held_copied += 1;
            continue;
        }
        match crate::claude_local_otel::unlink_telemetry_pair(support_dir, stem, pair) {
            Ok(true) => {
                run.retired_roots += 1;
                run.retired_bytes += pair.bytes;
                unlinked = true;
            }
            Ok(false) => run.held_roots += 1,
            Err(_) => run.read_fault += 1,
        }
    }
    if unlinked && crate::claude_local_otel::sync_telemetry_dirs(support_dir).is_err() {
        run.read_fault += 1;
    }
    run
}
/// The ONE protection set, as stems: every root the roster lists, the index
/// keys, the census, witness families (legacy owners included),
/// account holds, Tail heads and named parents. A removed key is protected
/// unless a same-name stat proves it absent beneath every configured root.
/// `None`: the Tail heads could not be read (everything is held).
fn protected_stems(
    index: &ScanIndex,
    scan_roots: &[PathBuf],
    removed: &BTreeSet<String>,
    named: &[String],
    roster: &g7_debt::Roster,
) -> Option<BTreeSet<String>> {
    let heads = state_v2::tail_head_keys(index).ok()?;
    // Witnessed families with their legacy owners.
    let families = index.claude_usage_family_witnesses.keys().chain(
        index
            .claude_usage_family_witnesses
            .values()
            .flat_map(|witness| witness.legacy_owner_roots.iter()),
    );
    let mut roots = BTreeSet::<&str>::new();
    let keys = listed_keys(roster, removed)
        .chain(index.files.keys())
        .chain(index.claude_request_census.records().map(|(key, _)| key))
        .chain(index.claude_account_deferred_holds.keys())
        .chain(&heads);
    roots.extend(keys.filter_map(|key| root_of(key)));
    roots.extend(families.chain(named).map(String::as_str));
    for key in removed {
        let same_name_absent = scan_roots
            .iter()
            .find_map(|root| Path::new(key).strip_prefix(root).ok())
            .is_some_and(|relative| {
                scan_roots
                    .iter()
                    .all(|root| sampled_audit::proven_absent(&root.join(relative), scan_roots))
            });
        if !same_name_absent {
            roots.extend(root_of(key));
        }
    }
    Some(roots.into_iter().map(telemetry_stem).collect())
}

/// One census traversal (subagents included, no deadline: it runs after the
/// save) for every candidate: a record holding one of a candidate's request
/// ids is a copy and keeps it. A listed file whose loss-free record proves its
/// scan is known through the ids of that read, even if the file has grown
/// since: a copy is written when its file is created, and a transcript then
/// appends only its own turns. Any other listed file (no record, lossy,
/// retired, twin, over budget) is unknown and keeps every candidate whose
/// first request is not newer than the file (a copy is written after the
/// requests it copies; no mtime keeps all).
fn copied_candidates(
    index: &ScanIndex,
    removed: &BTreeSet<String>,
    roster: &g7_debt::Roster,
    candidates: &[(String, crate::claude_local_otel::TelemetryPair)],
) -> Vec<bool> {
    if candidates.is_empty() {
        return Vec::new();
    }
    let census = &index.claude_request_census;
    let mut wanted = BTreeMap::<u64, Vec<usize>>::new();
    for (at, (_, pair)) in candidates.iter().enumerate() {
        for id in &pair.request_ids {
            wanted
                .entry(claude_request_census::claude_request_hash(id))
                .or_default()
                .push(at);
        }
    }
    let union = wanted.keys().copied().collect::<Vec<_>>();
    let mut copied = vec![false; candidates.len()];
    claude_request_census::ClaudeRequestCensus::walk_transcript_holders(
        census.records(),
        None,
        |_, _, record| {
            for hash in held_candidates(record, &union) {
                for &at in &wanted[&hash] {
                    copied[at] = true;
                }
            }
        },
    );
    let unknown = roster
        .listed
        .iter()
        .filter(|(key, _)| !removed.contains(*key) && root_of(key).is_some())
        .filter(|(key, _)| {
            !census
                .get(key)
                .is_some_and(|record| !record.is_lossy() && record.proves_scan())
        })
        .map(|(_, mtime)| mtime.unwrap_or(u64::MAX))
        .max();
    for (copied, (_, pair)) in copied.iter_mut().zip(candidates) {
        *copied |= unknown.is_some_and(|unknown| unknown >= pair.first_observed);
    }
    copied
}
