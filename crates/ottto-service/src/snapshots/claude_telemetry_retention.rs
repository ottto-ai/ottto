//! Claude telemetry retention: delete a session's API and trace side files once
//! every transcript of that session is gone. The side files are read only for
//! the session's own transcripts, for transcripts that copied its requests,
//! and for state that still names its root; each of those keeps the pair.
//!
//! Runs after a successful selected save whose upload completed and fully
//! settled (a deferred, rejected, shed or partial upload drops the run), only
//! while the last root walk began in this process and listed every root with
//! no walk issue. Candidates: the roots whose indexed members this pass
//! retired, plus every stored pair once per process (the backlog). Nothing is
//! persisted: a crash between the two unlinks leaves one member, which the
//! next run deletes.
use super::claude_request_census::held_candidates;
use super::claude_request_money::e2::{scan_evidence, Evidence, SIDE_CALL_DEADLINE};
use super::money_freshness::index_current_since_start;
use super::*;
use crate::claude_local_otel::telemetry_stem;
use crate::local_resource_diagnostics::ClaudeTelemetryRetention as Counts;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Instant;

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

/// `removed`: this pass's removed keys; `named`: sessions this pass's
/// snapshots name as parent or root.
pub(crate) fn retire_claude_telemetry(
    support_dir: &Path,
    index: &ScanIndex,
    scan_roots: &[PathBuf],
    removed: &BTreeSet<String>,
    named: &[String],
) {
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
    let mut run = if stems.is_empty() {
        Counts::default()
    } else {
        retire(
            support_dir,
            index,
            scan_roots,
            removed,
            named,
            &roster,
            stems,
        )
    };
    run.read_fault += listing_fault;
    if run != Counts::default() {
        crate::local_resource_diagnostics::claude_telemetry_retention(run);
    }
}

/// One run over `stems`: every stem is retired, held or a read fault.
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
            Ok(pair) if pair.last_write >= fence => run.held_roots += 1,
            Ok(pair) => candidates.push((stem, pair)),
        }
    }
    let copied = copied_candidates(index, removed, roster, &candidates);
    let mut unlinked = false;
    for ((stem, pair), copied) in candidates.iter().zip(copied) {
        if copied {
            run.held_roots += 1;
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
/// keys, the census, pending and witness families (legacy owners included),
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
    let pending = claude_pending_family_session_ids(index);
    let mut roots = BTreeSet::<&str>::new();
    let keys = roster
        .listed
        .keys()
        .filter(|key| !removed.contains(*key))
        .chain(index.files.keys())
        .chain(index.claude_request_census.records().map(|(key, _)| key))
        .chain(index.claude_account_deferred_holds.keys())
        .chain(&heads);
    roots.extend(keys.filter_map(|key| root_of(key)));
    roots.extend(pending.iter().chain(named).map(String::as_str));
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

/// One census traversal (subagents included) for every candidate: a record
/// holding one of a candidate's request ids is a copy and keeps it. A listed
/// file proves which requests it holds only through its census record of the
/// listed revision (same mtime) that the `e2` source verification calls
/// current; any other listed file (no record, stale, queued, lossy, no
/// mtime) is unknown and keeps every candidate whose first request is not
/// newer than the file (a copy is written after the requests it copies). An
/// unfinished traversal keeps them all.
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
    let walked =
        census.walk_transcript_holders(Instant::now() + SIDE_CALL_DEADLINE, |_, _, record| {
            for hash in held_candidates(record, &union) {
                for &at in &wanted[&hash] {
                    copied[at] = true;
                }
            }
        });
    if walked.is_none() {
        return vec![true; candidates.len()];
    }
    let unknown = roster
        .listed
        .iter()
        .filter(|(key, _)| !removed.contains(*key) && root_of(key).is_some())
        .filter(|(key, listed)| {
            !census.get(key).is_some_and(|record| {
                !record.is_lossy()
                    && listed.is_some_and(|listed| record.modified() == Some(listed))
                    && scan_evidence(index, key, record) == Evidence::Current
            })
        })
        .map(|(_, mtime)| mtime.unwrap_or(u64::MAX))
        .max();
    for (copied, (_, pair)) in copied.iter_mut().zip(candidates) {
        *copied |= unknown.is_some_and(|unknown| unknown >= pair.first_observed);
    }
    copied
}
