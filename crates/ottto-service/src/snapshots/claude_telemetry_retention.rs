//! Claude telemetry retention: delete a session's API and trace side files once
//! every transcript of that session is gone. The side files are read only for
//! the session's own transcripts, for transcripts that copied its requests,
//! and for state that still names its root; each of those keeps the pair.
//!
//! Runs after a successful selected save whose upload fully settled, only
//! while the last root walk began in this process and listed every root with
//! no walk issue. Candidates: the roots whose indexed members this pass
//! retired, plus every stored pair once per process (the backlog). Nothing is
//! persisted: a crash between the two unlinks leaves one member, which the
//! next run deletes.
use super::claude_request_census::held_candidates;
use super::money_freshness::index_current_since_start;
use super::*;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Keys this pass removed from the index (the retirer's work).
pub(crate) fn removed_index_keys(before: &ScanIndex, after: &ScanIndex) -> BTreeSet<String> {
    before
        .files
        .keys()
        .filter(|key| !after.files.contains_key(*key))
        .cloned()
        .collect()
}

fn stem(root: &str) -> String {
    format!("{:x}", Sha256::digest(root.as_bytes()))
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
    // [retired_roots, retired_bytes, held_roots, read_fault]
    let mut counts = [0_u64; 4];
    let mut stems = removed
        .iter()
        .filter_map(|key| root_of(key))
        .map(stem)
        .collect::<BTreeSet<_>>();
    if backlog {
        match crate::claude_local_otel::telemetry_stems(support_dir) {
            Ok(all) => stems.extend(all),
            Err(_) => counts[3] += 1,
        }
    }
    if !stems.is_empty() {
        retire(
            support_dir,
            index,
            scan_roots,
            removed,
            named,
            &roster,
            stems,
            &mut counts,
        );
    }
    if counts != [0; 4] {
        crate::local_resource_diagnostics::claude_telemetry_retention(counts);
    }
}

#[allow(clippy::too_many_arguments)]
fn retire(
    support_dir: &Path,
    index: &ScanIndex,
    scan_roots: &[PathBuf],
    removed: &BTreeSet<String>,
    named: &[String],
    roster: &g7_debt::Roster,
    stems: BTreeSet<String>,
    counts: &mut [u64; 4],
) {
    let Some(protected) = protected_stems(index, scan_roots, removed, named, roster) else {
        counts[2] += stems.len() as u64;
        return;
    };
    // A pair written after the roster's walk began is kept.
    let fence = i64::try_from(roster.started_at_ms / 1000).unwrap_or(i64::MAX);
    let mut candidates = Vec::new();
    for stem in stems.into_iter().filter(|stem| !protected.contains(stem)) {
        match crate::claude_local_otel::read_telemetry_pair(support_dir, &stem) {
            Err(()) => counts[3] += 1,
            Ok(pair) if pair.last_write >= fence => counts[2] += 1,
            Ok(pair) => candidates.push((stem, pair)),
        }
    }
    let copied = copied_candidates(index, removed, roster, &candidates);
    let mut unlinked = false;
    for ((stem, pair), copied) in candidates.iter().zip(copied) {
        if copied {
            counts[2] += 1;
            continue;
        }
        match crate::claude_local_otel::unlink_telemetry_pair(support_dir, stem, pair) {
            Ok(true) => {
                counts[0] += 1;
                counts[1] += pair.bytes;
                unlinked = true;
            }
            Ok(false) => counts[2] += 1,
            Err(_) => counts[3] += 1,
        }
    }
    if unlinked && crate::claude_local_otel::sync_telemetry_dirs(support_dir).is_err() {
        counts[3] += 1;
    }
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
    Some(roots.into_iter().map(stem).collect())
}

/// One census traversal (subagents included) for every candidate: a record
/// holding one of a candidate's request ids is a copy and keeps it. A listed
/// file with no record for its listed revision is unknown; it keeps every
/// candidate whose first request is not newer than the file (a copy is written
/// after the requests it copies). An unfinished traversal keeps them all.
fn copied_candidates(
    index: &ScanIndex,
    removed: &BTreeSet<String>,
    roster: &g7_debt::Roster,
    candidates: &[(String, crate::claude_local_otel::TelemetryPair)],
) -> Vec<bool> {
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
        census.walk_transcript_holders(Instant::now() + Duration::from_secs(60), |_, _, record| {
            for hash in held_candidates(record, &union) {
                for &at in &wanted[&hash] {
                    copied[at] = true;
                }
            }
        });
    if walked.is_none() {
        return vec![true; candidates.len()];
    }
    // The listed revision's record lists every request id the file held.
    let unknown = roster
        .listed
        .iter()
        .filter(|(key, _)| !removed.contains(*key) && root_of(key).is_some())
        .filter(|(key, mtime)| {
            !census.get(key).is_some_and(|record| {
                record.proves_scan()
                    && !record.is_lossy()
                    && record
                        .modified()
                        .zip(**mtime)
                        .is_some_and(|(read, listed)| read >= listed)
            })
        })
        .map(|(_, mtime)| mtime.unwrap_or(u64::MAX))
        .max();
    for (copied, (_, pair)) in copied.iter_mut().zip(candidates) {
        *copied |= unknown.is_some_and(|unknown| unknown >= pair.first_observed);
    }
    copied
}
