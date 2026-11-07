//! Discovery traversal: the bounded walk over the configured scan roots.
//!
//! `state` holds what the walk persists between pages: its checkpoint, queued
//! paths, counts and residue, with the records kept beside them.

pub(in crate::snapshots) mod state;

use crate::snapshots::*;

pub(in crate::snapshots) fn scan_traversal_context_fingerprint(
    source: SnapshotSource,
    roots: &[PathBuf],
    backfill_window_days: u64,
) -> String {
    scan_traversal_context_fingerprint_with(source, roots, None, backfill_window_days)
}

/// A traversal or carry origin saved under the earlier form, which also bound
/// the delivery context and the replay generation, consumed its queue under
/// the same walk when that form equals the active one: keep it under the new
/// form. Anything else stays a mismatch and starts the walk as before.
pub(in crate::snapshots) fn adopt_legacy_traversal_fingerprint(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    backfill_window_days: u64,
) {
    let legacy = scan_traversal_context_fingerprint_with(
        source,
        roots,
        Some([
            index.active_upload_context_fingerprint.as_deref(),
            index.historical_replay_generation.as_deref(),
        ]),
        backfill_window_days,
    );
    let current = scan_traversal_context_fingerprint(source, roots, backfill_window_days);
    if let Some(fingerprint) = index
        .traversal
        .as_mut()
        .map(|t| &mut t.context_fingerprint)
        .filter(|fingerprint| **fingerprint == legacy)
    {
        fingerprint.clone_from(&current);
    }
}

/// The walk's identity: what decides which files are discovered and how a
/// queue resumes. No setting, capability or replay directive is an input; a
/// replay clears the traversal itself. `legacy` reproduces the earlier form,
/// which bound the delivery context and the replay generation, for adoption.
pub(in crate::snapshots) fn scan_traversal_context_fingerprint_with(
    source: SnapshotSource,
    roots: &[PathBuf],
    legacy: Option<[Option<&str>; 2]>,
    backfill_window_days: u64,
) -> String {
    let mut digest = Sha256::new();
    update_length_prefixed(
        &mut digest,
        if legacy.is_some() {
            b"ottto:snapshot-bounded-traversal:v1"
        } else {
            b"ottto:snapshot-bounded-traversal:v2"
        },
    );
    update_length_prefixed(&mut digest, source.api_slug().as_bytes());
    // A persisted queue contains paths already consumed under the scanner that
    // created it. Resuming that queue after an upgrade without binding these
    // derivations can skip the consumed prefix under the new identity and
    // publish a mixed old/new terminal census. Parser-only releases remain
    // resumable; reviewed scan/open identity changes start a fresh bounded
    // traversal so every pre-existing candidate is reconsidered.
    update_length_prefixed(&mut digest, source.scan_identity_version().as_bytes());
    if source == SnapshotSource::Codex {
        update_length_prefixed(&mut digest, CODEX_CONTEXT_BUCKET_REVISIT.as_bytes());
    }
    update_length_prefixed(&mut digest, LOCAL_SCAN_INDEX_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(&mut digest, OPENED_OBJECT_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(
        &mut digest,
        JSONL_TERMINAL_DISPOSITION_GENERATION.as_bytes(),
    );
    update_length_prefixed(&mut digest, &backfill_window_days.to_be_bytes());
    for value in legacy.into_iter().flatten() {
        update_length_prefixed(&mut digest, value.unwrap_or("none").as_bytes());
    }
    for root in roots {
        update_length_prefixed(&mut digest, root.to_string_lossy().as_bytes());
    }
    format!("{:x}", digest.finalize())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::snapshots) enum TraversalProgress {
    Started,
    Resumed,
}

pub(in crate::snapshots) fn ensure_bounded_traversal(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    backfill_window_days: u64,
) -> TraversalProgress {
    if source == SnapshotSource::ClaudeCode {
        rearm_cause::retain(index);
    }
    adopt_legacy_traversal_fingerprint(source, roots, index, backfill_window_days);
    let context_fingerprint =
        scan_traversal_context_fingerprint(source, roots, backfill_window_days);
    let context_observation = (source == SnapshotSource::ClaudeCode).then(|| {
        claude_contract::compare_context(claude_contract::TraversalContext {
            retained: index
                .traversal
                .as_ref()
                .map(|t| t.context_fingerprint.as_str()),
            backfill: backfill_window_days,
            active: index.active_upload_context_fingerprint.as_deref(),
            replay: index.historical_replay_generation.as_deref(),
            roots,
        })
    });
    let prior_traversal_context_matches = index
        .traversal
        .as_ref()
        .is_some_and(|traversal| traversal.context_fingerprint == context_fingerprint);
    let retry_attempt = if let Some(traversal) = index
        .traversal
        .as_ref()
        .filter(|traversal| traversal.context_fingerprint == context_fingerprint)
    {
        // Pending re-reads do not hold the bounded retry. Every remaining
        // read/discovery error keeps its existing clock retry.
        let family_retry_due = rfc3339_unix_seconds(collected_at).is_some_and(|now| {
            source == SnapshotSource::ClaudeCode
                        && index.claude_usage_authority_quarantine.iter().any(|(root, record)| {
                            record.disposition == ClaudeUsageAuthorityQuarantineDisposition::RetryPending
                                && record.retry_after_unix_seconds <= now
                                // A start already served all deadlines at or
                                // before it, even if a held/deleted member
                                // yielded no item and retained its old record.
                                && rfc3339_unix_seconds(&traversal.census_window_end)
                                    .is_some_and(|started| record.retry_after_unix_seconds > started)
                                && index.claude_usage_family_witnesses.get(root).is_some_and(|witness| {
                                    claude_usage_authority_preserves_pending(record, witness)
                                })
                        })
        });
        let terminal_unhealthy = traversal.pending_directories.is_empty()
            && !traversal
                .pending_candidates
                .iter()
                .any(|candidate| candidate.census_member)
            && traversal.counts.has_errors();
        // What clears the latch: a generation that completes drops the
        // traversal, and a changed scan context takes the `else` branch below;
        // both start the next traversal at attempt zero. What bounds it: the
        // attempt saturates at `UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS`, the delay
        // at `UNHEALTHY_SCAN_RETRY_MAX_SECONDS`, and a deadline that is past,
        // absurdly far ahead, or missing altogether (an index persisted before
        // the deadline existed) is due now. The retry depends on the clock
        // alone, never on new input arriving.
        let retry_due = match rfc3339_unix_seconds(collected_at) {
            Some(now) => {
                traversal
                    .unhealthy_retry_not_before_unix_seconds
                    .map_or(true, |deadline| {
                        now >= deadline
                            || deadline > now.saturating_add(UNHEALTHY_SCAN_RETRY_MAX_SECONDS)
                    })
                    || family_retry_due
            }
            // A malformed or backwards observation clock must not turn the
            // durable red witness into a permanent fence. Retrying remains
            // bounded by the per-tick traversal limits.
            None => true,
        };
        (terminal_unhealthy && retry_due).then(|| {
            traversal
                .unhealthy_retry_attempt
                .min(UNHEALTHY_SCAN_RETRY_MAX_ATTEMPTS)
        })
    } else {
        Some(0)
    };
    let Some(retry_attempt) = retry_attempt else {
        return TraversalProgress::Resumed;
    };

    // Capture only fixed counters before the existing reset/rearm. A missing
    // prior traversal does not explain why it was removed; the retirement
    // record, when available, supplies that independent witness.
    let transition = traversal_transition::Starting::capture(
        source,
        index,
        collected_at,
        prior_traversal_context_matches,
        retry_attempt,
    );

    // A prior partially settled page may have advanced its traversal past an
    // entity whose replacement was not accepted. Finishing that generation
    // deliberately leaves this marker set and drops the traversal so the next
    // cycle starts one clean follow-up walk. Reaching this point means that
    // follow-up (or another explicit fresh generation) is now starting. Any
    // new partial settlement stamps the marker again before persistence.
    index.bounded_sweep_had_unsettled_upload = false;
    index.bounded_sweep_unsettled_causes = 0;

    transition.emit(source);

    let mut census = ScanCensus::default();
    let resolved_roots = roots
        .iter()
        .map(|root| {
            let problems_before = census
                .unreadable_path_count
                .saturating_add(census.disappeared_file_count);
            let resolved = resolve_configured_scan_root(source, root, &mut census);
            let problems_after = census
                .unreadable_path_count
                .saturating_add(census.disappeared_file_count);
            (root, resolved, problems_after > problems_before)
        })
        .collect::<Vec<_>>();
    let currently_resolved = resolved_roots
        .iter()
        .filter_map(|(_, resolved, _)| resolved.as_ref())
        .collect::<Vec<_>>();
    let missing_roots = resolved_roots
        .iter()
        .filter(|(_, resolved, _)| resolved.is_none())
        .map(|(root, _, _)| *root)
        .collect::<Vec<_>>();
    let missing_root_reported_problem = resolved_roots
        .iter()
        .any(|(_, resolved, reported_problem)| resolved.is_none() && *reported_problem);
    // Upgrade compatibility: indexes written before the durable root witness
    // existed can still prove that a now-missing root was previously observed.
    // Direct roots are inferred by lexical containment below. A vanished
    // configured symlink has no recoverable canonical target, so retain the
    // exact prior index paths until a future resolved root covers them. This
    // avoids falsely promoting every unrelated optional root to required.
    if prior_traversal_context_matches {
        index.legacy_unresolved_root_file_witnesses.retain(|key| {
            index.files.contains_key(key)
                && !currently_resolved
                    .iter()
                    .any(|root| Path::new(key).starts_with(root))
        });
    } else {
        // A changed root set is an explicit new census scope, not evidence that
        // one of its absent optional roots owns every old out-of-scope path.
        index.legacy_unresolved_root_file_witnesses.clear();
    }
    if prior_traversal_context_matches && !missing_roots.is_empty() {
        index.legacy_unresolved_root_file_witnesses.extend(
            index
                .files
                .keys()
                .filter(|key| {
                    !currently_resolved
                        .iter()
                        .any(|root| Path::new(key).starts_with(root))
                        && !missing_roots
                            .iter()
                            .any(|root| Path::new(key).starts_with(root))
                })
                .cloned(),
        );
    }
    let mut scan_roots = Vec::new();
    let mut pending_directories = VecDeque::new();
    for (root, resolved, resolver_reported_problem) in resolved_roots {
        let root_key = local_index_key(root);
        if let Some(scan_root) = resolved {
            index.known_configured_scan_roots.insert(root_key);
            scan_roots.push(scan_root.clone());
            pending_directories.push_back(ScanTraversalPath {
                scan_root: scan_root.clone(),
                path: scan_root,
                census_member: true,
                watcher_hint: false,
            });
            continue;
        }
        let inferred_from_old_index = index
            .files
            .keys()
            .any(|key| Path::new(key).starts_with(root));
        if inferred_from_old_index {
            index.known_configured_scan_roots.insert(root_key.clone());
        }
        if index.known_configured_scan_roots.contains(&root_key) && !resolver_reported_problem {
            disappearance_diagnostics::increment(
                &mut census.disappeared_file_count,
                source,
                disappearance_diagnostics::Cause::RootResolutionUnresolved,
            );
        }
    }
    if !index.legacy_unresolved_root_file_witnesses.is_empty() && !missing_root_reported_problem {
        disappearance_diagnostics::increment(
            &mut census.disappeared_file_count,
            source,
            disappearance_diagnostics::Cause::RootResolutionUnresolved,
        );
    }
    let counts = ScanTraversalCounts {
        directory_entry_cap_exceeded_count: census.directory_entry_cap_exceeded_count,
        symlink_rejected_count: census.symlink_rejected_count,
        unreadable_path_count: census.unreadable_path_count,
        unreadable_causes: census.unreadable_causes,
        retired_parent_unresolvable: serde::de::IgnoredAny,
        oversized_file_count: census.oversized_file_count,
        disappeared_file_count: census.disappeared_file_count,
        malformed_json_line_count: census.malformed_json_line_count,
        invalid_utf8_line_count: census.invalid_utf8_line_count,
        over_line_cap_count: census.over_line_cap_count,
        recognized_usage_drop_count: census.recognized_usage_drop_count,
        ownership_incomplete_file_count: census.ownership_incomplete_file_count,
        ..ScanTraversalCounts::default()
    };
    if let Some(parts) = context_observation {
        claude_contract::started_context(&context_fingerprint, parts, roots);
    }
    index.traversal = Some(ScanTraversalCheckpoint {
        context_fingerprint,
        census_window_end: collected_at.to_string(),
        scan_roots,
        pending_directories,
        pending_candidates: VecDeque::new(),
        observed_index_keys: Default::default(),

        oversized_discovery: Default::default(),

        codex_rollout_paths: BTreeSet::new(),
        codex_join_directory_census: (source == SnapshotSource::Codex)
            .then(codex_file_join::DirectoryCensus::new),
        reconciliation_upper_bound: index.files.keys().next_back().into_iter().max().cloned(),
        reconciliation_after: None,
        reconciliation_started: false,
        watcher_hint_seen: false,
        codex_freshness_yield: false,
        retired_codex_parent_resolution_retry_required: serde::de::IgnoredAny,
        unhealthy_retry_attempt: retry_attempt,
        unhealthy_retry_not_before_unix_seconds: None,
        counts,
        residue: ScanTraversalResidue::default(),
        listing_started_unix_seconds: rfc3339_unix_seconds(collected_at),
        listing_owed_requeued_unix_seconds: Default::default(),
    });
    TraversalProgress::Started
}

/// Keep fitting pages together. Dedicated scheduling is only useful when
/// the queued population could spend the file or singleton byte allowance.
/// The estimate mirrors `PageBudget::plan`: a file larger than the singleton
/// allowance is cursor work with its own per-page budget, so it cannot spend
/// this one. Each indexed singleton also counts one sample pair for its memo
/// check. It never grants a read or increases a budget; an underestimate
/// only defers a file to the next page. Metadata failure keeps the ordinary
/// path and its existing error handling.
pub(in crate::snapshots) fn codex_selection_may_exhaust_page(
    traversal: &ScanTraversalCheckpoint,
    file_limit: usize,
    files: &SharedMap<String, ScanIndexEntry>,
) -> bool {
    if traversal.pending_candidates.len() > file_limit {
        return true;
    }
    let byte_limit = sampled_scan::codex_cursor::Limits::current().singleton();
    let mut expected = 0_u64;
    for candidate in &traversal.pending_candidates {
        let Ok(metadata) = fs::symlink_metadata(&candidate.path) else {
            continue;
        };
        if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > byte_limit {
            continue;
        }
        let samples = if files.contains_key(&local_index_key(&candidate.path)) {
            sampled_scan::codex_cursor::SAMPLE_READ_BYTES
        } else {
            0
        };
        expected = expected
            .saturating_add(metadata.len())
            .saturating_add(samples);
        if expected > byte_limit {
            return true;
        }
    }
    false
}

/// Codex scan-root sets whose last non-fresh selecting page was a census turn.
/// Scheduling only and RAM only: the index is reloaded every page, and a
/// restart costs at most one rotation. One entry per configured root set.
static CODEX_CENSUS_TURN_LAST: Mutex<BTreeSet<Vec<PathBuf>>> = Mutex::new(BTreeSet::new());

fn codex_census_turns() -> std::sync::MutexGuard<'static, BTreeSet<Vec<PathBuf>>> {
    CODEX_CENSUS_TURN_LAST.lock().unwrap_or_else(|poisoned| {
        CODEX_CENSUS_TURN_LAST.clear_poison();
        poisoned.into_inner()
    })
}

pub(in crate::snapshots) fn codex_census_turn_was_last(roots: &[PathBuf]) -> bool {
    codex_census_turns().contains(roots)
}

pub(in crate::snapshots) fn note_codex_census_turn(roots: &[PathBuf], census: bool) {
    let mut turns = codex_census_turns();
    if !census {
        turns.remove(roots);
    } else if !turns.contains(roots) {
        turns.insert(roots.to_vec());
    }
}

/// Priority only, never read admission. Byte length is content-relevant;
/// ctime, inode, permissions and mtime alone cannot promote an unchanged file.
/// New paths need a watcher/roster hint so a cold history walk stays FIFO.
pub(in crate::snapshots) fn codex_fresh_data_pending(
    candidate: &ScanTraversalPath,
    index: &ScanIndex,
) -> bool {
    let key = local_index_key(&candidate.path);
    let entry = index.files.get(&key);
    if entry.is_none() && !candidate.watcher_hint {
        return false;
    }
    fs::symlink_metadata(&candidate.path).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && index
                .codex_physical_matches(&key, &metadata)
                .ok()
                .flatten()
                .map(|(matched, _)| matched)
                .map_or_else(
                    || entry.map_or(true, |entry| entry.size_bytes != metadata.len()),
                    |unchanged| !unchanged,
                )
    })
}

/// Once a kept generation's latest walk has finished, re-list its roots
/// every `LISTING_INTERVAL_SECONDS`, metadata only, or at once when the
/// watcher cannot vouch for what changed (`list_all`). The pass queues only
/// changed or owed files (`ScanIndex::listing_unchanged`) and never starts a
/// generation, so it re-arms nothing; it can only delay this generation's
/// discovery, never complete it. A walk this page started has passed no
/// directory yet, so it serves the request itself; any other running walk is
/// never restarted, and the request stays in `list_all` for after it.
pub(in crate::snapshots) fn start_due_listing_pass(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    collected_at: &str,
    walk_started: bool,
    list_all: &mut ListingRequest,
) {
    let Some(now) = rfc3339_unix_seconds(collected_at) else {
        return;
    };
    let requested =
        list_all.requested() && (walk_started || traversal.pending_directories.is_empty());
    if requested {
        let request = std::mem::take(list_all);
        eprintln!(
            "local snapshot listing for {}: {request}",
            source.api_slug()
        );
    }
    if !traversal.pending_directories.is_empty() {
        return;
    }
    if !requested {
        let Some(started) = traversal.listing_started_unix_seconds else {
            traversal.listing_started_unix_seconds = Some(now);
            return;
        };
        if now < started.saturating_add(LISTING_INTERVAL_SECONDS) {
            return;
        }
    }
    traversal.listing_started_unix_seconds = Some(now);
    traversal.counts.listing_generations += 1;
    let roots = traversal.scan_roots.clone();
    traversal
        .pending_directories
        .extend(roots.into_iter().map(|root| ScanTraversalPath {
            scan_root: root.clone(),
            path: root,
            census_member: false,
            watcher_hint: false,
        }));
}

/// Whether this re-listing pass may queue an owed file whose stamp is
/// unchanged: once per file per `LISTING_OWED_PACE_SECONDS`, measured from
/// the start of the pass that queued it.
pub(in crate::snapshots) fn pace_listing_owed(
    traversal: &mut ScanTraversalCheckpoint,
    key: &str,
) -> bool {
    let Some(now) = traversal.listing_started_unix_seconds else {
        return true;
    };
    let fresh = |at: &u64| now < at.saturating_add(LISTING_OWED_PACE_SECONDS);
    let paced = &mut traversal.listing_owed_requeued_unix_seconds;
    if paced.get(key).is_some_and(&fresh) {
        return false;
    }
    paced.retain(|_, at| fresh(at));
    paced.insert(key.to_owned(), now);
    true
}

/// Watcher hints go through `ScanIndex::hint_settled`: a settled file
/// (ctime-only events included) is dropped; a vanished one is kept for the
/// exact removal path. Owner requests keep their unchanged files: a leased reason re-offer
/// here, the audit retry by calling the queue directly. A hint never admits a
/// first read past the first-read bound.
pub(in crate::snapshots) fn changed_watcher_hints(
    index: &ScanIndex,
    hinted_paths: &[PathBuf],
) -> Vec<PathBuf> {
    let census_unix_seconds = index
        .traversal
        .as_ref()
        .and_then(|walk| rfc3339_unix_seconds(&walk.census_window_end));
    hinted_paths
        .iter()
        .filter(|path| {
            index.reason_reoffer_leased(&local_index_key(path))
                || !fs::symlink_metadata(path).is_ok_and(|metadata| {
                    metadata.is_file()
                        && (index.hint_settled(path, &metadata)
                            || first_read_aged(
                                index,
                                path,
                                metadata
                                    .modified()
                                    .ok()
                                    .and_then(unix_seconds)
                                    .unwrap_or_default(),
                                census_unix_seconds,
                            ))
                })
        })
        .cloned()
        .collect()
}

/// A hinted or re-listed path joins the census unless this generation
/// already observed it on Codex (its growth is next-generation evidence).
pub(in crate::snapshots) fn fresh_path_census_member(
    source: SnapshotSource,
    traversal: &ScanTraversalCheckpoint,
    path: &Path,
) -> bool {
    source != SnapshotSource::Codex
        || !traversal
            .observed_index_keys
            .contains(&local_index_key(path))
}

/// Returns how many Codex hints re-entered as next-generation evidence.
pub(in crate::snapshots) fn enqueue_watcher_hints(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    hinted_paths: &[PathBuf],
    watcher_overflowed: bool,
) -> u64 {
    // Ordinary, bounded watcher paths are exact path hints. They join the
    // durable traversal census and are revalidated by the same no-follow open
    // and post-read identity checks as directory-discovered candidates. Only
    // overflow/backend loss makes the watcher evidence incomplete and forces a
    // following clean generation.
    traversal.watcher_hint_seen |= watcher_overflowed;
    let mut next_generation = 0_u64;
    let mut pending = traversal
        .pending_candidates
        .iter()
        .enumerate()
        .map(|(position, candidate)| (candidate.path.clone(), position))
        .collect::<BTreeMap<_, _>>();
    let ordered = hinted_paths.iter();
    for path in ordered {
        if !transcript_path_admitted(source, path)
            || (source == SnapshotSource::ClaudeCode
                && claude_transcript_excluded_from_snapshots(path))
        {
            continue;
        }

        if let Some(&position) = pending.get(path) {
            let member = fresh_path_census_member(source, traversal, path);
            if let Some(candidate) = traversal.pending_candidates.get_mut(position) {
                // Every source: order only; a vanished Claude/Pi path keeps its removal route.
                candidate.watcher_hint |=
                    source == SnapshotSource::Codex || fs::symlink_metadata(path).is_ok();
                // Claude/Pi: the hint joins the census as it would if nothing
                // were queued for it (a re-listed or re-read non-member).
                if source != SnapshotSource::Codex {
                    candidate.census_member |= member;
                }
            }
            continue;
        }
        let Some(scan_root) = traversal
            .scan_roots
            .iter()
            .find(|root| path.starts_with(root))
            .cloned()
        else {
            continue;
        };
        // A Codex path this generation already processed (observed and no
        // longer pending) was read after `census_window_end`, so its growth
        // is next-generation evidence. It is still read when the page budget
        // allows, but it no longer holds the census; the next generation's
        // walk re-reads it if it is stale.
        let census_member = fresh_path_census_member(source, traversal, path);
        next_generation += u64::from(source == SnapshotSource::Codex && !census_member);
        // FIFO keeps an actively rewritten path from repeatedly jumping ahead
        // of an older remove/rename hint in a small bounded page.
        pending.insert(path.clone(), traversal.pending_candidates.len());
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root,
            path: path.clone(),
            census_member,
            watcher_hint: true,
        });
    }
    next_generation
}

/// Keep a retained Codex generation's roster current without a re-walk.
///
/// A generation whose discovery finished but whose census is incomplete is
/// kept: a red one until its bounded retry, a green-but-incomplete one until it
/// completes. Its roster and directory witness are the ownership evidence for
/// every later page. Left frozen, one rollout created after the walk made each
/// page that selected it unprovable, and the whole page was held until the next
/// walk. Here only directories whose witness moved are re-listed, one level
/// deep: rollouts that appeared join the roster and the census candidates
/// exactly as the walk adds them, rollouts that left drop out of the roster,
/// and new subdirectories go through the ordinary bounded walk. Files already
/// in the roster are not re-selected here: the re-listing pass queues their
/// growth. A listing the walk would turn red (a
/// symlink, an unreadable entry, a change during the listing, a vanished
/// entry) refreshes nothing: that directory keeps its old witness and the
/// existing holds apply until a later tick or the next walk.
pub(in crate::snapshots) fn refresh_retained_codex_roster(
    source: SnapshotSource,
    index: &mut ScanIndex,
    backfill_window_days: u64,
    growth: Option<&discovery_growth::Page>,
) {
    let mut traversal = index.traversal.take().expect("traversal initialized");
    refresh_retained_codex_directories(source, &mut traversal, backfill_window_days, index, growth);
    index.traversal = Some(traversal);
}

fn refresh_retained_codex_directories(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    backfill_window_days: u64,
    index: &ScanIndex,
    growth: Option<&discovery_growth::Page>,
) {
    if source != SnapshotSource::Codex || codex_census_walk_pending(traversal) {
        return;
    }
    let recovery = DiscoveryRecovery::from(&index.files);
    let retention = DiscoveryRetention {
        growth,
        ..discovery_retention!(index)
    };
    let moved = match traversal.codex_join_directory_census.as_ref() {
        // An unproved walk stays unproved until a fresh generation.
        Some(census) if census.local_diagnostic_counts().0 => census.moved_directories(),
        _ => return,
    };
    let census_unix_seconds = rfc3339_unix_seconds(&traversal.census_window_end);
    for directory in moved {
        let Some(scan_root) = traversal.owning_scan_root(&directory).cloned() else {
            continue;
        };
        let census = traversal
            .codex_join_directory_census
            .as_mut()
            .expect("census checked above");
        let (before, (present, appeared, new_directories)) =
            match census.relist(&directory, &traversal.codex_rollout_paths) {
                Ok(Some(listing)) => listing,
                Ok(None) if directory != scan_root => {
                    census.retire(&directory);
                    traversal
                        .codex_rollout_paths
                        .retain(|key| !Path::new(key).starts_with(&directory));
                    continue;
                }
                _ => continue,
            };
        census.refresh(&directory, &before);
        traversal.codex_rollout_paths.retain(|key| {
            Path::new(key).parent() != Some(directory.as_path()) || present.contains(key)
        });
        for (path, metadata) in appeared {
            traversal.codex_rollout_paths.insert(local_index_key(&path));
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(unix_seconds)
                .unwrap_or_default();
            retention.observe_stamped_growth(
                &path,
                metadata.len(),
                modified_unix_seconds,
                codex_fragment::Stamp::metadata(&metadata),
            );
            let aged = census_unix_seconds.is_some_and(|now| {
                !is_recent_enough_at(modified_unix_seconds, now, backfill_window_days)
            });
            let owes_stamped = aged
                && retention.owes_stamped(
                    source,
                    &path,
                    metadata.len(),
                    codex_fragment::Stamp::metadata(&metadata),
                );
            let requires_recovery = recovery.requires(source, &path, metadata.len());
            if !requires_recovery && aged && !owes_stamped {
                line_delivery_unselected(source.api_slug(), UnselectedReason::Age);
                continue;
            }
            if first_read_aged(index, &path, modified_unix_seconds, census_unix_seconds) {
                line_delivery_unselected(source.api_slug(), UnselectedReason::FirstReadAge);
                continue;
            }
            crate::local_resource_diagnostics::observe_file_size(source, metadata.len());
            traversal.counts.max_unread_bytes = traversal.counts.max_unread_bytes.max(
                metadata.len().saturating_sub(
                    retention
                        .files
                        .get(&local_index_key(&path))
                        .map_or(0, |entry| entry.size_bytes),
                ),
            );
            traversal.counts.discovered_file_count += 1;
            traversal.observed_index_keys.insert(local_index_key(&path));

            if let Some(existing) = traversal
                .pending_candidates
                .iter_mut()
                .find(|candidate| candidate.path == path)
            {
                existing.census_member = true;
                existing.watcher_hint = true;
            } else {
                traversal.pending_candidates.push_back(ScanTraversalPath {
                    scan_root: scan_root.clone(),
                    path,
                    census_member: true,
                    watcher_hint: true,
                });
            }
        }
        // A directory that appeared after the walk (a new Codex day) carries
        // the same freshness provenance as a rollout that appeared directly;
        // the walk hands it to every file beneath. Scheduling only.
        traversal
            .pending_directories
            .extend(new_directories.into_iter().map(|path| ScanTraversalPath {
                scan_root: scan_root.clone(),
                path,
                census_member: true,
                watcher_hint: true,
            }));
    }
}

/// F5: queue `keys` again as census members of the generation that observed
/// them. Each passes the ordinary candidate gate on a later page: one counted
/// read. Keys not observed, already queued or outside every root are skipped.
pub(in crate::snapshots) fn requeue_observed_keys(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
    keys: Vec<String>,
    cause: &'static str,
) {
    let queued = traversal
        .pending_candidates
        .iter()
        .map(|candidate| local_index_key(&candidate.path))
        .collect::<BTreeSet<_>>();
    let owed = keys
        .into_iter()
        .filter(|key| traversal.observed_index_keys.contains(key) && !queued.contains(key))
        .filter_map(|key| {
            let path = PathBuf::from(key);
            Some(ScanTraversalPath {
                scan_root: traversal.owning_scan_root(&path)?.clone(),
                path,
                census_member: true,
                watcher_hint: false,
            })
        })
        .collect::<Vec<_>>();
    if owed.is_empty() {
        return;
    }
    crate::local_resource_diagnostics::traversal_point(
        "discovery_requeue",
        source.api_slug(),
        &json!({"cause": cause, "requeued": owed.len()}),
    );
    traversal.pending_candidates.extend(owed);
}

/// F5, checkpoints an older binary wrote: once per process, queue again the
/// files a retained generation observed but never indexed. Its partial
/// checkpoint kept the page's traversal (file dequeued and observed) without
/// the unacknowledged entry, so the file waited for the next generation (K7).
/// Files another record owns (residue, inventory hold, terminal disposition,
/// decode hold), or gone are left alone.
pub(in crate::snapshots) fn requeue_unindexed_observed(
    source: SnapshotSource,
    index: &mut ScanIndex,
) {
    let Some(traversal) = index.traversal.as_ref() else {
        return;
    };
    let orphans = traversal
        .observed_index_keys
        .iter()
        .filter(|key| {
            !index.files.contains_key(*key)
                && !traversal.residue.index_keys.contains(*key)
                && !traversal
                    .residue
                    .codex_inventory_hold
                    .as_ref()
                    .is_some_and(|hold| hold.owed.contains(*key))
                && !index.terminal_jsonl_dispositions.contains_key(*key)
                && !index.claude_account_deferred_holds.contains_key(*key)
                && !index.decode_holds_file(key)
                && fs::symlink_metadata(key)
                    .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        })
        .cloned()
        .collect::<Vec<_>>();
    let traversal = index.traversal.as_mut().expect("traversal checked above");
    requeue_observed_keys(source, traversal, orphans, "load");
}

/// Remember the candidates an incomplete Codex header inventory held on this
/// page, with what made it incomplete. With an incomplete inventory every
/// selected candidate is held, so this page's residue is exactly the held
/// set. An inventory that hit a population or read bound, or had no stable
/// census, records nothing: only a fresh walk changes that, and the walk
/// selects them again.
pub(in crate::snapshots) fn record_codex_inventory_hold(
    traversal: &mut ScanTraversalCheckpoint,
    inventory: &codex_file_join::HeaderInventory,
    held: &BTreeSet<String>,
) {
    if held.is_empty() {
        return;
    }
    let outside_roster = held
        .iter()
        .filter(|key| !traversal.codex_rollout_paths.contains(*key))
        .map(|key| (key.clone(), codex_file_join::path_witness(Path::new(key))))
        .collect::<Vec<_>>();
    let census_walk_pending = codex_census_walk_pending(traversal);
    let hold = traversal
        .residue
        .codex_inventory_hold
        .get_or_insert_with(CodexInventoryHold::default);
    // Without a refused record or an unlisted candidate, the walk's open
    // directories were what kept the roster from proving the page.
    hold.awaiting_directories |=
        census_walk_pending || (inventory.refused.is_empty() && outside_roster.is_empty());
    hold.owed.extend(held.iter().cloned());
    // The newest witness is the one a later tick has to see move.
    hold.refused_headers.extend(
        inventory
            .refused
            .iter()
            .map(|(key, witness)| (key.clone(), witness.clone())),
    );
    hold.outside_roster.extend(outside_roster);
}

/// Queue the candidates of a `CodexInventoryHold` again once its evidence
/// has moved: a refused first record changed, was replaced, is gone or left
/// the roster; a held
/// candidate outside the roster joined it or is gone; or the walk finished its
/// directories. The check costs one `lstat` per recorded path. Unmoved
/// evidence queues nothing, so a hold that cannot be resolved re-reads no
/// transcript. Only candidates still in the roster are queued, at the back,
/// after any watcher hints, and they meet the same inventory, ownership,
/// capture, send and checkpoint gates as any candidate. If the evidence still
/// does not prove the page, it is held and recorded again.
pub(in crate::snapshots) fn release_codex_inventory_hold(
    source: SnapshotSource,
    traversal: &mut ScanTraversalCheckpoint,
) {
    if source != SnapshotSource::Codex || codex_census_walk_pending(traversal) {
        return;
    }
    let Some(hold) = traversal.residue.codex_inventory_hold.as_ref() else {
        return;
    };
    let moved = |key: &String, witness: &Option<String>| {
        codex_file_join::path_witness(Path::new(key)) != *witness
    };
    let released = hold.awaiting_directories
        || hold.refused_headers.iter().any(|(key, witness)| {
            // A record that vanished before its read has no witness to move;
            // leaving the roster is its evidence.
            !traversal.codex_rollout_paths.contains(key) || moved(key, witness)
        })
        || hold.outside_roster.iter().any(|(key, witness)| {
            traversal.codex_rollout_paths.contains(key) || moved(key, witness)
        });
    if !released {
        return;
    }
    let hold = traversal
        .residue
        .codex_inventory_hold
        .take()
        .expect("hold checked above");
    let mut pending = traversal
        .pending_candidates
        .iter()
        .map(|candidate| local_index_key(&candidate.path))
        .collect::<BTreeSet<_>>();
    let mut unlisted = CodexInventoryHold::default();
    for key in hold.owed {
        if !traversal.codex_rollout_paths.contains(&key) {
            // Selecting a file the roster cannot prove would hold the page
            // again. One that still exists stays owed until it is listed.
            if let Some(witness) = codex_file_join::path_witness(Path::new(&key)) {
                unlisted.outside_roster.insert(key.clone(), Some(witness));
                unlisted.owed.insert(key);
            }
            continue;
        }
        if !pending.insert(key.clone()) {
            continue;
        }
        let path = PathBuf::from(key);
        let Some(scan_root) = traversal.owning_scan_root(&path).cloned() else {
            continue;
        };
        traversal.pending_candidates.push_back(ScanTraversalPath {
            scan_root,
            path,
            census_member: true,
            watcher_hint: false,
        });
    }
    if !unlisted.owed.is_empty() {
        traversal.residue.codex_inventory_hold = Some(unlisted);
    }
}
