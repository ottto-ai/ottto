//! RAM scheduling only. No persisted field, read authority or absence credit.
use super::*;
use crate::transcript_acquisition::AuditDebt;

pub(super) const TERMINAL_OFF_FRESHNESS_WALK_CEILING_SECONDS: u64 = 1800;
const OBSERVATIONS_PER_SCOPE: usize = MAX_BACKFILL_FILES_PER_SOURCE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stat {
    length: u64,
    modified: Option<u128>,
    identity: Option<[u64; 2]>,
    birth: u64,
}
impl Stat {
    fn capture(metadata: &fs::Metadata) -> Option<Self> {
        (metadata.is_file() && !metadata.file_type().is_symlink()).then(|| Self {
            length: metadata.len(),
            modified: metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_nanos()),
            identity: physical_identity(metadata),
            birth: metadata
                .created()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .and_then(|d| u64::try_from(d.as_nanos()).ok())
                .unwrap_or(0),
        })
    }
}
#[derive(Clone, Default)]
struct Observation {
    stat: Option<Stat>,
    round: u64,
    first_seen: u64,
    targeted: Option<[u8; 32]>,
    served: Option<(Option<Stat>, [u8; 32])>,
    served_root: Option<[u8; 32]>,
    served_at: Option<u64>,
}
#[derive(Clone, Default)]
struct Walk {
    now: u64,
    last_walk: Option<u64>,
    coalesced_since: Option<u64>,
    round: u64,
    suppressing: bool,
    target_cursor: Option<String>,
    held_roots: BTreeSet<String>,
    oversized: BTreeSet<String>,
    observations: BTreeMap<[u8; 32], Observation>,
}
#[cfg(test)]
thread_local! {
    static WALKS: std::cell::RefCell<BTreeMap<String, Walk>> = const { std::cell::RefCell::new(BTreeMap::new()) };
}
// Bound aggregate metadata too: a busy installation cannot multiply a
// full cohort by all 64 context slots. Eviction permits extra stat work only.
fn trim(memo: &mut BTreeMap<String, Walk>) {
    while memo.values().map(|w| w.observations.len()).sum::<usize>() > 4 * OBSERVATIONS_PER_SCOPE {
        let oldest = memo
            .iter()
            .min_by_key(|(_, w)| w.last_walk)
            .map(|(k, _)| k.clone())
            .unwrap();
        memo.remove(&oldest);
        eprintln!("terminal_off_observation_scope_evicted scopes=1");
    }
}
fn with_walks<T>(f: impl FnOnce(&mut BTreeMap<String, Walk>) -> T) -> T {
    #[cfg(test)]
    {
        WALKS.with(|v| {
            let mut memo = v.borrow_mut();
            let result = f(&mut memo);
            trim(&mut memo);
            result
        })
    }
    #[cfg(not(test))]
    {
        static WALKS: std::sync::OnceLock<std::sync::Mutex<BTreeMap<String, Walk>>> =
            std::sync::OnceLock::new();
        let mut memo = WALKS
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let result = f(&mut memo);
        trim(&mut memo);
        result
    }
}
fn digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}
fn observation<'a>(walk: &'a mut Walk, key: &str) -> &'a mut Observation {
    let key = digest(key);
    if !walk.observations.contains_key(&key) && walk.observations.len() >= OBSERVATIONS_PER_SCOPE {
        let oldest = walk
            .observations
            .iter()
            .min_by_key(|(_, v)| v.first_seen)
            .map(|(k, _)| *k)
            .unwrap();
        walk.observations.remove(&oldest);
        eprintln!("terminal_off_observation_evicted keys=1: metadata retry allowed, never proof");
    }
    let now = walk.now;
    walk.observations.entry(key).or_insert_with(|| Observation {
        first_seen: now,
        ..Default::default()
    })
}
fn blocked(walk: &Walk, key: &str, stat: Option<Stat>, token: Option<[u8; 32]>) -> bool {
    let held = claude_index_path_member_ref(Path::new(key)).is_some_and(|m| {
        walk.held_roots
            .contains(&claude_full_rearm_root_digest(m.root))
    });
    (held
        || walk
            .oversized
            .contains(&oversized_discovery::path_hash(Path::new(key))))
        && walk.observations.get(&digest(key)).is_some_and(|o| {
            // A frozen census window cannot renew a retry floor. Every real
            // serve starts this key's next six-hour floor in process memory.
            o.served_at
                .is_some_and(|at| walk.now < at.saturating_add(6 * 3600))
                && stat.is_some_and(|s| s.identity.is_some() && s.modified.is_some() && s.birth > 0)
                && o.served.is_some_and(|(old, revision)| {
                    old == stat && token.map_or(true, |t| t == revision)
                })
        })
}
fn revision(index: &ScanIndex, key: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    for value in [
        index
            .active_upload_context_fingerprint
            .as_deref()
            .unwrap_or(""),
        index.historical_replay_generation.as_deref().unwrap_or(""),
    ] {
        update_length_prefixed(&mut h, value.as_bytes());
    }
    h.update(index.context_curve_replay_epoch.to_be_bytes());
    h.update(
        index
            .active_effective_upload_body_witness_revision
            .to_be_bytes(),
    );
    let _ = key;
    update_length_prefixed(&mut h, LOCAL_SCAN_INDEX_IDENTITY_VERSION.as_bytes());
    update_length_prefixed(
        &mut h,
        index
            .claude_request_identity_contract
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
    );
    h.update([u8::from(index.claude_request_identity_contract_changed)]);
    h.finalize().into()
}

fn cause(index: &ScanIndex, key: &str, now: u64) -> Option<&'static str> {
    let entry = index.files.get(key)?;
    let debt = sampled_audit::debt_for_key(index, key, now);
    let mintable = entry.last_upload_body_witness.is_some()
        && index
            .file_snapshot_fingerprints
            .get(key)
            .is_some_and(|v| !v.is_empty());
    let contract_retry = index
        .terminal_contract_retries
        .values()
        .any(|owner| owner == key);

    let cause = if contract_retry {
        "activity_or_quarantine_retry"
    } else if entry.source_file_fingerprint.is_empty() {
        "cleared_fingerprint"
    } else if !entry.has_unverified_source()
        && entry.scan_identity_version.as_deref() != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    {
        "identity_version"
    } else if mintable && index.effective_upload_body_witness_revision_requires_adoption(key) {
        "body_witness_revision"
    } else if mintable && index.file_upload_context_requires_adoption(key) {
        "upload_context"
    } else if debt.is_some_and(|d| now >= d.due_unix_seconds) {
        "audit_due"
    } else {
        return None;
    };
    Some(cause)
}

fn service_token(
    token: [u8; 32],
    debt: Option<AuditDebt>,
    stat: Option<Stat>,
    cause: &str,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(token);
    update_length_prefixed(&mut h, cause.as_bytes());
    h.update(debt.map_or(0, |d| d.due_unix_seconds).to_be_bytes());
    if let Some(s) = stat {
        h.update(s.length.to_be_bytes());
        h.update(s.modified.unwrap_or(0).to_be_bytes());
        for n in s.identity.unwrap_or_default() {
            h.update(n.to_be_bytes());
        }
        h.update(s.birth.to_be_bytes());
    }
    h.finalize().into()
}

/// A watcher is an immediate key hint, never evidence of a completed walk.
pub(super) fn hint_allowed(traversal: &ScanTraversalCheckpoint, path: &Path) -> bool {
    if !claude_terminal_off() {
        return true;
    }

    let Some(scope) = terminal_off_traversal_scope(traversal) else {
        return true;
    };
    let key = local_index_key(path);
    let stat = fs::symlink_metadata(path)
        .ok()
        .and_then(|m| Stat::capture(&m));
    let floor_blocked = with_walks(|memo| {
        memo.get(&scope)
            .is_some_and(|w| blocked(w, &key, stat, None))
    });
    // A one-shot watcher hint keeps its queue custody through backoff.
    // The ordinary selector owns the #903 open gate, not this enqueue.
    !floor_blocked
}

/// `false`: coalesce a requested walk; `true`: start it. Targeted work is
/// independent. Unknown/restarted RAM state permits one walk without proof.
pub(super) fn prepare(index: &mut ScanIndex, now: u64, _at: &str, requested: bool) -> bool {
    if !claude_terminal_off() {
        return false;
    }

    let scope = terminal_off_rediscovery_scope(index).expect("traversal");
    let traversal = index.traversal.as_ref().unwrap();
    let empty = traversal.pending_directories.is_empty() && traversal.pending_candidates.is_empty();
    let held_roots = index
        .claude_full_rearm_progress
        .held_family_roots
        .clone()
        .unwrap_or_default();
    let oversized = traversal.oversized_discovery.keys().cloned().collect();
    let (start, new_round, coalesced, ceiling, interval, oldest, metadata_bytes) =
        with_walks(|memo| {
            if !memo.contains_key(&scope) && memo.len() >= TERMINAL_OFF_REDISCOVERY_SCOPES {
                let oldest = memo
                    .iter()
                    .min_by_key(|(_, w)| w.last_walk)
                    .map(|(k, _)| k.clone())
                    .unwrap();
                memo.remove(&oldest);
            }
            let walk = memo.entry(scope).or_default();
            walk.now = now;
            walk.held_roots = held_roots;
            walk.oversized = oversized;

            let ceiling = !empty
                && walk.last_walk.is_some_and(|last| {
                    now.saturating_sub(last) >= TERMINAL_OFF_FRESHNESS_WALK_CEILING_SECONDS
                });
            let start = requested && (empty || walk.last_walk.is_none() || ceiling);
            let coalesced = requested && !start;
            if coalesced {
                walk.coalesced_since.get_or_insert(now);
            }
            let interval = walk.last_walk.map_or(0, |last| now.saturating_sub(last));
            let oldest = traversal
                .pending_candidates
                .iter()
                .map(|p| {
                    walk.observations
                        .get(&digest(&local_index_key(&p.path)))
                        .map_or(walk.coalesced_since.unwrap_or(now), |o| o.first_seen)
                })
                .min()
                .map_or(0, |since| now.saturating_sub(since));
            if start {
                walk.last_walk = Some(now);
                walk.coalesced_since = None;
                walk.suppressing = !empty;
                if empty {
                    walk.round = walk.round.saturating_add(1);
                    for o in walk.observations.values_mut() {
                        o.targeted = None;
                    }
                }
            }
            (
                start,
                start && empty,
                coalesced,
                start && ceiling,
                interval,
                oldest,
                crate::heap_layout_bound::completed_bound(walk, 64 * 1024 * 1024),
            )
        });
    if ceiling {
        // Start the capped root probe now, even if an older directory queue
        // is long. Preserve its entries; only metadata roots take priority.
        let traversal = index.traversal.as_mut().unwrap();
        for root in traversal.scan_roots.iter().rev() {
            let prior = traversal
                .pending_directories
                .iter()
                .position(|p| p.path == *root)
                .and_then(|i| traversal.pending_directories.remove(i));
            traversal
                .pending_directories
                .push_front(prior.unwrap_or_else(|| ScanTraversalPath {
                    scan_root: root.clone(),
                    path: root.clone(),
                    census_member: true,
                    watcher_hint: false,
                }));
        }
    }
    if new_round {
        index
            .traversal
            .as_mut()
            .unwrap()
            .observed_index_keys
            .clear();
    }
    // Lead B's name is also E3's rediscovery_ceiling_forced; one counter.
    crate::local_resource_diagnostics::traversal_point(
        "terminal_off_freshness",
        "claude_code",
        &json!({
            "rediscovery_coalesced": u64::from(coalesced), "root_walk_forced_by_freshness_cap": u64::from(ceiling),
            "walk_interval_seconds": interval, "oldest_unscanned_age_seconds": oldest, "observation_metadata_bytes":metadata_bytes, "bytes":0
        }),
    );
    start
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WalkPath {
    Enqueue,
    ObserveOnly,
    SkipAlreadyObserved,
}

pub(super) fn walk_path(
    traversal: &ScanTraversalCheckpoint,
    path: &Path,
    metadata: &fs::Metadata,
    pending: bool,
    watcher: bool,
) -> WalkPath {
    if !claude_terminal_off() {
        return WalkPath::Enqueue;
    }

    let Some(scope) = terminal_off_traversal_scope(traversal) else {
        return WalkPath::Enqueue;
    };
    let key = local_index_key(path);
    let stat = Stat::capture(metadata);
    with_walks(|memo| {
        let Some(walk) = memo.get_mut(&scope) else {
            return WalkPath::Enqueue;
        };
        let enqueue_suppressed = !watcher && (pending || blocked(walk, &key, stat, None));
        if !watcher
            && walk.suppressing
            && stat.is_some_and(|s| s.identity.is_some() && s.modified.is_some() && s.birth > 0)
            && walk
                .observations
                .get(&digest(&key))
                .is_some_and(|o| o.round == walk.round && o.stat == stat)
        {
            return WalkPath::SkipAlreadyObserved;
        }
        let now = walk.now;
        let round = walk.round;
        let o = observation(walk, &key);
        if o.stat.is_none() || o.round != round {
            o.first_seen = now;
        }
        o.stat = stat;
        o.round = round;
        if metadata.len() > MAX_CLAUDE_JSONL_FILE_BYTES {
            o.served = Some((stat, [0; 32]));
            o.served_at = Some(now);
        }
        if enqueue_suppressed {
            WalkPath::ObserveOnly
        } else {
            WalkPath::Enqueue
        }
    })
}

pub(super) fn served(index: &ScanIndex, candidate: &CandidateFile, now: u64) {
    if !claude_terminal_off() {
        return;
    }

    let Some(scope) = terminal_off_rediscovery_scope(index) else {
        return;
    };
    let key = local_index_key(&candidate.path);
    let token = revision(index, &key);
    let stat = Some(Stat {
        length: candidate.size_bytes,
        modified: Some(candidate.modified_unix_nanos as u128),
        identity: candidate.physical_identity,
        birth: candidate.fingerprint_birth_nanos,
    });
    let debt = sampled_audit::debt_for_key(index, &key, now);
    let cause = cause(index, &key, now).unwrap_or("watcher_stat_change");
    with_walks(|memo| {
        if let Some(walk) = memo.get_mut(&scope) {
            let round = walk.round;
            let now = walk.now;
            let o = observation(walk, &key);
            if o.round != round {
                o.first_seen = now;
            }
            o.stat = stat;
            o.round = round;
            o.served = Some((stat, token));
            o.served_at = Some(now);
            o.served_root = Some(digest(&local_index_key(&candidate.scan_root)));
            o.targeted = Some(service_token(token, debt, stat, cause));
        }
    });
}

pub(super) fn targeted(index: &mut ScanIndex, now: u64, limit: usize) {
    if !claude_terminal_off() {
        return;
    }

    let Some(scope) = terminal_off_rediscovery_scope(index) else {
        return;
    };
    let mut pending = index
        .traversal
        .as_ref()
        .unwrap()
        .pending_candidates
        .iter()
        .map(|p| local_index_key(&p.path))
        .collect::<BTreeSet<_>>();
    if limit == 0 {
        return;
    }
    // Bound inspections (and thus stats), not merely successful admissions.
    // A RAM cursor gives blocked/served cohorts fair turns without an O(N)
    // metadata sweep on each page. Losing it only restarts scheduling.
    let cursor = with_walks(|m| m.get(&scope).and_then(|w| w.target_cursor.clone()));
    let keys = if let Some(cursor) = cursor.as_ref() {
        index
            .files
            .range((
                std::ops::Bound::Excluded(cursor.clone()),
                std::ops::Bound::Unbounded,
            ))
            .chain(index.files.range(..=cursor.clone()))
            .take(limit)
            .map(|(k, _)| k.clone())
            .collect::<Vec<_>>()
    } else {
        index.files.keys().take(limit).cloned().collect::<Vec<_>>()
    };
    let inspected = keys.len();
    let mut stats = 0;
    if let Some(last) = keys.last() {
        with_walks(|m| {
            if let Some(w) = m.get_mut(&scope) {
                w.target_cursor = Some(last.clone());
            }
        });
    }
    let mut selected = Vec::new();
    for key in &keys {
        if pending.contains(key)
            || sampled_audit::candidate_open_blocked(key, now)
            || index.file_upload_context_waits_for_retry(key)
        {
            continue;
        }
        let debt = sampled_audit::debt_for_key(index, key, now);
        if debt.is_some_and(|d| now < d.due_unix_seconds) {
            continue;
        }
        let Some(cause) = cause(index, key, now) else {
            continue;
        };
        let token = revision(index, key);
        stats += 1;
        let stat = fs::symlink_metadata(key)
            .ok()
            .and_then(|m| Stat::capture(&m));
        let retry_ready = sampled_audit::failed_open_retry_ready(key, now);
        let admitted = with_walks(|memo| {
            let Some(walk) = memo.get_mut(&scope) else {
                return false;
            };
            if blocked(walk, key, stat, Some(token)) {
                return false;
            }
            let token = service_token(token, debt, stat, cause);
            let o = observation(walk, key);
            if o.targeted == Some(token) && !retry_ready {
                return false;
            }
            o.targeted = Some(token);
            true
        });
        if !admitted {
            continue;
        }
        let traversal = index.traversal.as_ref().unwrap();
        let served_root = with_walks(|m| {
            m.get(&scope)
                .and_then(|w| w.observations.get(&digest(key)))
                .and_then(|o| o.served_root)
        });
        // Preserve actual native acquisition custody. Only cold keys without
        // an admitted/served owner use the traversal's existing inference.
        let root = served_root
            .and_then(|owner| {
                traversal
                    .scan_roots
                    .iter()
                    .find(|root| digest(&local_index_key(root)) == owner)
                    .cloned()
            })
            .or_else(|| {
                index
                    .claude_full_rearm_progress
                    .terminal_off_admitted
                    .iter()
                    .find(|p| {
                        local_index_key(&p.path) == *key
                            && traversal.scan_roots.contains(&p.scan_root)
                    })
                    .map(|p| p.scan_root.clone())
            })
            .or_else(|| traversal.owning_scan_root(Path::new(key)).cloned());
        let Some(root) = root else {
            continue;
        };
        selected.push(ScanTraversalPath {
            scan_root: root,
            path: PathBuf::from(key),
            census_member: false,
            watcher_hint: false,
        });
        pending.insert(key.clone());
        crate::local_resource_diagnostics::traversal_point(
            "terminal_off_targeted",
            "claude_code",
            &json!({"cause":cause,"keys":1,"bytes":0}),
        );
    }
    index
        .traversal
        .as_mut()
        .unwrap()
        .pending_candidates
        .extend(selected);
    crate::local_resource_diagnostics::traversal_point(
        "terminal_off_target_inspections",
        "claude_code",
        &json!({"keys":inspected,"stat_operations":stats,"allowance":limit,"bytes":0}),
    );
}

crate::heap_layout_bound::fields!(Stat; length, modified, identity, birth);
crate::heap_layout_bound::fields!(Observation; stat, round, first_seen, targeted, served, served_root, served_at);
crate::heap_layout_bound::fields!(Walk; now, last_walk, coalesced_since, round, suppressing, target_cursor, held_roots, oversized, observations);

pub(super) fn retry_blocked(index: &ScanIndex, key: &str) -> bool {
    if !claude_terminal_off() {
        return false;
    }
    let Some(scope) = terminal_off_rediscovery_scope(index) else {
        return false;
    };
    let stat = fs::symlink_metadata(key)
        .ok()
        .and_then(|m| Stat::capture(&m));
    let token = revision(index, key);
    with_walks(|m| {
        m.get(&scope).is_some_and(|w| {
            blocked(w, key, stat, Some(token)) || sampled_audit::candidate_open_blocked(key, w.now)
        })
    })
}
