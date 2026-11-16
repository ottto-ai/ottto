//! When each Codex account on this Mac last created a session, so an account
//! with no session for 72 hours is read about every 22 hours instead of
//! every 6.
//!
//! The map is folded from every ordinary Codex scan page before the page's
//! progress is saved, so evidence a page consumes is recorded first. It
//! proves idleness only after a complete, loss-free census generation that
//! started after every break in observation (a page gap, a resume, a policy
//! stop) covered every home the read would use. Anything else fails open:
//! the account stays on the 6 hour cadence.
//!
//! The file stays on this Mac. It is never uploaded, logged, or put in
//! status, diagnostics or support bundles. Pair keys are the hashed account
//! and workspace ids snapshots already carry. Entries expire 90 days after
//! their time and are pruned by later folds; stopping collection deletes
//! nothing.

use super::{
    atomic_json_write, logins::LoginDiscovery, runtime_ready_grant, AccountIdentityHashes,
    GrantStore, StateBinding, GRANT_DIR, SENTINEL_FILE,
};
use crate::agent_status::AgentStatusCollection;
use crate::snapshots::{codex_creator_pair, rfc3339_unix_seconds, SnapshotItem, SourceScanResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) const ACTIVITY_FILE: &str = "account-activity.json";
const SCHEMA_VERSION: u16 = 1;
/// A page later than this after the previous one is a gap in observation.
const PAGE_GAP_SECONDS: u64 = 2 * 60 * 60;
/// How long an account must be unused, and observed, before it is idle.
pub(super) const IDLE_AFTER_SECONDS: u64 = 72 * 60 * 60;
/// The newest clean generation may be at most this old.
const ANCHOR_MAX_AGE_SECONDS: u64 = 24 * 60 * 60;
const CLOCK_SLACK_SECONDS: u64 = 5 * 60;
const RETENTION_SECONDS: u64 = 90 * 24 * 60 * 60;
/// A generation must admit files this many days old to cover the idle window.
const HORIZON_DAYS: u64 = 3;

/// Map files this process failed to replace. Until a full reset is written,
/// every account reading one is active.
static UNTRUSTED: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct ActivityMap {
    schema_version: u16,
    /// `None`: no runtime-ready consent at the last write.
    binding: Option<StateBinding>,
    /// Moved only by a full reset.
    tracking_since: u64,
    last_page_at: u64,
    last_page_current: bool,
    /// The latest loss, gap, resume or policy stop.
    barrier_at: Option<u64>,
    generation: Option<Generation>,
    anchor: Option<Anchor>,
    unattributed_at: Option<u64>,
    #[serde(default)]
    pair_unknown_at: BTreeMap<String, u64>,
    #[serde(default)]
    activity: BTreeMap<String, u64>,
}

/// The census generation pages are currently walking.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Generation {
    window_end: u64,
    homes: Vec<PathBuf>,
    clean: bool,
}

/// The latest complete, loss-free generation after every barrier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Anchor {
    window_end: u64,
    homes: Vec<PathBuf>,
}

impl fmt::Debug for ActivityMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivityMap")
            .field("schema_version", &self.schema_version)
            .field("bound", &self.binding.is_some())
            .field("tracking_since", &self.tracking_since)
            .field("last_page_at", &self.last_page_at)
            .field("last_page_current", &self.last_page_current)
            .field("barrier_at", &self.barrier_at)
            .field("generation", &self.generation)
            .field("anchor", &self.anchor)
            .field("unattributed", &self.unattributed_at.is_some())
            .field("pair_unknown", &self.pair_unknown_at.len())
            .field("activity", &self.activity.len())
            .finish()
    }
}

impl fmt::Debug for Generation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Generation")
            .field("window_end", &self.window_end)
            .field("homes", &self.homes.len())
            .field("clean", &self.clean)
            .finish()
    }
}

impl fmt::Debug for Anchor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Anchor")
            .field("window_end", &self.window_end)
            .field("homes", &self.homes.len())
            .finish()
    }
}

/// The activity map's file. Written only by the snapshot cycle; the
/// collector only reads it, and the atomic rename keeps every read whole.
pub(crate) struct ActivityStore {
    path: PathBuf,
}

impl fmt::Debug for ActivityStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivityStore")
            .finish_non_exhaustive()
    }
}

impl ActivityStore {
    pub(crate) fn in_support_dir(support_dir: &Path) -> Self {
        Self {
            path: support_dir.join(GRANT_DIR).join(ACTIVITY_FILE),
        }
    }

    /// The map beside the collector's state file.
    pub(super) fn beside(state_path: &Path) -> Self {
        Self {
            path: state_path.with_file_name(ACTIVITY_FILE),
        }
    }

    /// The map a tick may trust: none while this process could not record a
    /// page, and none when missing, corrupt or another schema.
    pub(super) fn load_trusted(&self) -> Option<ActivityMap> {
        if self.untrusted() {
            return None;
        }
        self.read()
    }

    fn read(&self) -> Option<ActivityMap> {
        let raw = fs::read(&self.path).ok()?;
        serde_json::from_slice::<ActivityMap>(&raw)
            .ok()
            .filter(|map| map.schema_version == SCHEMA_VERSION)
    }

    fn untrusted(&self) -> bool {
        untrusted_paths().contains(&self.path)
    }

    /// Replace the file. On failure the old file may survive, so it is
    /// removed and this process stops trusting the path until a full reset
    /// is written. When the removal fails too and the daemon restarts, the
    /// old map is trusted again (an accepted, disclosed residual). Errors are
    /// never formatted: they can name the path.
    fn write(&self, map: &ActivityMap, clears_untrusted: bool) {
        if atomic_json_write(&self.path, map).is_ok() {
            if clears_untrusted {
                untrusted_paths().remove(&self.path);
            }
            return;
        }
        let _ = fs::remove_file(&self.path);
        untrusted_paths().insert(self.path.clone());
    }

    /// A restart: this process forgets the paths it distrusted.
    #[cfg(test)]
    pub(super) fn forget_process_distrust(&self) {
        untrusted_paths().remove(&self.path);
    }
}

fn untrusted_paths() -> std::sync::MutexGuard<'static, BTreeSet<PathBuf>> {
    UNTRUSTED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What one ordinary Codex scan page tells the map.
pub(crate) struct Page<'a> {
    pub(crate) snapshots: &'a [SnapshotItem],
    /// Every Codex home the scan walked.
    pub(crate) homes: &'a [PathBuf],
    /// No state, sidecar, decode, home-list or file loss on this page.
    pub(crate) loss_free: bool,
    /// No cap or deferral left selected work for a later page.
    pub(crate) current: bool,
    pub(crate) census_complete: bool,
    /// The generation's census time; `None` when unreadable.
    pub(crate) window_end: Option<u64>,
    pub(crate) window_days: u64,
}

impl<'a> Page<'a> {
    pub(crate) fn of_scan(
        scan: &'a SourceScanResult,
        status: &'a AgentStatusCollection,
        decode_holds_empty: bool,
    ) -> Self {
        let no_loss_counts = [
            scan.symlink_rejected_count,
            scan.directory_entry_cap_exceeded_count,
            scan.unreadable_path_count,
            scan.oversized_file_count,
            scan.disappeared_file_count,
            scan.malformed_json_line_count,
            scan.invalid_utf8_line_count,
            scan.over_line_cap_count,
            scan.recognized_usage_drop_count,
            scan.ownership_incomplete_file_count,
            scan.zero_snapshot_usage_evidence_count,
        ]
        .iter()
        .all(|count| *count == 0)
            && scan.dropped_usage_record_count == 0;
        Self {
            snapshots: &scan.snapshots,
            homes: &status.codex_scan_homes,
            loss_free: scan.state_census_complete
                && scan.sidecar_census_complete
                && decode_holds_empty
                && no_loss_counts
                && status.codex_scan_homes_complete,
            current: !scan.scan_cap_hit
                && !scan.page_file_limit_hit
                && !scan.charge_deferred
                && scan.skipped_file_count_due_to_limit == 0,
            census_complete: scan.census_complete,
            window_end: rfc3339_unix_seconds(&scan.census_window_end),
            window_days: scan.backfill_window_days,
        }
    }
}

/// The snapshot cycle's hook for one finished ordinary Codex page.
pub(crate) fn fold_codex_page(support_dir: &Path, page: &Page<'_>) {
    fold(
        &ActivityStore::in_support_dir(support_dir),
        &GrantStore::in_support_dir(support_dir),
        &support_dir.join(SENTINEL_FILE),
        page,
        now_seconds(),
    );
}

/// A Codex policy stop: a barrier, written once per stop.
pub(crate) fn note_policy_stop(support_dir: &Path) {
    note_barrier(
        &ActivityStore::in_support_dir(support_dir),
        now_seconds(),
        true,
    );
}

/// Codex resumed after a pause: a barrier.
pub(crate) fn note_resume(support_dir: &Path) {
    note_barrier(
        &ActivityStore::in_support_dir(support_dir),
        now_seconds(),
        false,
    );
}

fn now_seconds() -> u64 {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap_or_default()
}

/// Fold one page. Without runtime-ready consent, or with the local off
/// switch present, nothing is observed and nothing is deleted; the binding
/// is dropped once, so the next consented page starts a full reset.
pub(super) fn fold(
    store: &ActivityStore,
    grants: &GrantStore,
    sentinel: &Path,
    page: &Page<'_>,
    now: u64,
) {
    let binding = runtime_ready_grant(grants)
        .ok()
        .filter(|_| !sentinel.is_file())
        .and_then(|grant| grant.backend_binding.as_ref().map(StateBinding::of));
    let Some(binding) = binding else {
        if let Some(mut map) = store.read().filter(|map| map.binding.is_some()) {
            map.binding = None;
            map.anchor = None;
            map.generation = None;
            store.write(&map, false);
        }
        return;
    };
    let untrusted = store.untrusted();
    let mut map = match store.read() {
        Some(map) if !untrusted && map.binding.as_ref() == Some(&binding) => map,
        previous => ActivityMap::reset(previous, binding, now),
    };
    if now.saturating_sub(map.last_page_at) > PAGE_GAP_SECONDS {
        map.add_barrier(now);
    }
    map.classify(page, now);
    map.observe(page.snapshots, now);
    map.last_page_at = now;
    map.prune(now);
    store.write(&map, untrusted);
}

/// A barrier on the existing map. `once` skips the write when a barrier
/// already follows the last page and no anchor is left to clear.
fn note_barrier(store: &ActivityStore, now: u64, once: bool) {
    let Some(mut map) = store.read() else {
        return;
    };
    if once && map.anchor.is_none() && map.barrier_at.is_some_and(|at| at >= map.last_page_at) {
        return;
    }
    map.add_barrier(now);
    store.write(&map, false);
}

impl ActivityMap {
    /// Pages may have run without a fold, so evidence may be gone for good:
    /// only 72 fresh hours of observation age it out. Observations are kept.
    fn reset(previous: Option<ActivityMap>, binding: StateBinding, now: u64) -> Self {
        let previous = previous.unwrap_or_default();
        Self {
            schema_version: SCHEMA_VERSION,
            binding: Some(binding),
            tracking_since: now,
            last_page_at: now,
            last_page_current: false,
            barrier_at: Some(now),
            generation: None,
            anchor: None,
            unattributed_at: previous.unattributed_at,
            pair_unknown_at: previous.pair_unknown_at,
            activity: previous.activity,
        }
    }

    /// A break in observation: only a clean generation started after it can
    /// anchor again. The 72 hour clock keeps running.
    fn add_barrier(&mut self, now: u64) {
        self.barrier_at = Some(now);
        self.anchor = None;
        if let Some(generation) = &mut self.generation {
            generation.clean = false;
        }
    }

    fn classify(&mut self, page: &Page<'_>, now: u64) {
        if !page.loss_free {
            self.add_barrier(now);
        }
        self.last_page_current = page.loss_free && page.current;
        let Some(window_end) = page.window_end else {
            if let Some(generation) = &mut self.generation {
                generation.clean = false;
            }
            return;
        };
        let mut homes = page.homes.to_vec();
        homes.sort();
        homes.dedup();
        let covers_horizon = page.window_days >= HORIZON_DAYS;
        match self
            .generation
            .as_mut()
            .filter(|generation| generation.window_end == window_end)
        {
            Some(generation) => {
                if generation.homes != homes || !covers_horizon {
                    generation.clean = false;
                }
            }
            None => {
                self.generation = Some(Generation {
                    window_end,
                    homes,
                    clean: page.loss_free && covers_horizon,
                });
            }
        }
        let Some(generation) = &self.generation else {
            return;
        };
        if page.loss_free
            && page.census_complete
            && generation.clean
            && self.barrier_at.is_none_or(|barrier| window_end > barrier)
        {
            self.anchor = Some(Anchor {
                window_end,
                homes: generation.homes.clone(),
            });
        }
    }

    fn observe(&mut self, snapshots: &[SnapshotItem], now: u64) {
        let latest = now.saturating_add(CLOCK_SLACK_SECONDS);
        for item in snapshots {
            let at = item
                .source_last_activity_at
                .as_deref()
                .and_then(rfc3339_unix_seconds)
                .filter(|at| *at <= latest);
            match (codex_creator_pair(item), at) {
                (Some((account, workspace)), Some(at)) => {
                    let last = self
                        .activity
                        .entry(pair_key(account, workspace))
                        .or_insert(at);
                    *last = (*last).max(at);
                }
                (Some((account, workspace)), None) => {
                    self.pair_unknown_at
                        .insert(pair_key(account, workspace), now);
                }
                (None, at) => {
                    self.unattributed_at = self.unattributed_at.max(Some(at.unwrap_or(now)));
                }
            }
        }
    }

    fn prune(&mut self, now: u64) {
        let live = |at: &u64| now.saturating_sub(*at) <= RETENTION_SECONDS;
        self.activity.retain(|_, at| live(at));
        self.pair_unknown_at.retain(|_, at| live(at));
        self.unattributed_at = self.unattributed_at.filter(live);
    }

    fn times(&self) -> impl Iterator<Item = u64> + '_ {
        [
            Some(self.tracking_since),
            Some(self.last_page_at),
            self.barrier_at,
            self.unattributed_at,
            self.generation
                .as_ref()
                .map(|generation| generation.window_end),
            self.anchor.as_ref().map(|anchor| anchor.window_end),
        ]
        .into_iter()
        .flatten()
        .chain(self.pair_unknown_at.values().copied())
        .chain(self.activity.values().copied())
    }
}

fn pair_key(account: &str, workspace: &str) -> String {
    format!("{account}:{workspace}")
}

/// Whether this login is proven idle: read about every 22 hours. Every
/// condition must hold; anything unproven keeps the 6 hour cadence.
pub(super) fn idle(
    map: Option<&ActivityMap>,
    discovery: &LoginDiscovery,
    binding: &StateBinding,
    first_seen: u64,
    identity: Option<&AccountIdentityHashes>,
    now: u64,
) -> bool {
    let (Some(map), Some(identity)) = (map, identity) else {
        return false;
    };
    let Some(anchor) = &map.anchor else {
        return false;
    };
    // Activity at `at` blocks idleness until it is strictly older than 72 h.
    let quiet = |at: Option<&u64>| at.is_none_or(|at| now.saturating_sub(*at) > IDLE_AFTER_SECONDS);
    let pair = pair_key(
        &identity.account_identifier_hash,
        &identity.provider_workspace_hash,
    );
    map.schema_version == SCHEMA_VERSION
        && map.binding.as_ref() == Some(binding)
        && map
            .times()
            .all(|at| at <= now.saturating_add(CLOCK_SLACK_SECONDS))
        && now.saturating_sub(map.tracking_since) >= IDLE_AFTER_SECONDS
        && now.saturating_sub(map.last_page_at) <= PAGE_GAP_SECONDS
        && map.last_page_current
        && map
            .barrier_at
            .is_none_or(|barrier| anchor.window_end > barrier)
        && anchor.window_end >= map.tracking_since
        && anchor.window_end >= now.saturating_sub(ANCHOR_MAX_AGE_SECONDS)
        && first_seen > 0
        && anchor.window_end >= first_seen
        && discovery.complete
        && discovery.codex_scan_enabled
        && discovery
            .coverage_homes
            .0
            .iter()
            .all(|home| anchor.homes.contains(home))
        && quiet(map.unattributed_at.as_ref())
        && quiet(map.pair_unknown_at.get(&pair))
        && quiet(map.activity.get(&pair))
}
