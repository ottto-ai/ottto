//! Audit status lives in the existing per-file index, never in a new ledger.
use super::*;
use crate::transcript_acquisition::{AuditDebt, AUDIT_INTERVAL_SECONDS};
use crate::transcript_cache::CACHE_ENTRIES;

// v1 did not distinguish an ordinary Tail from a published FE prefix.
pub(super) const UNVERIFIED_IDENTITY: &str = "semantic_sync:v2+sampled_unverified:v1";
const UNVERIFIED_STEM: &str = "semantic_sync:v2+sampled_unverified:";
const PROVENANCE_IDENTITY: &str = "semantic_sync:v2+sampled_unverified:v2";

// Deadline and provenance occupy the EXISTING version string. c = complete
// native recomposition; p = sealed prefix. No new inline or persisted field.
const MAX_MARKER_BYTES: usize = 64;
pub(super) fn marker(due: u64) -> String {
    provenance_marker(due, false)
}
fn provenance_marker(due: u64, prefix: bool) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(MAX_MARKER_BYTES);
    write!(
        &mut value,
        "{PROVENANCE_IDENTITY}:{due}:{}",
        if prefix { "p" } else { "c" }
    )
    .expect("bounded marker formats");
    value
}
fn decode_marker(version: &str) -> Option<(u64, bool)> {
    let (due, provenance) = version
        .strip_prefix(PROVENANCE_IDENTITY)?
        .strip_prefix(':')?
        .split_once(':')?;
    if due.is_empty() || !due.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let due = due.parse().ok()?;
    Some((
        due,
        match provenance {
            "c" => false,
            "p" => true,
            _ => return None,
        },
    ))
}
impl ScanIndexEntry {
    pub(super) fn has_unverified_source(&self) -> bool {
        self.scan_identity_version
            .as_deref()
            .is_some_and(|version| version.starts_with(UNVERIFIED_STEM))
    }
    /// FE writes every prefix tag under the sampled stem, and replay keeps stem
    /// entries, so only a stem can carry a prefix. A stem fails closed unless
    /// it decodes as a v2 c tag; None and legacy identities are not prefixes.
    pub(super) fn has_prefix_provenance(&self) -> bool {
        self.has_unverified_source()
            && self
                .scan_identity_version
                .as_deref()
                .is_some_and(|version| !matches!(decode_marker(version), Some((_, false))))
    }
    pub(super) fn unverified_deadline(&self) -> Option<u64> {
        if !self.has_unverified_source() {
            return None;
        }
        let version = self.scan_identity_version.as_deref()?;
        Some(
            decode_marker(version)
                .map(|(due, _)| due)
                .unwrap_or_else(|| {
                    // Preserve a v1 deadline, but never infer complete provenance.
                    version
                        .strip_prefix(UNVERIFIED_STEM)
                        .and_then(|tail| tail.strip_prefix("v1:"))
                        .filter(|due| {
                            !due.is_empty() && due.bytes().all(|byte| byte.is_ascii_digit())
                        })
                        .and_then(|due| due.parse().ok())
                        .unwrap_or(0)
                }),
        )
    }
    pub(super) fn set_unverified_deadline(&mut self, due: u64) {
        self.scan_identity_version = Some(provenance_marker(due, self.has_prefix_provenance()));
    }
    /// Only an existing sampled stem carries provenance. A missing or legacy
    /// identity still reads as prefix until re-recorded, but an ordinary
    /// record never mints `p`; FE marks its prefix after `record`.
    pub(super) fn carried_audit_version(&self) -> String {
        if self.has_unverified_source() {
            provenance_marker(
                self.unverified_deadline().unwrap_or(0),
                self.has_prefix_provenance(),
            )
        } else {
            LOCAL_SCAN_INDEX_IDENTITY_VERSION.into()
        }
    }
    pub(super) fn carry_sampled_audit(&mut self, working: &Self) {
        if let Some(due) = working.unverified_deadline() {
            self.scan_identity_version = Some(provenance_marker(
                self.unverified_deadline().map_or(due, |old| old.min(due)),
                self.has_prefix_provenance() || working.has_prefix_provenance(),
            ));
        }
    }
    pub(super) fn audit_obligation(&self, now: u64) -> Option<AuditDebt> {
        if !self.has_unverified_source() {
            return None;
        }
        let deadline = self
            .unverified_deadline()
            .filter(|deadline| {
                *deadline > 0
                    && now
                        .checked_add(AUDIT_INTERVAL_SECONDS)
                        .is_some_and(|latest| *deadline <= latest)
            })
            .unwrap_or(now);
        Some(AuditDebt {
            due_unix_seconds: deadline,
        })
    }
    pub(super) fn audit_requires_full(&self, now: u64) -> bool {
        self.audit_obligation(now)
            .is_some_and(|debt| now >= debt.due_unix_seconds)
    }
    pub(super) fn retain_history_evidence(&self) -> bool {
        self.codex_history_is_protected() || self.has_unverified_source()
    }
}
impl ScanIndex {
    /// Called only by a current validated native source completion. Entry/source
    /// equality fences an older completion; the existing writer owns lock/CAS.
    /// A delivery ACK never calls this method as source-verification authority.
    pub(super) fn stage_sampled_audit(
        &mut self,
        key: &str,
        source_fingerprint: &str,
        debt: AuditDebt,
    ) -> bool {
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        let due = entry
            .unverified_deadline()
            .map_or(debt.due_unix_seconds, |old| old.min(debt.due_unix_seconds));
        entry.set_unverified_deadline(due);
        true
    }
    /// This caller just finished a loss-free, EOF-revalidated native Full or
    /// Tail recomposition. FE never retains a prefix reduction in the cache,
    /// so a Tail here replays a complete retained baseline, not an FE body.
    /// Keep the audit debt: complete provenance is not Full-audit credit.
    pub(super) fn complete_native_recomposition(
        &mut self,
        key: &str,
        source_fingerprint: &str,
    ) -> bool {
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        if entry.has_prefix_provenance() {
            crate::local_resource_diagnostics::cache_lifecycle::record(
                crate::local_resource_diagnostics::cache_lifecycle::Event::PrefixTagCleared,
            );
        }
        entry.scan_identity_version = Some(
            entry
                .unverified_deadline()
                .map(marker)
                .unwrap_or_else(|| LOCAL_SCAN_INDEX_IDENTITY_VERSION.into()),
        );
        true
    }
    pub(super) fn mark_sealed_prefix(&mut self, key: &str, source_fingerprint: &str) -> bool {
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.source_file_fingerprint == source_fingerprint)
        else {
            return false;
        };
        entry.scan_identity_version = Some(provenance_marker(
            entry.unverified_deadline().unwrap_or(0),
            true,
        ));
        true
    }
    pub(super) fn complete_full_audit(&mut self, key: &str, source_fingerprint: &str) -> bool {
        if !self.complete_native_recomposition(key, source_fingerprint) {
            return false;
        }
        self.files
            .get_mut(key)
            .expect("validated entry")
            .scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        true
    }
}

/// An accepted sampled generation must be verified even after its activity
/// ages out. The existing bounded walk remains its sole scheduler. Other old
/// files keep the configured window, and secure opens/file caps still apply.
pub(super) fn path_requires_verification(
    files: &BTreeMap<String, ScanIndexEntry>,
    path: &Path,
) -> bool {
    files
        .get(&local_index_key(path))
        .is_some_and(ScanIndexEntry::has_unverified_source)
}

pub(super) fn normalize_marker_storage(index: &mut ScanIndex) {
    for entry in index
        .files
        .values_mut()
        .filter(|entry| entry.has_unverified_source())
    {
        if entry
            .scan_identity_version
            .as_ref()
            .is_some_and(|tag| tag.capacity() > MAX_MARKER_BYTES)
        {
            entry.set_unverified_deadline(0);
        }
    }
}

/// Restorations per sampled scan: under a steady scan cadence, at most one
/// restored audit falls due per page.
const HOLD_DEADLINE_RESTORES_PER_SCAN: usize = 1;

/// A plain-v2 entry whose census record is an N1 hold owes its deadline back
/// (option B below). Until a scan restores it, reconciliation keeps it as it
/// keeps a marked entry: an unobserved aged file must not be pruned, with its
/// hold, while it waits for the per-scan or audit-slot budget.
pub(super) fn awaits_hold_deadline_restoration(index: &ScanIndex, key: &str) -> bool {
    index.files.get(key).is_some_and(|entry| {
        entry.scan_identity_version.as_deref() == Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
    }) && index
        .claude_request_census
        .get(key)
        .is_some_and(|record| record.identity_incomplete_hold())
}

/// Option B (SOURCE rule 3: a hold may delay a re-offer, never cancel it). A
/// marker-erasing daemon (0.1.189's parse-free migrate) rewrote held entries
/// to plain v2, dropping their audit deadline; an unchanged file then skips
/// forever and an aged one leaves discovery. Re-derive the marker from the
/// persisted census hold: one interval out, as a Tail stages it, and tagged
/// `p` because plain v2 cannot prove the lost tag was `c`. Each restored
/// entry owes one Full; the deadline only delays it. Restorations take free
/// audit slots and always leave one, so sampling stays supported. A key
/// whose unattempted progress slot (or failed-open backoff) already owes an
/// earlier due keeps it: converting the obligation re-arms debt, never moves
/// it later (#865).
pub(super) fn restore_held_audit_deadlines(index: &mut ScanIndex, now: u64) -> usize {
    let pending = index
        .files
        .values()
        .filter(|entry| entry.has_unverified_source())
        .take(CACHE_ENTRIES)
        .count();
    let budget = CACHE_ENTRIES
        .saturating_sub(pending.saturating_add(1))
        .min(HOLD_DEADLINE_RESTORES_PER_SCAN);
    let Some(due) = now.checked_add(AUDIT_INTERVAL_SECONDS) else {
        return 0;
    };
    let keys = index
        .claude_request_census
        .records()
        .map(|(key, _)| key)
        .filter(|key| awaits_hold_deadline_restoration(index, key))
        .take(budget)
        .cloned()
        .collect::<Vec<_>>();
    let owed = index
        .held_audit_progress
        .as_ref()
        .filter(|slot| !slot.attempted && slot.due > 0)
        .map(|slot| (slot.key.clone(), slot.due));
    for key in &keys {
        let due = owed
            .as_ref()
            .filter(|(owed, _)| owed == key)
            .map_or(due, |(_, owed)| due.min(*owed));
        let due = with_open_backoff(|backoff| backoff.owed(key)).map_or(due, |owed| due.min(owed));
        if let Some(entry) = index.files.get_mut(key) {
            entry.scan_identity_version = Some(provenance_marker(due, true));
        }
    }
    if !keys.is_empty() {
        super::claude_request_census::note_identity_incomplete_hold_deadlines_restored(
            keys.len() as u64
        );
    }
    keys.len()
}

/// Saturated sampled slots must not make a plain-v2 hold wait for an
/// unrelated unavailable/oversized file forever. One durable rotating slot
/// schedules a native Full after a fresh interval, without allocating a
/// sampled marker or taking the last sampled slot. It grants no authority.
/// `attempted` is set only once the secure open succeeds. A failed open
/// rotates too but keeps the owed due, so debt never moves later; census
/// holds stay eligible for the next round. A key whose open keeps failing
/// backs off and then parks (`OpenBackoff`), and holds the slot only while no
/// other key can use it, so it never starves a readable member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct HeldAuditProgress {
    pub(super) key: String,
    pub(super) due: u64,
    pub(super) attempted: bool,
}
crate::heap_layout_bound::fields!(HeldAuditProgress; key, due, attempted);

pub(super) fn progress_debt(index: &ScanIndex, key: &str, now: u64) -> Option<AuditDebt> {
    let slot = index.held_audit_progress.as_ref()?;
    (slot.key == key && now >= slot.due && awaits_hold_deadline_restoration(index, key)).then_some(
        AuditDebt {
            due_unix_seconds: slot.due,
        },
    )
}

pub(super) fn debt_for_key(index: &ScanIndex, key: &str, now: u64) -> Option<AuditDebt> {
    index
        .files
        .get(key)
        .and_then(|entry| entry.audit_obligation(now))
        .or_else(|| progress_debt(index, key, now))
}

/// A held key the slot may serve: bounded, still awaiting restoration, and
/// owned by a scan root, so its Full can be queued.
fn progress_eligible(index: &ScanIndex, key: &str) -> bool {
    key.len() <= 4096
        && awaits_hold_deadline_restoration(index, key)
        && index
            .traversal
            .as_ref()
            .is_some_and(|traversal| traversal.first_matching_scan_root(Path::new(key)).is_some())
}

/// BTreeMap order plus a persisted cursor gives every held path a turn,
/// including when a prior turn failed its secure open/cap. A key that is
/// backing off or parked is chosen only when no other key is eligible: it
/// then holds the slot, and its due, without being queued.
fn next_progress_key(index: &ScanIndex, after: Option<&str>, now: u64) -> Option<String> {
    let records = || {
        index
            .claude_request_census
            .records()
            .map(|(key, _)| key)
            .filter(|key| progress_eligible(index, key.as_str()))
    };
    let pick = |blocked: bool| {
        let wanted = |key: &&String| open_blocked(key, now) == blocked;
        records()
            .filter(wanted)
            .find(|key| after.map_or(true, |after| key.as_str() > after))
            .or_else(|| records().find(wanted))
            .cloned()
    };
    pick(false).or_else(|| pick(true))
}

/// A slot for `key` never owes a later due than its failed-open backoff, or
/// than the same key's unattempted previous slot.
fn progress_slot(key: String, due: u64, previous: Option<&HeldAuditProgress>) -> HeldAuditProgress {
    let due = with_open_backoff(|backoff| backoff.owed(&key)).map_or(due, |owed| due.min(owed));
    let due = previous
        .filter(|slot| slot.key == key && !slot.attempted && slot.due > 0)
        .map_or(due, |slot| due.min(slot.due));
    HeldAuditProgress {
        key,
        due,
        attempted: false,
    }
}

/// GUARDRAILS rule 5: a progress Full whose secure open keeps failing backs
/// off instead of retrying every page: 1 page after the first failure,
/// doubling, each wait capped at 6 h. The eighth consecutive failure parks
/// the key (one alarm); a parked key is retried only after its stat changes,
/// or after a restart. RAM only: nothing here is persisted, and its owed due,
/// census hold and slot are never cleared or moved later.
const OPEN_PARK_FAILURES: u8 = 8;
const OPEN_BACKOFF_CAP_SECONDS: u64 = 6 * 60 * 60;
/// Census keys are at most 4 KiB, so the map stays bounded (about 1 MiB at
/// worst). On overflow the longest-quiet entry is evicted (counted) and that
/// key may retry (rule 7: fail toward reading); its owed due moves into the
/// slot with it, so the debt is never dropped or moved later.
const OPEN_BACKOFF_KEYS: usize = 256;

type OpenStamp = Option<[i64; 7]>;

fn open_stamp(key: &str) -> OpenStamp {
    let metadata = std::fs::metadata(key).ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some([
            metadata.dev() as i64,
            metadata.ino() as i64,
            metadata.size() as i64,
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ])
    }
    #[cfg(not(unix))]
    {
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |elapsed| elapsed.as_nanos() as i64);
        Some([metadata.len() as i64, modified, 0, 0, 0, 0, 0])
    }
}

#[derive(Debug, Clone)]
struct OpenFailure {
    failures: u8,
    owed_due: u64,
    first_failed: u64,
    last_failed: u64,
    retry_page: u64,
    stamp: OpenStamp,
}

#[derive(Debug)]
struct OpenBackoff {
    page: u64,
    keys: BTreeMap<String, OpenFailure>,
    /// Process total of overflow evictions.
    evicted: u64,
}

/// One recorded failure: `parked` exactly when it parks the key, and the
/// overflow-evicted key with its owed due.
struct RecordedFailure {
    parked: Option<OpenFailure>,
    evicted: Option<(String, u64)>,
}

impl OpenBackoff {
    const fn new() -> Self {
        Self {
            page: 0,
            keys: BTreeMap::new(),
            evicted: 0,
        }
    }
    fn blocked(&self, key: &str, now: u64) -> bool {
        self.keys.get(key).is_some_and(|failure| {
            (failure.failures >= OPEN_PARK_FAILURES
                || (self.page < failure.retry_page
                    && now < failure.last_failed.saturating_add(OPEN_BACKOFF_CAP_SECONDS)))
                && open_stamp(key) == failure.stamp
        })
    }
    fn owed(&self, key: &str) -> Option<u64> {
        self.keys.get(key).map(|failure| failure.owed_due)
    }
    fn record_failure(&mut self, key: &str, due: u64, now: u64) -> RecordedFailure {
        let mut evicted = None;
        if !self.keys.contains_key(key) && self.keys.len() >= OPEN_BACKOFF_KEYS {
            let quiet = self
                .keys
                .iter()
                .min_by_key(|(_, failure)| failure.last_failed)
                .map(|(key, _)| key.clone());
            if let Some(quiet) = quiet {
                evicted = self
                    .keys
                    .remove(&quiet)
                    .map(|failure| (quiet, failure.owed_due));
                self.evicted = self.evicted.saturating_add(1);
            }
        }
        let page = self.page;
        let failure = self.keys.entry(key.to_owned()).or_insert(OpenFailure {
            failures: 0,
            owed_due: due,
            first_failed: now,
            last_failed: now,
            retry_page: page,
            stamp: None,
        });
        failure.failures = failure.failures.saturating_add(1);
        failure.owed_due = failure.owed_due.min(due);
        failure.last_failed = now;
        failure.retry_page = page.saturating_add(1 << u32::from(failure.failures - 1).min(62));
        failure.stamp = open_stamp(key);
        RecordedFailure {
            parked: (failure.failures == OPEN_PARK_FAILURES).then(|| failure.clone()),
            evicted,
        }
    }
}

#[cfg(not(test))]
static OPEN_BACKOFF: std::sync::Mutex<OpenBackoff> = std::sync::Mutex::new(OpenBackoff::new());
#[cfg(test)]
thread_local! {
    static OPEN_BACKOFF: std::cell::RefCell<OpenBackoff> =
        const { std::cell::RefCell::new(OpenBackoff::new()) };
}

/// A leaf lock: `run` never takes another lock or re-enters.
fn with_open_backoff<T>(run: impl FnOnce(&mut OpenBackoff) -> T) -> T {
    #[cfg(not(test))]
    {
        run(&mut OPEN_BACKOFF
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }
    #[cfg(test)]
    OPEN_BACKOFF.with(|backoff| run(&mut backoff.borrow_mut()))
}

fn open_blocked(key: &str, now: u64) -> bool {
    with_open_backoff(|backoff| backoff.blocked(key, now))
}

/// Census-line counts: keys whose progress open failed and are still owed
/// (backing off or parked), and the age of the oldest first failure.
pub(super) fn held_audit_open_failed(now: u64) -> (usize, u64) {
    with_open_backoff(|backoff| {
        (
            backoff.keys.len(),
            backoff
                .keys
                .values()
                .map(|failure| now.saturating_sub(failure.first_failed))
                .max()
                .unwrap_or(0),
        )
    })
}

/// Census-line process total: overflow evictions from the backoff map.
pub(super) fn held_audit_open_backoff_evicted() -> u64 {
    with_open_backoff(|backoff| backoff.evicted)
}

#[cfg(test)]
pub(super) fn reset_open_backoff_for_test() {
    with_open_backoff(|backoff| *backoff = OpenBackoff::new());
}

#[cfg(test)]
mod open_backoff_tests;

/// The queued progress Full for `key` passed its secure open: the slot's
/// turn is spent, so the next preparation rotates to a fresh interval, and
/// any failed-open backoff ends.
pub(super) fn progress_opened(index: &mut ScanIndex, key: &str) {
    if let Some(slot) = index
        .held_audit_progress
        .as_mut()
        .filter(|slot| slot.key == key)
    {
        slot.attempted = true;
        with_open_backoff(|backoff| backoff.keys.remove(key));
    }
}

#[derive(Serialize)]
struct HeldAuditOpenParked {
    held_audit_open_failures: u8,
    held_audit_open_owed_age_seconds: u64,
    held_audit_open_failed_keys: usize,
}

/// The queued progress Full for `key` failed its secure open. Back the key
/// off (or park it), then rotate the turn, wrapping to `key` itself when no
/// other member is eligible, but keep the owed due: a failed open never
/// re-arms a later deadline.
pub(super) fn progress_open_failed(index: &mut ScanIndex, key: &str, now: u64) {
    let Some(due) = index
        .held_audit_progress
        .as_ref()
        .filter(|slot| slot.key == key && !slot.attempted)
        .map(|slot| slot.due)
    else {
        return;
    };
    let (recorded, keys) =
        with_open_backoff(|backoff| (backoff.record_failure(key, due, now), backoff.keys.len()));
    if let Some(parked) = recorded.parked {
        // Counts only; no path or id. Once per park.
        crate::local_resource_diagnostics::claude_held_audit_open_parked(&HeldAuditOpenParked {
            held_audit_open_failures: parked.failures,
            held_audit_open_owed_age_seconds: now.saturating_sub(parked.owed_due),
            held_audit_open_failed_keys: keys,
        });
    }
    let previous = index.held_audit_progress.take();
    // Rule 7: an overflow-evicted key may retry, so it takes the next turn,
    // and its owed due moves into the slot: the debt is never dropped.
    let (evicted, evicted_due) = recorded.evicted.unzip();
    index.held_audit_progress = evicted
        .filter(|evicted| progress_eligible(index, evicted))
        .or_else(|| next_progress_key(index, Some(key), now))
        .map(|next| {
            let mut slot = progress_slot(next, due, previous.as_ref());
            slot.due = evicted_due.map_or(slot.due, |owed| slot.due.min(owed));
            slot
        });
}

/// Select this page's progress slot: keep an unattempted, unblocked slot,
/// else rotate. Returns the key to queue: the slot is due and its key is not
/// backing off or parked. A blocked key keeps the slot and its due unqueued.
fn schedule_held_audit_progress(index: &mut ScanIndex, now: u64) -> Option<String> {
    with_open_backoff(|backoff| {
        backoff.page = backoff.page.saturating_add(1);
        backoff
            .keys
            .retain(|key, _| awaits_hold_deadline_restoration(index, key));
    });
    let previous = index.held_audit_progress.clone();
    let keep = previous.as_ref().is_some_and(|slot| {
        !slot.attempted
            && slot.due > 0
            && now
                .checked_add(AUDIT_INTERVAL_SECONDS)
                .is_some_and(|latest| slot.due <= latest)
            && progress_eligible(index, slot.key.as_str())
            && !open_blocked(&slot.key, now)
    });
    if !keep {
        let key = next_progress_key(index, previous.as_ref().map(|slot| slot.key.as_str()), now);
        index.held_audit_progress = key
            .zip(now.checked_add(AUDIT_INTERVAL_SECONDS))
            .map(|(key, due)| progress_slot(key, due, previous.as_ref()));
    }
    let slot = index.held_audit_progress.as_ref()?;
    (now >= slot.due && !open_blocked(&slot.key, now)).then(|| slot.key.clone())
}

impl OwnedSourceScan {
    /// At most one additional Full attempt per page. The queue contains only
    /// a bounded path and deadline; entry/census identity is never rewritten.
    pub(super) fn prepare_held_audit_progress(&mut self, now: u64) {
        if self.file_limit == 0 {
            return;
        }
        let Some(key) = schedule_held_audit_progress(&mut self.index, now) else {
            return;
        };
        let path = PathBuf::from(&key);
        // First match, not deepest: the root enters the sampled scope hash.
        let Some(root) = self
            .index
            .traversal
            .as_ref()
            .and_then(|traversal| traversal.first_matching_scan_root(&path).cloned())
        else {
            return;
        };
        let Some(entry) = self.index.files.get(&key) else {
            return;
        };
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: root,
            path,
            size_bytes: entry.size_bytes,
            modified_unix_seconds: entry.modified_unix_seconds,
            modified_unix_nanos: entry.modified_unix_nanos.unwrap_or_default(),
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
        };
        // Mirror candidate conversion's census observation. An old queued
        // age rejection must not delete a successful recovery at settlement.
        if !self.census.claude_vanished_index_keys.contains(&key) {
            self.census.removed_index_keys.remove(&key);
        }
        self.census.observed_index_keys.insert(key.clone());
        self.identified_candidates
            .retain(|candidate| local_index_key(&candidate.path) != key);
        self.identified_candidates.push_front(candidate);
        // Preserve the ordinary page limit and every displaced candidate.
        while self.identified_candidates.len() > self.file_limit.max(1) {
            let candidate = self.identified_candidates.pop_back().unwrap();
            if let Some(traversal) = self.index.traversal.as_mut() {
                traversal.pending_candidates.push_front(ScanTraversalPath {
                    scan_root: candidate.scan_root,
                    path: candidate.path,
                    census_member: true,
                    watcher_hint: false,
                });
            }
        }
        super::claude_request_census::note_identity_incomplete_hold_deadlines_restored(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> ScanIndexEntry {
        serde_json::from_value(json!({
            "size_bytes": 1, "modified_unix_seconds": 1,
            "modified_unix_nanos": 1, "source_file_fingerprint": "source",
            "last_snapshot_fingerprint": null,
            "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
        }))
        .unwrap()
    }
    fn candidate() -> CandidateFile {
        CandidateFile {
            physical_identity: None,
            scan_root: PathBuf::from("/synthetic"),
            path: PathBuf::from("/synthetic/session.jsonl"),
            size_bytes: 1,
            modified_unix_seconds: 1,
            modified_unix_nanos: 1,
            source_file_fingerprint: "source".into(),
            legacy_source_file_fingerprint: "legacy".into(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".into(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
        }
    }
    fn index() -> ScanIndex {
        let mut index = ScanIndex::default();
        let key = local_index_key(&candidate().path);
        index.files.insert(key.clone(), entry());
        index.confirmed_empty_files.insert(key);
        index
    }
    #[test]
    fn sampled_audit_oldest_deadline_not_ack_or_tail_controls_idle_selection() {
        let mut index = index();
        let candidate = candidate();
        let key = local_index_key(&candidate.path);
        assert!(!index.stage_sampled_audit(
            &key,
            "stale",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert!(index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert!(index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 300
            }
        ));
        assert_eq!(
            index.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            200
        );
        assert_eq!(
            index.candidate_decision_at(&candidate, 199),
            CandidateDecision::Skip
        );
        assert_eq!(
            index.candidate_decision_at(&candidate, 200),
            CandidateDecision::Parse
        );
        let subset = index.committable_subset(&index.clone(), &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            subset.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            200
        );
        assert!(!index.complete_full_audit(&key, "older-source"));
        assert!(index.files[&key].has_unverified_source());
        assert!(index.complete_full_audit(&key, "source"));
        assert!(!index.files[&key].has_unverified_source());
    }
    #[test]
    fn sampled_audit_malformed_and_replay_markers_remain_due_without_resetting_index() {
        for malformed in [
            json!(null),
            json!(0),
            json!(-1),
            json!("later"),
            json!({"due":200}),
            json!(u64::MAX),
        ] {
            let mut raw = serde_json::to_value(entry()).unwrap();
            raw["scan_identity_version"] = json!(format!("{UNVERIFIED_IDENTITY}:{}", malformed));
            let mut index = index();
            let key = local_index_key(&candidate().path);
            index
                .files
                .insert(key.clone(), serde_json::from_value(raw).unwrap());
            assert!(index.files[&key].audit_requires_full(100));
            index.prepare_historical_replay("new-generation".into());
            assert!(index.files[&key].audit_requires_full(100));
            assert_eq!(index.files.len(), 1);
        }
        let mut index = index();
        let key = local_index_key(&candidate().path);
        index.files.get_mut(&key).unwrap().scan_identity_version = Some(UNVERIFIED_IDENTITY.into());
        index.record(candidate(), None, ScanParseOutcome::ConfirmedEmpty);
        assert_eq!(index.files[&key].unverified_deadline(), Some(0));
        index.prepare_historical_replay("replay".into());
        assert!(index.files[&key].audit_requires_full(100));
    }
    #[test]
    fn sampled_audit_shed_body_retains_newer_debt_with_previous_delivery_authority() {
        let mut previous = index();
        let key = local_index_key(&candidate().path);
        let old = "a".repeat(64);
        let new = "b".repeat(64);
        previous.confirmed_empty_files.remove(&key);
        previous
            .files
            .get_mut(&key)
            .unwrap()
            .last_snapshot_fingerprint = Some(old.clone());
        previous
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint = "old-source".into();
        previous
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([old.clone()]));
        let mut working = previous.clone();
        working
            .files
            .get_mut(&key)
            .unwrap()
            .last_snapshot_fingerprint = Some(new.clone());
        working.files.get_mut(&key).unwrap().source_file_fingerprint = "new-source".into();
        working
            .file_snapshot_fingerprints
            .insert(key.clone(), BTreeSet::from([new.clone()]));
        assert!(working.stage_sampled_audit(
            &key,
            "new-source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        let shed = working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
        assert_eq!(
            shed.files[&key].last_snapshot_fingerprint.as_deref(),
            Some(old.as_str())
        );
        assert_eq!(shed.files[&key].source_file_fingerprint, "old-source");
        assert_eq!(
            shed.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            200
        );
        let accepted =
            working.committable_subset(&previous, &BTreeSet::from([new]), &BTreeMap::new());
        assert_eq!(accepted.files[&key].source_file_fingerprint, "new-source");
        assert!(accepted.files[&key].has_unverified_source());
    }
    #[test]
    fn sampled_audit_missing_source_and_existing_cas_cannot_erase_obligation() {
        let root = std::env::temp_dir().join(format!(
            "ottto-audit-index-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let path = root.join("index.json");
        let mut index = index();
        let key = local_index_key(&candidate().path);
        index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200,
            },
        );
        index.remove_file_entry(&key);
        assert!(index.files.contains_key(&key));
        index.save(&path).unwrap();
        let mut older = ScanIndex::load(&path).unwrap();
        let mut current = ScanIndex::load(&path).unwrap();
        assert!(current.files[&key].has_unverified_source());
        current.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 150,
            },
        );
        current.save(&path).unwrap();
        older.complete_full_audit(&key, "source");
        assert!(older.save(&path).is_err());
        let loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            loaded.files[&key]
                .audit_obligation(100)
                .unwrap()
                .due_unix_seconds,
            150
        );
        fs::remove_dir_all(root).unwrap();
    }

    /// Option B: only a plain-v2 entry whose census record is an N1 hold gets
    /// a deadline back; one per scan, one interval out, prefix-tagged, and
    /// never into the last free audit slot.
    #[test]
    fn option_b_restores_only_erased_hold_deadlines_paced_by_audit_slots() {
        use crate::snapshots::claude_request_census::{
            identity_incomplete_hold_deadlines_restored_total as restored_total,
            ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
            CLAUDE_REQUEST_CENSUS_DERIVATION,
        };
        let held = || {
            Record::synthetic_for_test(&"a".repeat(64), 1, Shape::IdentityIncomplete, vec![1])
                .with_unverified_for_test(true)
        };
        let mut retired = held();
        retired.retire();
        let mut index = ScanIndex::default();
        for (key, record) in [
            ("held-a", held()),
            ("held-b", held()),
            ("held-legacy-entry", held()),
            ("not-held-retired", retired),
            (
                "not-held-stale-derivation",
                held().with_derivation_for_test(CLAUDE_REQUEST_CENSUS_DERIVATION + 1),
            ),
            ("not-held-verified", held().with_unverified_for_test(false)),
            (
                "not-held-exact",
                Record::synthetic_for_test(&"a".repeat(64), 1, Shape::Exact, vec![1])
                    .with_unverified_for_test(true),
            ),
        ] {
            index.files.insert(key.into(), entry());
            index
                .claude_request_census_mut_for_test()
                .insert_for_test(key, record);
        }
        index
            .files
            .get_mut("held-legacy-entry")
            .unwrap()
            .scan_identity_version = Some("semantic_sync:v1".into());
        let plain = |index: &ScanIndex| {
            index
                .files
                .iter()
                .filter(|(_, entry)| !entry.has_unverified_source())
                .map(|(key, _)| key.clone())
                .collect::<BTreeSet<_>>()
        };
        let before = plain(&index);
        let total = restored_total();

        assert_eq!(restore_held_audit_deadlines(&mut index, 100), 1);
        assert_eq!(restored_total(), total + 1);
        let restored = &index.files["held-a"];
        assert_eq!(
            restored.unverified_deadline(),
            Some(100 + AUDIT_INTERVAL_SECONDS)
        );
        assert!(
            restored.has_prefix_provenance(),
            "plain v2 cannot prove `c`"
        );
        assert!(!restored.audit_requires_full(100), "no read at restoration");
        assert!(restored.audit_requires_full(100 + AUDIT_INTERVAL_SECONDS));
        assert!(
            !index.files["held-b"].has_unverified_source(),
            "one per scan"
        );

        // The next scan restores the next hold; a restored entry is not
        // restored again, and nothing else ever is.
        assert_eq!(restore_held_audit_deadlines(&mut index, 200), 1);
        assert_eq!(
            index.files["held-a"].unverified_deadline(),
            Some(100 + AUDIT_INTERVAL_SECONDS)
        );
        assert_eq!(
            index.files["held-b"].unverified_deadline(),
            Some(200 + AUDIT_INTERVAL_SECONDS)
        );
        assert_eq!(restore_held_audit_deadlines(&mut index, 300), 0);
        assert_eq!(restored_total(), total + 2);
        let mut unchanged = before;
        unchanged.remove("held-a");
        unchanged.remove("held-b");
        assert_eq!(plain(&index), unchanged);
        assert_eq!(
            index.files["held-legacy-entry"]
                .scan_identity_version
                .as_deref(),
            Some("semantic_sync:v1")
        );

        // Restoration leaves the last audit slot free, so a full pending
        // set keeps sampling supported and restores nothing.
        let mut full = ScanIndex::default();
        full.files.insert("held".into(), entry());
        full.claude_request_census_mut_for_test()
            .insert_for_test("held", held());
        for slot in 0..CACHE_ENTRIES - 1 {
            let mut pending = entry();
            pending.set_unverified_deadline(1);
            full.files.insert(format!("pending-{slot}"), pending);
        }
        assert_eq!(restore_held_audit_deadlines(&mut full, 100), 0);
        assert!(!full.files["held"].has_unverified_source());
        full.files.remove("pending-0");
        assert_eq!(restore_held_audit_deadlines(&mut full, 100), 1);
        assert_eq!(restored_total(), total + 3);
    }
}

#[cfg(test)]
mod provenance_tests {
    use super::*;
    fn index() -> ScanIndex {
        let mut index = ScanIndex::default();
        let entry = serde_json::from_value(json!({
            "size_bytes": 1, "modified_unix_seconds": 1,
            "modified_unix_nanos": 1, "source_file_fingerprint": "source",
            "last_snapshot_fingerprint": null,
            "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
        }))
        .unwrap();
        index.files.insert("file".into(), entry);
        index
    }
    #[test]
    fn prefix_provenance_survives_record_replay_and_deadline_carry() {
        let mut index = index();
        index
            .files
            .get_mut("file")
            .unwrap()
            .set_unverified_deadline(200);
        assert!(index.mark_sealed_prefix("file", "source"));
        let mut ordinary = self::index();
        ordinary
            .files
            .get_mut("file")
            .unwrap()
            .set_unverified_deadline(300);
        ordinary
            .files
            .get_mut("file")
            .unwrap()
            .carry_sampled_audit(&index.files["file"]);
        assert!(ordinary.files["file"].has_prefix_provenance());
        assert_eq!(ordinary.files["file"].unverified_deadline(), Some(200));
        let mut carried: ScanIndexEntry =
            serde_json::from_value(serde_json::to_value(&index.files["file"]).unwrap()).unwrap();
        carried.scan_identity_version = Some(carried.carried_audit_version());
        carried.set_unverified_deadline(150);
        assert!(carried.has_prefix_provenance());
        assert_eq!(carried.unverified_deadline(), Some(150));
        index.prepare_historical_replay("replay".into());
        assert!(index.files["file"].has_prefix_provenance());
        assert_eq!(index.files["file"].unverified_deadline(), Some(200));
    }
    #[test]
    fn prefix_clear_requires_exact_fingerprint_and_keeps_tail_audit_debt() {
        let mut index = index();
        index
            .files
            .get_mut("file")
            .unwrap()
            .set_unverified_deadline(200);
        assert!(index.mark_sealed_prefix("file", "source"));
        assert!(!index.complete_native_recomposition("file", "stale"));
        assert!(!index.complete_full_audit("file", "stale"));
        assert!(index.files["file"].has_prefix_provenance());
        assert!(index.complete_native_recomposition("file", "source"));
        assert!(!index.files["file"].has_prefix_provenance());
        assert_eq!(index.files["file"].unverified_deadline(), Some(200));
        assert!(index.mark_sealed_prefix("file", "source"));
        assert!(index.complete_full_audit("file", "source"));
        assert!(!index.files["file"].has_prefix_provenance());
        assert!(!index.files["file"].has_unverified_source());
    }
    #[test]
    fn provenance_marker_stays_inside_existing_marker_budget() {
        // Native comparison's unchanged charge rounds this legacy bound to 64.
        let budget = (UNVERIFIED_IDENTITY.len() + 1 + 20).next_power_of_two();
        for prefix in [false, true] {
            let tag = provenance_marker(u64::MAX, prefix);
            assert!(tag.capacity() <= MAX_MARKER_BYTES);
            assert!(tag.capacity() <= budget);
            assert_eq!(decode_marker(&tag), Some((u64::MAX, prefix)));
        }
    }
    /// c22 G1: `record` carries only an existing sampled stem. A replay-reset
    /// or legacy entry (never a prefix, SOURCE Option 1) re-recorded without
    /// verification or obligation becomes the clean identity; the same
    /// completion's FE mark still tags `p`.
    #[test]
    fn ordinary_record_never_mints_prefix_but_fe_mark_after_record_does() {
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: PathBuf::from("/synthetic"),
            path: PathBuf::from("/synthetic/session.jsonl"),
            size_bytes: 1,
            modified_unix_seconds: 1,
            modified_unix_nanos: 1,
            source_file_fingerprint: "source".into(),
            legacy_source_file_fingerprint: "legacy".into(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: "opened".into(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
        };
        let key = local_index_key(&candidate.path);
        for reset in [None, Some("semantic_sync:v1"), Some("unknown-provenance")] {
            let mut entry = index().files.remove("file").unwrap();
            entry.scan_identity_version = reset.map(Into::into);
            assert!(
                !entry.has_prefix_provenance(),
                "{reset:?}: SOURCE Option 1: a non-stem identity is not a prefix"
            );
            let mut ordinary = ScanIndex::default();
            ordinary.files.insert(key.clone(), entry);
            let mut marked = ordinary.clone();
            let ((), counts) = crate::local_resource_diagnostics::cache_lifecycle::observe(|| {
                ordinary.record(candidate.clone(), None, ScanParseOutcome::ConfirmedEmpty)
            });
            let entry = &ordinary.files[&key];
            assert_eq!(
                entry.scan_identity_version.as_deref(),
                Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION),
                "{reset:?}"
            );
            assert!(!entry.has_prefix_provenance(), "{reset:?}");
            assert!(!entry.has_unverified_source(), "{reset:?}: no audit debt");
            assert!(entry.audit_obligation(100).is_none(), "{reset:?}");
            assert_eq!(counts.prefix_tag_clears, 0, "{reset:?}");
            marked.record(candidate.clone(), None, ScanParseOutcome::ConfirmedEmpty);
            assert!(marked.mark_sealed_prefix(&key, "source"));
            assert!(marked.files[&key].has_unverified_source(), "{reset:?}");
            assert!(marked.files[&key].has_prefix_provenance(), "{reset:?}");
        }
    }
}
