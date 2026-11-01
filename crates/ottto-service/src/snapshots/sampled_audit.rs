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
    /// Existing obligations are never evicted. Imported over-cap populations
    /// must drain before any new marker can be admitted.
    pub(super) fn can_stage_sampled_audit(&self, key: &str) -> bool {
        self.files
            .get(key)
            .is_some_and(ScanIndexEntry::has_unverified_source)
            || self
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .take(CACHE_ENTRIES)
                .count()
                < CACHE_ENTRIES
    }

    pub(super) fn retire_quiet_audit(&mut self, key: &str, fingerprint: &str) -> bool {
        let Some(entry) = self.files.get_mut(key).filter(|entry| {
            entry.observed_fingerprint() == fingerprint
                && entry.has_unverified_source()
                && !entry.has_prefix_provenance()
        }) else {
            return false;
        };
        entry.scan_identity_version = Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION.into());
        true
    }

    /// Called only by a current validated native source completion. Entry/source
    /// equality fences an older completion; the existing writer owns lock/CAS.
    /// A delivery ACK never calls this method as source-verification authority.
    pub(super) fn stage_sampled_audit(
        &mut self,
        key: &str,
        source_fingerprint: &str,
        debt: AuditDebt,
    ) -> bool {
        if !self.can_stage_sampled_audit(key) {
            return false;
        }
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.observed_fingerprint() == source_fingerprint)
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
            .filter(|entry| entry.observed_fingerprint() == source_fingerprint)
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
        if !self.can_stage_sampled_audit(key) {
            return false;
        }
        let Some(entry) = self
            .files
            .get_mut(key)
            .filter(|entry| entry.observed_fingerprint() == source_fingerprint)
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
        if claude_terminal_off() {
            with_open_backoff(|backoff| backoff.keys.remove(key));
        }
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
        .is_some_and(|entry| entry.has_unverified_source() || entry.rearmed())
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
    let obligation = index
        .files
        .get(key)
        .and_then(|entry| entry.audit_obligation(now));
    if claude_terminal_off() {
        // The earliest of the entry, progress and failed-open obligations.
        return obligation
            .into_iter()
            .chain(progress_debt(index, key, now))
            .map(|debt| debt.due_unix_seconds)
            .chain(failed_open_debt(key, now))
            .min()
            .map(|due_unix_seconds| AuditDebt { due_unix_seconds });
    }
    obligation.or_else(|| progress_debt(index, key, now))
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
            (!claude_terminal_off() || failure.failures > 0)
                && (failure.failures >= OPEN_PARK_FAILURES
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

/// All candidate admissions share this stat-wake check, before secure open.
pub(super) fn candidate_open_blocked(key: &str, now: u64) -> bool {
    if !claude_terminal_off() {
        return false;
    }
    open_blocked(key, now)
}
/// Scheduling only: an existing failed-open obligation may retry when its
/// own throttle expires; a successful ordinary open is not such a retry.
pub(super) fn failed_open_retry_ready(key: &str, now: u64) -> bool {
    if !claude_terminal_off() {
        return false;
    }
    with_open_backoff(|memo| {
        memo.keys.get(key).is_some_and(|f| f.failures > 0) && !memo.blocked(key, now)
    })
}
pub(super) fn failed_open_debt(key: &str, now: u64) -> Option<u64> {
    if !claude_terminal_off() {
        return None;
    }
    with_open_backoff(|backoff| backoff.owed(key)).filter(|due| now >= *due)
}

/// Census-line counts: keys whose progress open failed and are still owed
/// (backing off or parked), and the age of the oldest first failure.
pub(super) fn held_audit_open_failed(now: u64) -> (usize, u64) {
    with_open_backoff(|backoff| {
        (
            backoff
                .keys
                .values()
                .filter(|failure| failure.failures > 0)
                .count(),
            backoff
                .keys
                .values()
                .filter(|failure| failure.failures > 0)
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
/// any failed-open backoff ends. Terminal-off clears throttling, NOT the
/// owed verification: another key may own the slot, so it retains the exact
/// numeric due in the bounded map until a marker/native acquisition carries
/// it or a completed source verification retires it.
pub(super) fn progress_opened(index: &mut ScanIndex, key: &str) {
    let terminal_off = claude_terminal_off();
    if let Some(slot) = index
        .held_audit_progress
        .as_mut()
        .filter(|slot| slot.key == key)
    {
        slot.attempted = true;
        if !terminal_off {
            with_open_backoff(|backoff| backoff.keys.remove(key));
        }
    }
    if terminal_off {
        with_open_backoff(|backoff| {
            if let Some(failure) = backoff.keys.get_mut(key) {
                failure.failures = 0;
                failure.retry_page = backoff.page;
            }
        });
    }
}

#[derive(Serialize)]
struct HeldAuditOpenParked {
    held_audit_open_failures: u8,
    held_audit_open_owed_age_seconds: u64,
    held_audit_open_failed_keys: usize,
}

// All actual failed opens of an already owed key, including constructor
// preflight, share the bounded failure record. No census/ACK state changes.
fn record_open_failure(key: &str, due: u64, now: u64) -> RecordedFailure {
    let (recorded, keys) =
        with_open_backoff(|backoff| (backoff.record_failure(key, due, now), backoff.keys.len()));
    if let Some(parked) = recorded.parked.as_ref() {
        // Counts only; no path or id. Once per park.
        crate::local_resource_diagnostics::claude_held_audit_open_parked(&HeldAuditOpenParked {
            held_audit_open_failures: parked.failures,
            held_audit_open_owed_age_seconds: now.saturating_sub(parked.owed_due),
            held_audit_open_failed_keys: keys,
        });
    }
    recorded
}
pub(super) fn candidate_open_failed(key: &str, now: u64) {
    if !claude_terminal_off() {
        return;
    }
    if let Some(due) = failed_open_debt(key, now) {
        record_open_failure(key, due, now);
    }
}

/// The queued progress Full for `key` failed its secure open. Back the key
/// off (or park it), then rotate the turn, wrapping to `key` itself when no
/// other member is eligible, but keep the owed due: a failed open never
/// re-arms a later deadline.
pub(super) fn progress_open_failed(index: &mut ScanIndex, key: &str, now: u64) {
    let terminal_off = claude_terminal_off();
    let Some(due) = index
        .held_audit_progress
        .as_ref()
        .filter(|slot| slot.key == key && !slot.attempted)
        .map(|slot| slot.due)
        // failed_open_debt is None with the switch OFF.
        .or_else(|| failed_open_debt(key, now))
    else {
        return;
    };
    let recorded = record_open_failure(key, due, now);
    // An ordinary admission can be a previously failed key while another
    // member owns the progress slot. Its failure must not steal that turn.
    if terminal_off
        && index
            .held_audit_progress
            .as_ref()
            .is_some_and(|slot| slot.key != key)
    {
        return;
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
        // Restoring a plain-v2 hold changes its representation, not its
        // failed-open obligation. Keep the same-stat park and original D
        // until source verification discharges them (or the entry is gone).
        backoff.keys.retain(|key, _| {
            awaits_hold_deadline_restoration(index, key)
                || claude_terminal_off()
                    && index
                        .files
                        .get(key)
                        .is_some_and(ScanIndexEntry::has_unverified_source)
        });
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
            withheld_content_stamp: None,
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

impl SourceScanResult {
    /// Transfer a released account hold's acquisition debt before upload/save.
    /// Working retirements never refund their committed marker reservation.
    pub(crate) fn preserve_released_account_audits(
        &self,
        index: &mut ScanIndex,
        previous: &ScanIndex,
        cache: &sampled_scan::SharedCache,
        roots: &[PathBuf],
        backfill_window_days: u64,
    ) {
        let mut reserved = previous
            .files
            .values()
            .filter(|entry| entry.has_unverified_source())
            .count()
            .saturating_add(
                index
                    .files
                    .iter()
                    .filter(|(key, entry)| {
                        entry.has_unverified_source()
                            && !previous
                                .files
                                .get(*key)
                                .is_some_and(ScanIndexEntry::has_unverified_source)
                    })
                    .count(),
            );
        let mut staged = 0_u64;
        let mut queued = 0_u64;
        for (key, fingerprint) in self.completed_parses() {
            if !previous.claude_account_deferred_holds.contains_key(key)
                || index.claude_account_deferred_holds.contains_key(key)
                || !index
                    .files
                    .get(key)
                    .is_some_and(|entry| !entry.has_unverified_source())
            {
                continue;
            }
            // None is unknown/missing retained custody; keep a discoverable
            // retry rather than assuming that a missing copy discharged debt.
            let debt = cache.retained().ok().and_then(|retained| {
                retained
                    .peek(key)
                    .map(|entry| entry.checkpoint.audit_debt())
            });
            if debt == Some(None) {
                continue;
            }
            if let Some(Some(debt)) = debt {
                if reserved < CACHE_ENTRIES
                    && index
                        .files
                        .get(key)
                        .is_some_and(|entry| entry.observed_fingerprint() == fingerprint)
                    && index.stage_sampled_audit(key, fingerprint, debt)
                {
                    reserved += 1;
                    staged += 1;
                    continue;
                }
            }
            // This existing explicit-reparse witness survives traversal resets
            // and ages. It never labels an audit/clock Full or grants credit.
            index
                .files
                .get_mut(key)
                .expect("current parsed entry")
                .source_file_fingerprint
                .clear();
            if index.traversal.is_none() {
                ensure_bounded_traversal(
                    SnapshotSource::ClaudeCode,
                    roots,
                    index,
                    &self.census_window_end,
                    backfill_window_days,
                );
            }
            if let Some(traversal) = index.traversal.as_mut() {
                enqueue_watcher_hints(
                    SnapshotSource::ClaudeCode,
                    traversal,
                    &[PathBuf::from(key)],
                    false,
                );
            }
            queued += 1;
        }
        if staged + queued > 0 {
            crate::local_resource_diagnostics::traversal_point(
                "sampled_audit_account_release",
                "claude_code",
                &serde_json::json!({"marker_staged": staged, "retry_queued": queued}),
            );
        }
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
            withheld_content_stamp: None,
        }
    }
    fn index() -> ScanIndex {
        let mut index = ScanIndex::default();
        let key = local_index_key(&candidate().path);
        index.files.insert(key.clone(), entry());
        index.confirmed_empty_files.insert(key);
        index
    }
    /// [behaviour] Virtual recovery keeps grown keys observed without reading before due.
    #[test]
    fn virtual_recovery_keeps_grown_keys_observed_without_reading_before_due() {
        use crate::snapshots::claude_request_census::{
            ClaudeRequestCensusRecord as Record, ClaudeRequestCensusShape as Shape,
        };
        let mut index = index();
        let mut candidate = candidate();
        let key = local_index_key(&candidate.path);
        let record =
            Record::synthetic_for_test(&"a".repeat(64), 1, Shape::IdentityIncomplete, vec![1])
                .with_unverified_for_test(true);
        index
            .claude_request_census_mut_for_test()
            .insert_for_test(&key, record);
        let now = 10 * 86_400;
        let due = now + 100;
        index.held_audit_progress = Some(HeldAuditProgress {
            key: key.clone(),
            due,
            attempted: false,
        });
        candidate.size_bytes += 1;
        candidate.source_file_fingerprint = "changed".into();
        assert!(awaits_hold_deadline_restoration(&index, &key));
        assert!(
            discovery_retention!(index).owes_with_len(
                SnapshotSource::ClaudeCode,
                &candidate.path,
                candidate.size_bytes
            ),
            "growth stays discoverable, never dropped"
        );
        let decide = |index: &ScanIndex, candidate: &CandidateFile, at| {
            index.candidate_decision_in_window(candidate, at, Some(at), 7)
        };
        let mut recent = candidate.clone();
        recent.modified_unix_seconds = now;
        assert_eq!(
            decide(&index, &recent, now),
            (
                CandidateDecision::Parse,
                Some(CandidateParseReason::TranscriptChanged)
            ),
            "recent growth preserves main's immediate selection"
        );
        assert_eq!(
            decide(&index, &candidate, due - 1).0,
            CandidateDecision::Skip,
            "scheduling future virtual debt cannot acquire the grown file"
        );
        assert_eq!(
            decide(&index, &candidate, due),
            (CandidateDecision::Parse, Some(CandidateParseReason::Audit)),
            "due read retains its counted audit cause"
        );
        index
            .files
            .get_mut(&key)
            .unwrap()
            .source_file_fingerprint
            .clear();
        assert_eq!(
            decide(&index, &candidate, due - 1).0,
            CandidateDecision::Parse,
            "genuine external rearm is not hidden by the virtual delay"
        );
    }

    #[test]
    fn cap_retry_keeps_durable_custody_without_a_traversal_or_marker() {
        let mut index = index();
        let candidate = candidate();
        let key = local_index_key(&candidate.path);
        assert!(index.traversal.is_none());
        assert!(!path_requires_verification(&index.files, &candidate.path));
        queue_cap_retry(&mut index, &candidate);
        let mut loaded: ScanIndex =
            serde_json::from_slice(&serde_json::to_vec(&index).unwrap()).unwrap();
        assert!(loaded.traversal.is_none());
        assert!(path_requires_verification(&loaded.files, &candidate.path));
        assert!(!loaded.files[&key].has_unverified_source());
        assert_eq!(loaded.files[&key].size_bytes, 1);
        // Same-process provenance survives the index round-trip until an
        // actual Full completes; merely queuing the retry emits no Full.
        let probe = crate::local_resource_diagnostics::Probe::start();
        assert!(probe.rearm_fulls().is_empty());
        let full = crate::transcript_acquisition::ReadMode::Full(
            crate::transcript_acquisition::FullReason::StateMissing,
        );
        probe.rearm_full_selected(&key, full);
        probe.rearm_full_completed(&key, full, 3);
        assert_eq!(
            serde_json::to_value(probe.rearm_fulls()).unwrap(),
            json!({"rearm_cleared{audit_cap_delay}": {"count": 1, "completed_native_bytes": 3}})
        );
        loaded.files.remove(&key);
        queue_cap_retry(&mut loaded, &candidate);
        assert!(!loaded.files.contains_key(&key), "no invented membership");
    }

    #[test]
    fn marked_population_admission_and_quiet_retirement_share_the_cap() {
        let mut index = index();
        for n in 0..CACHE_ENTRIES {
            let key = format!("missing-{n}");
            index.files.insert(key.clone(), entry());
            assert!(index.stage_sampled_audit(
                &key,
                "source",
                AuditDebt {
                    due_unix_seconds: 200
                }
            ));
        }
        let key = local_index_key(&candidate().path);
        assert!(!index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert!(!index.mark_sealed_prefix(&key, "source"));
        assert!(index.stage_sampled_audit(
            "missing-0",
            "source",
            AuditDebt {
                due_unix_seconds: 100
            }
        ));
        assert!(index.mark_sealed_prefix("missing-0", "source"));
        assert!(
            !index.retire_quiet_audit("missing-0", "source"),
            "prefix cannot retire"
        );
        assert!(!index.retire_quiet_audit("missing-1", "stale"));
        assert!(index.retire_quiet_audit("missing-1", "source"));
        assert!(index.stage_sampled_audit(
            &key,
            "source",
            AuditDebt {
                due_unix_seconds: 200
            }
        ));
        assert_eq!(
            index
                .files
                .values()
                .filter(|entry| entry.has_unverified_source())
                .count(),
            CACHE_ENTRIES
        );
        assert!(index.files["missing-0"].has_unverified_source());
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
            withheld_content_stamp: None,
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

/// Keep a provisionally retired path selectable if partial-save reconciliation
/// restores its marker. Preserve the actual read's root: guessing from nested
/// roots could change the acquisition scope. A committed retirement skips it.
pub(super) fn queue_quiet_retirement(index: &mut ScanIndex, key: &str, scan_root: PathBuf) {
    queue_pending(index, Path::new(key), || scan_root, false, false);
}

/// The one deduplicated pending-candidate insert. Callers keep their own side
/// effects (rearm cause, growth residue); an absent traversal queues nothing.
/// The root is produced only on insertion.
fn queue_pending(
    index: &mut ScanIndex,
    path: &Path,
    scan_root: impl FnOnce() -> PathBuf,
    census_member: bool,
    watcher_hint: bool,
) {
    if let Some(traversal) = index.traversal.as_mut() {
        if !traversal
            .pending_candidates
            .iter()
            .any(|queued| queued.path == path)
        {
            traversal.pending_candidates.push_back(ScanTraversalPath {
                scan_root: scan_root(),
                path: path.to_owned(),
                census_member,
                watcher_hint,
            });
        }
    }
}

/// A cap delay is still owed: persist an age-bypassing retry without advancing
/// the committed file size or claiming source/census completion.
pub(super) fn queue_cap_retry(index: &mut ScanIndex, candidate: &CandidateFile) {
    // The queue can disappear on a context-changing traversal replacement.
    // Reuse the existing durable reparse witness at every age/open gate and
    // in partial saves; keep the committed size and marker population intact.
    let key = local_index_key(&candidate.path);
    if let Some(entry) = index.files.get_mut(&key) {
        crate::local_resource_diagnostics::rearm_cause::clear(
            &key,
            entry,
            crate::local_resource_diagnostics::rearm_cause::Cause::AuditCapDelay,
        );
    }
    queue_pending(
        index,
        &candidate.path,
        || candidate.scan_root.clone(),
        true,
        true,
    );
}

/// Positive removal only: a file or intermediate directory is NotFound beneath
/// a readable ancestor securely reached from a configured, readable root.
/// Missing roots, symlinks and permission errors keep the audit and account debt.
/// This is absence authority, never source verification or census credit.
pub(super) fn proven_absent(path: &Path, roots: &[PathBuf]) -> bool {
    absence_parent(path, roots).is_some()
}

/// Pin the nearest existing parent so its inode cannot be reused between probes.
/// Depth binds the missing component when an intermediate directory is absent.
#[derive(Debug)]
pub(super) struct AbsenceParent {
    directory: File,
    depth: usize,
}
impl AbsenceParent {
    pub(super) fn same_parent(&self, other: &Self) -> bool {
        #[cfg(unix)]
        {
            self.depth == other.depth
                && self
                    .directory
                    .metadata()
                    .ok()
                    .zip(other.directory.metadata().ok())
                    .is_some_and(|(a, b)| a.dev() == b.dev() && a.ino() == b.ino())
        }
        #[cfg(not(unix))]
        {
            let _ = (self, other);
            false
        }
    }
}
/// The pinned parent of the first configured root it is proven under,
/// only when the root has no symlink in any component (its real path is
/// itself) and that parent is on the root's device. A redirected prefix or a
/// mounted-over or replaced volume is unmount-like and stays loss.
pub(super) fn absence_parent_on_root_device(
    path: &Path,
    roots: &[PathBuf],
) -> Option<AbsenceParent> {
    #[cfg(unix)]
    {
        roots.iter().find_map(|root| {
            let configured: PathBuf = root.components().collect();
            if fs::canonicalize(root).ok()? != configured {
                return None;
            }
            let parent = absence_parent(path, std::slice::from_ref(root))?;
            let device = fs::symlink_metadata(root).ok()?.dev();
            (parent.directory.metadata().ok()?.dev() == device).then_some(parent)
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (path, roots);
        None
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for AbsenceParent {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            directory: _,
            depth: _,
        } = self;
        c.add(0)
    }
}

pub(super) fn absence_parent(path: &Path, roots: &[PathBuf]) -> Option<AbsenceParent> {
    #[cfg(unix)]
    {
        roots
            .iter()
            .find_map(|root| proven_absent_beneath_root(path, root).ok().flatten())
    }
    #[cfg(not(unix))]
    {
        let _ = (path, roots);
        None
    }
}

#[cfg(unix)]
fn proven_absent_beneath_root(path: &Path, root: &Path) -> std::io::Result<Option<AbsenceParent>> {
    fn open_directory(parent: &File, name: &std::ffi::CStr) -> std::io::Result<File> {
        // Match open_candidate_beneath_root: every directory is readable and
        // no component below the configured root may redirect through a link.
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }
    fn name_absent(parent: &File, name: &std::ffi::CStr) -> std::io::Result<bool> {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        // A dangling symlink is present, not positive absence. Stat relative
        // to the pinned parent without opening any transcript bytes.
        let result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                metadata.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            return Ok(false);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            Ok(true)
        } else {
            Err(error)
        }
    }
    fn same_directory(left: &File, right: &File) -> std::io::Result<bool> {
        let left = left.metadata()?;
        let right = right.metadata()?;
        Ok(left.dev() == right.dev() && left.ino() == right.ino())
    }

    if !root.is_absolute()
        || root
            .components()
            .any(|part| !matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Ok(None);
    }
    // Preserve the nofollow check on the root's final component even when its
    // configured spelling has a trailing separator or `/.`.
    let root: PathBuf = root.components().collect();
    let Ok(relative) = path.strip_prefix(&root) else {
        return Ok(None);
    };
    let mut names = Vec::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Ok(None);
        };
        let Ok(name) = std::ffi::CString::new(name.as_bytes()) else {
            return Ok(None);
        };
        names.push(name);
    }
    let Some((final_name, parents)) = names.split_last() else {
        return Ok(None);
    };
    let mut root_options = fs::OpenOptions::new();
    root_options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let mut directories = vec![root_options.open(&root)?];
    let mut missing_name = final_name;
    for name in parents {
        match open_directory(directories.last().expect("opened ancestor"), name) {
            Ok(next) => directories.push(next),
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                // The last pinned directory is the nearest existing ancestor.
                // Do not traverse the missing suffix or accept any other error.
                missing_name = name;
                break;
            }
            Err(error) => return Err(error),
        }
    }
    if !name_absent(directories.last().expect("opened ancestor"), missing_name)? {
        return Ok(None);
    }

    // A removed/replaced ancestor can leave a readable but detached descriptor.
    // Rewalk from the configured root and compare every pinned directory before
    // accepting ENOENT at the same missing component. Any observed substitution
    // or recreation (even an empty directory) keeps the debt.
    let mut directory = root_options.open(&root)?;
    if !same_directory(&directory, &directories[0])? {
        return Ok(None);
    }
    for (name, original) in parents.iter().zip(&directories[1..]) {
        directory = open_directory(&directory, name)?;
        if !same_directory(&directory, original)? {
            return Ok(None);
        }
    }
    if !name_absent(&directory, missing_name)? {
        return Ok(None);
    }
    Ok(Some(AbsenceParent {
        directory,
        depth: directories.len(),
    }))
}

#[cfg(all(test, unix))]
mod absence_tests {
    use super::*;
    use std::os::unix::fs::symlink;

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let root = crate::test_scratch::unique_path("ottto-audit-absence");
            fs::create_dir(&root).unwrap();
            Self(root)
        }
        fn transcript(&self) -> PathBuf {
            let path = self.0.join("root/project/session/subagents/file.jsonl");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"owed transcript").unwrap();
            path
        }
        fn roots(&self) -> Vec<PathBuf> {
            vec![self.0.join("root")]
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn intermediate_symlink_cannot_prove_absence_in_another_tree() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        let saved = fixture.0.join("original-project");
        fs::rename(fixture.0.join("root/project"), &saved).unwrap();
        let replacement = fixture.0.join("replacement-project");
        fs::create_dir_all(replacement.join("session/subagents")).unwrap();
        symlink(&replacement, fixture.0.join("root/project")).unwrap();
        // Reproduce the old predicate's false proof: the final parent is a
        // readable directory, and only the transcript name is NotFound.
        assert_eq!(
            fs::symlink_metadata(&path).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(fs::read_dir(path.parent().unwrap()).is_ok());
        assert!(!proven_absent(&path, &fixture.roots()));
        assert!(saved.join("session/subagents/file.jsonl").is_file());
    }

    #[test]
    fn real_deletion_beneath_readable_parent_proves_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        assert!(!proven_absent(&path, &fixture.roots()));
        fs::remove_file(&path).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn missing_intermediate_directory_beneath_readable_root_proves_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
        fs::remove_dir_all(fixture.0.join("root/project")).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"recreated transcript").unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn missing_configured_root_cannot_prove_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_dir_all(fixture.0.join("root")).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn dangling_symlink_or_non_directory_ancestor_cannot_prove_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        let project = fixture.0.join("root/project");
        fs::remove_dir_all(&project).unwrap();
        symlink("missing-project", &project).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
        fs::remove_file(&project).unwrap();
        fs::write(&project, b"not a directory").unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn unreadable_existing_ancestor_or_root_cannot_prove_absence() {
        use std::os::unix::fs::PermissionsExt;

        // Root can bypass directory permissions; this control needs an
        // unprivileged process to exercise the permission-error boundary.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let fixture = Fixture::new();
        let path = fixture.transcript();
        let root = fixture.0.join("root");
        fs::remove_dir_all(path.parent().unwrap()).unwrap();
        for directory in [path.parent().unwrap().parent().unwrap(), root.as_path()] {
            let permissions = fs::metadata(directory).unwrap().permissions();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o0)).unwrap();
            let absent = proven_absent(&path, &fixture.roots());
            fs::set_permissions(directory, permissions).unwrap();
            assert!(!absent);
        }
    }

    #[test]
    fn recreated_transcript_is_present_even_after_positive_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_file(&path).unwrap();
        assert!(proven_absent(&path, &fixture.roots()));
        fs::write(&path, b"new transcript").unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
        fs::remove_file(&path).unwrap();
        symlink("missing-target", &path).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }

    #[test]
    fn uncertain_roots_and_non_normal_paths_cannot_prove_absence() {
        let fixture = Fixture::new();
        let path = fixture.transcript();
        fs::remove_file(&path).unwrap();
        assert!(!proven_absent(&path, &[]));
        assert!(!proven_absent(&path, &[fixture.0.join("elsewhere")]));
        assert!(!proven_absent(&fixture.0.join("root"), &fixture.roots()));
        assert!(!proven_absent(
            &path.parent().unwrap().join("../subagents/file.jsonl"),
            &fixture.roots()
        ));
        let root_link = fixture.0.join("root-link");
        symlink(fixture.0.join("root"), &root_link).unwrap();
        for root in [root_link.clone(), root_link.join(""), root_link.join(".")] {
            assert!(!proven_absent(
                &root.join("project/session/subagents/file.jsonl"),
                &[root]
            ));
        }
        fs::remove_dir_all(fixture.0.join("root")).unwrap();
        assert!(!proven_absent(&path, &fixture.roots()));
    }
}

#[cfg(all(test, not(unix)))]
mod absence_non_unix_tests {
    #[test]
    fn absence_never_grants_authority_without_secure_directory_descriptors() {
        assert!(!super::proven_absent(
            std::path::Path::new("missing/file.jsonl"),
            &[std::path::PathBuf::from("missing")]
        ));
    }
}

/// V2-only selection bookkeeping. The key keeps the index key's PL class;
/// sizes, generations and consecutive uncertainty are N. It conveys no proof.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(super) struct GrowthRetention {
    predecessor_size: Option<u64>,
    uncertain_passes: u32,
    pub(super) checked_generation: Option<u64>,
    last_growth_full_unix: Option<u64>,
}
crate::heap_layout_bound::fields!(GrowthRetention; predecessor_size, uncertain_passes, checked_generation, last_growth_full_unix);

/// Whether this graph generation already revalidated `key` (runtime-only memo).
pub(super) fn growth_checked(index: &ScanIndex, key: &str) -> bool {
    let (generation, keys) = &index.v2().growth_checked;
    *generation == index.generation && keys.contains(key)
}

pub(super) fn growth_active(index: &ScanIndex) -> bool {
    crate::snapshots::state_v2::state_v2_growth_retention_active(index)
}

/// Owed native growth debt. Fresh growth (`len > size_bytes`) is main's
/// owes_stamped/codex_fragment::grown, which every age gate checks first.
pub(super) fn growth_selectable(
    source: SnapshotSource,
    path: &Path,
    growth: Option<&BTreeMap<String, GrowthRetention>>,
) -> bool {
    source == SnapshotSource::ClaudeCode
        && growth.is_some_and(|growth| {
            growth
                .get(&local_index_key(path))
                .is_some_and(|state| state.predecessor_size.is_some())
        })
}

fn retain_growth(index: &mut ScanIndex, key: &str, len: Option<u64>) {
    let Some(entry) = index.files.get(key) else {
        return;
    };
    let size = entry.size_bytes;
    let state = index
        .v2_mut()
        .growth_retention
        .entry(key.to_owned())
        .or_default();
    if state.predecessor_size.is_none() {
        state.predecessor_size = Some(size);
        crate::local_resource_diagnostics::v2_growth_retained(
            len.unwrap_or(size).saturating_sub(size),
        );
    }
    if let Some(walk) = index.traversal.as_mut() {
        walk.residue.index_keys.insert(key.to_owned());
    }
}

pub(super) fn retain_candidate_growth(
    source: SnapshotSource,
    index: &mut ScanIndex,
    candidate: &CandidateFile,
) {
    if !growth_active(index) {
        return;
    }
    let key = local_index_key(&candidate.path);
    // Selection, not an age gate: fresh growth starts its debt here.
    let grown = source == SnapshotSource::ClaudeCode
        && index
            .files
            .get(&key)
            .is_some_and(|entry| candidate.size_bytes > entry.size_bytes);
    if grown || growth_selectable(source, &candidate.path, Some(&index.v2().growth_retention)) {
        retain_growth(index, &key, Some(candidate.size_bytes));
    }
}

/// Metadata only, through the acquisition path's configured-root/no-follow open.
/// A failed open is never negative growth evidence. Positive absence keeps the
/// existing independent absence rules (including unreadable/missing roots).
pub(super) fn revalidate_growth(index: &mut ScanIndex, key: &str, roots: &[PathBuf]) -> bool {
    if !growth_active(index) || !index.files.contains_key(key) {
        return false;
    }
    let path = Path::new(key);
    let root = roots
        .iter()
        .filter(|root| path.starts_with(root))
        .max_by_key(|root| root.components().count());
    let len = root.and_then(|root| {
        let candidate = CandidateFile {
            physical_identity: None,
            scan_root: root.clone(),
            path: path.to_owned(),
            size_bytes: 0,
            modified_unix_seconds: 0,
            modified_unix_nanos: 0,
            source_file_fingerprint: String::new(),
            legacy_source_file_fingerprint: String::new(),
            legacy_config_reconciliation_required: false,
            opened_object_identity: String::new(),
            fingerprint_changed_nanos: 0,
            fingerprint_birth_nanos: 0,
            withheld_content_stamp: None,
        };
        open_candidate_beneath_root(&candidate)
            .ok()?
            .metadata()
            .ok()
            .filter(|stat| stat.is_file())
            .map(|stat| stat.len())
    });
    let uncertain = len.is_none() && !proven_absent(path, roots);
    crate::local_resource_diagnostics::v2_growth_revalidate(uncertain);
    let retained = uncertain
        || index
            .v2()
            .growth_retention
            .get(key)
            .is_some_and(|state| state.predecessor_size.is_some())
            && len.is_some()
        || len.is_some_and(|len| len > index.files[key].size_bytes);
    if retained {
        retain_growth(index, key, len);
    }
    let generation = index.generation;
    // Restored residue needs a known status, or every page would re-select it.
    let residue = index
        .traversal
        .as_ref()
        .is_some_and(|walk| walk.residue.index_keys.contains(key));
    let v2 = index.v2_mut();
    note_growth_checked(v2, generation, key);
    if uncertain {
        let state = v2.growth_retention.entry(key.to_owned()).or_default();
        if state.checked_generation != Some(generation) {
            state.checked_generation = Some(generation);
            state.uncertain_passes = state.uncertain_passes.saturating_add(1);
            if state.uncertain_passes > 3 {
                crate::local_resource_diagnostics::v2_growth_uncertain_alarm(
                    state.uncertain_passes,
                );
            }
        }
    } else if let Some(state) = v2.growth_retention.get_mut(key) {
        // Persist only a status change: no per-generation rewrite.
        state.uncertain_passes = 0;
        state.checked_generation.get_or_insert(generation);
    } else if residue {
        // Other check-only results (aged or kept-overlap retirement
        // candidates) persist nothing; the runtime memo bounds the work.
        v2.growth_retention.insert(
            key.to_owned(),
            GrowthRetention {
                checked_generation: Some(generation),
                ..GrowthRetention::default()
            },
        );
    }
    if !retained {
        return false;
    }
    if let Some(root) = root {
        queue_growth_path(index, key, root.clone(), true);
    }
    true
}

fn queue_growth_path(index: &mut ScanIndex, key: &str, scan_root: PathBuf, census_member: bool) {
    queue_pending(index, Path::new(key), || scan_root, census_member, false);
    if let Some(walk) = index.traversal.as_mut() {
        walk.residue.index_keys.insert(key.to_owned());
    }
}

pub(super) fn queue_growth_retry(index: &mut ScanIndex, candidate: &CandidateFile) {
    queue_growth_path(
        index,
        &local_index_key(&candidate.path),
        candidate.scan_root.clone(),
        false,
    );
}

/// Only witnessed growth debt excludes retirement. An undiscovered range or
/// residue without a growth entry conveys no retention authority.
pub(super) fn growth_excluded_parts(
    key: &str,
    growth: &BTreeMap<String, GrowthRetention>,
    walk: Option<&ScanTraversalCheckpoint>,
    terminal_residue: Option<&BTreeSet<String>>,
) -> bool {
    growth.get(key).is_some_and(|state| {
        state.predecessor_size.is_some()
            || state.checked_generation.is_none()
                && (walk.is_some_and(|walk| walk.residue.index_keys.contains(key))
                    || terminal_residue.is_some_and(|keys| keys.contains(key)))
    })
}

pub(super) fn growth_retirement_excluded(index: &ScanIndex, key: &str) -> bool {
    growth_active(index)
        && growth_excluded_parts(
            key,
            &index.v2().growth_retention,
            index.traversal.as_ref(),
            None,
        )
}

/// Only native completion calls this; opens, length equality, progress saves,
/// audit retirement and delivery ACKs do not settle source growth.
pub(super) fn settle_growth(index: &mut ScanIndex, key: &str) {
    if growth_active(index) {
        let _ = state_v2::save_read_completed(index, key);
        let generation = index.generation;
        let v2 = index.v2_mut();
        if let Some(state) = v2.growth_retention.get_mut(key) {
            state.predecessor_size = None;
            state.uncertain_passes = 0;
            state.checked_generation = Some(generation);
            note_growth_checked(v2, generation, key);
        }
    }
}

/// Checked this generation: retirement must not revalidate (and re-retain) it.
fn note_growth_checked(v2: &mut state_v2::IndexState, generation: u64, key: &str) {
    if v2.growth_checked.0 != generation {
        v2.growth_checked = (generation, BTreeSet::new());
    }
    v2.growth_checked.1.insert(key.to_owned());
}

pub(super) fn growth_subset(
    index: &ScanIndex,
    previous: &ScanIndex,
    safe: &BTreeSet<String>,
) -> BTreeMap<String, GrowthRetention> {
    let mut debt = index.v2().growth_retention.clone();
    if !growth_active(index) {
        return debt;
    }
    for (key, state) in &previous.v2().growth_retention {
        if !safe.contains(key) {
            let current = debt.entry(key.clone()).or_insert_with(|| state.clone());
            if state.predecessor_size.is_some() {
                current.predecessor_size = state.predecessor_size;
            }
        }
    }
    merge_growth_claims(&mut debt, &previous.v2().growth_retention);
    debt
}

pub(super) const GROWTH_FULL_INTERVAL: u64 = 6 * 60 * 60;

pub(super) fn prune_growth_retention(index: &mut ScanIndex, now: u64) {
    let files = &index.files;
    let Some(v2) = index.v2.as_mut() else { return };
    let before = v2.growth_retention.len();
    v2.growth_retention.retain(|key, state| {
        files.contains_key(key)
            || state
                .last_growth_full_unix
                .is_some_and(|last| now < last.saturating_add(GROWTH_FULL_INTERVAL))
    });
    let reclaimed = before - v2.growth_retention.len();
    if reclaimed > 0 && growth_active(index) {
        crate::local_resource_diagnostics::claude_state_v2(&serde_json::json!({
            "growth_claim_reclaimed": reclaimed
        }));
    }
}

/// A load lineage shares only the generation of its own claim-only commits.
/// Ordinary saves replace this context, so stale clones cannot skip their CAS.
/// No transcript, checkpoint payload or second pacing store lives here.
#[derive(Debug)]
pub(super) struct GrowthClaimContext {
    path: PathBuf,
    base_generation: u64,
    v2_owner: Option<std::sync::Weak<state_v2::Runtime>>,
    receipt: Mutex<Option<(u64, (u64, u64))>>,
}
impl crate::heap_layout_bound::HeapLayoutBound for GrowthClaimContext {
    // The only heap allocation is the immutable path; the mutable receipt
    // contains only inline integers, so its heap charge cannot change.
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        crate::heap_layout_bound::HeapLayoutBound::heap_bound(&self.path, c)
    }
}
pub(super) fn bind_growth_claims(index: &mut ScanIndex, path: &Path) {
    index.v2_mut().growth_claim_context = Some(Arc::new(GrowthClaimContext {
        path: path.to_owned(),
        base_generation: index.generation,
        v2_owner: index.v2().persistence_v2.as_ref().map(Arc::downgrade),
        receipt: Mutex::new(None),
    }));
}
pub(super) fn renew_growth_claims(index: &mut ScanIndex, path: &Path) {
    if index.v2().growth_claim_context.is_some() {
        bind_growth_claims(index, path);
    }
}
pub(super) fn own_growth_claim_generation(index: &ScanIndex, path: &Path) -> Option<u64> {
    let context = index.v2().growth_claim_context.as_ref()?;
    let (generation, stamp) = (*context.receipt.lock().ok()?)?;
    let matches = growth_owner_matches(index, context)
        && state_v2::confirmed_growth_stamp(index, path).ok() == Some(stamp)
        && stamp.0 == generation;
    (context.path == path
        && index.generation == context.base_generation
        && generation > context.base_generation
        && matches)
        .then_some(generation)
}

fn growth_owner_matches(index: &ScanIndex, context: &GrowthClaimContext) -> bool {
    match (&index.v2().persistence_v2, &context.v2_owner) {
        (Some(runtime), Some(owner)) => owner
            .upgrade()
            .is_some_and(|owner| Arc::ptr_eq(runtime, &owner)),
        _ => false,
    }
}

fn authenticate_growth_generation(index: &ScanIndex, path: &Path) -> Result<()> {
    let context = index
        .v2()
        .growth_claim_context
        .as_ref()
        .context("growth claim context missing")?;
    anyhow::ensure!(
        context.path == path && growth_owner_matches(index, context),
        "growth claim owner changed"
    );
    let expected = own_growth_claim_generation(index, path).unwrap_or(index.generation);
    anyhow::ensure!(
        state_v2::confirmed_growth_stamp(index, path)?.0 == expected,
        "growth claim needs index reload"
    );
    Ok(())
}

/// Called by save while the checkpoint lock still protects this publication.
/// A same-generation replacement must not become a claim-lineage CAS bypass.
pub(super) fn publish_growth_claim_receipt(index: &ScanIndex, path: &Path) -> Result<()> {
    let context = index
        .v2()
        .growth_claim_context
        .as_ref()
        .context("growth claim context missing")?;
    anyhow::ensure!(context.path == path, "growth claim path changed");
    anyhow::ensure!(
        growth_owner_matches(index, context),
        "growth claim owner changed"
    );
    let stamp = state_v2::confirmed_growth_stamp(index, path)?;
    anyhow::ensure!(
        stamp.0 == index.generation,
        "growth claim publication changed"
    );
    *context
        .receipt
        .lock()
        .map_err(|_| anyhow::anyhow!("growth claim receipt unavailable"))? =
        Some((index.generation, stamp));
    Ok(())
}

/// Claims are monotonic even when a subset restores an older file entry or
/// native completion clears its selection debt. A failed read still spent it.
pub(super) fn merge_growth_claims(
    target: &mut BTreeMap<String, GrowthRetention>,
    committed: &BTreeMap<String, GrowthRetention>,
) {
    for (key, state) in committed {
        if let Some(claim) = state.last_growth_full_unix {
            let current = target.entry(key.clone()).or_default();
            current.last_growth_full_unix =
                Some(current.last_growth_full_unix.unwrap_or(0).max(claim));
        }
    }
}

fn claim_growth_full(index: &mut ScanIndex, key: &str, now: u64) -> Result<bool> {
    let recent = |state: &GrowthRetention| {
        state
            .last_growth_full_unix
            .is_some_and(|last| now < last.saturating_add(GROWTH_FULL_INTERVAL))
    };
    if index.v2().growth_retention.get(key).is_some_and(recent)
        || index.decode_holds.contains("growth_retention", key)
    {
        return Ok(false);
    }
    let context = index
        .v2()
        .growth_claim_context
        .clone()
        .context("growth Full needs a committed scan index")?;
    // Decode the committed index, not the working page: persisting a claim
    // must never publish unaccepted bodies, progress or census changes.
    authenticate_growth_generation(index, &context.path)?;
    let mut committed = ScanIndex::load(&context.path)?;
    anyhow::ensure!(
        growth_owner_matches(&committed, &context),
        "growth claim owner changed"
    );
    authenticate_growth_generation(index, &context.path)?;
    let expected = own_growth_claim_generation(index, &context.path).unwrap_or(index.generation);
    anyhow::ensure!(
        committed.generation == expected,
        "growth claim needs index reload"
    );
    committed.require_persistence_available()?;
    if committed.v2().growth_retention.get(key).is_some_and(recent)
        || committed.decode_holds.contains("growth_retention", key)
    {
        merge_growth_claims(
            &mut index.v2_mut().growth_retention,
            &committed.v2().growth_retention,
        );
        return Ok(false);
    }
    let mut claim = index
        .v2()
        .growth_retention
        .get(key)
        .cloned()
        .unwrap_or_default();
    claim.last_growth_full_unix = Some(now);
    committed
        .v2_mut()
        .growth_retention
        .insert(key.to_owned(), claim);
    // Existing save owns lock, full CAS, atomic publication and fsync. If it
    // fails (including ambiguous publication), no acquisition is authorized.
    committed.v2_mut().growth_claim_context = Some(context.clone());
    committed.save_growth_claim(&context.path)?;
    let _lock = CheckpointLock::acquire(&context.path)?;
    publish_growth_claim_receipt(&committed, &context.path)?;
    merge_growth_claims(
        &mut index.v2_mut().growth_retention,
        &committed.v2().growth_retention,
    );
    Ok(true)
}

/// Identity has already been checked by open_and_identify and ReadPlan.
/// Rewrites/shrinks keep their own counted cause; a missing reusable checkpoint
/// takes the existing Full only after a durable six-hour claim.
pub(super) fn growth_read_admitted(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    mode: crate::transcript_acquisition::ReadMode,
) -> bool {
    if !growth_active(index) {
        return true;
    }
    growth_read_admitted_at(index, candidate, mode, sampled_scan::now_seconds())
}
pub(super) fn growth_read_admitted_at(
    index: &mut ScanIndex,
    candidate: &CandidateFile,
    mode: crate::transcript_acquisition::ReadMode,
    now: u64,
) -> bool {
    use crate::transcript_acquisition::{FullReason, ReadMode};
    if !growth_active(index) {
        return true;
    }
    let key = local_index_key(&candidate.path);
    let oversize = match state_v2::save_oversize_active(index) {
        Ok(held) => held,
        Err(_) => return false,
    };
    // A stale graph must not erase committed growth debt and bypass pacing.
    // Authenticate even rewrite Fulls before consulting working-page debt.
    if index.v2().persistence_v2.is_some() && (oversize || matches!(mode, ReadMode::Full(_))) {
        let valid = (|| -> Result<()> {
            let path = &index
                .v2()
                .growth_claim_context
                .as_ref()
                .context("growth claim context missing")?
                .path;
            let _lock = CheckpointLock::acquire(path)?;
            authenticate_growth_generation(index, path)
        })();
        if valid.is_err() {
            state_v2::growth_claim_refused("lineage");
            return false;
        }
    }
    let held = index.decode_holds.contains("growth_retention", &key);
    if !oversize
        && !held
        && !index
            .v2()
            .growth_retention
            .get(&key)
            .is_some_and(|state| state.predecessor_size.is_some())
    {
        return true;
    }
    if oversize
        || matches!(
            mode,
            ReadMode::Full(
                FullReason::StateMissing
                    | FullReason::InvalidCheckpoint
                    | FullReason::UnsupportedIdentity
            )
        )
    {
        return match claim_growth_full(index, &key, now) {
            Ok(admitted) => {
                if oversize && admitted {
                    crate::local_resource_diagnostics::claude_state_v2(&serde_json::json!({
                        "save_oversize_growth_full": 1
                    }));
                }
                admitted
            }
            Err(_) => {
                if index.v2().persistence_v2.is_some() {
                    state_v2::growth_claim_refused("publication");
                }
                false
            }
        };
    }
    true
}

#[cfg(test)]
mod growth_tests {
    use super::super::claude_request_census::{
        ClaudeRequestCensusRecord, ClaudeRequestCensusShape,
    };
    use super::*;

    const ACCEPTED: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    struct Fixture {
        root: PathBuf,
        path: PathBuf,
        key: String,
    }
    impl Fixture {
        fn new() -> Self {
            let root = crate::test_scratch::canonical_private_dir("ottto-v2-growth");
            let path = root.join("session.jsonl");
            fs::write(&path, b"old\n").unwrap();
            let key = local_index_key(&path);
            Self { root, path, key }
        }
        fn index(&self) -> ScanIndex {
            let index = self.legacy_index();
            self.persist(&index);
            ScanIndex::load(&self.storage_path()).unwrap()
        }
        fn legacy_index(&self) -> ScanIndex {
            let mut index = ScanIndex::default();
            let entry = serde_json::from_value(serde_json::json!({
                "size_bytes": 4, "modified_unix_seconds": 1, "modified_unix_nanos": 1,
                "source_file_fingerprint": "a".repeat(64), "last_snapshot_fingerprint": ACCEPTED,
                "scan_identity_version": LOCAL_SCAN_INDEX_IDENTITY_VERSION,
            }))
            .unwrap();
            index.files.insert(self.key.clone(), entry);
            index.accepted_snapshot_fingerprints.insert(ACCEPTED.into());
            let record = ClaudeRequestCensusRecord::synthetic_for_test(
                &"a".repeat(64),
                1,
                ClaudeRequestCensusShape::Exact,
                vec![7],
            )
            .with_modified_for_test(Some(1));
            index
                .claude_request_census
                .insert_for_test(&self.key, record);
            ensure_bounded_traversal(
                SnapshotSource::ClaudeCode,
                std::slice::from_ref(&self.root),
                &mut index,
                "2026-10-07T12:00:00Z",
                30,
            );
            let walk = index.traversal.as_mut().unwrap();
            // The old directory has already been visited and age-skipped.
            walk.pending_directories.clear();
            walk.pending_candidates.clear();
            walk.observed_index_keys.clear();
            walk.reconciliation_upper_bound = Some(self.key.clone());
            index
        }
        fn storage_path(&self) -> PathBuf {
            self.root
                .join("snapshots/destinations")
                .join("a".repeat(64))
                .join("claude_code-test-scan-index.json")
        }
        fn persist(&self, index: &ScanIndex) {
            let path = self.storage_path();
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let progress = serde_json::to_vec(&serde_json::json!({
                "schema_version": 3,
                "destination_namespace_hash": "a".repeat(64),
            }))
            .unwrap();
            if index.v2().persistence_v2.is_some() {
                index.clone().save(&path).unwrap();
            } else {
                state_v2::money_test_support::publish(index, &path, &progress);
            }
        }
        fn grow(&self) {
            fs::write(&self.path, b"old\nappend\n").unwrap();
        }
        fn pending(&self) -> ScanTraversalPath {
            ScanTraversalPath {
                scan_root: self.root.clone(),
                path: self.path.clone(),
                census_member: true,
                watcher_hint: false,
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let path = self.storage_path();
            if path.parent().is_some_and(Path::exists) {
                state_v2::money_test_support::erase_published(&path);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    fn restart_lenient(index: &ScanIndex) -> ScanIndex {
        if index.v2.is_some() || index.decode_holds.contains_field("growth_retention") {
            let root = crate::test_scratch::canonical_private_dir("growth-row-restart");
            let mut restored = state_v2::money_test_support::roundtrip_rows(
                index,
                &root.join("state.v2.sqlite.import"),
            );
            super::super::lenient_decode::post_decode_hydrated(
                &mut restored,
                "fixture",
                "claude_code",
            )
            .unwrap();
            fs::remove_dir_all(root).unwrap();
            restored.v2_mut().persistence_v2 = index.v2().persistence_v2.clone();
            restored
        } else {
            let mut bytes = Vec::new();
            super::super::lenient_decode::write_index(&mut bytes, index).unwrap();
            super::super::lenient_decode::read(
                std::io::Cursor::new(bytes),
                "fixture",
                "claude_code",
            )
            .unwrap()
        }
    }
    fn restart(index: &ScanIndex) -> ScanIndex {
        // V1 deliberately drops this field. Its independent v2 rows retain it.
        let serde: ScanIndex = serde_json::from_slice(&serde_json::to_vec(index).unwrap()).unwrap();
        assert!(serde.v2.is_none());
        let stored = restart_lenient(index);
        assert_eq!(stored.v2().growth_retention, index.v2().growth_retention);
        stored
    }

    /// [money] f1 resumed reconciliation keeps growth after hold and restart.
    #[test]
    fn f1_resumed_reconciliation_keeps_growth_after_hold_and_restart() {
        for age_days in [31, 40] {
            let fixture = Fixture::new();
            let held = fixture.index();
            fixture.grow();
            let mut resumed = restart(&held);
            let ((done, ()), rows) = crate::local_resource_diagnostics::capture(|| {
                let done = reconcile_missing_index_entries_with_limit(&mut resumed, 1);
                (done, ())
            });
            assert!(!done, "new census work defers terminal");
            assert_eq!(resumed.files[&fixture.key].size_bytes, 4);
            assert!(resumed.accepted_snapshot_fingerprints.contains(ACCEPTED));
            assert_eq!(resumed.claude_request_census.hash_total_for_test(), 1);
            assert!(resumed
                .traversal
                .as_ref()
                .unwrap()
                .residue
                .index_keys
                .contains(&fixture.key));
            assert_eq!(
                resumed
                    .traversal
                    .as_ref()
                    .unwrap()
                    .reconciliation_after
                    .as_deref(),
                Some(fixture.key.as_str())
            );
            assert!(rows
                .iter()
                .any(|row| row["counts"]["v2_growth_revalidate"]["stats"] == 1));
            resumed = restart(&resumed);
            let bounded = restart_lenient(&resumed);
            assert_eq!(bounded.v2().growth_retention, resumed.v2().growth_retention);
            assert!(resumed.v2().growth_retention[&fixture.key]
                .predecessor_size
                .is_some());
            let mut census = ScanCensus::default();
            let now = unix_seconds(SystemTime::now()).unwrap() + age_days * 86400;
            let candidate = candidate_from_traversal_path(
                SnapshotSource::ClaudeCode,
                fixture.pending(),
                &mut census,
                Some(now),
                30,
                // v2 growth follows the index (production derivation).
                &mut crate::snapshots::CandidateDiscovery::new(&mut resumed.clone(), None),
            )
            .unwrap();
            assert!(open_and_identify_scan_candidate_at(
                SnapshotSource::ClaudeCode,
                candidate,
                &mut census,
                crate::snapshots::CandidateWindow {
                    census_unix_seconds: Some(now),
                    backfill_window_days: 30,
                    retention: crate::snapshots::DiscoveryRetention::unverified(&resumed.files),
                    growth: Some(&resumed.v2().growth_retention),
                },
                sampled_scan::now_seconds(),
            )
            .is_some());
        }
    }

    /// [money] f2 progress restart terminal excludes debt until native settlement.
    #[test]
    fn f2_progress_restart_terminal_excludes_debt_until_native_settlement() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        assert!(revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root)
        ));
        // A progress checkpoint can advance working bytes before settlement.
        index.files.get_mut(&fixture.key).unwrap().size_bytes = 11;
        let mut index = restart(&index);
        index.traversal.as_mut().unwrap().pending_candidates.clear();
        let window = 40 * 86400;
        assert_eq!(index.retire_claude_transcript_records_for_test(window).0, 0);
        assert_eq!(index.claude_request_census.hash_total_for_test(), 1);
        let state = index.files[&fixture.key].clone();
        index
            .files
            .get_mut(&fixture.key)
            .unwrap()
            .set_unverified_deadline(window + 10);
        settle_growth(&mut index, &fixture.key);
        assert!(
            index.files[&fixture.key].has_unverified_source(),
            "growth settlement does not erase audit debt"
        );
        index.files.insert(fixture.key.clone(), state);
        index.traversal.as_mut().unwrap().reconciliation_after = Some(fixture.key.clone());
        // Native settlement's existing residue bookkeeping removes that key.
        index
            .traversal
            .as_mut()
            .unwrap()
            .residue
            .index_keys
            .remove(&fixture.key);
        assert_eq!(index.retire_claude_transcript_records_for_test(window).0, 1);
        assert_eq!(index.claude_request_census.hash_total_for_test(), 0);
    }

    /// [money] f2 admission pressure keeps retained hashes and defers new record.
    #[test]
    fn f2_admission_pressure_keeps_retained_hashes_and_defers_new_record() {
        for prechecked in [true, false] {
            let fixture = Fixture::new();
            let mut index = fixture.index();
            fixture.grow();
            if prechecked {
                revalidate_growth(
                    &mut index,
                    &fixture.key,
                    std::slice::from_ref(&fixture.root),
                );
            }
            let cap = super::super::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_HASHES;
            let record = ClaudeRequestCensusRecord::synthetic_for_test(
                &"a".repeat(64),
                1,
                ClaudeRequestCensusShape::Exact,
                (0..cap as u64).collect(),
            )
            .with_modified_for_test(Some(1));
            index
                .claude_request_census
                .insert_for_test(&fixture.key, record);
            let mut index = restart(&index);
            let new_record = ClaudeRequestCensusRecord::synthetic_for_test(
                &"b".repeat(64),
                40 * 86400,
                ClaudeRequestCensusShape::Exact,
                vec![u64::MAX],
            );
            let outcome =
                index.insert_transcript_record_for_test("new-key", new_record, 40 * 86400);
            assert_ne!(
                outcome,
                super::super::claude_request_census::ClaudeRequestCensusInsert::Stored
            );
            assert_eq!(
                index
                    .claude_request_census
                    .record_for_test(&fixture.key)
                    .unwrap()
                    .request_hashes_for_test()
                    .len(),
                cap
            );
            // Occupancy release also excludes this key, even above 90%.
            assert_eq!(
                index
                    .retire_claude_transcript_records_for_test(40 * 86400)
                    .0,
                0
            );
            assert_eq!(
                index.claude_request_census.totals_for_test(),
                index.claude_request_census.recounted_for_test()
            );
        }
    }

    /// [regress] retained same key rollback restores exact custody inside tombstone reserve.
    #[test]
    fn retained_same_key_rollback_restores_exact_custody_inside_tombstone_reserve() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let whole = super::super::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
            - 1024 * 1024;
        let padding = "x".repeat(3900);
        let mut n = 0;
        while index.claude_request_census.serialized_total_for_test() <= whole + 16384 {
            let record = ClaudeRequestCensusRecord::synthetic_for_test(
                &"b".repeat(64),
                40 * 86400,
                ClaudeRequestCensusShape::OverBudget,
                vec![],
            )
            .with_modified_for_test(Some(40 * 86400));
            assert_ne!(
                index
                    .claude_request_census
                    .insert_for_test(&format!("reserve-{n:05}-{padding}"), record,),
                super::super::claude_request_census::ClaudeRequestCensusInsert::Refused
            );
            n += 1;
        }
        let before = index
            .claude_request_census
            .get(&fixture.key)
            .unwrap()
            .clone();
        let hashes = before.request_hashes_for_test().as_ptr();
        let bytes = serde_json::to_vec(&before).unwrap();
        let totals = index.claude_request_census.totals_for_test();
        assert!(totals.1 > whole);
        assert!(
            totals.1
                < super::super::claude_request_census::MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES
        );
        let outcome = index.insert_transcript_record_for_test(
            &fixture.key,
            before.clone().with_request_hashes_for_test(vec![7, 8]),
            40 * 86400,
        );
        assert_ne!(
            outcome,
            super::super::claude_request_census::ClaudeRequestCensusInsert::Stored
        );
        let restored = index.claude_request_census.get(&fixture.key).unwrap();
        assert_eq!(
            serde_json::to_vec(restored).unwrap(),
            bytes,
            "exact old record"
        );
        assert_eq!(
            restored.request_hashes_for_test().as_ptr(),
            hashes,
            "same shared hash buffer"
        );
        assert_eq!(index.claude_request_census.totals_for_test(), totals);
        assert_eq!(index.claude_request_census.recounted_for_test(), totals);
    }

    /// [off=main] f3 off preserves v1 age and bytes.
    #[test]
    fn f3_off_preserves_v1_age_and_bytes() {
        let fixture = Fixture::new();
        let mut index = fixture.legacy_index();
        fixture.grow();
        let before = serde_json::to_vec(&index).unwrap();
        assert!(!growth_active(&index));
        let candidate = identified(&fixture, &index);
        assert!(growth_read_admitted_at(
            &mut index,
            &candidate,
            crate::transcript_acquisition::ReadMode::Full(
                crate::transcript_acquisition::FullReason::StateMissing
            ),
            100,
        ));
        assert!(!revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root)
        ));
        assert_eq!(serde_json::to_vec(&index).unwrap(), before);
        assert!(!serde_json::from_slice::<serde_json::Value>(&before)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("growth_retention"));
        assert_eq!(serde_json::to_vec(&restart(&index)).unwrap(), before);
        let mut census = ScanCensus::default();
        let now = unix_seconds(SystemTime::now()).unwrap() + 40 * 86400;
        // Main's #876 retains an indexed grown file across the window
        // (DiscoveryRetention::owes_stamped / codex_fragment::grown); OFF
        // selects it exactly as main does, without any v2 growth custody.
        assert!(candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            fixture.pending(),
            &mut census,
            Some(now),
            30,
            // v2 growth follows the index (production derivation).
            &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None),
        )
        .is_some());
        assert!(reconcile_missing_index_entries_with_limit(&mut index, 1));
        assert!(!index.files.contains_key(&fixture.key));
    }

    /// [money] f9 uncertainty alarms on fourth consecutive saved pass without dropping.
    #[test]
    fn f9_uncertainty_alarms_on_fourth_consecutive_saved_pass_without_dropping() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        let missing_root = fixture.root.join("not-configured");
        for pass in 1..=4 {
            index.generation = pass;
            let (_, rows) = crate::local_resource_diagnostics::capture(|| {
                assert!(revalidate_growth(
                    &mut index,
                    &fixture.key,
                    std::slice::from_ref(&missing_root)
                ));
                // Repeat in the same pass must not spend another uncertainty.
                assert!(revalidate_growth(
                    &mut index,
                    &fixture.key,
                    std::slice::from_ref(&missing_root)
                ));
            });
            assert_eq!(
                rows.iter()
                    .any(|row| row["stage"] == "v2_growth_uncertain_alarm"),
                pass == 4
            );
            assert!(index.files.contains_key(&fixture.key));
            index = restart(&index);
        }
        assert_eq!(
            index.v2().growth_retention[&fixture.key].uncertain_passes,
            4
        );
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        assert_eq!(
            index.v2().growth_retention[&fixture.key].uncertain_passes,
            0
        );
    }
    /// [regress] N5: retirement revalidation persisted a growth row for every
    /// unchanged aged candidate and rewrote debt rows every generation.
    #[test]
    fn retirement_revalidation_persists_no_check_only_rows() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        assert_eq!(
            index
                .retire_claude_transcript_records_for_test(40 * 86400)
                .0,
            1
        );
        assert!(index.files.contains_key(&fixture.key));
        assert!(!index.v2().growth_retention.contains_key(&fixture.key));
        // A debt row records its checked status once, not every generation.
        fixture.grow();
        let roots = std::slice::from_ref(&fixture.root);
        assert!(revalidate_growth(&mut index, &fixture.key, roots));
        let checked = index.v2().growth_retention[&fixture.key].checked_generation;
        assert!(checked.is_some());
        index.generation += 1;
        assert!(revalidate_growth(&mut index, &fixture.key, roots));
        assert_eq!(
            index.v2().growth_retention[&fixture.key].checked_generation,
            checked
        );
    }

    /// [money] f3 identity causes are not reclassified as retained growth.
    #[test]
    fn f3_identity_causes_are_not_reclassified_as_retained_growth() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            fixture.pending(),
            &mut census,
            None,
            30,
            // v2 growth follows the index (production derivation).
            &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None),
        )
        .unwrap();
        let (candidate, _) = open_and_identify_scan_candidate_at(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            crate::snapshots::CandidateWindow {
                census_unix_seconds: None,
                backfill_window_days: 30,
                retention: crate::snapshots::DiscoveryRetention::unverified(&index.files),
                growth: Some(&index.v2().growth_retention),
            },
            sampled_scan::now_seconds(),
        )
        .unwrap();
        for cause in [
            FullReason::Replaced,
            FullReason::Shrunk,
            FullReason::HeadChanged,
            FullReason::BoundaryChanged,
            FullReason::SameSizeEdit,
        ] {
            assert!(growth_read_admitted(
                &mut index,
                &candidate,
                ReadMode::Full(cause)
            ));
        }
        assert!(growth_read_admitted(&mut index, &candidate, ReadMode::Tail));
        assert!(
            !growth_read_admitted(
                &mut restart(&index),
                &candidate,
                ReadMode::Full(FullReason::StateMissing)
            ),
            "no restart allowance without a durable Full claim"
        );
    }

    /// [money] f2 growth subset restores debt for unsettled file only.
    #[test]
    fn f2_growth_subset_restores_debt_for_unsettled_file_only() {
        let fixture = Fixture::new();
        let mut previous = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut previous,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let mut working = previous.clone();
        settle_growth(&mut working, &fixture.key);
        let mut subset = restart(&working);
        subset.v2_mut().growth_retention = growth_subset(&working, &previous, &BTreeSet::new());
        assert!(restart(&subset).v2().growth_retention[&fixture.key]
            .predecessor_size
            .is_some());
        assert!(
            growth_subset(&working, &previous, &BTreeSet::from([fixture.key.clone()]))
                .values()
                .all(|state| state.predecessor_size.is_none())
        );
    }
    fn identified(fixture: &Fixture, index: &ScanIndex) -> CandidateFile {
        let mut census = ScanCensus::default();
        let candidate = candidate_from_traversal_path(
            SnapshotSource::ClaudeCode,
            fixture.pending(),
            &mut census,
            None,
            30,
            // v2 growth follows the index (production derivation).
            &mut crate::snapshots::CandidateDiscovery::new(&mut index.clone(), None),
        )
        .unwrap();
        open_and_identify_scan_candidate_at(
            SnapshotSource::ClaudeCode,
            candidate,
            &mut census,
            crate::snapshots::CandidateWindow {
                census_unix_seconds: None,
                backfill_window_days: 30,
                retention: crate::snapshots::DiscoveryRetention::unverified(&index.files),
                growth: Some(&index.v2().growth_retention),
            },
            sampled_scan::now_seconds(),
        )
        .unwrap()
        .0
    }

    /// [money] f3 growth full claim survives restart failure and subset save.
    #[test]
    fn f3_growth_full_claim_survives_restart_failure_and_subset_save() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        for reason in [
            FullReason::StateMissing,
            FullReason::InvalidCheckpoint,
            FullReason::UnsupportedIdentity,
        ] {
            let fixture = Fixture::new();
            let path = fixture.storage_path();
            let mut initial = fixture.index();
            fixture.grow();
            revalidate_growth(
                &mut initial,
                &fixture.key,
                std::slice::from_ref(&fixture.root),
            );
            fixture.persist(&initial);
            let previous = ScanIndex::load(&path).unwrap();
            let mut unrelated = ScanIndex::load(&path).unwrap();
            let mut working = previous.clone();
            let candidate = identified(&fixture, &working);
            // The working page's progress/output is not committable yet.
            working.files.get_mut(&fixture.key).unwrap().size_bytes = 999;
            working
                .files
                .get_mut(&fixture.key)
                .unwrap()
                .last_snapshot_fingerprint = Some("d".repeat(64));
            let now = 100_000;
            assert!(growth_read_admitted_at(
                &mut working,
                &candidate,
                ReadMode::Full(reason),
                now
            ));
            // Simulate acquisition failure after admission. There is no refund:
            // a restart before any outcome save must still see the claim.
            fs::remove_file(&fixture.path).unwrap();
            assert!(open_candidate_beneath_root(&candidate).is_err());
            let mut resumed = ScanIndex::load(&path).unwrap();
            assert_eq!(resumed.files[&fixture.key].size_bytes, 4);
            assert_eq!(
                resumed.v2().growth_retention[&fixture.key].last_growth_full_unix,
                Some(now)
            );
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + GROWTH_FULL_INTERVAL - 1
            ));
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now - 1
            ));
            assert!(
                unrelated.save(&path).is_err(),
                "independent stale loads still fail CAS"
            );
            // Subset publication restores the old file, never the spent claim.
            let mut subset =
                working.committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new());
            assert_eq!(subset.files[&fixture.key].size_bytes, 4);
            subset.save(&path).unwrap();
            assert!(
                working.save(&path).is_err(),
                "ordinary publication ends the old claim-only lineage"
            );
            let mut resumed = ScanIndex::load(&path).unwrap();
            assert_eq!(
                resumed.v2().growth_retention[&fixture.key].last_growth_full_unix,
                Some(now)
            );
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + 1
            ));
            assert!(growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + GROWTH_FULL_INTERVAL
            ));
            assert!(!growth_read_admitted_at(
                &mut resumed,
                &candidate,
                ReadMode::Full(reason),
                now + GROWTH_FULL_INTERVAL
            ));
            // Even a settled key keeps its clock if it grows again soon.
            settle_growth(&mut resumed, &fixture.key);
            assert_eq!(
                resumed.v2().growth_retention[&fixture.key].last_growth_full_unix,
                Some(now + GROWTH_FULL_INTERVAL)
            );
        }
    }

    /// [money] f3 growth full without durable index never reads.
    #[test]
    fn f3_growth_full_without_durable_index_never_reads() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        let candidate = identified(&fixture, &index);
        // A graph without a load-lineage receipt cannot authorize acquisition.
        index.v2_mut().growth_claim_context = None;
        assert!(!growth_read_admitted_at(
            &mut index,
            &candidate,
            ReadMode::Full(FullReason::StateMissing),
            100
        ));
        assert_eq!(
            index.v2().growth_retention[&fixture.key].last_growth_full_unix,
            None
        );
    }

    /// [money] f3 recent claim outlives removal until interval expires.
    #[test]
    fn f3_recent_claim_outlives_removal_until_interval_expires() {
        let fixture = Fixture::new();
        let mut index = fixture.index();
        index.v2_mut().growth_retention.insert(
            fixture.key.clone(),
            GrowthRetention {
                last_growth_full_unix: Some(100),
                ..Default::default()
            },
        );
        index.files.clear();
        prune_growth_retention(&mut index, 100 + GROWTH_FULL_INTERVAL - 1);
        assert_eq!(
            restart(&index).v2().growth_retention[&fixture.key].last_growth_full_unix,
            Some(100)
        );
        prune_growth_retention(&mut index, 100 + GROWTH_FULL_INTERVAL);
        assert!(index.v2().growth_retention.is_empty());
    }
    /// [money] f3 malformed growth claim stays held across codec round trips.
    #[test]
    fn f3_malformed_growth_claim_stays_held_across_codec_round_trips() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let initial = fixture.index();
        let candidate = identified(&fixture, &initial);
        for bad in [
            serde_json::json!({"last_growth_full_unix": "bad"}),
            serde_json::json!({"last_growth_full_unix": "x".repeat(4097)}),
        ] {
            let mut seeded = initial.clone();
            let bytes = serde_json::to_vec(&bad).unwrap();
            let charge = bytes.len() as u64 + 256;
            seeded
                .decode_holds
                .v2_insert("growth_retention", fixture.key.clone(), bytes, None, charge)
                .unwrap();
            let mut decoded = restart_lenient(&seeded);
            assert!(decoded
                .decode_holds
                .contains("growth_retention", &fixture.key));
            assert!(!growth_read_admitted_at(
                &mut decoded,
                &candidate,
                ReadMode::Full(FullReason::StateMissing),
                100
            ));
            let raw = decoded
                .decode_holds
                .v2_entries()
                .find(|(field, key, ..)| *field == "growth_retention" && *key == fixture.key)
                .unwrap()
                .2;
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(raw).unwrap(),
                bad
            );
            let decoded = restart_lenient(&decoded);
            assert!(decoded
                .decode_holds
                .contains("growth_retention", &fixture.key));
        }
    }

    /// [money] f3 failed claim save never authorizes full or spends memory only.
    #[test]
    fn f3_failed_claim_save_never_authorizes_full_or_spends_memory_only() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let path = fixture.storage_path();
        let mut index = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut index,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        fixture.persist(&index);
        let mut stale = ScanIndex::load(&path).unwrap();
        let candidate = identified(&fixture, &stale);
        let mut newer = ScanIndex::load(&path).unwrap();
        newer.save(&path).unwrap();
        assert!(!growth_read_admitted_at(
            &mut stale,
            &candidate,
            ReadMode::Full(FullReason::StateMissing),
            100
        ));
        assert_eq!(
            stale.v2().growth_retention[&fixture.key].last_growth_full_unix,
            None
        );
        assert_eq!(
            ScanIndex::load(&path).unwrap().v2().growth_retention[&fixture.key]
                .last_growth_full_unix,
            None
        );
    }
    /// [money] f3 claim receipt rejects same generation checkpoint replacement.
    #[test]
    fn f3_claim_receipt_rejects_same_generation_checkpoint_replacement() {
        use crate::transcript_acquisition::{FullReason, ReadMode};
        let fixture = Fixture::new();
        let path = fixture.storage_path();
        let mut initial = fixture.index();
        fixture.grow();
        revalidate_growth(
            &mut initial,
            &fixture.key,
            std::slice::from_ref(&fixture.root),
        );
        fixture.persist(&initial);
        let mut working = ScanIndex::load(&path).unwrap();
        let candidate = identified(&fixture, &working);
        assert!(growth_read_admitted_at(
            &mut working,
            &candidate,
            ReadMode::Full(FullReason::StateMissing),
            100
        ));
        let db_path = path.with_file_name(format!(
            "{}.v2.sqlite",
            path.file_name().unwrap().to_str().unwrap()
        ));
        let bytes = fs::read(&db_path).unwrap();
        let replacement = fixture.root.join("replacement.sqlite");
        fs::write(&replacement, &bytes).unwrap();
        fs::rename(&replacement, &db_path).unwrap();
        assert!(
            working.save(&path).is_err(),
            "same generation alone is not exact claim publication custody"
        );
        assert_eq!(fs::read(&db_path).unwrap(), bytes);
    }
}
