//! MONEY N3 lightness: a durable per-key bound on duplicate-key rebuilds.
//!
//! An ambiguous duplicate census key rearms its transcript (an empty index
//! fingerprint reads as Parse(Rearmed)), so the next pass re-reads Claude
//! history even with activation OFF. Failures, restarts or renewed corruption
//! could repeat that without limit. Each key gets at most
//! `MAX_ATTEMPTS_PER_WINDOW` rearms per rolling `WINDOW_SECONDS`.
//!
//! - Stamps live in the shadow state and the daemon saves a grant before its
//!   scan can read (`persist_grants`), so a crash cannot erase an attempt.
//! - A future stamp counts as recent (clamped to now: fail closed under clock
//!   rollback, and it still expires one window after it is first seen).
//! - A persisted rearm is counted again on the first load of each process, or
//!   when this process already started its parse. A bounded sweep that has not
//!   reached the key yet does not spend an attempt.
//! - Past the bound the key is not rearmed: its last indexed fingerprint is
//!   restored, its record stays absent, its duplicate stays counted in
//!   `decode_duplicate_keys_dropped`, and the census line counts it in
//!   `census_duplicate_rebuild_exhausted` with a rate-limited alarm. A clean
//!   decode of the key's record or the window passing clears it.
//! - Tracked keys are capped; past the cap, or after a malformed guard, new
//!   keys are refused (not rearmed) and counted for one window.
//! - The fingerprint a grant emptied is saved outside the shadow state, in the
//!   index's own strictly decoded `claude_census_rebuild_priors`. It is lost
//!   only with the index entries themselves, so a malformed, duplicated or
//!   closed shadow cannot make a rearm free: a saved prior whose key the guard
//!   no longer holds is an orphan. Its fingerprint is restored (no re-read),
//!   the key is held exhausted for one window, and
//!   `census_duplicate_rebuild_orphaned` plus an alarm count it.
//! - Only well-formed fingerprints (64 lowercase hex, the only Claude index
//!   form) are rearmed; anything else is refused at insert, so every saved
//!   prior and the guard stay small and decodable.
//!
//! A key whose fingerprint was already empty when its duplicate was found is
//! another mechanism's rearm; this bound does not track it.
use super::*;

pub(super) const WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
pub(super) const MAX_ATTEMPTS_PER_WINDOW: usize = 2;
/// The index is saved pretty-printed: one tracked key is one line of at most
/// about 80 B (two 20-digit stamps). 512 keys stay far below this guard's own
/// cap, and with a full `s` marker (about 311 KiB) below the shadow field's
/// 512 KiB decode cap, so saved state never closes itself.
pub(crate) const MAX_TRACKED_KEYS: usize = 512;
const MAX_GUARD_RAW_BYTES: usize = 128 * 1024;
/// A Claude index fingerprint: lowercase hex SHA-256.
const PRIOR_BYTES: usize = 64;
const MAX_ALARMS_PER_TERMINAL: usize = 8;
/// `closed_at` value of a guard that must be stamped at its next apply.
const UNSTAMPED: u64 = u64::MAX;

const PENDING: u8 = 1;
const STARTED: u8 = 2;
const EXHAUSTED: u8 = 4;

/// The persisted guard (`"n"` in the shadow state).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DuplicateRebuildGuard {
    /// First 16 hex digits of the key's SHA-256.
    #[serde(default, rename = "k", skip_serializing_if = "BTreeMap::is_empty")]
    keys: BTreeMap<String, TrackedKey>,
    /// New keys refused because the tracked set was full or the guard closed.
    #[serde(default, rename = "u", skip_serializing_if = "is_zero")]
    untracked_refused: u64,
    #[serde(default, rename = "ua", skip_serializing_if = "is_zero")]
    untracked_refused_at: u64,
    /// Rearms found orphaned (prior saved, guard lost), counted for one window.
    #[serde(default, rename = "o", skip_serializing_if = "is_zero")]
    orphaned: u64,
    #[serde(default, rename = "oa", skip_serializing_if = "is_zero")]
    orphaned_at: u64,
    #[serde(default, rename = "c", skip_serializing_if = "Option::is_none")]
    closed_at: Option<u64>,
}
crate::heap_layout_bound::fields!(DuplicateRebuildGuard; keys, untracked_refused, untracked_refused_at, orphaned, orphaned_at, closed_at);

/// One compact string per key, `"<flags>:<stamp>,<stamp>"`, so the
/// pretty-printed index spends one line on it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrackedKey {
    /// Rearm stamps (unix seconds), at most the two most recent.
    attempts: Vec<u64>,
    flags: u8,
    /// Read from the earlier `"<flags>:<stamps>:<prior>"` form; moved into
    /// the saved priors at the next apply and never written back.
    legacy_prior: Option<String>,
}
crate::heap_layout_bound::fields!(TrackedKey; attempts, flags, legacy_prior);

impl Serialize for TrackedKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let attempts = self
            .attempts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(",");
        match &self.legacy_prior {
            // Kept through the ON reader's normalization pass, which runs
            // before `apply` migrates it; `apply` always takes it, so saves
            // write the current form.
            Some(prior) => {
                serializer.collect_str(&format_args!("{}:{attempts}:{prior}", self.flags))
            }
            None => serializer.collect_str(&format_args!("{}:{attempts}", self.flags)),
        }
    }
}
impl<'de> Deserialize<'de> for TrackedKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let malformed = || <D::Error as serde::de::Error>::custom("rebuild guard key");
        let text = String::deserialize(deserializer)?;
        let mut parts = text.splitn(3, ':');
        let (Some(flags), Some(attempts)) = (parts.next(), parts.next()) else {
            return Err(malformed());
        };
        let legacy_prior = parts
            .next()
            .filter(|prior| !prior.is_empty())
            .map(str::to_owned);
        let attempts = if attempts.is_empty() {
            Vec::new()
        } else {
            attempts
                .split(',')
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| malformed())?
        };
        Ok(Self {
            attempts,
            flags: flags.parse().map_err(|_| malformed())?,
            legacy_prior,
        })
    }
}

fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// The only fingerprint a grant may empty, and so the only prior saved.
fn valid_prior(fingerprint: &str) -> bool {
    fingerprint.len() == PRIOR_BYTES && lower_hex(fingerprint.as_bytes())
}

/// `ScanIndex::claude_census_rebuild_priors`: key id -> the fingerprint its
/// outstanding grant emptied. Strict like the index entries it protects: an
/// oversized, duplicated or malformed map fails the index decode (quarantine,
/// as for any malformed entry), so a prior is never dropped while its entry
/// survives.
pub(crate) fn deserialize_priors<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    struct Priors;
    impl<'de> Visitor<'de> for Priors {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("duplicate rebuild priors")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let malformed = || <A::Error as serde::de::Error>::custom("rebuild priors");
            let mut priors = BTreeMap::new();
            while let Some(id) = map.next_key::<String>()? {
                let prior = map.next_value::<String>()?;
                if priors.len() >= MAX_TRACKED_KEYS
                    || id.len() != 16
                    || !lower_hex(id.as_bytes())
                    || !valid_prior(&prior)
                    || priors.insert(id, prior).is_some()
                {
                    return Err(malformed());
                }
            }
            Ok(priors)
        }
    }
    deserializer.deserialize_map(Priors)
}

/// Clamp a future stamp to `now` (recent, fail closed); true while it is
/// inside the window.
fn recent(stamp: &mut u64, now: u64) -> bool {
    *stamp = (*stamp).min(now);
    now - *stamp <= WINDOW_SECONDS
}

impl TrackedKey {
    fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

impl DuplicateRebuildGuard {
    fn closed() -> Self {
        Self {
            closed_at: Some(UNSTAMPED),
            ..Self::default()
        }
    }

    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Decode `"n"`: anything oversized or out of shape closes the guard.
    pub(super) fn decode(raw: &str) -> Self {
        if raw.len() > MAX_GUARD_RAW_BYTES {
            return Self::closed();
        }
        serde_json::from_str::<Self>(raw)
            .ok()
            .filter(|guard| {
                guard.keys.len() <= MAX_TRACKED_KEYS
                    && guard.keys.iter().all(|(id, key)| {
                        id.len() == 16
                            && lower_hex(id.as_bytes())
                            && key.attempts.len() <= MAX_ATTEMPTS_PER_WINDOW
                            && key.legacy_prior.as_ref().map_or(0, String::len)
                                <= MAX_CLAUDE_REQUEST_CENSUS_SCALAR_BYTES
                            && key.flags & !(PENDING | STARTED | EXHAUSTED) == 0
                    })
            })
            .unwrap_or_else(Self::closed)
    }

    /// Clamp future stamps to `now` and forget whatever left the window.
    fn settle_clock(&mut self, now: u64) {
        if let Some(mut closed) = self.closed_at {
            self.closed_at = recent(&mut closed, now).then_some(closed);
        }
        if self.untracked_refused > 0 && !recent(&mut self.untracked_refused_at, now) {
            self.untracked_refused = 0;
            self.untracked_refused_at = 0;
        }
        if self.orphaned > 0 && !recent(&mut self.orphaned_at, now) {
            self.orphaned = 0;
            self.orphaned_at = 0;
        }
        for key in self.keys.values_mut() {
            key.attempts.retain_mut(|stamp| recent(stamp, now));
            key.attempts.sort_unstable();
        }
    }

    fn refuse_untracked(&mut self, now: u64) {
        self.untracked_refused = self.untracked_refused.saturating_add(1);
        self.untracked_refused_at = now;
    }

    fn exhausted_keys(&self) -> u64 {
        let tracked = self.keys.values().filter(|key| key.has(EXHAUSTED)).count() as u64;
        tracked.saturating_add(self.untracked_refused)
    }
}

/// Never persisted: grants this load made, and refusals of keys the guard
/// could not track (for the terminal alarm).
#[derive(Debug, Clone, Default)]
pub(crate) struct Transient {
    grants: Vec<String>,
    refusals: Vec<(String, &'static str)>,
}
crate::heap_layout_bound::fields!(Transient; grants, refusals);

pub(crate) fn key_id(key: &str) -> String {
    let mut id = safety_key_id(key);
    id.truncate(16);
    id
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static PERSISTED: std::cell::RefCell<BTreeSet<String>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
    static ALARMED: std::cell::RefCell<BTreeSet<(String, &'static str)>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
    static ALARM_LINES: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
/// Keys whose current rearm this process already saved before its scan.
#[cfg(not(test))]
static PERSISTED: std::sync::Mutex<BTreeSet<String>> = std::sync::Mutex::new(BTreeSet::new());
/// One alarm per key and cause per process.
#[cfg(not(test))]
static ALARMED: std::sync::Mutex<BTreeSet<(String, &'static str)>> =
    std::sync::Mutex::new(BTreeSet::new());

fn system_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
#[cfg(test)]
fn now_unix() -> u64 {
    TEST_NOW
        .with(std::cell::Cell::get)
        .unwrap_or_else(system_now)
}
#[cfg(not(test))]
fn now_unix() -> u64 {
    system_now()
}

#[cfg(test)]
fn with_persisted<T>(f: impl FnOnce(&mut BTreeSet<String>) -> T) -> T {
    PERSISTED.with(|set| f(&mut set.borrow_mut()))
}
#[cfg(not(test))]
fn with_persisted<T>(f: impl FnOnce(&mut BTreeSet<String>) -> T) -> T {
    f(&mut PERSISTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

#[cfg(test)]
fn with_alarmed<T>(f: impl FnOnce(&mut BTreeSet<(String, &'static str)>) -> T) -> T {
    ALARMED.with(|set| f(&mut set.borrow_mut()))
}
#[cfg(not(test))]
fn with_alarmed<T>(f: impl FnOnce(&mut BTreeSet<(String, &'static str)>) -> T) -> T {
    f(&mut ALARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

fn first_alarm(id: &str, cause: &'static str) -> bool {
    with_alarmed(|set| set.len() < MAX_TRACKED_KEYS * 2 && set.insert((id.to_owned(), cause)))
}

fn emit_alarm(line: String) {
    #[cfg(test)]
    ALARM_LINES.with(|lines| lines.borrow_mut().push(line.clone()));
    eprintln!("{line}");
}

/// Decode-time decision for every fresh ambiguous key, every pending key and
/// every saved prior. Replaces the unconditional rearm; cheap no-op on a
/// healthy index.
pub(super) fn apply(index: &mut ScanIndex) {
    if index.claude_request_census.ambiguous.is_empty()
        && index.claude_request_census_shadow.rebuild_bound.is_none()
        && index.claude_census_rebuild_priors.is_empty()
    {
        return;
    }
    let now = now_unix();
    let mut guard = index
        .claude_request_census_shadow
        .rebuild_bound
        .take()
        .map_or_else(DuplicateRebuildGuard::default, |guard| *guard);
    if guard.closed_at == Some(UNSTAMPED) {
        guard.closed_at = Some(now);
    }
    guard.settle_clock(now);
    let mut priors = std::mem::take(&mut index.claude_census_rebuild_priors);
    // An earlier checkpoint kept each pending key's prior inside the guard.
    for (id, key) in guard.keys.iter_mut() {
        if let Some(prior) = key.legacy_prior.take() {
            if key.has(PENDING) && valid_prior(&prior) {
                priors.entry(id.clone()).or_insert(prior);
            }
        }
    }
    let mut transient = Transient::default();
    let ambiguous = &index.claude_request_census.ambiguous;
    // Ids to resolve: fresh duplicates by name, pending keys and orphans by hash.
    let mut resolved = BTreeMap::<String, String>::new();
    for key in ambiguous {
        let Some(entry) = index.files.get(key) else {
            continue;
        };
        let id = key_id(key);
        let pending = guard.keys.get(&id).is_some_and(|key| key.has(PENDING));
        if entry.source_file_fingerprint.is_empty() {
            // Another mechanism's rearm, this bound's own pending grant, or an
            // orphan (resolved below).
            if pending {
                resolved.insert(id, key.clone());
            }
            continue;
        }
        let cause = if !valid_prior(&entry.source_file_fingerprint) {
            Some("fingerprint_format")
        } else if guard.keys.contains_key(&id) {
            None
        } else if guard.closed_at.is_some() {
            Some("guard_state_closed")
        } else if guard.keys.len() >= MAX_TRACKED_KEYS {
            Some("tracked_key_cap")
        } else {
            None
        };
        if let Some(cause) = cause {
            guard.refuse_untracked(now);
            if transient.refusals.len() < MAX_ALARMS_PER_TERMINAL {
                transient.refusals.push((id, cause));
            }
            continue;
        }
        guard.keys.entry(id.clone()).or_default().flags |= PENDING;
        priors.insert(id.clone(), entry.source_file_fingerprint.clone());
        resolved.insert(id, key.clone());
    }
    // A saved prior whose key the guard no longer holds pending: the guard was
    // lost (malformed, duplicated or closed shadow) after its grant was saved.
    // Priors exist only for pending keys, so they never outgrow the guard.
    let orphans: Vec<String> = priors
        .keys()
        .filter(|id| !guard.keys.get(*id).is_some_and(|key| key.has(PENDING)))
        .cloned()
        .collect();
    let unresolved: BTreeSet<&String> = guard
        .keys
        .iter()
        .filter(|(_, key)| key.has(PENDING))
        .map(|(id, _)| id)
        .chain(&orphans)
        .filter(|id| !resolved.contains_key(*id))
        .collect();
    if !unresolved.is_empty() {
        let mut found = BTreeMap::new();
        for key in index.files.keys() {
            let id = key_id(key);
            if unresolved.contains(&id) {
                found.insert(id, key.clone());
            }
        }
        resolved.extend(found);
    }
    for id in orphans {
        let Some(prior) = priors.remove(&id) else {
            continue;
        };
        let Some(entry) = resolved.get(&id).and_then(|key| index.files.get_mut(key)) else {
            continue;
        };
        if !entry.source_file_fingerprint.is_empty() {
            // Rebuilt or replaced since: nothing of this rearm is outstanding.
            continue;
        }
        // Spent, not free: restore the fingerprint so the unchanged transcript
        // has no Rearmed reason, and hold the key exhausted for one window
        // (in a closed guard too: holding a key only refuses).
        entry.source_file_fingerprint.clone_from(&prior);
        guard.orphaned = guard.orphaned.saturating_add(1);
        guard.orphaned_at = now;
        if guard.keys.contains_key(&id) || guard.keys.len() < MAX_TRACKED_KEYS {
            let tracked = guard.keys.entry(id.clone()).or_default();
            tracked.attempts = vec![now; MAX_ATTEMPTS_PER_WINDOW];
            tracked.flags = PENDING | EXHAUSTED;
            priors.insert(id.clone(), prior);
        } else {
            guard.refuse_untracked(now);
        }
        if transient.refusals.len() < MAX_ALARMS_PER_TERMINAL {
            transient.refusals.push((id, "orphaned_rearm"));
        }
    }
    for (id, tracked) in guard.keys.iter_mut() {
        if !tracked.has(PENDING) {
            continue;
        }
        let Some(entry) = resolved
            .get(id)
            .and_then(|key| index.files.get_mut(key).map(|entry| (key, entry)))
        else {
            // The key left the index; keep only its stamps.
            tracked.flags = 0;
            priors.remove(id);
            continue;
        };
        let (key, entry) = entry;
        if !ambiguous.contains(key) && index.claude_request_census.get(key).is_some() {
            // A clean decode of the rebuilt record clears the terminal state.
            tracked.flags = 0;
            priors.remove(id);
            continue;
        }
        let rearmed = entry.source_file_fingerprint.is_empty();
        let attempt_due = tracked.has(EXHAUSTED)
            || !rearmed
            || tracked.has(STARTED)
            || !with_persisted(|set| set.contains(id));
        if !attempt_due {
            continue;
        }
        if !rearmed && valid_prior(&entry.source_file_fingerprint) {
            priors.insert(id.clone(), entry.source_file_fingerprint.clone());
        }
        // No saved prior, no grant: a rearm must always be restorable.
        if tracked.attempts.len() < MAX_ATTEMPTS_PER_WINDOW && priors.contains_key(id) {
            tracked.attempts.push(now);
            tracked.flags = PENDING;
            entry.source_file_fingerprint.clear();
            transient.grants.push(id.clone());
        } else {
            // The prior stays while the key is pending: a partial save may
            // still commit the emptied fingerprint, and the next load restores
            // it again.
            tracked.flags = PENDING | EXHAUSTED;
            if let Some(prior) = priors.get(id).filter(|_| rearmed) {
                entry.source_file_fingerprint.clone_from(prior);
            }
        }
    }
    guard
        .keys
        .retain(|_, key| key.has(PENDING) || !key.attempts.is_empty());
    index.claude_census_rebuild_priors = priors;
    index.claude_request_census_shadow.rebuild_bound = (!guard.is_empty()).then(|| Box::new(guard));
    index.claude_request_census.rebuild_transient = transient;
}

/// A Claude parse is starting: the current rearm of this key is being spent.
/// The process-local grant is consumed too, so a working index discarded
/// after a failed read still counts the next rearm.
pub(crate) fn note_started(index: &mut ScanIndex, path: &Path) {
    let Some(guard) = index.claude_request_census_shadow.rebuild_bound.as_mut() else {
        return;
    };
    if !guard.keys.values().any(|key| key.has(PENDING)) {
        return;
    }
    let id = key_id(&super::super::local_index_key(path));
    if let Some(key) = guard.keys.get_mut(&id).filter(|key| key.has(PENDING)) {
        key.flags |= STARTED;
        with_persisted(|set| set.remove(&id));
    }
}

/// Daemon load, before its scan can read: make this load's grants durable.
/// A failed save fails the cycle before any transcript is re-read.
pub(crate) fn persist_grants(index: &mut ScanIndex, path: &Path) -> anyhow::Result<()> {
    if index
        .claude_request_census
        .rebuild_transient
        .grants
        .is_empty()
    {
        return Ok(());
    }
    index.save(path)?;
    let grants = std::mem::take(&mut index.claude_request_census.rebuild_transient.grants);
    with_persisted(|set| {
        for id in grants {
            if set.len() >= MAX_TRACKED_KEYS && !set.contains(&id) {
                // Unrecorded: the next load counts it again (fail closed).
                break;
            }
            set.insert(id);
        }
    });
    Ok(())
}

/// Census-line counters (exhausted, orphaned) and rate-limited alarms.
pub(super) fn terminal(index: &ScanIndex) -> (u64, u64) {
    let Some(guard) = index.claude_request_census_shadow.rebuild_bound.as_deref() else {
        return (0, 0);
    };
    let mut emitted = 0;
    let tracked = guard
        .keys
        .iter()
        .filter(|(_, key)| key.has(EXHAUSTED))
        .map(|(id, key)| {
            let retry_after = key
                .attempts
                .first()
                .map_or(0, |stamp| stamp.saturating_add(WINDOW_SECONDS + 1));
            (
                id.as_str(),
                "rebuild_bound_7d",
                key.attempts.len(),
                retry_after,
            )
        });
    let untracked = index
        .claude_request_census
        .rebuild_transient
        .refusals
        .iter()
        .map(|(id, cause)| {
            let retry_after = match *cause {
                "guard_state_closed" => guard.closed_at.unwrap_or(guard.untracked_refused_at),
                "orphaned_rearm" => guard.orphaned_at,
                _ => guard.untracked_refused_at,
            }
            .saturating_add(WINDOW_SECONDS + 1);
            (id.as_str(), *cause, 0, retry_after)
        });
    for (id, cause, attempts, retry_after) in tracked.chain(untracked) {
        if emitted >= MAX_ALARMS_PER_TERMINAL {
            break;
        }
        if first_alarm(id, cause) {
            emitted += 1;
            emit_alarm(format!(
                "local snapshot census duplicate rebuild exhausted alarm key_hash8={} cause={cause} attempts_7d={attempts} retry_after_unix={retry_after}; record stays absent, duplicate stays counted, no further rearm",
                &id[..8]
            ));
        }
    }
    (guard.exhausted_keys(), guard.orphaned)
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    pub(crate) use super::{key_id, MAX_TRACKED_KEYS};

    pub(crate) struct Clock;
    impl Drop for Clock {
        fn drop(&mut self) {
            TEST_NOW.with(|now| now.set(None));
        }
    }
    pub(crate) fn set_now(now: u64) -> Clock {
        TEST_NOW.with(|cell| cell.set(Some(now)));
        Clock
    }
    /// A new daemon process: no grant saved yet, no alarm emitted yet.
    pub(crate) fn restart() {
        PERSISTED.with(|set| set.borrow_mut().clear());
        ALARMED.with(|set| set.borrow_mut().clear());
    }
    pub(crate) fn alarm_lines() -> Vec<String> {
        ALARM_LINES.with(|lines| lines.borrow().clone())
    }
    pub(crate) fn attempts(index: &ScanIndex, key: &str) -> Vec<u64> {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .and_then(|guard| guard.keys.get(&key_id(key)))
            .map(|key| key.attempts.clone())
            .unwrap_or_default()
    }
    pub(crate) fn exhausted(index: &ScanIndex, key: &str) -> bool {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .and_then(|guard| guard.keys.get(&key_id(key)))
            .is_some_and(|key| key.has(EXHAUSTED))
    }
    /// Tracked keys of a guard that decoded (not closed).
    pub(crate) fn tracked_open(index: &ScanIndex) -> Option<usize> {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .filter(|guard| guard.closed_at.is_none())
            .map(|guard| guard.keys.len())
    }
    /// The saved shadow field as written, and as main's serializer (which has
    /// no rebuild guard) writes the same state.
    pub(crate) fn shadow_bytes(index: &ScanIndex) -> (String, String) {
        let mut main = index.claude_request_census_shadow.clone();
        main.rebuild_bound = None;
        (
            serde_json::to_string(&index.claude_request_census_shadow).unwrap(),
            serde_json::to_string(&main).unwrap(),
        )
    }
    /// The fingerprint `key`'s outstanding grant emptied, as saved.
    pub(crate) fn prior(index: &ScanIndex, key: &str) -> Option<String> {
        index
            .claude_census_rebuild_priors
            .get(&key_id(key))
            .cloned()
    }
    pub(crate) fn pending(index: &ScanIndex, key: &str) -> bool {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .and_then(|guard| guard.keys.get(&key_id(key)))
            .is_some_and(|key| key.has(PENDING))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_priors(raw: &str) -> serde_json::Result<BTreeMap<String, String>> {
        deserialize_priors(&mut serde_json::Deserializer::from_str(raw))
    }

    /// MONEY P2: the largest guard and prior map this module can write, saved
    /// as the daemon saves the index (pretty-printed), decode back intact and
    /// far below the guard's own cap.
    #[test]
    fn worst_case_saved_guard_and_priors_decode_intact() {
        let ids = (0..MAX_TRACKED_KEYS).map(|slot| format!("{slot:016x}"));
        let guard = DuplicateRebuildGuard {
            keys: ids
                .clone()
                .map(|id| {
                    let key = TrackedKey {
                        attempts: vec![u64::MAX; MAX_ATTEMPTS_PER_WINDOW],
                        flags: STARTED | EXHAUSTED,
                        legacy_prior: None,
                    };
                    (id, key)
                })
                .collect(),
            untracked_refused: u64::MAX,
            untracked_refused_at: u64::MAX,
            orphaned: u64::MAX,
            orphaned_at: u64::MAX,
            closed_at: None,
        };
        let priors: BTreeMap<String, String> =
            ids.map(|id| (id, "f".repeat(PRIOR_BYTES))).collect();
        let mut index = ScanIndex::default();
        index.claude_request_census_shadow.rebuild_bound = Some(Box::new(guard.clone()));
        index.claude_census_rebuild_priors = priors.clone();
        let saved = serde_json::to_vec_pretty(&index).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        let raw_guard =
            serde_json::to_string_pretty(&value["claude_request_census_shadow"]["n"]).unwrap();
        // Saved two levels deeper than `raw_guard`: at most 8 more bytes a line.
        let saved_guard_bytes = raw_guard.len() + 8 * raw_guard.lines().count();
        assert!(
            saved_guard_bytes <= MAX_GUARD_RAW_BYTES / 2,
            "{saved_guard_bytes}"
        );
        assert_eq!(DuplicateRebuildGuard::decode(&raw_guard), guard);
        let raw_priors =
            serde_json::to_string_pretty(&value["claude_census_rebuild_priors"]).unwrap();
        assert_eq!(decode_priors(&raw_priors).unwrap(), priors);
        // The whole saved index decodes with the guard open and every key kept.
        let decoded = super::super::decode_index(saved.as_slice()).unwrap();
        let decoded = decoded
            .claude_request_census_shadow
            .rebuild_bound
            .expect("guard kept");
        assert_eq!(decoded.closed_at, None);
        assert_eq!(decoded.keys.len(), MAX_TRACKED_KEYS);
    }

    /// Only real Claude index fingerprints are saved as priors; anything else
    /// in the strict map fails its decode instead of being dropped.
    #[test]
    fn priors_accept_only_well_formed_fingerprints() {
        let hex = "a".repeat(PRIOR_BYTES);
        assert!(valid_prior(&hex));
        for invalid in [
            String::new(),
            "\u{1}".repeat(128),
            "A".repeat(PRIOR_BYTES),
            "a".repeat(PRIOR_BYTES + 1),
            "g".repeat(PRIOR_BYTES),
        ] {
            assert!(!valid_prior(&invalid), "{invalid:?}");
        }
        let id = "0123456789abcdef";
        assert!(decode_priors(&format!(r#"{{"{id}":"{hex}"}}"#)).is_ok());
        for raw in [
            format!(r#"{{"{id}":"\u0001"}}"#),
            format!(r#"{{"{id}":"{}"}}"#, "A".repeat(PRIOR_BYTES)),
            format!(r#"{{"0123456789ABCDEF":"{hex}"}}"#),
            format!(r#"{{"{id}":"{hex}","{id}":"{hex}"}}"#),
            format!(r#"{{"{id}":1}}"#),
            r#"["x"]"#.to_owned(),
        ] {
            assert!(decode_priors(&raw).is_err(), "{raw}");
        }
        let over_cap = (0..=MAX_TRACKED_KEYS)
            .map(|slot| format!(r#""{slot:016x}":"{hex}""#))
            .collect::<Vec<_>>()
            .join(",");
        assert!(decode_priors(&format!("{{{over_cap}}}")).is_err());
    }
}
