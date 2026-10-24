//! MONEY N3 lightness: a durable per-key bound on duplicate-key rebuilds.
//!
//! An ambiguous duplicate census key loses its record, so its transcript must
//! be re-read once to rebuild it, even with activation OFF. Failures,
//! restarts or renewed corruption could repeat that without limit. Each key
//! gets at most `MAX_ATTEMPTS_PER_WINDOW` rearms per rolling `WINDOW_SECONDS`.
//!
//! - A rearm lives only in this guard and in the load's transient set; it
//!   never writes the index fingerprint (SI-724-B1). Candidate selection reads
//!   an unchanged transcript of a granted key as Parse(Rearmed). Identity
//!   rearms (contract-5, family correction, stale uncarry, committable
//!   subsets) clear the same fingerprint independently: they stay visible to
//!   their own consumers, are saved as they are and always read. This bound
//!   never restores, overwrites or holds them.
//! - Nothing a rearm needs is saved in an entry, so whatever erases the guard
//!   (a downgrade, an older binary's save, corruption) erases only the rearm:
//!   the entry keeps its real fingerprint and is not re-read (MONEY P1a).
//! - Stamps live in the shadow state and the daemon saves a grant before its
//!   scan can read (`persist_grants`), so a crash cannot erase an attempt.
//! - A future stamp counts as recent (clamped to now: fail closed under clock
//!   rollback, and it still expires one window after it is first seen).
//! - A persisted rearm is counted again on the first load of each process, or
//!   when this process already started its parse. A bounded sweep that has not
//!   reached the key yet does not spend an attempt.
//! - Past the bound the key is not rearmed: its record stays absent, its
//!   duplicate stays counted in `decode_duplicate_keys_dropped`, and the
//!   census line counts it in `census_duplicate_rebuild_exhausted` with a
//!   rate-limited alarm. A clean decode of the key's record clears it; the
//!   window passing allows only a new counted attempt.
//! - Tracked keys are capped; past the cap new keys are refused (not rearmed)
//!   and counted for one window.
//! - A lost or ambiguous guard closes admission for one window (SI-724-B3):
//!   a malformed `n`, a duplicated `n` or key id, a malformed or duplicated
//!   shadow state, or a saved prior whose key the guard no longer holds (an
//!   orphan, counted in `census_duplicate_rebuild_orphaned`). Rebuilds already
//!   spent cannot be replenished by losing the guard.
//! - Earlier checkpoints saved a rearm as an empty fingerprint, with the
//!   fingerprint it emptied in `claude_census_rebuild_priors` (or inside the
//!   guard). Only that pair, a pending key plus its prior, positively marks an
//!   empty fingerprint as this bound's own (SI B2 condition 2). It takes a
//!   counted attempt, or past the bound it is held (candidate selection skips
//!   it) until the window allows one. It is never restored. An empty
//!   fingerprint without that marker (another mechanism's rearm, or a lost
//!   guard or priors field) takes the ordinary path and is re-offered.
//! - The priors field is decoded in isolation (MONEY P1b): by the index
//!   reader, and by the field's own lenient decoder on a plain Serde path. A
//!   malformed, duplicated, oversized, truncated or wrong-type field never
//!   fails the index decode: every entry, binding, ACK and latch is kept, the
//!   priors are dropped (their marked keys take the ordinary path), admission
//!   closes for one window, and `census_rebuild_priors_decode_refused` counts
//!   it. Counters and alarms are count-only.
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
/// Exhausted, with an earlier checkpoint's marked empty fingerprint:
/// skipped (never read, never restored) until a counted attempt is allowed.
const HELD: u8 = 8;

/// The persisted guard (`"n"` in the shadow state).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DuplicateRebuildGuard {
    /// First 16 hex digits of the key's SHA-256.
    #[serde(
        default,
        rename = "k",
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_keys"
    )]
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
    /// Loads whose priors field was refused, counted for one window.
    #[serde(default, rename = "p", skip_serializing_if = "is_zero")]
    priors_refused: u64,
    #[serde(default, rename = "pa", skip_serializing_if = "is_zero")]
    priors_refused_at: u64,
    #[serde(default, rename = "c", skip_serializing_if = "Option::is_none")]
    closed_at: Option<u64>,
}
crate::heap_layout_bound::fields!(DuplicateRebuildGuard; keys, untracked_refused, untracked_refused_at, orphaned, orphaned_at, priors_refused, priors_refused_at, closed_at);

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

/// `"k"`: a repeated key id is ambiguous (which copy holds the stamps is
/// unknown), so it fails the guard's decode and closes it (SI-724-B3).
fn deserialize_keys<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, TrackedKey>, D::Error> {
    struct Keys;
    impl<'de> Visitor<'de> for Keys {
        type Value = BTreeMap<String, TrackedKey>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("rebuild guard keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut keys = BTreeMap::new();
            while let Some((id, key)) = map.next_entry::<String, TrackedKey>()? {
                if keys.len() >= MAX_TRACKED_KEYS || keys.insert(id, key).is_some() {
                    return Err(<A::Error as serde::de::Error>::custom("rebuild guard keys"));
                }
            }
            Ok(keys)
        }
    }
    deserializer.deserialize_map(Keys)
}

/// A real Claude index fingerprint: the only form tracked, and the only
/// prior accepted.
fn valid_prior(fingerprint: &str) -> bool {
    fingerprint.len() == PRIOR_BYTES && lower_hex(fingerprint.as_bytes())
}

/// Strict: an oversized, duplicated or malformed map is an error. Run only
/// in isolation (`decode_priors`), so that error refuses the field.
fn strict_priors<'de, D: Deserializer<'de>>(
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

/// `ScanIndex::claude_census_rebuild_priors`: key id -> the fingerprint an
/// earlier checkpoint's rearm emptied (the legacy N3 marker). Captured raw,
/// so no token inside it (an overflowing number included) is interpreted by
/// the enclosing decode, then decoded in isolation: on any plain Serde path
/// a refused value reads as no priors, never as an index decode error (SI B2
/// condition 1). The index reader isolates the field before this runs and
/// counts the refusal.
pub(crate) fn deserialize_priors<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, String>, D::Error> {
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    Ok(decode_priors(raw.get().as_bytes()).unwrap_or_default())
}

/// The isolated decode of the priors field (MONEY P1b): `None` refuses it,
/// and the index reader hands the index an empty map and a refusal instead
/// of failing the whole decode.
pub(super) fn decode_priors(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let priors = strict_priors(&mut decoder).ok()?;
    decoder.end().ok()?;
    Some(priors)
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
    /// A lost or ambiguous guard: no rebuild is admitted for one window.
    pub(super) fn closed() -> Self {
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
                            && key.flags & !(PENDING | STARTED | EXHAUSTED | HELD) == 0
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
        if self.priors_refused > 0 && !recent(&mut self.priors_refused_at, now) {
            self.priors_refused = 0;
            self.priors_refused_at = 0;
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

/// Never persisted: grants this load made, the index keys whose unchanged
/// transcript candidate selection re-reads, and refusals of keys the guard
/// could not track (for the terminal alarm).
#[derive(Debug, Clone, Default)]
pub(crate) struct Transient {
    grants: Vec<String>,
    rearmed: BTreeSet<String>,
    refusals: Vec<(String, &'static str)>,
}
crate::heap_layout_bound::fields!(Transient; grants, rearmed, refusals);

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
/// healthy index. `priors_refused`: the reader refused the priors field.
/// Never writes an index entry: a grant is recorded in the guard and the
/// load's transient set only.
pub(super) fn apply(index: &mut ScanIndex, priors_refused: bool) {
    if !priors_refused
        && index.claude_request_census.ambiguous.is_empty()
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
    if priors_refused {
        // Which empty fingerprints are this bound's own is unknown this load:
        // trust no marker (a duplicated field's first copy included), so
        // every empty fingerprint takes the ordinary path, and admit nothing
        // for one window.
        priors.clear();
        guard.priors_refused = guard.priors_refused.saturating_add(1);
        guard.priors_refused_at = now;
        guard.closed_at = Some(now);
    }
    // An earlier checkpoint kept each pending key's prior inside the guard.
    for (id, key) in guard.keys.iter_mut() {
        if let Some(prior) = key.legacy_prior.take() {
            if key.has(PENDING) && valid_prior(&prior) {
                priors.entry(id.clone()).or_insert(prior);
            }
        }
    }
    let mut transient = Transient::default();
    // A saved prior whose key the guard no longer holds pending: the guard was
    // lost (malformed, duplicated or closed shadow) after an earlier
    // checkpoint saved that rearm. Its spent attempts are unknown, so
    // admission closes for one window (SI-724-B3). The prior is dropped: its
    // entry, empty or not, takes the ordinary path (SI B2 condition 2).
    let orphans: Vec<String> = priors
        .keys()
        .filter(|id| !guard.keys.get(*id).is_some_and(|key| key.has(PENDING)))
        .cloned()
        .collect();
    for id in orphans {
        priors.remove(&id);
        guard.orphaned = guard.orphaned.saturating_add(1);
        guard.orphaned_at = now;
        guard.closed_at = Some(now);
        if transient.refusals.len() < MAX_ALARMS_PER_TERMINAL {
            transient.refusals.push((id, "orphaned_rearm"));
        }
    }
    let ambiguous = &index.claude_request_census.ambiguous;
    // Ids to resolve: fresh duplicates by name, pending keys by hash.
    let mut resolved = BTreeMap::<String, String>::new();
    for key in ambiguous {
        let Some(entry) = index.files.get(key) else {
            continue;
        };
        let id = key_id(key);
        let pending = guard.keys.get(&id).is_some_and(|key| key.has(PENDING));
        if entry.source_file_fingerprint.is_empty() {
            // Another mechanism's rearm, which reads anyway, or a key this
            // bound already tracks (resolved below).
            if pending {
                resolved.insert(id, key.clone());
            }
            continue;
        }
        let cause = if !valid_prior(&entry.source_file_fingerprint) {
            Some("fingerprint_format")
        } else if guard.keys.contains_key(&id) {
            None
        } else if priors_refused {
            Some("priors_decode_refused")
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
        resolved.insert(id, key.clone());
    }
    let unresolved: BTreeSet<&String> = guard
        .keys
        .iter()
        .filter(|(id, key)| key.has(PENDING) && !resolved.contains_key(*id))
        .map(|(id, _)| id)
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
    let open = guard.closed_at.is_none();
    for (id, tracked) in guard.keys.iter_mut() {
        if !tracked.has(PENDING) {
            continue;
        }
        let Some((key, entry)) = resolved
            .get(id)
            .and_then(|key| index.files.get(key).map(|entry| (key, entry)))
        else {
            // The key left the index; keep only its stamps.
            tracked.flags = 0;
            priors.remove(id);
            continue;
        };
        if !ambiguous.contains(key) && index.claude_request_census.get(key).is_some() {
            // A clean decode of the rebuilt record clears the terminal state.
            tracked.flags = 0;
            priors.remove(id);
            continue;
        }
        let empty = entry.source_file_fingerprint.is_empty();
        // Only an earlier checkpoint's rearm is an empty fingerprint this
        // bound owns: a pending key with its saved prior.
        let marked = empty && priors.contains_key(id);
        if !marked {
            priors.remove(id);
        }
        if empty && !marked {
            // SI-724-B1: another mechanism's rearm, or a lost marker. It reads
            // as it is; this bound never holds, restores or overwrites it.
            tracked.flags &= !HELD;
            continue;
        }
        let attempt_due = tracked.has(EXHAUSTED)
            || tracked.has(STARTED)
            || !with_persisted(|set| set.contains(id));
        if !attempt_due {
            // This process saved the grant and has not started its read.
            if !empty {
                transient.rearmed.insert(key.clone());
            }
            continue;
        }
        if open && tracked.attempts.len() < MAX_ATTEMPTS_PER_WINDOW {
            tracked.attempts.push(now);
            tracked.flags = PENDING;
            transient.grants.push(id.clone());
            // A marked entry is already empty and reads as Rearmed.
            if !empty {
                transient.rearmed.insert(key.clone());
            }
        } else {
            // Refused, never a free rearm. A marked empty fingerprint is held
            // (candidate selection skips it) until the window allows a new
            // counted attempt; it is never restored.
            tracked.flags = PENDING | EXHAUSTED;
            if marked {
                tracked.flags |= HELD;
            }
            if priors_refused && transient.refusals.len() < MAX_ALARMS_PER_TERMINAL {
                transient
                    .refusals
                    .push((id.clone(), "priors_decode_refused"));
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

/// Candidate selection (MONEY P1a, legacy): `key`'s empty fingerprint is an
/// earlier checkpoint's rearm this bound refuses for now. It is skipped,
/// never read, until a counted attempt is allowed.
pub(crate) fn held(index: &ScanIndex, key: &str) -> bool {
    index
        .claude_request_census_shadow
        .rebuild_bound
        .as_deref()
        .filter(|guard| guard.keys.values().any(|tracked| tracked.has(HELD)))
        .is_some_and(|guard| {
            guard
                .keys
                .get(&key_id(key))
                .is_some_and(|tracked| tracked.has(HELD))
        })
}

/// Candidate selection: `key` holds an unspent grant of this load, so its
/// unchanged transcript is re-read (Parse(Rearmed)) with its fingerprint
/// untouched.
pub(crate) fn rearmed(index: &ScanIndex, key: &str) -> bool {
    index
        .claude_request_census
        .rebuild_transient
        .rearmed
        .contains(key)
}

/// A Claude parse is starting: the current rearm of this key is being spent.
/// The process-local grant is consumed too, so a working index discarded
/// after a failed read still counts the next rearm.
pub(crate) fn note_started(index: &mut ScanIndex, path: &Path) {
    let rearmed = &mut index.claude_request_census.rebuild_transient.rearmed;
    if !rearmed.is_empty() {
        rearmed.remove(&super::super::local_index_key(path));
    }
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

/// Census-line counters (exhausted, orphaned, priors refused) and
/// rate-limited alarms.
pub(super) fn terminal(index: &ScanIndex) -> (u64, u64, u64) {
    let Some(guard) = index.claude_request_census_shadow.rebuild_bound.as_deref() else {
        return (0, 0, 0);
    };
    let mut emitted = 0;
    let tracked = guard
        .keys
        .iter()
        .filter(|(_, key)| key.has(EXHAUSTED))
        .map(|(id, key)| {
            // A closed guard refuses until it reopens; otherwise the oldest
            // stamp's expiry allows the next counted attempt.
            let (cause, since) = match guard.closed_at {
                Some(closed_at) if key.attempts.len() < MAX_ATTEMPTS_PER_WINDOW => {
                    ("guard_state_closed", Some(closed_at))
                }
                _ if key.has(HELD) => ("legacy_rearm_held", key.attempts.first().copied()),
                _ => ("rebuild_bound_7d", key.attempts.first().copied()),
            };
            let retry_after = since.map_or(0, |stamp| stamp.saturating_add(WINDOW_SECONDS + 1));
            (id.as_str(), cause, key.attempts.len(), retry_after)
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
                "priors_decode_refused" => guard.priors_refused_at,
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
    (guard.exhausted_keys(), guard.orphaned, guard.priors_refused)
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
    /// Held: an emptied fingerprint with nothing to restore it (never read).
    pub(crate) fn held(index: &ScanIndex, key: &str) -> bool {
        super::held(index, key)
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

    /// The field's own decoder, as a plain Serde path runs it.
    fn field_priors(raw: &str) -> serde_json::Result<BTreeMap<String, String>> {
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
            priors_refused: u64::MAX,
            priors_refused_at: u64::MAX,
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
        assert_eq!(field_priors(&raw_priors).unwrap(), priors);
        assert_eq!(decode_priors(raw_priors.as_bytes()), Some(priors));
        // The whole saved index decodes with the guard open and every key kept.
        let decoded = super::super::decode_index(saved.as_slice()).unwrap();
        let decoded = decoded
            .claude_request_census_shadow
            .rebuild_bound
            .expect("guard kept");
        assert_eq!(decoded.closed_at, None);
        assert_eq!(decoded.keys.len(), MAX_TRACKED_KEYS);
    }

    /// Only real Claude index fingerprints are accepted as priors. Anything
    /// else refuses the whole field: the reader's isolated decode returns
    /// `None` (MONEY P1b), and the field's own decoder reads no priors instead
    /// of failing the index decode (SI B2 condition 1).
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
        let well_formed = format!(r#"{{"{id}":"{hex}"}}"#);
        assert_eq!(field_priors(&well_formed).unwrap().len(), 1);
        assert!(decode_priors(format!(" {well_formed} ").as_bytes()).is_some());
        let over_cap = (0..=MAX_TRACKED_KEYS)
            .map(|slot| format!(r#""{slot:016x}":"{hex}""#))
            .collect::<Vec<_>>()
            .join(",");
        for raw in [
            format!(r#"{{"{id}":"\u0001"}}"#),
            format!(r#"{{"{id}":"{}"}}"#, "A".repeat(PRIOR_BYTES)),
            format!(r#"{{"0123456789ABCDEF":"{hex}"}}"#),
            format!(r#"{{"{id}":"{hex}","{id}":"{hex}"}}"#),
            format!(r#"{{"{id}":1}}"#),
            format!(r#"{{"{id}":{{"{id}":"{hex}"}}}}"#),
            format!(r#"{{"{id}":["{hex}"]}}"#),
            format!(r#"{{"{id}":null,"fedcba9876543210":"{hex}"}}"#),
            r#"["x"]"#.to_owned(),
            r#""x""#.to_owned(),
            "7".to_owned(),
            "true".to_owned(),
            // Truncated values: a short prior, a short id.
            format!(r#"{{"{id}":"{}"}}"#, &hex[..PRIOR_BYTES - 1]),
            format!(r#"{{"{}":"{hex}"}}"#, &id[..15]),
            "null".to_owned(),
            format!("{{{over_cap}}}"),
            // Overflowing numbers: never interpreted by the enclosing decode.
            "1e400".to_owned(),
            format!(r#"{{"{id}":1e400}}"#),
        ] {
            assert_eq!(decode_priors(raw.as_bytes()), None, "{raw}");
            assert_eq!(field_priors(&raw).unwrap(), BTreeMap::new(), "{raw}");
        }
        // Truncated or trailing bytes: refused by the reader's isolated decode.
        for raw in [
            format!(r#"{{"{id}":"{hex}","#),
            format!(r#"{{"{id}":"{hex}"}} {{}}"#),
            String::new(),
        ] {
            assert_eq!(decode_priors(raw.as_bytes()), None, "{raw}");
        }
    }

    /// SI B2 condition 1: on a plain Serde path a refused priors value of any
    /// shape decodes the index with no priors, every entry kept.
    #[test]
    fn refused_priors_never_fail_a_plain_serde_index_decode() {
        let mut base = serde_json::to_value(ScanIndex::default()).unwrap();
        base["files"] = serde_json::json!({
            "/tmp/kept.jsonl": {
                "size_bytes": 1,
                "modified_unix_seconds": 1,
                "source_file_fingerprint": "b".repeat(PRIOR_BYTES),
                "last_snapshot_fingerprint": null
            }
        });
        for priors in [
            serde_json::json!(7),
            serde_json::json!("x"),
            serde_json::json!(null),
            serde_json::json!(["x"]),
            serde_json::json!({ "0123456789abcdef": 1 }),
            serde_json::json!({ "0123456789abcdef": "A" }),
        ] {
            let mut value = base.clone();
            value["claude_census_rebuild_priors"] = priors.clone();
            let decoded: ScanIndex = serde_json::from_value(value.clone()).unwrap();
            assert!(decoded.claude_census_rebuild_priors.is_empty(), "{priors}");
            assert_eq!(decoded.files.len(), 1, "{priors}");
            let decoded: ScanIndex = serde_json::from_str(&value.to_string()).unwrap();
            assert!(decoded.claude_census_rebuild_priors.is_empty(), "{priors}");
            assert_eq!(
                decoded.files["/tmp/kept.jsonl"].source_file_fingerprint,
                "b".repeat(PRIOR_BYTES)
            );
        }
        // Overflowing numbers exist only as text, never as a `Value`.
        for priors in ["1e400", r#"{"0123456789abcdef":1e400}"#] {
            let mut value = base.clone();
            value["claude_census_rebuild_priors"] = serde_json::json!("OVERFLOW");
            let raw = value.to_string().replace("\"OVERFLOW\"", priors);
            let decoded: ScanIndex = serde_json::from_str(&raw).unwrap();
            assert!(decoded.claude_census_rebuild_priors.is_empty(), "{priors}");
            assert_eq!(decoded.files.len(), 1, "{priors}");
        }
    }

    /// SI-724-B3: a repeated key id in `"k"` is ambiguous and closes the guard.
    #[test]
    fn duplicate_guard_key_ids_close_the_guard() {
        let one = r#"{"k":{"0123456789abcdef":"0:1,2"}}"#;
        assert_eq!(DuplicateRebuildGuard::decode(one).closed_at, None);
        for raw in [
            r#"{"k":{"0123456789abcdef":"0:1,2","0123456789abcdef":"0:"}}"#,
            r#"{"k":{"0123456789abcdef":"0:1,2"},"k":{}}"#,
        ] {
            assert_eq!(
                DuplicateRebuildGuard::decode(raw),
                DuplicateRebuildGuard::closed(),
                "{raw}"
            );
        }
    }
}
