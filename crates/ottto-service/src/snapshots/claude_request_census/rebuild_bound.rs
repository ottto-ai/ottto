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
//!   never restores, overwrites or holds them. They all go through
//!   `rearm_source_fingerprint`, which also revokes this bound's hold on an
//!   earlier checkpoint's key once per arming (SI-724-B1b,
//!   `revoke_for_identity`): the key leaves the guard, its token stays in `r`
//!   for one window, and `census_duplicate_rebuild_identity_revoked` counts
//!   it. Repairs of damaged state, recovery re-reads and re-parse debt a
//!   committable subset carries revoke nothing. The revoke is durable before
//!   the key is selected (MONEY 724g P1): until the daemon saves it
//!   (`persist_revokes`, before its scan steps, or the cycle's own save) the
//!   key stays held, so a crash or a discarded working index can only repeat
//!   an unsaved revoke, which again re-offers the key once saved.
//! - Nothing a rearm needs is saved in an entry, so whatever erases the guard
//!   (a downgrade, an older binary's save, corruption) erases only the rearm:
//!   the entry keeps its real fingerprint and is not re-read (MONEY P1a).
//! - Stamps live in the shadow state and the daemon saves a grant before its
//!   scan can read (`persist_grants`), so a crash cannot erase an attempt.
//! - Stamps are used exactly as persisted (MONEY 724h condition 3). A wall
//!   clock that goes backward never clamps, expires or shrinks one: a stamp
//!   after now still counts toward the bound, the witness and any closure.
//!   Behind the guard's latest persisted stamp, time is no new authority: no
//!   grant is made or reused, no new key admitted and no read admitted
//!   (`grant_clock_regressed`, counted like an exhausted key), until the
//!   clock passes that stamp. A grant found spent (by admission or the census
//!   terminal) stays spent in its process, in the same working index too,
//!   until a new counted attempt. A stamp is only ever raised, never lowered
//!   by a refusal on backward time, so the latest stamp (and the witness)
//!   never falls: every closure (a lost or duplicated guard, refused priors,
//!   an orphan) starts no earlier than the saved witness (of any copy), and
//!   an identity revoke keeps the removed key's latest stamp. An alarm's
//!   retry is never before the clock passes the latest stamp.
//! - MONEY 724i P2: `claude_census_rebuild_wall_high_water` retains the
//!   maximum wall time observed on every N3 load and save, including cycles
//!   with no new grant. Time below that maximum spends an unread grant as
//!   `grant_clock_regressed`, even above every attempt stamp. In-process
//!   elapsed time also bounds grant age, so rollback hidden between wall
//!   observations cannot prolong the read span. Reloads and saves retain
//!   the original monotonic birth; a restart requires a new counted grant.
//! - A persisted rearm is counted again on the first load of each process, or
//!   when this process already started its parse. A bounded sweep that has not
//!   reached the key yet does not spend an attempt. A grant authorizes a read
//!   only within `N3_GRANT_MAX_LOAD_TO_READ` of its stamp (MONEY 724h P2),
//!   checked when candidate selection admits the read, not only at load: a
//!   later read, or a later load of this process's saved, unspent grant,
//!   finds it spent. A spent grant is never a free read: the key is skipped
//!   (an earlier checkpoint's marked empty fingerprint is held), counted on
//!   the census line as exhausted (`grant_read_span_expired`), and read only
//!   through a new counted attempt from the same budget, saved before its
//!   scan. A stamp counts toward the bound for `ATTEMPT_WINDOW_SECONDS`
//!   (one window plus the read span), so the bound holds for actual reads:
//!   at most `MAX_ATTEMPTS_PER_WINDOW` in any rolling `WINDOW_SECONDS`.
//! - Past the bound the key is not rearmed: its record stays absent, its
//!   duplicate stays counted in `decode_duplicate_keys_dropped`, and the
//!   census line counts it in `census_duplicate_rebuild_exhausted` with a
//!   rate-limited alarm. A clean decode of the key's record clears it; the
//!   window passing allows only a new counted attempt.
//! - Tracked keys are capped; past the cap new keys are refused (not rearmed)
//!   and counted for one window.
//! - A lost or ambiguous guard closes admission for one window (SI-724-B3):
//!   a malformed `n`, a duplicated `n` or key id, a malformed or duplicated
//!   shadow state, a saved prior whose key the guard no longer holds (an
//!   orphan), or a missing `n` with evidence of earlier activity: the
//!   shadow's window witness (`nw`, the guard's latest stamp, saved beside
//!   `n`) still inside the window, a priors field present, or the
//!   "N3 initialized" marker (`claude_census_rebuild_initialized`, SI-724-B3b)
//!   present. The marker is written with the guard's first state and retires
//!   only with an empty guard; a malformed marker is itself a lost guard.
//!   Orphans and
//!   missing guards count in `census_duplicate_rebuild_orphaned`. Only a
//!   checkpoint with no such evidence starts a fresh guard. Rebuilds already
//!   spent cannot be replenished by losing the guard (MONEY 724f P1).
//! - Earlier checkpoints saved a rearm as an empty fingerprint (its prior in
//!   `claude_census_rebuild_priors` or inside the guard). The guard positively
//!   records such a key: pending, saved without `CURRENT`. Its empty
//!   fingerprint is this bound's own (SI B2 condition 2, MONEY P1a), with or
//!   without its prior: it is held (candidate selection skips it, counted and
//!   alarmed) and read only through a counted attempt this load stamps and the
//!   daemon saves before its scan, at most the bound per window. It is never
//!   restored. An empty fingerprint of a current-form key, or of a key the
//!   guard does not hold (another mechanism's rearm, or a lost guard), takes
//!   the ordinary path and is re-offered.
//! - The priors field is decoded in isolation (MONEY P1b): by the index
//!   reader, and by the field's own lenient decoder on a plain Serde path. A
//!   malformed, oversized, truncated or wrong-type value never fails the
//!   index decode: every entry, binding, ACK and latch is kept, the
//!   priors are dropped (marking never depends on them), admission closes for
//!   one window, and `census_rebuild_priors_decode_refused` counts it.
//!   Counters and alarms are count-only. A duplicated priors or marker
//!   field name is a root-level defect: like any duplicated index field it
//!   refuses the index (kept on disk, the source paused), never quarantined
//!   or defaulted. The marker value is isolated the same way.
//!
//! A key whose fingerprint was already empty when its duplicate was found is
//! another mechanism's rearm; this bound does not track it.
use super::*;

pub(super) const WINDOW_SECONDS: u64 = 7 * 24 * 60 * 60;
/// MONEY 724h P2: the longest a grant may wait between the load that stamps
/// it and the read it authorizes. A granted key is read only while
/// `now <= stamp + N3_GRANT_MAX_LOAD_TO_READ`, checked when candidate
/// selection admits the read (`rearmed`, `held`); past it the grant is spent.
/// The longest observed full traversal is about 90 minutes (0.1.193 Full
/// scans took 80-90 min), so 12 h refuses no realistic read in a healthy
/// cycle, while bounding how far a read can trail its stamp.
pub(crate) const N3_GRANT_MAX_LOAD_TO_READ: u64 = 12 * 60 * 60;
/// A rearm stamp counts toward `MAX_ATTEMPTS_PER_WINDOW` for one window plus
/// the read span. A third grant is stamped only once an earlier stamp `s` has
/// left this window, after `s + WINDOW_SECONDS + N3_GRANT_MAX_LOAD_TO_READ`,
/// and that stamp's read came no later than `s + N3_GRANT_MAX_LOAD_TO_READ`,
/// so more than `WINDOW_SECONDS` separate the two reads: any rolling
/// `WINDOW_SECONDS` of actual reads holds at most `MAX_ATTEMPTS_PER_WINDOW`
/// (strict, independent of when each load ran).
pub(super) const ATTEMPT_WINDOW_SECONDS: u64 = WINDOW_SECONDS + N3_GRANT_MAX_LOAD_TO_READ;
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
/// Identity-arming evidence longer than this revokes nothing.
const MAX_ARMING_BYTES: usize = 4096;
/// Distinct armings that may revoke one key in a window; past that a
/// re-entered hold stays held (fail closed, read through the bound).
const MAX_REVOKE_TOKENS: usize = 3;
/// `closed_at` value of a guard that must be stamped at its next apply.
const UNSTAMPED: u64 = u64::MAX;
/// The marker value of a present but malformed "N3 initialized" marker.
const MARKER_REFUSED: u64 = u64::MAX;

const PENDING: u8 = 1;
const STARTED: u8 = 2;
const EXHAUSTED: u8 = 4;
/// Exhausted, with an earlier checkpoint's marked empty fingerprint:
/// skipped (never read, never restored) until a counted attempt is allowed.
const HELD: u8 = 8;
/// Tracked in the current form, whose rearm never writes the fingerprint: set
/// whenever the key's fingerprint is seen intact, so an empty fingerprint of
/// this key is never this bound's own (SI-724-B1). A pending key without it
/// was saved by an earlier checkpoint, whose rearm emptied the fingerprint:
/// that empty fingerprint is positively this bound's (MONEY P1a).
const CURRENT: u8 = 16;

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
    /// SI-724-B1b: earlier-checkpoint keys identity work took out of this
    /// bound's control, with the arming's token, for one window: one revoke
    /// per key per arming (`revoke_for_identity`).
    #[serde(
        default,
        rename = "r",
        skip_serializing_if = "BTreeMap::is_empty",
        deserialize_with = "deserialize_keys"
    )]
    revoked: BTreeMap<String, Revoked>,
    /// Identity revokes, counted for one window.
    #[serde(default, rename = "i", skip_serializing_if = "is_zero")]
    identity_revoked: u64,
    #[serde(default, rename = "ia", skip_serializing_if = "is_zero")]
    identity_revoked_at: u64,
    /// Never persisted: index keys this working index revoked that no save has
    /// made durable yet (MONEY 724g P1). Held until saved.
    #[serde(skip)]
    unsaved: UnsavedRevokes,
}
crate::heap_layout_bound::fields!(DuplicateRebuildGuard; keys, untracked_refused, untracked_refused_at, orphaned, orphaned_at, priors_refused, priors_refused_at, closed_at, revoked, identity_revoked, identity_revoked_at, unsaved);

/// The working index's revokes not yet saved (MONEY 724g P1). Transient:
/// never serialized and never part of the guard's value, so a guard equals
/// its saved and decoded form.
#[derive(Debug, Clone, Default)]
struct UnsavedRevokes {
    keys: BTreeSet<String>,
}
crate::heap_layout_bound::fields!(UnsavedRevokes; keys);

impl PartialEq for UnsavedRevokes {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}
impl Eq for UnsavedRevokes {}

/// One key's identity revokes in the window, `"<token>,<token>:<stamp>"`:
/// each arming's token (16 hex digits of its evidence's SHA-256), at most
/// `MAX_REVOKE_TOKENS` distinct, and the unix second of the latest revoke.
/// Every consumed token is kept, so a re-entered earlier-form hold is never
/// revoked twice by one arming, whatever armed it in between.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Revoked {
    tokens: Vec<String>,
    at: u64,
}
crate::heap_layout_bound::fields!(Revoked; tokens, at);

impl Serialize for Revoked {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{}:{}", self.tokens.join(","), self.at))
    }
}
impl<'de> Deserialize<'de> for Revoked {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let malformed = || <D::Error as serde::de::Error>::custom("rebuild guard revoke");
        let text = String::deserialize(deserializer)?;
        let (tokens, at) = text.split_once(':').ok_or_else(malformed)?;
        let mut parsed: Vec<String> = Vec::new();
        for token in tokens.split(',') {
            if parsed.len() >= MAX_REVOKE_TOKENS
                || token.len() != 16
                || !lower_hex(token.as_bytes())
                || parsed.iter().any(|seen| seen == token)
            {
                return Err(malformed());
            }
            parsed.push(token.to_owned());
        }
        Ok(Self {
            tokens: parsed,
            at: at.parse().map_err(|_| malformed())?,
        })
    }
}

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

/// `"k"` and `"r"`: a repeated key id is ambiguous (which copy holds the
/// stamps or the revoke is unknown), so it fails the guard's decode and
/// closes it (SI-724-B3).
fn deserialize_keys<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, V>, D::Error> {
    struct Keys<V>(std::marker::PhantomData<V>);
    impl<'de, V: Deserialize<'de>> Visitor<'de> for Keys<V> {
        type Value = BTreeMap<String, V>;
        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("rebuild guard keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut keys = BTreeMap::new();
            while let Some((id, key)) = map.next_entry::<String, V>()? {
                if keys.len() >= MAX_TRACKED_KEYS || keys.insert(id, key).is_some() {
                    return Err(<A::Error as serde::de::Error>::custom("rebuild guard keys"));
                }
            }
            Ok(keys)
        }
    }
    deserializer.deserialize_map(Keys(std::marker::PhantomData))
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
pub(crate) fn decode_priors(bytes: &[u8]) -> Option<BTreeMap<String, String>> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let priors = strict_priors(&mut decoder).ok()?;
    decoder.end().ok()?;
    Some(priors)
}

/// `ScanIndex::claude_census_rebuild_initialized` (SI-724-B3b): the unix
/// second the bound first held state. Captured raw and decoded in isolation:
/// a malformed value is present and refused (`u64::MAX`), never an index
/// decode error. The lenient index reader applies the same `decode_marker`.
pub(crate) fn deserialize_marker<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<u64, D::Error> {
    let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
    Ok(decode_marker(raw.get().as_bytes()))
}

/// A nonzero u64 below `u64::MAX`; anything else reads as refused.
pub(crate) fn decode_marker(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<u64>(bytes)
        .ok()
        .filter(|stamp| *stamp != 0 && *stamp != MARKER_REFUSED)
        .unwrap_or(MARKER_REFUSED)
}

/// SI-724-F1-B: the marker's isolated wire bytes as both index readers take
/// them: at most 20 bytes once surrounding whitespace is trimmed, else (or
/// past the evidence byte cap, `None`) refused.
pub(crate) fn decode_isolated_marker(bytes: Option<&[u8]>) -> u64 {
    bytes
        .map(<[u8]>::trim_ascii)
        .filter(|bytes| bytes.len() <= 20)
        .map_or(MARKER_REFUSED, decode_marker)
}

/// True while `stamp` is inside the window.
fn recent(stamp: u64, now: u64) -> bool {
    within(stamp, now, WINDOW_SECONDS)
}

/// `recent` for a rearm stamp (or the witness, which may be one): it counts
/// for `ATTEMPT_WINDOW_SECONDS`.
fn counted(stamp: u64, now: u64) -> bool {
    within(stamp, now, ATTEMPT_WINDOW_SECONDS)
}

/// MONEY 724h condition 3: a stamp is kept exactly as persisted. One after
/// `now` (the wall clock went backward) still counts and is never clamped:
/// backward time never expires a stamp early, frees budget or reopens a
/// closure, and a clock moving forward again never finds it shrunk.
fn within(stamp: u64, now: u64, window: u64) -> bool {
    now <= stamp || now - stamp <= window
}

/// Condition 3: a persisted stamp is only ever raised, never lowered by a
/// wall clock behind it, so the guard's latest stamp (the high-water and
/// the witness) never falls and no window it starts is shortened.
fn raise(at: &mut u64, now: u64) {
    *at = (*at).max(now);
}

/// `raise` for the closure stamp; `UNSTAMPED` is no stamp.
fn close(closed_at: &mut Option<u64>, now: u64) {
    *closed_at = Some(
        closed_at
            .filter(|at| *at != UNSTAMPED)
            .map_or(now, |at| at.max(now)),
    );
}

/// MONEY 724h P2 and condition 3: why `tracked`'s grant (its latest counted
/// stamp, saved before the scan) can no longer authorize a read, if it is
/// pending, neither refused nor started. Before `high_water`, the guard's
/// latest persisted stamp (which bounds the grant's own), the wall clock went
/// backward: no new authority. Past `N3_GRANT_MAX_LOAD_TO_READ` the span is
/// over.
fn grant_spent(tracked: &TrackedKey, now: u64, high_water: u64, born: u64) -> Option<&'static str> {
    let stamp = unread_grant(tracked)?;
    if now < high_water.max(stamp) {
        Some("grant_clock_regressed")
    } else if now > stamp.saturating_add(N3_GRANT_MAX_LOAD_TO_READ) || grant_age_expired(born) {
        Some("grant_read_span_expired")
    } else {
        None
    }
}

/// The stamp of `tracked`'s grant while it is pending, neither refused nor
/// started.
fn unread_grant(tracked: &TrackedKey) -> Option<u64> {
    if !tracked.has(PENDING) || tracked.has(EXHAUSTED) || tracked.has(STARTED) {
        return None;
    }
    tracked.attempts.last().copied()
}

/// `grant_spent`, sticky in this process: a grant `admission_refused` found
/// spent stays spent while its stamp is the key's latest, even in the same
/// working index once the wall clock is back inside its span.
fn spent_cause(
    id: &str,
    tracked: &TrackedKey,
    now: u64,
    high_water: u64,
    loaded_at: u64,
) -> Option<&'static str> {
    let stamp = unread_grant(tracked)?;
    let born = with_persisted(|grants| grants.get(id).copied())
        .filter(|grant| grant.stamp == stamp)
        .map_or(loaded_at, |grant| grant.born);
    grant_spent(tracked, now, high_water, born).or_else(|| {
        let (cause, overflow) = with_spent(|spent| {
            let cause = spent
                .grants
                .get(id)
                .filter(|(at, _)| *at == stamp)
                .map(|(_, cause)| *cause);
            (cause, spent.overflow)
        });
        cause.or_else(|| {
            // Once the cache fills, an unrecorded spend is possible. Only
            // proof of a newly saved counted attempt supplies authority.
            // Drop the spent lock before taking the persisted lock.
            (overflow
                && !with_persisted(|grants| grants.get(id).map(|grant| grant.stamp) == Some(stamp)))
            .then_some("grant_clock_regressed")
        })
    })
}

/// Records `id`'s grant at `stamp` as spent for `cause` in this process.
/// Never evict a refusal: even the oldest grant may be inside its span after
/// clock recovery. Overflow refuses unrecorded grants without durable proof
/// of a new counted attempt (`spent_cause`), keeping process history bounded.
fn record_spent(id: &str, stamp: u64, cause: &'static str) {
    with_spent(|spent| {
        if spent.grants.len() >= MAX_TRACKED_KEYS && !spent.grants.contains_key(id) {
            spent.overflow = true;
        } else {
            spent.grants.insert(id.to_owned(), (stamp, cause));
        }
    });
}

/// A grant found spent stays spent in this process: its saved grant is
/// forgotten, so no later load reuses it, even after the wall clock moves
/// back inside its span. Only a new counted attempt reads the key.
fn spend(id: &str, tracked: &TrackedKey) {
    let stamp = tracked.attempts.last().copied();
    with_persisted(|grants| {
        if grants.get(id).map(|grant| grant.stamp) == stamp {
            grants.remove(id);
        }
    });
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
                            && key.flags & !(PENDING | STARTED | EXHAUSTED | HELD | CURRENT) == 0
                    })
                    && guard.keys.len() + guard.revoked.len() <= MAX_TRACKED_KEYS
                    && guard
                        .revoked
                        .keys()
                        .all(|id| id.len() == 16 && lower_hex(id.as_bytes()))
            })
            .unwrap_or_else(Self::closed)
    }

    /// Forget whatever left the window; a future stamp is kept as persisted
    /// (MONEY 724h condition 3).
    fn settle_clock(&mut self, now: u64) {
        if let Some(closed) = self.closed_at {
            self.closed_at = recent(closed, now).then_some(closed);
        }
        if self.untracked_refused > 0 && !recent(self.untracked_refused_at, now) {
            self.untracked_refused = 0;
            self.untracked_refused_at = 0;
        }
        if self.orphaned > 0 && !recent(self.orphaned_at, now) {
            self.orphaned = 0;
            self.orphaned_at = 0;
        }
        if self.priors_refused > 0 && !recent(self.priors_refused_at, now) {
            self.priors_refused = 0;
            self.priors_refused_at = 0;
        }
        if self.identity_revoked > 0 && !recent(self.identity_revoked_at, now) {
            self.identity_revoked = 0;
            self.identity_revoked_at = 0;
        }
        self.revoked.retain(|_, revoked| recent(revoked.at, now));
        for key in self.keys.values_mut() {
            key.attempts.retain(|stamp| counted(*stamp, now));
            key.attempts.sort_unstable();
        }
    }

    fn refuse_untracked(&mut self, now: u64) {
        self.untracked_refused = self.untracked_refused.saturating_add(1);
        raise(&mut self.untracked_refused_at, now);
    }

    /// The window witness saved beside the guard: its latest stamp, or 0
    /// when it holds none (it then leaves the checkpoint with the guard).
    fn latest_stamp(&self) -> u64 {
        let counters = [
            (self.untracked_refused, self.untracked_refused_at),
            (self.orphaned, self.orphaned_at),
            (self.priors_refused, self.priors_refused_at),
            (self.identity_revoked, self.identity_revoked_at),
        ];
        self.keys
            .values()
            .flat_map(|key| key.attempts.iter().copied())
            .chain(self.revoked.values().map(|revoked| revoked.at))
            .chain(self.closed_at)
            .chain(
                counters
                    .into_iter()
                    .filter(|(count, _)| *count > 0)
                    .map(|(_, at)| at),
            )
            .max()
            .unwrap_or(0)
    }

    fn exhausted_keys(&self) -> u64 {
        let tracked = self.keys.values().filter(|key| key.has(EXHAUSTED)).count() as u64;
        tracked.saturating_add(self.untracked_refused)
    }
}

/// Never persisted: grants this load made (key id and stamp), the index keys
/// whose unchanged transcript candidate selection re-reads, and refusals of
/// keys the guard could not track (for the terminal alarm).
#[derive(Debug, Clone, Default)]
pub(crate) struct Transient {
    grants: Vec<(String, u64)>,
    rearmed: BTreeSet<String>,
    refusals: Vec<(String, &'static str)>,
    /// SI-724-F2: the guard itself was lost or refused this load (for the
    /// count-only guard alarm, raised even with no key pending).
    guard_loss: Option<&'static str>,
    /// Monotonic birth of grants made by this load. Reused grants retain
    /// their earlier birth in PERSISTED; neither saving nor reloading renews it.
    loaded_at: u64,
}
crate::heap_layout_bound::fields!(Transient; grants, rearmed, refusals, guard_loss, loaded_at);

pub(crate) fn key_id(key: &str) -> String {
    let mut id = safety_key_id(key);
    id.truncate(16);
    id
}

#[derive(Clone, Copy)]
struct ProcessGrant {
    stamp: u64,
    born: u64,
}

#[derive(Default)]
struct SpentGrants {
    grants: BTreeMap<String, (u64, &'static str)>,
    overflow: bool,
}

#[cfg(test)]
thread_local! {
    static TEST_ELAPSED: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static TEST_NOW: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
    static PERSISTED: std::cell::RefCell<BTreeMap<String, ProcessGrant>> =
        const { std::cell::RefCell::new(BTreeMap::new()) };
    static SPENT: std::cell::RefCell<SpentGrants> =
        const { std::cell::RefCell::new(SpentGrants {
            grants: BTreeMap::new(), overflow: false,
        }) };
    static ALARMED: std::cell::RefCell<BTreeSet<(String, &'static str)>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
    static ALARM_LINES: std::cell::RefCell<Vec<String>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
/// Keys whose current rearm this process already saved before its scan, with
/// the saved grant's stamp.
#[cfg(not(test))]
static PERSISTED: std::sync::Mutex<BTreeMap<String, ProcessGrant>> =
    std::sync::Mutex::new(BTreeMap::new());
/// Grants this process found spent as it admitted a read (key id, the
/// grant's stamp and why): refused for as long as that stamp is the key's
/// latest, in every working index of the process.
#[cfg(not(test))]
static SPENT: std::sync::Mutex<SpentGrants> = std::sync::Mutex::new(SpentGrants {
    grants: BTreeMap::new(),
    overflow: false,
});
/// One alarm per key and cause per process.
#[cfg(not(test))]
static ALARMED: std::sync::Mutex<BTreeSet<(String, &'static str)>> =
    std::sync::Mutex::new(BTreeSet::new());

/// Suspend-inclusive elapsed time, independent of wall-clock corrections.
/// macOS Instant/CLOCK_UPTIME_RAW stops in sleep; CLOCK_MONOTONIC_RAW is
/// mach_continuous_time in time units, including sleep. Linux BOOTTIME has
/// the same suspend-inclusive contract. Unsupported/failed clocks refuse.
fn monotonic_millis() -> u64 {
    #[cfg(test)]
    if let Some(elapsed) = TEST_ELAPSED.with(std::cell::Cell::get) {
        return elapsed;
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        #[cfg(target_os = "macos")]
        let clock = libc::CLOCK_MONOTONIC_RAW;
        #[cfg(target_os = "linux")]
        let clock = libc::CLOCK_BOOTTIME;
        let mut spec = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: clock_gettime writes only the provided initialized timespec.
        if unsafe { libc::clock_gettime(clock, &mut spec) } != 0 {
            return u64::MAX;
        }
        if spec.tv_sec < 0 || !(0..1_000_000_000).contains(&spec.tv_nsec) {
            return u64::MAX;
        }
        (spec.tv_sec as u64)
            .checked_mul(1000)
            .and_then(|seconds| seconds.checked_add(spec.tv_nsec as u64 / 1_000_000))
            .unwrap_or(u64::MAX)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    u64::MAX
}

fn grant_age_expired(born: u64) -> bool {
    let now = monotonic_millis();
    born == u64::MAX
        || now == u64::MAX
        || now < born
        || now - born > N3_GRANT_MAX_LOAD_TO_READ * 1000
}

/// Each N3 load and checkpoint observes wall time, even without a new grant.
/// The maximum is independent of guard retirement, and never reset by it.
pub(super) fn observe_clock(index: &mut ScanIndex) {
    if index.claude_census_rebuild_wall_high_water != 0
        || index.claude_request_census_shadow.rebuild_bound.is_some()
    {
        raise(&mut index.claude_census_rebuild_wall_high_water, now_unix());
    }
}

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
fn with_persisted<T>(f: impl FnOnce(&mut BTreeMap<String, ProcessGrant>) -> T) -> T {
    PERSISTED.with(|set| f(&mut set.borrow_mut()))
}
#[cfg(not(test))]
fn with_persisted<T>(f: impl FnOnce(&mut BTreeMap<String, ProcessGrant>) -> T) -> T {
    f(&mut PERSISTED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

#[cfg(test)]
fn with_spent<T>(f: impl FnOnce(&mut SpentGrants) -> T) -> T {
    SPENT.with(|set| f(&mut set.borrow_mut()))
}
#[cfg(not(test))]
fn with_spent<T>(f: impl FnOnce(&mut SpentGrants) -> T) -> T {
    f(&mut SPENT
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

/// SI-724-F2: the guard-loss alarm's own budget, one entry per cause (three
/// at most, outside the per-key cap), so key alarms never crowd it out. The
/// `"guard"` id never collides with a key id (hex).
fn first_guard_alarm(cause: &'static str) -> bool {
    with_alarmed(|set| set.insert(("guard".to_owned(), cause)))
}

fn emit_alarm(line: String) {
    #[cfg(test)]
    ALARM_LINES.with(|lines| lines.borrow_mut().push(line.clone()));
    eprintln!("{line}");
}

/// Decode-time decision for every fresh ambiguous key, every pending key and
/// every saved prior. Replaces the unconditional rearm; cheap no-op on a
/// healthy index. `priors_refused`: the reader refused the priors field;
/// `priors_seen`: the field was present at all. Never writes an index entry:
/// a grant is recorded in the guard and the load's transient set only.
pub(super) fn apply(index: &mut ScanIndex, priors_refused: bool, priors_seen: bool) {
    observe_clock(index);
    let witness = index.claude_request_census_shadow.rebuild_witness;
    let marker = index.claude_census_rebuild_initialized;
    if !priors_refused
        && !priors_seen
        && witness == 0
        && marker == 0
        && index.claude_request_census.ambiguous.is_empty()
        && index.claude_request_census_shadow.rebuild_bound.is_none()
        && index.claude_census_rebuild_priors.is_empty()
    {
        return;
    }
    let now = now_unix();
    // Condition 3: the saved witness as a stamp (a malformed one, `u64::MAX`,
    // is none). Every closure starts no earlier, so a guard rebuilt or closed
    // on backward time never lowers the latest stamp below it.
    let carried = if witness == u64::MAX { 0 } else { witness };
    // MONEY 724f P1: a missing guard is fresh only without evidence of
    // earlier activity. With its window witness still recent, a priors field
    // present, or the "N3 initialized" marker present (SI-724-B3b: the root
    // shadow or its `n` was dropped), it was lost (an external or older save
    // dropped it): its spent attempts are unknown, so admission closes for
    // one window. A refused priors field closes it below on its own.
    let marker_refused = marker == MARKER_REFUSED;
    let mut lost = false;
    // A guard decoded closed (malformed, duplicated or an ambiguous shadow).
    let mut undecodable = false;
    let mut guard = match index.claude_request_census_shadow.rebuild_bound.take() {
        Some(guard) => {
            undecodable = guard.closed_at == Some(UNSTAMPED);
            *guard
        }
        None => {
            // A future witness (the wall clock went backward) is recent.
            lost = !priors_refused
                && (priors_seen || marker != 0 || (witness != 0 && counted(witness, now)));
            if lost {
                DuplicateRebuildGuard::closed()
            } else {
                DuplicateRebuildGuard::default()
            }
        }
    };
    // A present guard whose contents no longer account for its still-counted
    // witness lost state too. In particular, `n: {}` beside a future `nw`
    // must never become a fresh guard or lower that saved witness.
    if carried > guard.latest_stamp() && counted(carried, now) {
        lost = true;
        close(&mut guard.closed_at, now.max(carried));
    }
    let missing = lost;
    if marker_refused && !priors_refused {
        // SI-724-B3b: value-level damage to the marker is isolated, and the
        // guard it vouches for is lost: closed for one window, never fresh.
        lost = true;
        guard.closed_at = Some(UNSTAMPED);
    }
    if guard.closed_at == Some(UNSTAMPED) {
        guard.closed_at = Some(now.max(carried));
    }
    // MONEY 724h condition 3: behind the guard's latest persisted stamp the
    // wall clock went backward. That time is no new authority: no grant is
    // made or reused, and no new key is admitted, until the clock passes it.
    let high_water = guard
        .latest_stamp()
        .max(index.claude_census_rebuild_wall_high_water);
    raise(&mut index.claude_census_rebuild_wall_high_water, now);
    let regressed = now < high_water;
    guard.settle_clock(now);
    let mut priors = std::mem::take(&mut index.claude_census_rebuild_priors);
    if lost && priors.is_empty() {
        // Counted like an orphan; a saved prior counts as one below instead.
        guard.orphaned = guard.orphaned.saturating_add(1);
        raise(&mut guard.orphaned_at, now);
    }
    if priors_refused {
        // Trust none of the priors (a duplicated field's first copy
        // included) and admit nothing for one window. Marking comes from the
        // guard, so this bound's own empty fingerprints stay held (MONEY
        // P1a); every other empty fingerprint takes the ordinary path.
        priors.clear();
        guard.priors_refused = guard.priors_refused.saturating_add(1);
        raise(&mut guard.priors_refused_at, now);
        close(&mut guard.closed_at, now.max(carried));
    }
    // A revoked key is out of this bound's control (SI-724-B1b): its prior
    // is dropped with it, never counted as an orphan.
    priors.retain(|id, _| !guard.revoked.contains_key(id));
    // An earlier checkpoint kept each pending key's prior inside the guard.
    for (id, key) in guard.keys.iter_mut() {
        if let Some(prior) = key.legacy_prior.take() {
            if key.has(PENDING) && valid_prior(&prior) {
                priors.entry(id.clone()).or_insert(prior);
            }
        }
    }
    let mut transient = Transient {
        loaded_at: monotonic_millis(),
        // SI-724-F2: alarmed (count-only) whether or not any key is pending.
        guard_loss: if marker_refused && !priors_refused {
            Some("marker_refused")
        } else if missing {
            Some("guard_missing")
        } else if undecodable {
            Some("guard_undecodable")
        } else {
            None
        },
        ..Transient::default()
    };
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
        raise(&mut guard.orphaned_at, now);
        close(&mut guard.closed_at, now.max(carried));
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
            Some(if lost {
                "guard_lost"
            } else {
                "guard_state_closed"
            })
        } else if regressed {
            Some("grant_clock_regressed")
        } else if guard.keys.len() + guard.revoked.len() >= MAX_TRACKED_KEYS {
            // A revoke moves its key's slot to `r` for one window.
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
        if !empty {
            // Seen intact: from now on an empty fingerprint is never this
            // bound's own.
            tracked.flags |= CURRENT;
        }
        // Only an earlier checkpoint's rearm is an empty fingerprint this
        // bound owns: a pending key the guard holds in the earlier form,
        // with or without its saved prior (MONEY P1a).
        let marked = empty && !tracked.has(CURRENT);
        if !marked {
            priors.remove(id);
        }
        if empty && !marked {
            // SI-724-B1: another mechanism's rearm of a current-form key. It
            // reads as it is; this bound never holds, restores or overwrites
            // it.
            tracked.flags &= !HELD;
            continue;
        }
        // MONEY 724g/724h P2: this process's saved grant authorizes a read
        // only while its own stamp is still one of the key's counted attempts
        // and within `N3_GRANT_MAX_LOAD_TO_READ` of now. Past either, or
        // with the wall clock behind the guard's latest stamp (condition 3),
        // it is spent, never moved forward: the read needs a fresh counted
        // attempt below, from the same budget.
        let unspent = if tracked.has(EXHAUSTED) || tracked.has(STARTED) {
            None
        } else {
            with_persisted(|grants| grants.get(id).copied()).filter(|grant| {
                tracked.attempts.contains(&grant.stamp)
                    && grant_spent(tracked, now, high_water, grant.born).is_none()
            })
        };
        if unspent.is_none() {
            // A save's throwaway CAS decode may be the first observer of a
            // spent grant. Remember it for the original working index too,
            // whose flags survive that discarded decode.
            if let Some(cause) = spent_cause(id, tracked, now, high_water, transient.loaded_at) {
                mark_spent(id, tracked, cause);
            } else {
                // Spent (or never this process's): never reused later.
                spend(id, tracked);
            }
        }
        if unspent.is_some() && open {
            // This process saved the grant and has not started its read. A
            // closed guard refuses it below instead. Its stamp stays: the
            // read is admitted only within the span (`rearmed`, `held`).
            if !empty {
                transient.rearmed.insert(key.clone());
            }
            continue;
        }
        if open && !regressed && tracked.attempts.len() < MAX_ATTEMPTS_PER_WINDOW {
            tracked.attempts.push(now);
            tracked.flags = PENDING | (tracked.flags & CURRENT);
            transient.grants.push((id.clone(), now));
            // A marked entry is already empty and reads as Rearmed: this
            // counted attempt is its only authorization, saved before the
            // daemon's scan (`persist_grants`).
            if !empty {
                transient.rearmed.insert(key.clone());
            }
        } else {
            // Refused, never a free rearm. A marked empty fingerprint is held
            // (candidate selection skips it) until the window allows a new
            // counted attempt; it is never restored.
            tracked.flags = PENDING | EXHAUSTED | (tracked.flags & CURRENT);
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
    // SI-724-B3b: the marker is written the first time the bound holds any
    // state (a grant included) and kept while it does; a refused one is
    // rewritten present. It retires only with an empty guard, which is
    // exactly a fresh one, so the guard and its marker leave the checkpoint
    // together and only a lost guard leaves the marker without it.
    if guard.is_empty() {
        index.claude_census_rebuild_initialized = 0;
    } else if marker == 0 || marker_refused {
        index.claude_census_rebuild_initialized = now.max(1);
    }
    index.claude_request_census_shadow.rebuild_witness = guard.latest_stamp();
    index.claude_request_census_shadow.rebuild_bound = (!guard.is_empty()).then(|| Box::new(guard));
    index.claude_request_census.rebuild_transient = transient;
}

/// SI-724-B1b, MONEY: identity work armed on `key` (`arming` is its
/// evidence, from which the one-shot token is derived) takes an earlier
/// checkpoint's key out of this bound's control, so the identity path
/// re-offers its empty fingerprint at once and this bound never delays it.
/// Called only from `rearm_source_fingerprint`, the one identity-clear path.
///
/// - Only a key this bound holds in the earlier form (pending without
///   `CURRENT`: its empty fingerprint is the bound's own) is revoked. Others
///   are not held, so nothing is revoked or counted.
/// - Once per key per arming: the token is recorded in the guard (`r`) for
///   one window, in the same index mutation as the arming's own clear. The
///   key stays held until a save makes both durable (MONEY 724g P1): the
///   daemon saves revokes made while its scan is built before the scan
///   selects anything (`persist_revokes`); later ones wait for the cycle's
///   own save. A crash or discarded working index before that loses both and
///   nothing was read: the re-derived arming revokes again, and the key is
///   re-offered once that revoke is saved. After the save a failed or
///   discarded scan finds the key already out of control and the token
///   consumed. The key's attempts and prior are dropped, never restored: from
///   here on it is the identity path's.
/// - Corruption cannot manufacture a revoke: missing or oversized evidence,
///   or an absent or ambiguous guard (decoded closed, so holding nothing),
///   revokes nothing and the key stays held. A guard
///   closed for its own bookkeeping still yields to identity work.
pub(crate) fn revoke_for_identity(
    shadow: &mut ClaudeRequestCensusShadowState,
    key: &str,
    arming: &str,
) {
    if arming.is_empty() || arming.len() > MAX_ARMING_BYTES {
        return;
    }
    let Some(guard) = shadow.rebuild_bound.as_deref_mut() else {
        return;
    };
    if guard.keys.is_empty() {
        return;
    }
    let id = key_id(key);
    if !guard
        .keys
        .get(&id)
        .is_some_and(|tracked| tracked.has(PENDING) && !tracked.has(CURRENT))
    {
        return;
    }
    let mut token = crate::snapshots::sha256_hex(&["census_rebuild_identity_revoke:v1", arming]);
    token.truncate(16);
    if guard.revoked.get(&id).is_some_and(|revoked| {
        revoked.tokens.contains(&token) || revoked.tokens.len() >= MAX_REVOKE_TOKENS
    }) {
        // The same arming already revoked this key once (a re-entered
        // earlier-form entry): never a second revoke for it. Past the token
        // cap the re-entered hold stays (fail closed).
        return;
    }
    // The key's slot moves to `r`: tracked keys and revokes share the cap.
    let now = now_unix();
    // Condition 3: the revoke keeps the removed key's latest stamp, so the
    // guard's latest stamp never falls with it.
    let latest = guard
        .keys
        .remove(&id)
        .and_then(|tracked| tracked.attempts.iter().max().copied())
        .unwrap_or(0);
    let revoked = guard.revoked.entry(id.clone()).or_default();
    revoked.tokens.push(token);
    raise(&mut revoked.at, now.max(latest));
    guard.identity_revoked = guard.identity_revoked.saturating_add(1);
    raise(&mut guard.identity_revoked_at, now);
    guard.unsaved.keys.insert(key.to_owned());
    shadow.rebuild_witness = guard.latest_stamp();
    with_persisted(|set| set.remove(&id));
}

/// MONEY 724g P1, daemon: before the scan selects anything, make the revokes
/// building it made durable. `committed` is the cycle's committed state (the
/// base of its partial commits); each unsaved revoke is applied to it exactly
/// as the working guard holds it (the key out of `k`, its tokens in `r`, the
/// counter), it is saved, and the working index takes its generation, as a
/// staged recovery capture does. The revoked key's entry must already be empty
/// in `committed` (an earlier checkpoint's held rearm is); otherwise, or with
/// no committed guard, the revoke stays unsaved and the key held until the
/// cycle's own save. A failed save fails the cycle before any read.
pub(crate) fn persist_revokes(
    working: &mut ScanIndex,
    committed: &mut ScanIndex,
    path: &Path,
) -> anyhow::Result<()> {
    let Some(guard) = working
        .claude_request_census_shadow
        .rebuild_bound
        .as_deref()
    else {
        return Ok(());
    };
    if guard.unsaved.keys.is_empty() {
        return Ok(());
    }
    let Some(saved) = committed
        .claude_request_census_shadow
        .rebuild_bound
        .as_deref_mut()
    else {
        return Ok(());
    };
    let mut made_durable = Vec::new();
    for key in &guard.unsaved.keys {
        let id = key_id(key);
        let Some(revoked) = guard.revoked.get(&id) else {
            continue;
        };
        if !committed
            .files
            .get(key)
            .is_some_and(|entry| entry.source_file_fingerprint.is_empty())
        {
            continue;
        }
        let new_tokens = revoked
            .tokens
            .iter()
            .filter(|token| {
                !saved
                    .revoked
                    .get(&id)
                    .is_some_and(|earlier| earlier.tokens.contains(token))
            })
            .count() as u64;
        saved.keys.remove(&id);
        saved.revoked.insert(id, revoked.clone());
        saved.identity_revoked = saved.identity_revoked.saturating_add(new_tokens);
        saved.identity_revoked_at = saved.identity_revoked_at.max(guard.identity_revoked_at);
        made_durable.push(key.clone());
    }
    if made_durable.is_empty() {
        return Ok(());
    }
    committed.claude_request_census_shadow.rebuild_witness = saved.latest_stamp();
    if matches!(
        committed.claude_census_rebuild_initialized,
        0 | MARKER_REFUSED
    ) {
        committed.claude_census_rebuild_initialized = now_unix().max(1);
    }
    committed.save(path)?;
    working.generation = committed.generation;
    if let Some(guard) = working
        .claude_request_census_shadow
        .rebuild_bound
        .as_deref_mut()
    {
        for key in made_durable {
            guard.unsaved.keys.remove(&key);
        }
    }
    Ok(())
}

/// Candidate selection (MONEY P1a, legacy): `key`'s empty fingerprint is an
/// earlier checkpoint's rearm this bound refuses for now. It is skipped,
/// never read, until a counted attempt is allowed, or until identity work's
/// revoke of it is saved (MONEY 724g P1). A counted attempt reads it only
/// within `N3_GRANT_MAX_LOAD_TO_READ` of its stamp, checked here, as the read
/// is admitted (MONEY 724h P2). A current-form key's empty fingerprint is
/// identity work's and never held.
pub(crate) fn held(index: &ScanIndex, key: &str) -> bool {
    let Some(guard) = index.claude_request_census_shadow.rebuild_bound.as_deref() else {
        return false;
    };
    if guard.unsaved.keys.contains(key) {
        return true;
    }
    if guard.keys.is_empty() {
        return false;
    }
    let id = key_id(key);
    guard.keys.get(&id).is_some_and(|tracked| {
        tracked.has(HELD)
            || (!tracked.has(CURRENT) && admission_refused(index, guard, &id, tracked))
    })
}

/// MONEY 724h P2 and condition 3, as candidate selection admits a read:
/// `tracked`'s grant is spent (its span over, or the wall clock behind the
/// guard's latest persisted stamp). A spent grant stays spent (`spend`).
fn admission_refused(
    index: &ScanIndex,
    guard: &DuplicateRebuildGuard,
    id: &str,
    tracked: &TrackedKey,
) -> bool {
    let Some(cause) = spent_cause(
        id,
        tracked,
        now_unix(),
        guard
            .latest_stamp()
            .max(index.claude_census_rebuild_wall_high_water),
        index.claude_request_census.rebuild_transient.loaded_at,
    ) else {
        return false;
    };
    mark_spent(id, tracked, cause);
    true
}

/// `tracked`'s grant was found spent (by admission or the terminal): its saved
/// grant is forgotten and the spend recorded, so it stays refused.
fn mark_spent(id: &str, tracked: &TrackedKey, cause: &'static str) {
    spend(id, tracked);
    if let Some(stamp) = unread_grant(tracked) {
        record_spent(id, stamp, cause);
    }
}

/// Candidate selection: `key` holds an unspent grant of this load, so its
/// unchanged transcript is re-read (Parse(Rearmed)) with its fingerprint
/// untouched, but only within `N3_GRANT_MAX_LOAD_TO_READ` of the grant's
/// stamp, checked here, as the read is admitted (MONEY 724h P2).
pub(crate) fn rearmed(index: &ScanIndex, key: &str) -> bool {
    index
        .claude_request_census
        .rebuild_transient
        .rearmed
        .contains(key)
        && index
            .claude_request_census_shadow
            .rebuild_bound
            .as_deref()
            .is_some_and(|guard| {
                let id = key_id(key);
                guard
                    .keys
                    .get(&id)
                    .is_some_and(|tracked| !admission_refused(index, guard, &id, tracked))
            })
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
    let born = index.claude_request_census.rebuild_transient.loaded_at;
    let grants = std::mem::take(&mut index.claude_request_census.rebuild_transient.grants);
    with_persisted(|set| {
        for (id, stamp) in grants {
            if set.len() >= MAX_TRACKED_KEYS && !set.contains_key(&id) {
                // Unrecorded: the next load counts it again (fail closed).
                break;
            }
            // A new grant, made durable, even one stamped in the same second
            // as a spent one: only the spent grant stays refused. Never
            // before its save (a save's throwaway decode makes grants too).
            with_spent(|spent| spent.grants.remove(&id));
            set.insert(id, ProcessGrant { stamp, born });
        }
    });
    Ok(())
}

/// Census-line counters (exhausted, orphaned, priors refused, identity
/// revoked) and rate-limited alarms.
pub(super) fn terminal(index: &ScanIndex) -> (u64, u64, u64, u64) {
    let Some(guard) = index.claude_request_census_shadow.rebuild_bound.as_deref() else {
        return (0, 0, 0, 0);
    };
    if let Some(cause) = index.claude_request_census.rebuild_transient.guard_loss {
        // SI-724-F2: count-only (no key identity), once per cause per process.
        if first_guard_alarm(cause) {
            let retry_after = guard
                .closed_at
                .unwrap_or(guard.orphaned_at)
                .saturating_add(WINDOW_SECONDS + 1);
            emit_alarm(format!(
                "local snapshot census duplicate rebuild guard lost alarm cause={cause} orphaned_7d={} exhausted_keys={} retry_after_unix={retry_after}; admission closed for one window, spent rebuilds not replenished",
                guard.orphaned,
                guard.exhausted_keys()
            ));
        }
    }
    // MONEY 724h P2: grants whose read span passed unread are spent; their
    // keys are refused (`rearmed`, `held`) until a new counted attempt, and
    // counted as exhausted. A current-form key counts only while this load's
    // grant still re-reads its intact fingerprint: an identity-armed empty
    // fingerprint is the identity path's read, never this bound's.
    let now = now_unix();
    let high_water = guard
        .latest_stamp()
        .max(index.claude_census_rebuild_wall_high_water);
    let transient = &index.claude_request_census.rebuild_transient;
    let rearmed_ids: BTreeMap<String, &String> = transient
        .rearmed
        .iter()
        .map(|key| (key_id(key), key))
        .collect();
    let spent: BTreeMap<&str, &'static str> = guard
        .keys
        .iter()
        .filter_map(|(id, key)| {
            Some((
                id,
                key,
                spent_cause(id, key, now, high_water, transient.loaded_at)?,
            ))
        })
        .filter(|(id, key, _)| {
            !key.has(CURRENT)
                || rearmed_ids
                    .get(*id)
                    .and_then(|key| index.files.get(*key))
                    .is_some_and(|entry| !entry.source_file_fingerprint.is_empty())
        })
        .map(|(id, _, cause)| (id.as_str(), cause))
        .collect();
    // Observed here first (no read admitted yet), a spent grant stays spent
    // as well. The identity path's key is never among them.
    for (&id, &cause) in &spent {
        if let Some(tracked) = guard.keys.get(id) {
            mark_spent(id, tracked, cause);
        }
    }
    let mut emitted = 0;
    // Behind the guard's latest stamp nothing is admitted until the wall
    // clock passes it, whatever else a retry waits for.
    let gate = if now < high_water {
        high_water.saturating_add(1)
    } else {
        0
    };
    let tracked = guard
        .keys
        .iter()
        .filter(|(id, key)| key.has(EXHAUSTED) || spent.contains_key(id.as_str()))
        .map(|(id, key)| {
            // A closed guard refuses until it reopens; otherwise the oldest
            // stamp's expiry allows the next counted attempt.
            let oldest = || {
                key.attempts
                    .first()
                    .map_or(0, |stamp| stamp.saturating_add(ATTEMPT_WINDOW_SECONDS + 1))
            };
            let regressed = gate != 0;
            let (cause, retry_after) = match guard.closed_at {
                _ if !key.has(EXHAUSTED) => {
                    let cause = spent[id.as_str()];
                    (
                        cause,
                        // The next load grants a new counted attempt if the
                        // budget allows one.
                        if key.attempts.len() >= MAX_ATTEMPTS_PER_WINDOW {
                            oldest()
                        } else if regressed {
                            gate
                        } else {
                            now
                        },
                    )
                }
                Some(closed_at) if key.attempts.len() < MAX_ATTEMPTS_PER_WINDOW => (
                    "guard_state_closed",
                    closed_at.saturating_add(WINDOW_SECONDS + 1),
                ),
                _ if regressed && key.attempts.len() < MAX_ATTEMPTS_PER_WINDOW => {
                    ("grant_clock_regressed", gate)
                }
                _ if key.has(HELD) => ("legacy_rearm_held", oldest()),
                _ => ("rebuild_bound_7d", oldest()),
            };
            (
                id.as_str(),
                cause,
                key.attempts.len(),
                retry_after.max(gate),
            )
        });
    let untracked = index
        .claude_request_census
        .rebuild_transient
        .refusals
        .iter()
        .map(|(id, cause)| {
            let retry_after = match *cause {
                "grant_clock_regressed" => high_water.saturating_add(1),
                cause => match cause {
                    "guard_state_closed" | "guard_lost" => {
                        guard.closed_at.unwrap_or(guard.untracked_refused_at)
                    }
                    "orphaned_rearm" => guard.orphaned_at,
                    "priors_decode_refused" => guard.priors_refused_at,
                    _ => guard.untracked_refused_at,
                }
                .saturating_add(WINDOW_SECONDS + 1),
            };
            (id.as_str(), *cause, 0, retry_after.max(gate))
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
    (
        guard.exhausted_keys().saturating_add(spent.len() as u64),
        guard.orphaned,
        guard.priors_refused,
        guard.identity_revoked,
    )
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    pub(crate) use super::{key_id, MAX_TRACKED_KEYS, N3_GRANT_MAX_LOAD_TO_READ};

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
    pub(crate) struct ElapsedClock;
    impl Drop for ElapsedClock {
        fn drop(&mut self) {
            TEST_ELAPSED.with(|cell| cell.set(None));
        }
    }
    pub(crate) fn set_elapsed(seconds: u64) -> ElapsedClock {
        TEST_ELAPSED.with(|cell| cell.set(Some(seconds * 1000)));
        ElapsedClock
    }
    /// A new daemon process: no grant saved yet, no alarm emitted yet.
    pub(crate) fn restart() {
        PERSISTED.with(|set| set.borrow_mut().clear());
        SPENT.with(|set| *set.borrow_mut() = SpentGrants::default());
        ALARMED.with(|set| set.borrow_mut().clear());
    }
    /// The per-key alarm budget spent by unrelated keys.
    pub(crate) fn saturate_key_alarms() {
        ALARMED.with(|set| {
            let mut set = set.borrow_mut();
            for n in 0..MAX_TRACKED_KEYS * 2 {
                set.insert((format!("{n:064x}"), "rebuild_bound_7d"));
            }
        });
    }
    /// Regression-spent grants from other checkpoints fill the process cache.
    pub(crate) fn saturate_spent_grants(except: &str, stamp: u64) {
        let except = key_id(except);
        for n in 0..=MAX_TRACKED_KEYS + 1 {
            let id = format!("{n:016x}");
            if id != except {
                record_spent(&id, stamp, "grant_clock_regressed");
            }
        }
        with_spent(|spent| {
            assert_eq!(spent.grants.len(), MAX_TRACKED_KEYS);
            assert!(spent.overflow);
        });
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
    /// `key` is tracked in the current form (its fingerprint seen intact).
    pub(crate) fn current_form(index: &ScanIndex, key: &str) -> bool {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .and_then(|guard| guard.keys.get(&key_id(key)))
            .is_some_and(|key| key.has(CURRENT))
    }
    /// The window witness saved beside the guard (`"nw"`).
    pub(crate) fn witness(index: &ScanIndex) -> u64 {
        index.claude_request_census_shadow.rebuild_witness
    }
    /// The stamps of `key` in the guard as saved at `path` (none without one).
    pub(crate) fn saved_stamps(path: &Path, key: &str) -> Vec<u64> {
        let saved: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        saved["claude_request_census_shadow"]["n"]["k"][key_id(key)]
            .as_str()
            .and_then(|tracked| serde_json::from_value::<TrackedKey>(tracked.into()).ok())
            .map(|tracked| tracked.attempts)
            .unwrap_or_default()
    }
    /// SI-724-B1b: identity revokes counted in the window, and whether `key`
    /// has a revoke recorded.
    pub(crate) fn identity_revoked(index: &ScanIndex) -> u64 {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .map_or(0, |guard| guard.identity_revoked)
    }
    /// MONEY 724g P1: `key`'s revoke is not saved yet (it stays held).
    pub(crate) fn revoke_unsaved(index: &ScanIndex, key: &str) -> bool {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .is_some_and(|guard| guard.unsaved.keys.contains(key))
    }
    pub(crate) fn revoked(index: &ScanIndex, key: &str) -> bool {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .is_some_and(|guard| guard.revoked.contains_key(&key_id(key)))
    }
    /// A guard is present and closed (never a fresh default).
    pub(crate) fn closed(index: &ScanIndex) -> bool {
        index
            .claude_request_census_shadow
            .rebuild_bound
            .as_ref()
            .is_some_and(|guard| guard.closed_at.is_some())
    }
    /// SI-724-B3b: the "N3 initialized" marker as loaded.
    pub(crate) fn marker(index: &ScanIndex) -> u64 {
        index.claude_census_rebuild_initialized
    }
    /// `key` as an earlier checkpoint saved this bound's exhausted, held
    /// rearm: pending without `CURRENT`, both attempts spent at `stamps`, its
    /// entry empty. Applied to the serialized index (a decode, as a load
    /// reads it, but without the load's apply).
    pub(crate) fn hold_earlier_form(value: &mut serde_json::Value, key: &str, stamps: [u64; 2]) {
        value["files"][key]["source_file_fingerprint"] = serde_json::json!("");
        let tracked = format!("{}:{},{}", PENDING | EXHAUSTED | HELD, stamps[0], stamps[1]);
        value["claude_request_census_shadow"]["n"]["k"][key_id(key)] = serde_json::json!(tracked);
        value["claude_census_rebuild_initialized"] = serde_json::json!(stamps[0]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Clock failure, reversal or sleep cannot turn unknown/late real age
    /// into authority. The inclusive span remains valid through its last ms.
    #[test]
    fn grant_age_failure_reversal_and_suspend_spend_the_grant() {
        let born = 1_000;
        for (now, expired) in [
            (born + N3_GRANT_MAX_LOAD_TO_READ * 1000, false),
            (born + N3_GRANT_MAX_LOAD_TO_READ * 1000 + 1, true),
            // Two awake hours plus eighteen suspended hours.
            (born + 20 * 3600 * 1000, true),
            (born - 1, true),
            (u64::MAX, true),
        ] {
            TEST_ELAPSED.with(|cell| cell.set(Some(now)));
            assert_eq!(grant_age_expired(born), expired, "clock={now}");
        }
        TEST_ELAPSED.with(|cell| cell.set(Some(1_000)));
        assert!(
            grant_age_expired(u64::MAX),
            "failed birth stays refused after recovery"
        );
        TEST_ELAPSED.with(|cell| cell.set(None));
    }

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
                    // Pending: only a pending key keeps a saved prior.
                    let key = TrackedKey {
                        attempts: vec![u64::MAX; MAX_ATTEMPTS_PER_WINDOW],
                        flags: PENDING | STARTED | EXHAUSTED | HELD | CURRENT,
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
            revoked: BTreeMap::new(),
            identity_revoked: u64::MAX,
            identity_revoked_at: u64::MAX,
            unsaved: UnsavedRevokes::default(),
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

        // SI-724-B1b: every slot revoked by the most armings fits the same
        // bound and decodes intact.
        let revoked = DuplicateRebuildGuard {
            revoked: (0..MAX_TRACKED_KEYS)
                .map(|slot| {
                    let tokens = (0..MAX_REVOKE_TOKENS)
                        .map(|token| format!("{token:016x}"))
                        .collect();
                    (
                        format!("{slot:016x}"),
                        Revoked {
                            tokens,
                            at: u64::MAX,
                        },
                    )
                })
                .collect(),
            identity_revoked: u64::MAX,
            identity_revoked_at: u64::MAX,
            ..DuplicateRebuildGuard::default()
        };
        let mut index = ScanIndex::default();
        index.claude_request_census_shadow.rebuild_bound = Some(Box::new(revoked.clone()));
        let saved = serde_json::to_vec_pretty(&index).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&saved).unwrap();
        let raw_guard =
            serde_json::to_string_pretty(&value["claude_request_census_shadow"]["n"]).unwrap();
        let saved_guard_bytes = raw_guard.len() + 8 * raw_guard.lines().count();
        assert!(
            saved_guard_bytes <= MAX_GUARD_RAW_BYTES / 2,
            "{saved_guard_bytes}"
        );
        assert_eq!(DuplicateRebuildGuard::decode(&raw_guard), revoked);
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

    /// SI-724-B3b: the "N3 initialized" marker is decoded in isolation. Only
    /// a nonzero u64 below `u64::MAX` is present and intact; any other value
    /// (zero, negative, a string, null, an array, an overflowing literal,
    /// `u64::MAX` itself) is present and refused, on a plain Serde path too,
    /// never an index decode error.
    #[test]
    fn markers_decode_in_isolation_and_refuse_every_malformed_value() {
        let base = serde_json::to_value(ScanIndex::default()).unwrap();
        for (raw, expected) in [
            ("5", 5),
            ("1790000000", 1_790_000_000),
            ("0", MARKER_REFUSED),
            ("-1", MARKER_REFUSED),
            ("\"5\"", MARKER_REFUSED),
            ("null", MARKER_REFUSED),
            ("[5]", MARKER_REFUSED),
            ("1e400", MARKER_REFUSED),
            ("5.5", MARKER_REFUSED),
            ("18446744073709551615", MARKER_REFUSED),
            ("18446744073709551616", MARKER_REFUSED),
        ] {
            assert_eq!(decode_marker(raw.as_bytes()), expected, "{raw}");
            let mut value = base.clone();
            value["claude_census_rebuild_initialized"] = serde_json::json!("MARKER");
            let index = value.to_string().replace("\"MARKER\"", raw);
            let decoded: ScanIndex = serde_json::from_str(&index).unwrap();
            assert_eq!(decoded.claude_census_rebuild_initialized, expected, "{raw}");
        }
    }

    /// SI-724-B1b: identity revokes (`"r"`) decode strictly with the guard.
    /// A repeated or malformed revoke, or tracked keys and revokes past
    /// their shared cap, closes the guard; nothing is revoked or restored.
    #[test]
    fn revokes_decode_strictly_and_share_the_tracked_cap() {
        let intact = r#"{"k":{"0123456789abcdef":"17:1,2"},"r":{"fedcba9876543210":"0123456789abcdef:3"},"i":1,"ia":3}"#;
        let guard = DuplicateRebuildGuard::decode(intact);
        assert_eq!(guard.closed_at, None);
        assert_eq!(guard.revoked.len(), 1);
        assert_eq!(guard.identity_revoked, 1);
        assert_eq!(
            serde_json::to_string(&guard).unwrap(),
            intact,
            "saved as decoded"
        );
        let tokens =
            r#"{"r":{"fedcba9876543210":"0123456789abcdef,1111111111111111,2222222222222222:3"}}"#;
        let guard = DuplicateRebuildGuard::decode(tokens);
        assert_eq!(guard.closed_at, None);
        assert_eq!(
            guard.revoked["fedcba9876543210"].tokens.len(),
            MAX_REVOKE_TOKENS
        );
        assert_eq!(serde_json::to_string(&guard).unwrap(), tokens);
        for broken in [
            r#"{"r":{"fedcba9876543210":"0123456789abcdef:3","fedcba9876543210":"0123456789abcdef:4"}}"#,
            r#"{"r":{"fedcba9876543210":"0123456789ABCDEF:3"}}"#,
            r#"{"r":{"fedcba9876543210":"0123456789abcdef"}}"#,
            r#"{"r":{"fedcba9876543210":"0123456789abcdef:x"}}"#,
            r#"{"r":{"fedcba987654321":"0123456789abcdef:3"}}"#,
            r#"{"r":{"fedcba9876543210":7}}"#,
            r#"{"r":[]}"#,
            r#"{"r":{"fedcba9876543210":":3"}}"#,
            r#"{"r":{"fedcba9876543210":"0123456789abcdef,:3"}}"#,
            r#"{"r":{"fedcba9876543210":"0123456789abcdef,0123456789abcdef:3"}}"#,
            r#"{"r":{"fedcba9876543210":"0123456789abcdef,1111111111111111,2222222222222222,3333333333333333:3"}}"#,
        ] {
            assert_eq!(
                DuplicateRebuildGuard::decode(broken).closed_at,
                Some(UNSTAMPED),
                "{broken}"
            );
        }
        let half = MAX_TRACKED_KEYS / 2;
        let full = DuplicateRebuildGuard {
            keys: (0..half)
                .map(|slot| {
                    (
                        format!("{slot:016x}"),
                        TrackedKey {
                            attempts: vec![1],
                            flags: PENDING | CURRENT,
                            legacy_prior: None,
                        },
                    )
                })
                .collect(),
            revoked: (half..MAX_TRACKED_KEYS)
                .map(|slot| {
                    (
                        format!("{slot:016x}"),
                        Revoked {
                            tokens: vec!["f".repeat(16)],
                            at: 1,
                        },
                    )
                })
                .collect(),
            ..DuplicateRebuildGuard::default()
        };
        let raw = serde_json::to_string(&full).unwrap();
        assert_eq!(DuplicateRebuildGuard::decode(&raw), full, "at the cap");
        let mut over = full.clone();
        over.revoked.insert(
            format!("{MAX_TRACKED_KEYS:016x}"),
            Revoked {
                tokens: vec!["f".repeat(16)],
                at: 1,
            },
        );
        let raw = serde_json::to_string(&over).unwrap();
        assert_eq!(
            DuplicateRebuildGuard::decode(&raw).closed_at,
            Some(UNSTAMPED),
            "past the shared cap"
        );
    }

    /// SI-724-B1b, MONEY: one revoke per key per arming even when an
    /// earlier-form hold re-enters between armings (A, then B, then A again
    /// revokes nothing), every consumed token kept. Past `MAX_REVOKE_TOKENS`
    /// distinct armings a re-entered hold stays held (fail closed).
    #[test]
    fn revokes_keep_every_consumed_arming_across_re_entry() {
        let _clock = test_support::set_now(1_790_000_000);
        let key = "/synthetic/re-entry.jsonl";
        let id = key_id(key);
        let held = TrackedKey {
            attempts: vec![1_790_000_000 - 60, 1_790_000_000 - 30],
            flags: PENDING | EXHAUSTED | HELD,
            legacy_prior: None,
        };
        let mut shadow = ClaudeRequestCensusShadowState {
            rebuild_bound: Some(Box::default()),
            ..ClaudeRequestCensusShadowState::default()
        };
        let re_enter = |shadow: &mut ClaudeRequestCensusShadowState| {
            let guard = shadow.rebuild_bound.as_deref_mut().unwrap();
            guard.keys.insert(id.clone(), held.clone());
        };
        let revoked = |shadow: &ClaudeRequestCensusShadowState| {
            let guard = shadow.rebuild_bound.as_deref().unwrap();
            (!guard.keys.contains_key(&id), guard.identity_revoked)
        };
        let mut expected = 0;
        for (arming, revokes) in [
            ("A", true),
            ("B", true),
            ("A", false),
            ("B", false),
            ("C", true),
            ("D", false),
            ("A", false),
        ] {
            re_enter(&mut shadow);
            revoke_for_identity(&mut shadow, key, arming);
            expected += u64::from(revokes);
            assert_eq!(revoked(&shadow), (revokes, expected), "{arming}");
        }
        let guard = shadow.rebuild_bound.as_deref().unwrap();
        assert_eq!(guard.revoked[&id].tokens.len(), MAX_REVOKE_TOKENS);
        // Saved and decoded with every token.
        let raw = serde_json::to_string(guard).unwrap();
        assert_eq!(&DuplicateRebuildGuard::decode(&raw), guard);
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
