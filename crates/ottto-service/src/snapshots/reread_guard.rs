//! Read-selection budget. Negative scheduling evidence only: never ACKs,
//! ownership, acceptance or permission to rebuild money history.
use super::*;
use serde::{Deserializer, Serializer};

/// Observe-only release. Enabling enforcement requires a separate reviewed PR
/// with durable debt, protected-read and replay-drip contracts completed.
pub(crate) const REREAD_GUARD_ENFORCE: bool = false;
/// Cap each sparse diagnostic map independently; capacity never blocks reads.
// Two index owners can coexist in the 8 MiB SourcePreparation frame. The
// existing walker charges these three maps 633,248 bytes per populated owner.
const MAX_TRACKED_KEYS: usize = 256;

const WEEK_HOURS: u32 = 7 * 24;
const GRANT_LIFETIME: u64 = 12 * 3600;
// Hour stamps round DOWN. Retaining for an additional hour plus the maximum
// grant age makes any two actual reads separated by >7d when a slot expires.
const RETAIN_HOURS: u32 = WEEK_HOURS + 12 + 1;
const ALARM_INTERVAL: u64 = 3600;
const CAUSES: usize = CANDIDATE_PARSE_REASON_COUNT + 1;

#[derive(Debug, Clone, Copy)]
struct ReplayGrant {
    revision: &'static str,
}
// An approved revision must be added explicitly, with its approval in review.
const REPLAY_GRANTS: &[ReplayGrant] = &[];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KeyHash([u8; 16]);
impl KeyHash {
    fn of(key: &str) -> Self {
        Self(
            Sha256::digest(key.as_bytes())[..16]
                .try_into()
                .expect("digest prefix"),
        )
    }
}
impl Serialize for KeyHash {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.collect_str(&format_args!("{:032x}", u128::from_be_bytes(self.0)))
    }
}
impl<'de> Deserialize<'de> for KeyHash {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let key = String::deserialize(d)?;
        if key.len() != 32
            || !key
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(serde::de::Error::custom("invalid reread key digest"));
        }
        u128::from_str_radix(&key, 16)
            .map(|v| Self(v.to_be_bytes()))
            .map_err(serde::de::Error::custom)
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for KeyHash {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        Some(())
    }
}

/// Stamp values and digest keys contain no owned allocations. Charge their
/// BTree nodes once, without spending one walker visit per scalar hour.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
struct StampMap(BTreeMap<KeyHash, [u32; 2]>);
impl std::ops::Deref for StampMap {
    type Target = BTreeMap<KeyHash, [u32; 2]>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for StampMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for StampMap {
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self(map): &Self = self;
        crate::heap_layout_bound::tree_nodes::<KeyHash, [u32; 2]>(map.len(), c)
    }
}

/// Counters belong to one traversal and survive page boundaries and restarts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct Tripwire {
    traversal: String,
    indexed: u64,
    planned: u64,
    cause_counts: [u64; CAUSES],
    runtime_cause_counts: [u64; CAUSES],
    full_reads: u64,
    plan_held: bool,
    last_alarm: u64,
}
crate::heap_layout_bound::fields!(Tripwire; traversal, indexed, planned, cause_counts, runtime_cause_counts, full_reads, plan_held, last_alarm);

#[derive(Debug, Clone, Copy)]
struct Reservation {
    wall: u64,
    born: u64,
    saved: bool,
    claimed: bool,
    replay: bool,
    upgrade: bool,
    growth: Option<KeyHash>,
}
crate::heap_layout_bound::fields!(Reservation; wall, born, saved, claimed, replay, upgrade, growth);

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct State {
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    replay_witnesses: BTreeMap<KeyHash, PhysicalWitness>,
    #[serde(alias = "refused")]
    over_budget: [u64; CAUSES],
    observed_reads: u64,
    tracking_dropped: u64,
    physical_tracking_dropped: u64,
    growth_tracking_dropped: u64,
    growth_full: StampMap,
    source_revision: String,
    // Sparse: no entry until a selected unchanged file spends an attempt.
    attempts: StampMap,
    wall_high_water: u64,
    replayed: BTreeMap<String, BTreeSet<KeyHash>>,
    tripwire: Tripwire,
    last_budget_alarm: u64,
    /// Malformed diagnostic state is counted; observe mode still admits reads.
    closed: bool,
    #[serde(skip)]
    reservations: BTreeMap<KeyHash, Reservation>,
    #[serde(skip)]
    require_save: bool,
}
crate::heap_layout_bound::fields!(State; replay_witnesses, over_budget, observed_reads, tracking_dropped, physical_tracking_dropped, growth_tracking_dropped, growth_full, source_revision, attempts, wall_high_water, replayed, tripwire, last_budget_alarm, closed, reservations, require_save);

#[derive(Debug, Clone, Copy)]
pub(super) struct Ticket {
    pub(super) durable: bool,
    replay: bool,
    wall: u64,
    born: u64,
}
crate::heap_layout_bound::fields!(Ticket; durable, replay, wall, born);
#[derive(Debug)]
pub(super) enum GroupAdmission {
    Ready,
    AwaitSave,
    Refuse,
}

#[derive(Debug)]
pub(super) enum Admission {
    Admit(Ticket),
    Refuse,
}

pub(super) fn physical_identity(metadata: &fs::Metadata) -> Option<[u64; 2]> {
    #[cfg(unix)]
    {
        Some([metadata.dev(), metadata.ino()])
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        None
    }
}

pub(super) fn byte_unchanged(entry: &ScanIndexEntry, candidate: &CandidateFile) -> bool {
    entry.size_bytes == candidate.size_bytes
        && entry.modified_unix_nanos.map_or_else(
            || entry.modified_unix_seconds == candidate.modified_unix_seconds,
            |mtime| mtime == candidate.modified_unix_nanos,
        )
}

fn cause(reason: Option<CandidateParseReason>) -> usize {
    reason.map_or(CAUSES - 1, |reason| reason as usize)
}
fn threshold(indexed: u64) -> u64 {
    (indexed / 20).max(300)
}
fn hour(now: u64) -> Option<u32> {
    u32::try_from(now / 3600).ok().filter(|v| *v > 0)
}
fn recent(stamp: u32, now: u32) -> bool {
    stamp != 0 && (stamp > now || now - stamp <= RETAIN_HOURS)
}
fn elapsed_valid(born: u64, now: u64) -> bool {
    born != u64::MAX && now != u64::MAX && now >= born && now - born <= GRANT_LIFETIME * 1000
}

/// Same suspend-inclusive clock as N3 (#724). Failure spends the ticket.
fn monotonic_millis() -> u64 {
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
        // SAFETY: initialized writable timespec. These clocks include suspend.
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

pub(super) fn now() -> u64 {
    #[cfg(test)]
    if let Some(now) = TEST_CLOCK.with(|clock| clock.get()) {
        return now;
    }
    unix_seconds(SystemTime::now()).unwrap_or(0)
}
#[cfg(test)]
thread_local! { static TEST_CLOCK: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
pub(super) fn set_now_for_test(now: u64) {
    TEST_CLOCK.with(|clock| clock.set(Some(now)));
}

impl State {
    pub(super) fn prune_on_load(&mut self, now: u64) {
        // Neither rollback nor a future stamp shrinks the retained window.
        if now >= self.wall_high_water {
            if let Some(now_hour) = hour(now) {
                self.attempts.retain(|_, slots| {
                    for slot in slots.iter_mut() {
                        if !recent(*slot, now_hour) {
                            *slot = 0;
                        }
                    }
                    slots.iter().any(|s| *s != 0)
                });
                let attempts = &self.attempts;
                self.replay_witnesses.retain(|key, witness| {
                    recent(witness.removed_hour, now_hour) || attempts.contains_key(key)
                });
            }
        }
        if self.wall_high_water != 0 || !self.attempts.is_empty() || !self.replayed.is_empty() {
            self.wall_high_water = self.wall_high_water.max(now);
        }
        if let Some(now_hour) = hour(now) {
            self.growth_full
                .retain(|_, record| now_hour.saturating_sub(record[0]) < 24);
        }
        while self.attempts.len() > MAX_TRACKED_KEYS {
            self.attempts.pop_last();
            self.tracking_dropped = self.tracking_dropped.saturating_add(1);
        }
        while self.replay_witnesses.len() > MAX_TRACKED_KEYS {
            self.replay_witnesses.pop_last();
            self.physical_tracking_dropped = self.physical_tracking_dropped.saturating_add(1);
        }
        while self.growth_full.len() > MAX_TRACKED_KEYS {
            self.growth_full.pop_last();
            self.growth_tracking_dropped = self.growth_tracking_dropped.saturating_add(1);
        }
        self.reservations.clear(); // Restart never reuses an unconsumed ticket.
    }
    pub(super) fn observe_clock(&mut self) {
        if self.wall_high_water != 0 || !self.attempts.is_empty() || !self.replayed.is_empty() {
            self.wall_high_water = self.wall_high_water.max(now());
        }
    }
    pub(super) fn begin_selection(&mut self) {
        self.require_save = false;
    }
    /// O3: use the existing durable replay ledger and pre-read reservation
    /// receipt. Restart loses the unused ticket, never the spent release/key.
    pub(super) fn upgrade_missing(&mut self, key: &str, consume: bool) -> bool {
        self.upgrade_bound(key, consume, None)
    }
    pub(super) fn upgrade_growth(&mut self, key: &str, c: &CandidateFile, consume: bool) -> bool {
        let stamp = KeyHash::of(&format!(
            "upgrade-growth:{key}:{}:{}",
            c.size_bytes, c.modified_unix_nanos
        ));
        self.upgrade_bound(key, consume, Some(stamp))
    }
    fn upgrade_bound(&mut self, key: &str, consume: bool, growth: Option<KeyHash>) -> bool {
        if self.closed {
            return false;
        }
        let id = KeyHash::of(key);
        if let Some(r) = self
            .reservations
            .get_mut(&id)
            .filter(|r| r.upgrade && r.saved && !r.claimed && r.growth == growth)
        {
            r.claimed = consume;
            return true;
        }
        let release = format!(
            "upgrade_state_missing:{}",
            ottto_core::compiled_release_version()
        );
        // Retain one persisted key/release. Growth binding is RAM-only;
        // restart may mint one extra grant under the transitional hold rule.
        let new_growth = growth.is_some()
            && self
                .reservations
                .get(&id)
                .map_or(true, |r| r.growth != growth);
        let spent = self.replayed.entry(release).or_default();
        if new_growth {
            spent.remove(&id);
        }
        if !spent.insert(id) {
            return false;
        }
        self.reservations.insert(
            id,
            Reservation {
                wall: now(),
                born: monotonic_millis(),
                saved: false,
                claimed: false,
                replay: true,
                upgrade: true,
                growth,
            },
        );
        false
    }
    pub(super) fn needs_save(&self) -> bool {
        self.reservations.values().any(|r| !r.saved)
    }
    pub(super) fn upgrade_claimed(&self, key: &str) -> bool {
        !self.closed
            && self
                .reservations
                .get(&KeyHash::of(key))
                .is_some_and(|r| r.upgrade && r.saved && r.claimed)
    }
    fn saved(&mut self) {
        for r in self.reservations.values_mut() {
            r.saved = true;
        }
    }
    fn admit(
        &mut self,
        key: &str,
        reason: Option<CandidateParseReason>,
        now: u64,
        elapsed: u64,
        revision: Option<&str>,
    ) -> Admission {
        #[cfg(test)]
        if !TEST_OBSERVATIONS.with(std::cell::Cell::get) {
            return Admission::Admit(observation_ticket());
        }
        if REREAD_GUARD_ENFORCE {
            self.admit_enforced(key, reason, now, elapsed, revision)
        } else {
            self.observe_reread(key, reason, now, elapsed)
        }
    }
    fn observe_reread(
        &mut self,
        key: &str,
        reason: Option<CandidateParseReason>,
        now: u64,
        elapsed: u64,
    ) -> Admission {
        let id = KeyHash::of(key);
        let now_hour = hour(now);
        let clock_invalid =
            self.closed || now < self.wall_high_water || elapsed == u64::MAX || now_hour.is_none();
        self.wall_high_water = self.wall_high_water.max(now);
        let tripwire_exceeded =
            self.tripwire.plan_held || self.tripwire.full_reads > threshold(self.tripwire.indexed);
        let mut budget_exceeded = clock_invalid;
        if let Some(now_hour) = now_hour.filter(|_| !clock_invalid) {
            if self.attempts.contains_key(&id) || self.attempts.len() < MAX_TRACKED_KEYS {
                let slots = self.attempts.entry(id).or_insert([0; 2]);
                for slot in slots.iter_mut() {
                    if !recent(*slot, now_hour) {
                        *slot = 0;
                    }
                }
                if let Some(slot) = slots.iter_mut().find(|slot| **slot == 0) {
                    *slot = now_hour;
                } else {
                    budget_exceeded = true;
                    // Keep the two most recent observations, never grow the payload.
                    slots.sort_unstable();
                    slots[0] = now_hour;
                }
            } else {
                // Lost diagnostic capacity must never affect selection.
                self.tracking_dropped = self.tracking_dropped.saturating_add(1);
            }
            if let Some(witness) = self.replay_witnesses.get_mut(&id) {
                witness.removed_hour = now_hour;
            }
        }
        if budget_exceeded || tripwire_exceeded {
            self.over_budget[cause(reason)] = self.over_budget[cause(reason)].saturating_add(1);
        }
        if budget_exceeded
            && (self.last_budget_alarm == 0
                || now.saturating_sub(self.last_budget_alarm) >= ALARM_INTERVAL)
        {
            eprintln!(
                "REREAD_BUDGET_EXHAUSTED mode=observe cause={} would_refuse=1",
                cause(reason)
            );
            self.last_budget_alarm = now;
        }
        self.observed_reads = self.observed_reads.saturating_add(1);
        self.tripwire.full_reads = self.tripwire.full_reads.saturating_add(1);
        self.tripwire.runtime_cause_counts[cause(reason)] =
            self.tripwire.runtime_cause_counts[cause(reason)].saturating_add(1);
        if self.tripwire.plan_held || self.tripwire.full_reads > threshold(self.tripwire.indexed) {
            self.tripwire.alarm(now);
        }
        Admission::Admit(Ticket {
            durable: true,
            replay: false,
            wall: now,
            born: elapsed,
        })
    }
    fn admit_enforced(
        &mut self,
        key: &str,
        reason: Option<CandidateParseReason>,
        now: u64,
        elapsed: u64,
        revision: Option<&str>,
    ) -> Admission {
        self.admit_with_grants(key, reason, now, elapsed, revision, REPLAY_GRANTS)
    }
    fn admit_with_grants(
        &mut self,
        key: &str,
        reason: Option<CandidateParseReason>,
        now: u64,
        elapsed: u64,
        revision: Option<&str>,
        grants: &[ReplayGrant],
    ) -> Admission {
        // A production scan without the committed-index save handoff has
        // no authority to issue a volatile reread ticket.
        if !self.require_save && !cfg!(test) {
            return Admission::Refuse;
        }
        let id = KeyHash::of(key);
        let stamp_high_water = self.attempts.get(&id).map_or(0, |slots| {
            u64::from(*slots.iter().max().unwrap_or(&0)) * 3600
        });
        let prior_high_water = self.wall_high_water.max(stamp_high_water);
        self.wall_high_water = prior_high_water.max(now);
        let Some(now_hour) = hour(now) else {
            return Admission::Refuse;
        };
        if self.closed || now < prior_high_water || elapsed == u64::MAX {
            if let Some(reservation) = self.reservations.get_mut(&id) {
                reservation.claimed = true;
            }
            return Admission::Refuse;
        }
        if let Some(reservation) = self.reservations.get_mut(&id).filter(|r| !r.claimed) {
            if now < reservation.wall
                || now - reservation.wall > GRANT_LIFETIME
                || !elapsed_valid(reservation.born, elapsed)
            {
                reservation.claimed = true;
                return Admission::Refuse;
            }
            let durable = reservation.saved || !self.require_save;
            if durable {
                reservation.claimed = true;
            }
            return Admission::Admit(Ticket {
                durable,
                replay: reservation.replay,
                wall: reservation.wall,
                born: reservation.born,
            });
        }
        let approved = revision
            .filter(|revision| grants.iter().any(|g| g.revision == *revision))
            .filter(|revision| {
                !self
                    .replayed
                    .get(*revision)
                    .is_some_and(|keys| keys.contains(&id))
            });
        if approved.is_none()
            && (self.tripwire.plan_held
                || self.tripwire.full_reads > threshold(self.tripwire.indexed))
        {
            self.tripwire.alarm(now);
            return Admission::Refuse;
        }
        let replay = approved.is_some();
        if let Some(revision) = approved {
            self.replayed
                .entry(revision.to_owned())
                .or_default()
                .insert(id);
        } else {
            let slots = self.attempts.entry(id).or_insert([0; 2]);
            for slot in slots.iter_mut() {
                if !recent(*slot, now_hour) {
                    *slot = 0;
                }
            }
            if let Some(slot) = slots.iter_mut().find(|slot| **slot == 0) {
                *slot = now_hour;
            } else {
                if self.last_budget_alarm == 0
                    || now.saturating_sub(self.last_budget_alarm) >= ALARM_INTERVAL
                {
                    eprintln!(
                        "REREAD_BUDGET_EXHAUSTED mode=enforce cause={}",
                        cause(reason)
                    );
                    self.last_budget_alarm = now;
                }
                return Admission::Refuse;
            }
        }
        let durable = !self.require_save;
        if !replay {
            // Charge conservatively before read preparation. Even a later
            // failure/cache hit spends this crash-safe attempt.
            self.tripwire.runtime_cause_counts[cause(reason)] =
                self.tripwire.runtime_cause_counts[cause(reason)].saturating_add(1);
            self.tripwire.full_reads = self.tripwire.full_reads.saturating_add(1);
            if self.tripwire.full_reads > threshold(self.tripwire.indexed) {
                self.tripwire.alarm(now);
            }
        }
        if let Some(witness) = self.replay_witnesses.get_mut(&id) {
            witness.removed_hour = now_hour;
        }
        self.reservations.insert(
            id,
            Reservation {
                wall: now,
                born: elapsed,
                saved: durable,
                claimed: durable,
                replay,
                upgrade: false,
                growth: None,
            },
        );
        Admission::Admit(Ticket {
            durable,
            replay,
            wall: now,
            born: elapsed,
        })
    }
    pub(super) fn disclosure(&self) -> String {
        let counts = CANDIDATE_PARSE_REASON_NAMES
            .iter()
            .copied()
            .chain(["override"])
            .zip(self.over_budget)
            .map(|(cause, count)| format!("unchanged_reread_over_budget{{{cause}}}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{counts} reread_mode=observe reread_observed={} reread_tracking_dropped{{attempts}}={} reread_tracking_dropped{{physical}}={} reread_tracking_dropped{{growth}}={} reread_planned={} reread_indexed={} reread_tripwire_would_fire={} growth_full={}",
            self.observed_reads, self.tracking_dropped, self.physical_tracking_dropped, self.growth_tracking_dropped, self.tripwire.planned, self.tripwire.indexed,
            self.tripwire.plan_held || self.tripwire.full_reads > threshold(self.tripwire.indexed),
            self.growth_full.values().map(|v| u64::from(v[1])).sum::<u64>()
        )
    }

    #[cfg(test)]
    fn ticket(&self, key: &str) -> Option<Ticket> {
        let r = self.reservations.get(&KeyHash::of(key))?;
        (r.claimed && (r.saved || !self.require_save)).then_some(Ticket {
            durable: true,
            replay: r.replay,
            wall: r.wall,
            born: r.born,
        })
    }
    pub(super) fn note_growth_full(&mut self, key: &str) {
        let Some(hour) = hour(now()) else {
            return;
        };
        if !self.growth_full.contains_key(&KeyHash::of(key))
            && self.growth_full.len() >= MAX_TRACKED_KEYS
        {
            self.growth_tracking_dropped = self.growth_tracking_dropped.saturating_add(1);
            return;
        }
        let record = self
            .growth_full
            .entry(KeyHash::of(key))
            .or_insert([hour, 0]);
        if hour.saturating_sub(record[0]) >= 24 {
            *record = [hour, 0];
        }
        record[1] = record[1].saturating_add(1);
        if record[1] == 25 {
            eprintln!("REREAD_GROWTH_FULL count=25 window_hours=24");
        }
    }
}
impl Tripwire {
    fn alarm(&mut self, now: u64) {
        if self.last_alarm == 0 || now.saturating_sub(self.last_alarm) >= ALARM_INTERVAL {
            let counts = if self.plan_held {
                &self.cause_counts
            } else {
                &self.runtime_cause_counts
            };
            let cause_counts = CANDIDATE_PARSE_REASON_NAMES
                .iter()
                .copied()
                .chain(["override"])
                .zip(counts)
                .filter(|(_, count)| **count > 0)
                .map(|(name, count)| format!("{name}:{count}"))
                .collect::<Vec<_>>()
                .join(",");
            eprintln!(
                "REREAD_TRIPWIRE mode=observe cause_counts={{{cause_counts}}} planned={} indexed={} admitted={}",
                self.planned, self.indexed, self.full_reads
            );
            self.last_alarm = now;
        }
    }
}

impl ScanIndex {
    /// No caller may turn a Refuse into proof, settlement or a restored fingerprint.
    pub(super) fn admit_unchanged_reread(
        &mut self,
        key: &str,
        reason: Option<CandidateParseReason>,
        now: u64,
    ) -> Admission {
        let revision = approved_revision(self);
        let admission = self
            .reread_guard
            .admit(key, reason, now, monotonic_millis(), revision);
        if let Some(traversal) = self.traversal.as_mut() {
            traversal.counts.unchanged_reread_admitted = self.reread_guard.tripwire.full_reads;
        }
        if matches!(admission, Admission::Refuse) {
            self.note_reread_refusal(reason);
        }
        admission
    }
    pub(super) fn note_reread_refusal(&mut self, reason: Option<CandidateParseReason>) {
        if !REREAD_GUARD_ENFORCE {
            return;
        }
        self.reread_guard.over_budget[cause(reason)] =
            self.reread_guard.over_budget[cause(reason)].saturating_add(1);
        if let Some(traversal) = self.traversal.as_mut() {
            traversal.counts.reread_budget_refused =
                traversal.counts.reread_budget_refused.saturating_add(1);
        }
        self.mark_bounded_sweep_unsettled();
    }
    /// Independent metadata obligations only. Stale pending is not itself
    /// a read: the traversal composes its actual funded re-arm set below.
    pub(super) fn reread_revision_changed(&self, source: SnapshotSource) -> bool {
        !self.reread_guard.source_revision.is_empty()
            && self.reread_guard.source_revision != source.scan_identity_version()
    }

    pub(super) fn reread_plan(
        &mut self,
        source: SnapshotSource,
        collected_at: &str,
        context: &str,
    ) -> bool {
        let version_changed = self.reread_revision_changed(source);
        self.reread_plan_inner(source, collected_at, context, None, version_changed)
    }

    /// Refresh even a same-window preliminary plan, before clearing entries.
    /// The predicate names only keys the caller will actually re-arm. Keep
    /// runtime observations already recorded on that traversal intact.
    pub(super) fn reread_plan_for_rearms(
        &mut self,
        source: SnapshotSource,
        collected_at: &str,
        context: &str,
        version_changed: bool,
        will_rearm: impl Fn(&str) -> bool,
    ) -> bool {
        self.reread_plan_inner(
            source,
            collected_at,
            context,
            Some(&will_rearm),
            version_changed,
        )
    }

    fn reread_plan_inner(
        &mut self,
        source: SnapshotSource,
        collected_at: &str,
        context: &str,
        will_rearm: Option<&dyn Fn(&str) -> bool>,
        version_changed: bool,
    ) -> bool {
        #[cfg(test)]
        if !TEST_OBSERVATIONS.with(std::cell::Cell::get) {
            return false;
        }
        if !matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex) {
            return false;
        }
        let id = sha256_hex(&[context, collected_at]);
        let same_traversal = self.reread_guard.tripwire.traversal == id;
        if same_traversal && will_rearm.is_none() {
            return REREAD_GUARD_ENFORCE && self.reread_guard.tripwire.plan_held;
        }
        self.reread_guard.source_revision = source.scan_identity_version().to_owned();
        let mut detached_keys: BTreeSet<_> =
            self.reread_guard.replay_witnesses.keys().copied().collect();
        for key in self.files.keys() {
            detached_keys.remove(&KeyHash::of(key));
        }
        let detached = detached_keys.len() as u64;
        drop(detached_keys);
        let mut tripwire = Tripwire {
            traversal: id,
            indexed: self.files.len() as u64 + detached,
            last_alarm: self.reread_guard.tripwire.last_alarm,
            full_reads: if same_traversal {
                self.reread_guard.tripwire.full_reads
            } else {
                0
            },
            runtime_cause_counts: if same_traversal {
                self.reread_guard.tripwire.runtime_cause_counts
            } else {
                [0; CAUSES]
            },
            ..Tripwire::default()
        };
        for (key, entry) in &self.files {
            let reason =
                if self.upload_context_fingerprint != self.active_upload_context_fingerprint {
                    Some(CandidateParseReason::UploadContext)
                } else if entry.source_file_fingerprint.is_empty()
                    || will_rearm.is_some_and(|contains| contains(key))
                {
                    Some(CandidateParseReason::Rearmed)
                } else if self.effective_upload_body_witness_revision_requires_adoption(key) {
                    Some(CandidateParseReason::BodyWitnessAdoption)
                } else if version_changed {
                    Some(CandidateParseReason::SourceChanged)
                } else if entry.scan_identity_version.as_deref()
                    != Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION)
                {
                    Some(CandidateParseReason::LegacyIdentity)
                } else {
                    None
                };
            if let Some(reason) = reason {
                tripwire.planned += 1;
                tripwire.cause_counts[cause(Some(reason))] += 1;
            }
        }
        let replay_debt = detached;
        tripwire.planned = tripwire.planned.saturating_add(replay_debt);
        tripwire.cause_counts[cause(Some(CandidateParseReason::Rearmed))] += replay_debt;
        let approved = approved_revision(self);
        let approved_remaining = approved.is_some_and(|revision| {
            self.reread_guard
                .replayed
                .get(revision)
                .map_or(true, |keys| (keys.len() as u64) < tripwire.indexed)
        });
        tripwire.plan_held = tripwire.planned > threshold(tripwire.indexed) && !approved_remaining;
        if tripwire.plan_held {
            tripwire.alarm(now());
        }
        let held = tripwire.plan_held;
        self.reread_guard.tripwire = tripwire;
        REREAD_GUARD_ENFORCE && held
    }
}

impl OwnedSourceScan {
    pub(crate) fn with_reread_persistence(mut self) -> Self {
        self.index.reread_guard.require_save = REREAD_GUARD_ENFORCE;
        self
    }
    /// Only the negative scheduling evidence is published. Never save working
    /// file bodies, ACKs, traversal progress or family authority before upload.
    pub(crate) fn persist_reread_reservations(
        &mut self,
        committed: &mut ScanIndex,
        path: &Path,
    ) -> Result<()> {
        if !self.index.reread_guard.needs_save() {
            return Ok(());
        }
        let previous =
            std::mem::replace(&mut committed.reread_guard, self.index.reread_guard.clone());
        if let Err(error) = committed.save(path) {
            committed.reread_guard = previous;
            return Err(error);
        }
        self.index.generation = committed.generation;
        self.index.reread_guard.saved();
        committed.reread_guard.saved();
        Ok(())
    }
}

impl OwnedJsonlParser {
    pub(super) fn bind_reread(&mut self, index: &ScanIndex, candidate: &CandidateFile) {
        self.reread_required = matches!(
            self.source,
            SnapshotSource::ClaudeCode | SnapshotSource::Codex
        ) && index.reread_unchanged_candidate(candidate);
        // Tickets are supplied by the current selection, never recovered
        // from an earlier read's already-claimed reservation.
        self.reread_ticket = None;
    }
    pub(super) fn assert_reread_ticket(&self) {
        #[cfg(test)]
        if self.reader.acquisition.as_ref().map_or(true, |plan| {
            matches!(
                plan.mode(),
                crate::transcript_acquisition::ReadMode::Full(_)
            )
        }) {
            assert!(
                !self.reread_required || self.reread_ticket.is_some_and(Ticket::valid),
                "byte-unchanged indexed Full read requires an Admit ticket"
            );
        }
    }
}

impl Ticket {
    fn valid(self) -> bool {
        let now = now();
        !REREAD_GUARD_ENFORCE
            || (self.durable
                && now >= self.wall
                && now - self.wall <= GRANT_LIFETIME
                && elapsed_valid(self.born, monotonic_millis()))
    }
}

impl OwnedJsonlParser {
    pub(super) fn reread_read_allowed(&self) -> bool {
        !REREAD_GUARD_ENFORCE
            || !self.reread_required
            || self.reader.acquisition.as_ref().is_some_and(|plan| {
                !matches!(
                    plan.mode(),
                    crate::transcript_acquisition::ReadMode::Full(_)
                )
            })
            || self.reread_ticket.is_some_and(Ticket::valid)
    }
}

impl<'de> Deserialize<'de> for State {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Default, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        struct Stored {
            replay_witnesses: BTreeMap<KeyHash, PhysicalWitness>,
            #[serde(alias = "refused")]
            over_budget: [u64; CAUSES],
            observed_reads: u64,
            tracking_dropped: u64,
            physical_tracking_dropped: u64,
            growth_tracking_dropped: u64,
            growth_full: StampMap,
            source_revision: String,
            attempts: StampMap,
            wall_high_water: u64,
            replayed: BTreeMap<String, BTreeSet<KeyHash>>,
            tripwire: Tripwire,
            last_budget_alarm: u64,
            closed: bool,
        }
        let raw = Box::<serde_json::value::RawValue>::deserialize(d)?;
        let stored = match serde_json::from_str::<Stored>(raw.get()) {
            Ok(stored) => stored,
            Err(_) => {
                return Ok(Self {
                    closed: true,
                    ..Self::default()
                })
            }
        };
        Ok(Self {
            replay_witnesses: stored.replay_witnesses,
            over_budget: stored.over_budget,
            observed_reads: stored.observed_reads,
            tracking_dropped: stored.tracking_dropped,
            physical_tracking_dropped: stored.physical_tracking_dropped,
            growth_tracking_dropped: stored.growth_tracking_dropped,
            growth_full: stored.growth_full,
            source_revision: stored.source_revision,
            attempts: stored.attempts,
            wall_high_water: stored.wall_high_water,
            replayed: stored.replayed,
            tripwire: stored.tripwire,
            last_budget_alarm: stored.last_budget_alarm,
            closed: stored.closed,
            ..Self::default()
        })
    }
}

#[cfg(test)]
pub(crate) struct TestClock(Option<u64>);
#[cfg(test)]
impl TestClock {
    pub(crate) fn freeze() -> Self {
        Self::at(now())
    }
    pub(crate) fn at(wall: u64) -> Self {
        Self(TEST_CLOCK.with(|clock| clock.replace(Some(wall))))
    }
    pub(crate) fn set(&self, wall: u64) {
        set_now_for_test(wall);
    }
}
#[cfg(test)]
impl Drop for TestClock {
    fn drop(&mut self) {
        TEST_CLOCK.with(|clock| clock.set(self.0));
    }
}
pub(super) fn load_now(observed: SystemTime) -> u64 {
    #[cfg(test)]
    if TEST_CLOCK.with(|clock| clock.get().is_some()) {
        return now();
    }
    unix_seconds(observed).unwrap_or(0)
}

#[cfg(test)]
pub(crate) fn clear_cache_for_test(cache: &sampled_scan::SharedCache) {
    cache.clear();
}
#[cfg(test)]
#[path = "reread_guard_tests.rs"]
mod tests;

impl ScanIndex {
    pub(super) fn reserve_reread_batch(
        &mut self,
        candidates: &VecDeque<CandidateFile>,
        forced_families: &BTreeSet<String>,
    ) {
        for candidate in candidates {
            let key = local_index_key(&candidate.path);
            if self
                .reread_guard
                .reservations
                .get(&KeyHash::of(&key))
                .is_some_and(|r| !r.claimed)
                || !self.reread_unchanged_candidate(candidate)
            {
                continue;
            }
            let (decision, reason) = self.candidate_decision_with_reason(candidate);
            let forced = claude_index_path_family_member(&candidate.path)
                .is_some_and(|(root, _)| forced_families.contains(&root));
            if forced
                || matches!(
                    decision,
                    CandidateDecision::Parse | CandidateDecision::ReconcileLegacy
                )
            {
                // Failed speculative reservations remain unselected; their
                // eventual common selection records any disclosed refusal.
                let reason = if forced {
                    Some(CandidateParseReason::ForcedFamily)
                } else {
                    reason
                };
                let revision = approved_revision(self);
                let _ = self
                    .reread_guard
                    .admit(&key, reason, now(), monotonic_millis(), revision);
            }
        }
    }
}

fn approved_revision(index: &ScanIndex) -> Option<&'static str> {
    REPLAY_GRANTS
        .iter()
        .find(|grant| {
            grant.revision == index.reread_guard.source_revision
                || index.historical_replay_generation.as_deref() == Some(grant.revision)
                || [SnapshotSource::ClaudeCode, SnapshotSource::Codex]
                    .iter()
                    .any(|source| {
                        let replay = crate::backfill::current_historical_replay(*source);
                        grant.revision == replay.revision
                            && index.historical_replay_generation.as_ref().is_some_and(
                                |generation| {
                                    generation.starts_with(&format!(
                                        "{}:{}:",
                                        source.api_slug(),
                                        replay.revision
                                    ))
                                },
                            )
                    })
        })
        .map(|grant| grant.revision)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PhysicalWitness {
    #[serde(default = "unknown_removal_hour")]
    removed_hour: u32,
    size: u64,
    mtime_ns: Option<u64>,
    mtime_seconds: u64,
    object: Option<[u64; 2]>,
}
impl crate::heap_layout_bound::HeapLayoutBound for PhysicalWitness {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, _: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // Exhaustive, typed destructuring makes any future owned field require
        // an explicit accounting change. All storage is in the charged node.
        let Self {
            removed_hour,
            size,
            mtime_ns,
            mtime_seconds,
            object,
        } = self;
        let _: (&u32, &u64, &Option<u64>, &u64, &Option<[u64; 2]>) =
            (removed_hour, size, mtime_ns, mtime_seconds, object);
        Some(())
    }
}
impl State {
    pub(super) fn is_empty(&self) -> bool {
        self.replay_witnesses.is_empty()
            && self.attempts.is_empty()
            && self.observed_reads == 0
            && self.tracking_dropped == 0
            && self.physical_tracking_dropped == 0
            && self.growth_tracking_dropped == 0
            && self.growth_full.is_empty()
            && self.source_revision.is_empty()
            && self.replayed.is_empty()
            && self.tripwire.traversal.is_empty()
            && self.wall_high_water == 0
            && !self.closed
            && self.over_budget.iter().all(|n| *n == 0)
    }
}
impl ScanIndex {
    pub(super) fn reread_unchanged_candidate(&self, candidate: &CandidateFile) -> bool {
        let key = local_index_key(&candidate.path);
        if let Some(entry) = self.files.get(&key) {
            return byte_unchanged(entry, candidate)
                && self
                    .reread_guard
                    .replay_witnesses
                    .get(&KeyHash::of(&key))
                    .and_then(|w| w.object)
                    .zip(candidate.physical_identity)
                    .map_or(true, |(old, new)| old == new);
        }
        self.reread_guard
            .replay_witnesses
            .get(&KeyHash::of(&key))
            .is_some_and(|w| {
                w.size == candidate.size_bytes
                    && w.mtime_ns.map_or_else(
                        || w.mtime_seconds == candidate.modified_unix_seconds,
                        |mtime| mtime == candidate.modified_unix_nanos,
                    )
                    && w.object
                        .zip(candidate.physical_identity)
                        .map_or(true, |(old, new)| old == new)
            })
    }
    pub(super) fn remember_replay_read_witnesses(&mut self) {
        for (key, entry) in &self.files {
            if entry.retain_history_evidence() {
                continue;
            }
            self.reread_guard.remember_entry(key, entry);
        }
    }
    pub(super) fn record_read_witness(&mut self, key: &str, candidate: &CandidateFile) {
        let id = KeyHash::of(key);
        if !self.reread_guard.replay_witnesses.contains_key(&id)
            && self.reread_guard.replay_witnesses.len() >= MAX_TRACKED_KEYS
        {
            self.reread_guard.physical_tracking_dropped = self
                .reread_guard
                .physical_tracking_dropped
                .saturating_add(1);
            return;
        }
        self.reread_guard.replay_witnesses.insert(
            id,
            PhysicalWitness {
                removed_hour: hour(now()).unwrap_or(u32::MAX),
                size: candidate.size_bytes,
                mtime_ns: Some(candidate.modified_unix_nanos),
                mtime_seconds: candidate.modified_unix_seconds,
                object: candidate.physical_identity,
            },
        );
    }
}

#[cfg(test)]
impl State {
    pub(super) fn require_test_memory_tickets(&mut self) {
        self.require_save = false;
    }
}

fn unknown_removal_hour() -> u32 {
    u32::MAX
}
impl State {
    fn remember_entry(&mut self, key: &str, entry: &ScanIndexEntry) {
        if !self.replay_witnesses.contains_key(&KeyHash::of(key))
            && self.replay_witnesses.len() >= MAX_TRACKED_KEYS
        {
            self.physical_tracking_dropped = self.physical_tracking_dropped.saturating_add(1);
            return;
        }
        self.replay_witnesses.insert(
            KeyHash::of(key),
            PhysicalWitness {
                removed_hour: hour(now()).unwrap_or(u32::MAX),
                size: entry.size_bytes,
                mtime_ns: entry.modified_unix_nanos,
                mtime_seconds: entry.modified_unix_seconds,
                object: self
                    .replay_witnesses
                    .get(&KeyHash::of(key))
                    .and_then(|w| w.object),
            },
        );
    }
}
impl ScanIndex {
    pub(super) fn remember_removed_read_witness(&mut self, key: &str) {
        if let Some(entry) = self.files.get(key) {
            self.reread_guard.remember_entry(key, entry);
        }
    }
    pub(super) fn reread_state_for_subset(
        &self,
        retained: &BTreeMap<String, ScanIndexEntry>,
    ) -> State {
        let mut state = self.reread_guard.clone();
        for (key, entry) in &self.files {
            if !retained.contains_key(key) {
                state.remember_entry(key, entry);
            }
        }
        state
    }
}

/// Identity-only PS reads are main Skip selections, outside main accounting.
pub(super) fn observation_ticket() -> Ticket {
    Ticket {
        durable: true,
        replay: false,
        wall: now(),
        born: monotonic_millis(),
    }
}

#[cfg(test)]
pub(crate) fn observe_plan_for_test(index: &mut ScanIndex, collected_at: &str) -> (bool, u64, u64) {
    let held = index.reread_plan(
        SnapshotSource::ClaudeCode,
        collected_at,
        "whole-history-observe",
    );
    (
        held,
        index.reread_guard.tripwire.planned,
        index.reread_guard.tripwire.last_alarm,
    )
}

#[cfg(test)]
pub(crate) fn planned_for_test(index: &ScanIndex) -> u64 {
    index.reread_guard.tripwire.planned
}

// Counterfactual control for the NEW observe-parity test only. This switches
// instrumentation, never a read allowance or the compiled enforcement mode.
#[cfg(test)]
thread_local! { static TEST_OBSERVATIONS: std::cell::Cell<bool> = const { std::cell::Cell::new(true) }; }
#[cfg(test)]
pub(crate) struct TestObservations(bool);
#[cfg(test)]
impl TestObservations {
    pub(crate) fn enabled(enabled: bool) -> Self {
        Self(TEST_OBSERVATIONS.with(|cell| cell.replace(enabled)))
    }
}
#[cfg(test)]
impl Drop for TestObservations {
    fn drop(&mut self) {
        TEST_OBSERVATIONS.with(|cell| cell.set(self.0));
    }
}
