//! Read-selection budget. Negative scheduling evidence only: never ACKs,
//! ownership, acceptance or permission to rebuild money history.
use super::*;
use serde::{Deserializer, Serializer};

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
}
crate::heap_layout_bound::fields!(Reservation; wall, born, saved, claimed, replay);

#[derive(Debug, Clone, Default, Serialize)]
pub(super) struct State {
    refused: [u64; CAUSES],
    growth_full: BTreeMap<KeyHash, [u32; 2]>,
    source_revision: String,
    // Sparse: no entry until a selected unchanged file spends an attempt.
    attempts: BTreeMap<KeyHash, [u32; 2]>,
    wall_high_water: u64,
    replayed: BTreeMap<String, BTreeSet<KeyHash>>,
    tripwire: Tripwire,
    last_budget_alarm: u64,
    /// A malformed budget refuses reads instead of losing negative evidence.
    closed: bool,
    #[serde(skip)]
    reservations: BTreeMap<KeyHash, Reservation>,
    #[serde(skip)]
    require_save: bool,
}
crate::heap_layout_bound::fields!(State; refused, growth_full, source_revision, attempts, wall_high_water, replayed, tripwire, last_budget_alarm, closed, reservations, require_save);

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
        // A legacy entry cannot prove replacement: conservatively budget it.
        && entry.physical_identity.zip(candidate.physical_identity)
            .map_or(true, |(old, new)| old == new)
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
            }
        }
        self.wall_high_water = self.wall_high_water.max(now);
        self.replayed
            .retain(|revision, _| REPLAY_GRANTS.iter().any(|g| g.revision == revision));
        if let Some(now_hour) = hour(now) {
            self.growth_full
                .retain(|_, record| now_hour.saturating_sub(record[0]) < 24);
        }
        self.reservations.clear(); // Restart never reuses an unconsumed ticket.
    }
    pub(super) fn observe_clock(&mut self) {
        self.wall_high_water = self.wall_high_water.max(now());
    }
    pub(super) fn needs_save(&self) -> bool {
        self.reservations.values().any(|r| !r.saved)
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
            let Some(slot) = slots.iter_mut().find(|slot| **slot == 0) else {
                if self.last_budget_alarm == 0
                    || now.saturating_sub(self.last_budget_alarm) >= ALARM_INTERVAL
                {
                    eprintln!("REREAD_BUDGET_EXHAUSTED cause={}", cause(reason));
                    self.last_budget_alarm = now;
                }
                return Admission::Refuse;
            };
            *slot = now_hour;
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
        self.reservations.insert(
            id,
            Reservation {
                wall: now,
                born: elapsed,
                saved: durable,
                claimed: durable,
                replay,
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
            .zip(self.refused)
            .map(|(cause, count)| format!("unchanged_reread_refused{{{cause}}}={count}"))
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{counts} reread_status={} growth_full={}",
            if self.refused.iter().any(|n| *n > 0) || self.tripwire.plan_held {
                "\"withheld: reread budget\""
            } else {
                "clear"
            },
            self.growth_full
                .values()
                .map(|v| u64::from(v[1]))
                .sum::<u64>()
        )
    }
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
                "REREAD_TRIPWIRE cause_counts={{{cause_counts}}} planned={} indexed={} admitted={}",
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
        let revision = self
            .historical_replay_generation
            .as_deref()
            .filter(|revision| REPLAY_GRANTS.iter().any(|g| g.revision == *revision))
            .or(Some(self.reread_guard.source_revision.as_str()));
        let revision = revision.map(str::to_owned);
        let admission =
            self.reread_guard
                .admit(key, reason, now, monotonic_millis(), revision.as_deref());
        if let Some(traversal) = self.traversal.as_mut() {
            traversal.counts.unchanged_reread_admitted = self.reread_guard.tripwire.full_reads;
        }
        if matches!(admission, Admission::Refuse) {
            self.note_reread_refusal(reason);
        }
        admission
    }
    pub(super) fn note_reread_refusal(&mut self, reason: Option<CandidateParseReason>) {
        self.reread_guard.refused[cause(reason)] =
            self.reread_guard.refused[cause(reason)].saturating_add(1);
        if let Some(traversal) = self.traversal.as_mut() {
            traversal.counts.reread_budget_refused =
                traversal.counts.reread_budget_refused.saturating_add(1);
        }
        self.mark_bounded_sweep_unsettled();
    }
    /// A conservative metadata-only plan. No transcript or private log reads.
    pub(super) fn reread_plan(
        &mut self,
        source: SnapshotSource,
        collected_at: &str,
        context: &str,
    ) -> bool {
        if !matches!(source, SnapshotSource::ClaudeCode | SnapshotSource::Codex) {
            return false;
        }
        let id = sha256_hex(&[context, collected_at]);
        if self.reread_guard.tripwire.traversal == id {
            return self.reread_guard.tripwire.plan_held;
        }
        self.reread_guard.refused = [0; CAUSES];
        let version_changed = self.reread_guard.source_revision != source.scan_identity_version();
        self.reread_guard.source_revision = source.scan_identity_version().to_owned();
        let mut tripwire = Tripwire {
            traversal: id,
            indexed: self.files.len() as u64,
            last_alarm: self.reread_guard.tripwire.last_alarm,
            ..Tripwire::default()
        };
        for (key, entry) in &self.files {
            let stale = source == SnapshotSource::ClaudeCode
                && claude_index_path_member_ref(Path::new(key)).is_some_and(|m| {
                    self.claude_usage_family_pending
                        .get(m.root)
                        .is_some_and(|pending| pending.census_window_end != collected_at)
                });
            let reason =
                if self.upload_context_fingerprint != self.active_upload_context_fingerprint {
                    Some(CandidateParseReason::UploadContext)
                } else if entry.source_file_fingerprint.is_empty() || stale {
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
        let approved = REPLAY_GRANTS.iter().find(|grant| {
            grant.revision == source.scan_identity_version()
                || self.historical_replay_generation.as_deref() == Some(grant.revision)
        });
        let approved_remaining = approved.is_some_and(|grant| {
            self.reread_guard
                .replayed
                .get(grant.revision)
                .map_or(true, |keys| keys.len() < self.files.len())
        });
        tripwire.plan_held = tripwire.planned > threshold(tripwire.indexed) && !approved_remaining;
        if tripwire.plan_held {
            tripwire.alarm(now());
        }
        let held = tripwire.plan_held;
        self.reread_guard.tripwire = tripwire;
        held
    }
}

impl OwnedSourceScan {
    pub(crate) fn with_reread_persistence(mut self) -> Self {
        self.index.reread_guard.require_save = true;
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
        ) && index
            .files
            .get(&local_index_key(&candidate.path))
            .is_some_and(|entry| byte_unchanged(entry, candidate));
        self.reread_ticket = index.reread_guard.ticket(&local_index_key(&candidate.path));
    }
    pub(super) fn assert_reread_ticket(&self) {
        #[cfg(test)]
        if self.reader.acquisition.as_ref().map_or(true, |plan| {
            matches!(
                plan.mode(),
                crate::transcript_acquisition::ReadMode::Full(_)
            )
        }) {
            debug_assert!(
                !self.reread_required || self.reread_ticket.is_some_and(Ticket::valid),
                "byte-unchanged indexed Full read requires an Admit ticket"
            );
        }
    }
}

impl Ticket {
    fn valid(self) -> bool {
        let now = now();
        self.durable
            && now >= self.wall
            && now - self.wall <= GRANT_LIFETIME
            && elapsed_valid(self.born, monotonic_millis())
    }
}

impl OwnedJsonlParser {
    pub(super) fn reread_read_allowed(&self) -> bool {
        !self.reread_required
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
            refused: [u64; CAUSES],
            growth_full: BTreeMap<KeyHash, [u32; 2]>,
            source_revision: String,
            attempts: BTreeMap<KeyHash, [u32; 2]>,
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
            refused: stored.refused,
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
                || !self
                    .files
                    .get(&key)
                    .is_some_and(|entry| byte_unchanged(entry, candidate))
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
                let revision = self.historical_replay_generation.clone();
                let _ = self.reread_guard.admit(
                    &key,
                    reason,
                    now(),
                    monotonic_millis(),
                    revision.as_deref(),
                );
            }
        }
    }
}
