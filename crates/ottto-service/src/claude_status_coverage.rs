//! Local status-coverage history for the `transcript_email` basis (plan §2a.9).
//!
//! The Claude status pass already qualifies each registered slot's login and
//! organization hashes. It reports those values here, or reports that it could
//! not. This module keeps a bounded history of *segments*: runs of consecutive
//! qualified observations of one (login, org) in one registered folder, no two
//! more than two cadences apart. A request may use its session's recorded
//! email only when one segment covers [session start − 300 s, request].
//!
//! Nothing here reads a file, calls a provider, changes cadence or reaches the
//! wire. The status pass never sees a result: a failure here (including a
//! poisoned lock) only makes coverage unavailable.
//!
//! The history is process-local on purpose. A restart or uninstall clears it,
//! so coverage never spans an unobserved restart, and no persisted status
//! state or local status output changes.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Status refresh cadence (`agent_status_refresh::INTERVAL`).
pub(crate) const CADENCE_SECONDS: u64 = 300;
/// Largest gap between consecutive observations inside one segment.
pub(crate) const MAX_GAP_SECONDS: u64 = 2 * CADENCE_SECONDS;
/// Coverage must begin this long before the session starts.
pub(crate) const SESSION_LEAD_SECONDS: u64 = 300;
/// Age cap: the longest session the basis may attribute.
pub(crate) const MAX_AGE_SECONDS: u64 = 30 * 24 * 60 * 60;
/// One history per registered slot; the default folder is never observed.
pub(crate) const MAX_SLOTS: usize = ottto_core::MAX_CLAUDE_ACCOUNT_SLOTS;
pub(crate) const MAX_SEGMENTS_PER_SLOT: usize = 32;
/// Hard cap on retained bytes, as counted by `Ledger::retained_bytes`.
/// Worst case under the entry caps: 10 slots × (32 B key + 80 B history +
/// 32 segments × (64 B inline + 128 B hashes)) = 62,560 B.
pub(crate) const MAX_BYTES: usize = 64 * 1024;

/// Opaque registered-folder key: SHA-256 over the normalized config dir.
pub(crate) type HomeKey = [u8; 32];

/// What one status pass established for one registered slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Observation<'a> {
    /// The login and organization hashes the pass qualified.
    Qualified { login: &'a str, org: &'a str },
    /// Failed, missing, contradictory or suppressed: ends coverage.
    Unavailable,
    /// The slot is signed out: its history is cleared.
    SignedOut,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Segment {
    login: String,
    org: String,
    start: u64,
    end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SlotHistory {
    /// Digest of the registration's opaque slot id: a replacement registration
    /// of the same folder starts over.
    slot: [u8; 32],
    segments: Vec<Segment>,
    /// The last segment may still be extended.
    open: bool,
    last_at: Option<u64>,
}

/// Bounded local history. Never serialized and never uploaded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ledger {
    slots: BTreeMap<HomeKey, SlotHistory>,
}

static LEDGER: Mutex<Ledger> = Mutex::new(Ledger {
    slots: BTreeMap::new(),
});

/// The basis is compiled out with contract-5 emission.
pub(crate) const fn enabled() -> bool {
    crate::snapshots::claude_request_identity::transcript_email_enabled()
}

pub(crate) fn home_key(config_dir: &Path) -> HomeKey {
    let normalized = config_dir.components().collect::<PathBuf>();
    let mut digest = Sha256::new();
    digest.update(b"claude_status_coverage:home:v1\0");
    digest.update(normalized.to_string_lossy().as_bytes());
    digest.finalize().into()
}

/// Key of the config dir holding a Claude transcript
/// (`<config dir>/projects/<project>/...`): the nearest `projects` ancestor's
/// parent. Only a registered slot's key can ever match a history.
pub(crate) fn transcript_home_key(transcript: &Path) -> Option<HomeKey> {
    transcript
        .ancestors()
        .skip(1)
        .find(|ancestor| ancestor.file_name().is_some_and(|name| name == "projects"))
        .and_then(Path::parent)
        .map(home_key)
}

fn slot_digest(slot_id: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"claude_status_coverage:slot:v1\0");
    digest.update(slot_id.as_bytes());
    digest.finalize().into()
}

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Producer hook for the status pass. `config_dir` is the registered slot's
/// folder; `default_dir` is the shared default folder, which never gains
/// coverage. Returns nothing: the status pass cannot depend on the feed.
pub(crate) fn observe(
    slot_id: &str,
    config_dir: Option<&str>,
    default_dir: &Path,
    captured_at: &str,
    observation: Observation<'_>,
) {
    if !enabled() {
        return;
    }
    let Some(config_dir) = config_dir else {
        return;
    };
    let key = home_key(Path::new(config_dir));
    if key == home_key(default_dir) {
        return;
    }
    let at = OffsetDateTime::parse(captured_at, &Rfc3339)
        .ok()
        .and_then(|at| u64::try_from(at.unix_timestamp()).ok());
    // A poisoned ledger stays unavailable for this process.
    if let Ok(mut ledger) = LEDGER.lock() {
        ledger.observe_at(key, slot_digest(slot_id), at, observation);
    }
}

/// Drops the history of every folder no longer registered.
pub(crate) fn retain_registered<'a>(config_dirs: impl Iterator<Item = &'a str>) {
    if !enabled() {
        return;
    }
    let keys = config_dirs
        .map(|dir| home_key(Path::new(dir)))
        .collect::<BTreeSet<_>>();
    if let Ok(mut ledger) = LEDGER.lock() {
        ledger.slots.retain(|key, _| keys.contains(key));
    }
}

/// The consumer's copy for one scan; `None` when the feed is unavailable.
pub(crate) fn snapshot() -> Option<Ledger> {
    if !enabled() {
        return None;
    }
    LEDGER.lock().ok().map(|ledger| ledger.clone())
}

#[cfg(test)]
pub(crate) fn with_global<T>(f: impl FnOnce(&mut Ledger) -> T) -> T {
    f(&mut LEDGER
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner))
}

#[cfg(test)]
pub(crate) fn poison_global_for_test() {
    let _ = std::thread::spawn(|| {
        let _guard = LEDGER.lock();
        panic!("poison the status-coverage ledger");
    })
    .join();
}

#[cfg(test)]
pub(crate) fn clear_global_for_test() {
    LEDGER.clear_poison();
    with_global(|ledger| ledger.slots.clear());
}

impl Ledger {
    pub(crate) fn observe_at(
        &mut self,
        key: HomeKey,
        slot: [u8; 32],
        at: Option<u64>,
        observation: Observation<'_>,
    ) {
        if self
            .slots
            .get(&key)
            .is_some_and(|history| history.slot != slot)
        {
            // Slot replacement: the old registration's coverage is not this one's.
            self.slots.remove(&key);
        }
        if !self.slots.contains_key(&key) {
            if self.slots.len() == MAX_SLOTS
                || !matches!(observation, Observation::Qualified { .. })
            {
                return;
            }
            self.slots.insert(
                key,
                SlotHistory {
                    slot,
                    // Fixed capacity: eviction precedes every push, so the
                    // vector never grows past the entry cap.
                    segments: Vec::with_capacity(MAX_SEGMENTS_PER_SLOT),
                    open: false,
                    last_at: None,
                },
            );
        }
        let history = self.slots.get_mut(&key).expect("history inserted above");
        let Some(at) = at else {
            history.open = false;
            return;
        };
        if history.last_at.is_some_and(|last| at < last) {
            // Clock regression: nothing recorded on the old clock is trusted.
            history.segments.clear();
            history.open = false;
        }
        history.last_at = Some(at);
        match observation {
            Observation::Qualified { login, org } if is_hash(login) && is_hash(org) => {
                match history.segments.last_mut() {
                    Some(last)
                        if history.open
                            && last.login == login
                            && last.org == org
                            && at - last.end <= MAX_GAP_SECONDS =>
                    {
                        last.end = at;
                    }
                    _ => {
                        if history.segments.len() == MAX_SEGMENTS_PER_SLOT {
                            history.segments.remove(0);
                        }
                        history.segments.push(Segment {
                            login: login.to_string(),
                            org: org.to_string(),
                            start: at,
                            end: at,
                        });
                        history.open = true;
                    }
                }
            }
            Observation::Qualified { .. } | Observation::Unavailable => history.open = false,
            Observation::SignedOut => {
                history.segments.clear();
                history.open = false;
            }
        }
        self.prune(at);
    }

    /// Age, entry and byte caps. Eviction only removes coverage.
    fn prune(&mut self, now: u64) {
        let cutoff = now.saturating_sub(MAX_AGE_SECONDS);
        for history in self.slots.values_mut() {
            history.segments.retain(|segment| segment.end >= cutoff);
            for segment in &mut history.segments {
                segment.start = segment.start.max(cutoff);
            }
            let excess = history.segments.len().saturating_sub(MAX_SEGMENTS_PER_SLOT);
            history.segments.drain(..excess);
        }
        while self.retained_bytes() > MAX_BYTES {
            let oldest = self
                .slots
                .iter()
                .filter_map(|(key, history)| Some((history.segments.first()?.end, *key)))
                .min();
            let Some((_, key)) = oldest else { break };
            let history = self.slots.get_mut(&key).expect("oldest slot exists");
            history.segments.remove(0);
            history.open &= !history.segments.is_empty();
        }
    }

    pub(crate) fn retained_bytes(&self) -> usize {
        self.slots
            .values()
            .map(|history| {
                std::mem::size_of::<HomeKey>()
                    + std::mem::size_of::<SlotHistory>()
                    + history.segments.capacity() * std::mem::size_of::<Segment>()
                    + history
                        .segments
                        .iter()
                        .map(|segment| segment.login.capacity() + segment.org.capacity())
                        .sum::<usize>()
            })
            .sum()
    }

    /// The (login, org) of the one segment covering `[from, to]` in `home`.
    pub(crate) fn covering(&self, home: &HomeKey, from: u64, to: u64) -> Option<(&str, &str)> {
        if from > to {
            return None;
        }
        self.slots
            .get(home)?
            .segments
            .iter()
            .find(|segment| segment.start <= from && segment.end >= to)
            .map(|segment| (segment.login.as_str(), segment.org.as_str()))
    }

    /// Every retained (login, org) pairing the status pass qualified: the
    /// `.claude.json` org-membership evidence of plan §2a.12(b).
    pub(crate) fn pairings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.slots.values().flat_map(|history| {
            history
                .segments
                .iter()
                .map(|segment| (segment.login.as_str(), segment.org.as_str()))
        })
    }
}

#[cfg(test)]
#[path = "claude_status_coverage_tests.rs"]
mod tests;
