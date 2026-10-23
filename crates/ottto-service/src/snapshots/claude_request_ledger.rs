//! P1 per-request money ledger (shadow only): who owns each Claude request id.
//!
//! The ledger has no resident owner index. Its holders are #664's census
//! records: the scan index's transcript records (keyed by file) and the
//! money ledger's own records (`claude_request_money::store`): telemetry
//! `otel:<sha256 of the root session id>` and message-only `mh:<file key>`.
//! A page sorts its own request hashes once and intersects them with every
//! record's sorted hashes, which is O(total hashes · log page hashes) work
//! per page under the page deadline and no memory kept between pages
//! (design v2 §2.3 planned a SoA owner index; P1 measures the scan first).
//!
//! The classifier is design v2 §3, one verdict per key:
//! - two or more telemetry roots: the root whose telemetry was first seen
//!   earliest (its first event time, then its session id) wins; every other
//!   root's copies are explicit two-owner losers;
//! - one telemetry root R: a copy outside R's family is removed; inside it,
//!   the only holder, else the member R's trace names, else the earliest
//!   first-seen birth, then the member id;
//! - no telemetry root: the earliest first-seen birth, then the member id.
//!
//! Every negative claim ("no other holder", "no telemetry owner", "no
//! transcript in the family") needs explicit completeness (§3.1): the
//! scoped holder group (the project directory, across config roots) has no
//! lost, over-budget, stale or unverified record, the telemetry sweep has
//! read past the unit's clock, and the root's trace is known when two
//! in-family members hold the id. On top of those, "no telemetry owner"
//! needs the census's holder view (`claude_request_money::coverage`), which
//! is incomplete until Fix 3. Unknown debt is `Undecided`, never a guess,
//! and keeps the family's coverage incomplete.
//!
//! Nothing here feeds a live decision: verdicts only shape the shadow body.

use super::claude_request_census::{
    message_key, ClaudeRequestCensus, ClaudeRequestCensusRecord, MAX_CLAUDE_REQUEST_CENSUS_HASHES,
    MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES, MESSAGE_KEY_PREFIX, TELEMETRY_KEY_PREFIX,
};
use super::claude_request_money::store::ClaudeLedger;
use super::{claude_index_path_family_member, ScanIndex};
use serde::Serialize;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};
use std::time::{Instant, UNIX_EPOCH};

/// Holders kept per hash; more makes the id undecided, never a guess.
pub(crate) const MAX_HOLDERS_PER_HASH: usize = 16;

/// Telemetry pressure retirement starts at 90% of the ledger's hash or
/// serialized budget and retires the oldest telemetry records until 80%.
const PRESSURE_START_PERCENT: usize = 90;
const PRESSURE_TARGET_PERCENT: usize = 80;

/// A telemetry row is written shortly after its request; a sweep that started
/// this long after a unit's clock has read the row if one exists.
pub(crate) const TELEMETRY_WRITE_GRACE_SECONDS: u64 = 60;

/// Why a unit is counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeCountedBy {
    /// Only this file holds the id (no telemetry claims it).
    Owned,
    /// The family's telemetry claims the id and this file is its holder.
    TelemetryProven,
    /// Several holders: this one wins by trace, then birth, then member id.
    PolicyOwned,
    /// Two telemetry roots: this family's root won (untagged).
    TwoOwnerWinner,
    /// No id: counted by its own file.
    Idless,
}

/// Why a unit is removed (its usage belongs to another entity).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRemovedBy {
    /// Another file (or another root's telemetry) owns it: a copy.
    Copy,
    /// Two telemetry roots claim it and another root won.
    TwoOwnerLoser,
}

/// Why a unit is undecided (held: neither counted nor removed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ClaudeUndecidedBy {
    /// More holders than the ledger keeps.
    Overflow,
    /// Two different request ids share the 8-byte hash on this page.
    Collision,
    /// The scoped group has a lost, over-budget, stale or unverified record.
    Scope,
    /// A message-only id while a record in its group does not know its
    /// message ids.
    MessageUnknown,
    /// The telemetry sweep has not read past the unit's clock.
    TelemetryUnswept,
    /// Two telemetry roots and one's first event time (or, at a tie, its
    /// session id) is unknown.
    TelemetryOrder,
    /// Several in-family holders and the root's trace was not read.
    TraceUnavailable,
    /// A competing holder's record is not current at its entry.
    StaleHolder,
    /// First-seen births are partly unknown.
    Births,
    /// No telemetry claims it and the census's holder view is not complete
    /// (`coverage::FamilyCoverage`): another holder may be unobserved.
    HolderView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaudeRequestVerdict {
    Counted(ClaudeCountedBy),
    Removed(ClaudeRemovedBy),
    Undecided(ClaudeUndecidedBy),
}

/// The census keys that hold each of a page's hashes.
#[derive(Debug, Default)]
pub(crate) struct ClaudeRequestHolders<'a> {
    transcript: BTreeMap<u64, Vec<&'a str>>,
    /// Message-only (`M`) ids by the ledger's `mh:` records of the current
    /// transcript revisions, as transcript keys.
    message: BTreeMap<u64, Vec<&'a str>>,
    telemetry: BTreeMap<u64, Vec<&'a str>>,
    overflow: BTreeSet<u64>,
    /// Record hashes compared (the scan's work, for diagnostics).
    pub(crate) compared: u64,
}

/// What one holder adds to the holder maps, charged before it is added: a
/// map entry's node share and its vector's growth.
const HOLD_BYTES: usize = 128;

/// Comparisons between two deadline checks inside one record.
const INTERSECT_CHECK_EVERY: u64 = 4096;

/// The hashes present in both sorted lists, probing the shorter list into
/// the longer one. False when `found` refuses or the deadline passes (it is
/// checked every `INTERSECT_CHECK_EVERY` comparisons, so a large record
/// cannot run past it).
fn intersect(
    left: &[u64],
    right: &[u64],
    compared: &mut u64,
    deadline: Instant,
    mut found: impl FnMut(u64) -> bool,
) -> bool {
    let (short, long) = if left.len() <= right.len() {
        (left, right)
    } else {
        (right, left)
    };
    for hash in short {
        *compared += 1;
        if *compared % INTERSECT_CHECK_EVERY == 0 && Instant::now() >= deadline {
            return false;
        }
        if long.binary_search(hash).is_ok() && !found(*hash) {
            return false;
        }
    }
    true
}

/// Add `key` as a holder of `hash`; false when its memory is not admitted.
fn hold<'a>(
    map: &mut BTreeMap<u64, Vec<&'a str>>,
    overflow: &mut BTreeSet<u64>,
    charge: &mut dyn FnMut(usize) -> bool,
    hash: u64,
    key: &'a str,
) -> bool {
    if !charge(HOLD_BYTES) {
        return false;
    }
    let list = map.entry(hash).or_default();
    if list.len() < MAX_HOLDERS_PER_HASH {
        list.push(key);
    } else {
        overflow.insert(hash);
    }
    true
}

/// Intersect the page's sorted unique request and message-only hashes with
/// every transcript record (`index`) and every telemetry and message-only
/// record (`ledger`). A retired record holds no hashes and so is never a
/// holder; birth stubs are no records; a `mh:` record of another revision
/// than its file's record is no holder. Every holder's memory is admitted
/// by `charge` first. None when the deadline passed or memory was refused.
pub(crate) fn scan_holders<'a>(
    index: &'a ClaudeRequestCensus,
    ledger: &'a ClaudeRequestCensus,
    page_hashes: &[u64],
    page_message_hashes: &[u64],
    deadline: Instant,
    charge: &mut dyn FnMut(usize) -> bool,
) -> Option<ClaudeRequestHolders<'a>> {
    let mut holders = ClaudeRequestHolders::default();
    let late = || Instant::now() >= deadline;
    for (key, record) in index.records() {
        let ClaudeRequestHolders {
            transcript,
            overflow,
            compared,
            ..
        } = &mut holders;
        if late()
            || !intersect(
                record.request_hashes(),
                page_hashes,
                compared,
                deadline,
                |hash| hold(transcript, overflow, &mut *charge, hash, key),
            )
        {
            return None;
        }
    }
    for (key, record) in ledger.records_with_prefix(TELEMETRY_KEY_PREFIX) {
        let ClaudeRequestHolders {
            telemetry,
            overflow,
            compared,
            ..
        } = &mut holders;
        if late()
            || !intersect(
                record.request_hashes(),
                page_hashes,
                compared,
                deadline,
                |hash| hold(telemetry, overflow, &mut *charge, hash, key),
            )
        {
            return None;
        }
    }
    if !page_message_hashes.is_empty() {
        for (key, record) in ledger.records_with_prefix(MESSAGE_KEY_PREFIX) {
            if late() {
                return None;
            }
            let file_key = &key[MESSAGE_KEY_PREFIX.len()..];
            if !index
                .get(file_key)
                .is_some_and(|file| file.same_fingerprint(record))
            {
                continue;
            }
            let ClaudeRequestHolders {
                message,
                overflow,
                compared,
                ..
            } = &mut holders;
            if !intersect(
                record.request_hashes(),
                page_message_hashes,
                compared,
                deadline,
                |hash| hold(message, overflow, &mut *charge, hash, file_key),
            ) {
                return None;
            }
        }
    }
    Some(holders)
}

/// The ledger knows the message-only ids of `key`'s current transcript
/// record: its `mh:` record is of the same revision.
pub(crate) fn message_known(
    index: &ClaudeRequestCensus,
    ledger: &ClaudeRequestCensus,
    key: &str,
) -> bool {
    index
        .get(key)
        .zip(ledger.get(&message_key(key)))
        .is_some_and(|(file, messages)| file.same_fingerprint(messages))
}

impl<'a> ClaudeRequestHolders<'a> {
    pub(crate) fn overflowed(&self, hash: u64) -> bool {
        self.overflow.contains(&hash)
    }

    pub(crate) fn transcript_holders(&self, hash: u64) -> &[&'a str] {
        self.transcript.get(&hash).map_or(&[][..], Vec::as_slice)
    }

    pub(crate) fn message_holders(&self, hash: u64) -> &[&'a str] {
        self.message.get(&hash).map_or(&[][..], Vec::as_slice)
    }

    /// `otel:` keys whose telemetry holds the hash.
    pub(crate) fn telemetry_holders(&self, hash: u64) -> &[&'a str] {
        self.telemetry.get(&hash).map_or(&[][..], Vec::as_slice)
    }

    /// A transcript record of family `root` holds the hash.
    pub(crate) fn has_transcript_holder_in(&self, hash: u64, root: &str) -> bool {
        self.transcript_holders(hash).iter().any(|key| {
            claude_index_path_family_member(Path::new(key))
                .is_some_and(|(holder_root, _)| holder_root == root)
        })
    }
}

/// The holder group of a transcript key (§3.1): its project directory name
/// (the encoded cwd), the same across config roots. A subagent file's group
/// is its root file's.
pub(crate) fn claude_project_group(key: &str) -> Option<&str> {
    let path = Path::new(key);
    let mut directories =
        path.parent()?
            .components()
            .rev()
            .filter_map(|component| match component {
                Component::Normal(value) => value.to_str(),
                _ => None,
            });
    let first = directories.next()?;
    if first == "subagents" {
        // `<group>/<root>/subagents/<agent>.jsonl`
        directories.next()?;
        directories.next()
    } else {
        Some(first)
    }
}

/// Why a scoped group or family is not complete (counted per page).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeScopeDebt {
    /// Indexed, built before, and no record (lost or not yet bootstrapped).
    pub(crate) lost: u64,
    pub(crate) over_budget: u64,
    /// The record's fingerprint or derivation is not the entry's.
    pub(crate) stale: u64,
    /// The record is from an unverified (or prefix-certified) parse.
    pub(crate) unverified: u64,
    /// The record does not know its message-only ids.
    pub(crate) message_unknown: u64,
    /// Indexed but never built: new in this traversal, not blocking.
    pub(crate) new_unrecorded: u64,
}

impl ClaudeScopeDebt {
    fn blocking(&self) -> bool {
        self.lost + self.over_budget + self.stale + self.unverified > 0
    }

    fn add(&mut self, other: &Self) {
        self.lost += other.lost;
        self.over_budget += other.over_budget;
        self.stale += other.stale;
        self.unverified += other.unverified;
        self.message_unknown += other.message_unknown;
        self.new_unrecorded += other.new_unrecorded;
    }
}

/// One indexed file's contribution to its group's completeness.
#[derive(Debug, Clone, Copy, Default)]
struct FileDebt(ClaudeScopeDebt);

fn file_debt(index: &ScanIndex, ledger: &ClaudeRequestCensus, key: &str) -> FileDebt {
    let mut debt = ClaudeScopeDebt::default();
    let Some(entry) = index.files.get(key) else {
        // A census record of an unindexed member (residue) is never a
        // current holder: its ids are unknown, unless it is retired.
        match index.claude_request_census.get(key) {
            Some(record) if record.over_budget() => debt.over_budget = 1,
            Some(record) if record.retired().is_none() => debt.stale = 1,
            _ => {}
        }
        return FileDebt(debt);
    };
    match index.claude_request_census.get(key) {
        None => {
            let never_built = entry.last_snapshot_fingerprint.is_none()
                && !index.file_snapshot_fingerprints.contains_key(key);
            if never_built {
                debt.new_unrecorded = 1;
            } else {
                debt.lost = 1;
            }
        }
        Some(record) if record.over_budget() => debt.over_budget = 1,
        // Retired records still count as recorded (their ids are old).
        Some(record) if record.retired().is_some() => {}
        Some(record) => {
            let current_fingerprint = super::claude_request_census::fingerprint_matches(
                record,
                &entry.source_file_fingerprint,
            );
            if !current_fingerprint || !record.current_derivation() {
                debt.stale = 1;
            } else if record.unverified_or_twin() {
                debt.unverified = 1;
            }
            if !message_known(&index.claude_request_census, ledger, key) {
                debt.message_unknown = 1;
            }
        }
    }
    FileDebt(debt)
}

/// Stats one page takes for the births of unbuilt group files (the rest are
/// unknown births).
const UNBUILT_BIRTH_STATS: usize = 64;

/// One file of a scoped group: its key, its debt and, when it is unbuilt
/// (`new_unrecorded`), its birth from a stat (None: unknown).
type GroupFile = (String, ClaudeScopeDebt, Option<u64>);

/// Explicit scoped completeness (§3.1) for the groups and families a page
/// touches, computed once per page from the index and the census.
#[derive(Debug, Default)]
pub(crate) struct ClaudeLedgerScope {
    /// Per group: every file's debt, by key (a unit's own file is excluded
    /// from its own negative claims).
    groups: BTreeMap<String, Vec<GroupFile>>,
    /// Per family root: the sum of its members' debt.
    families: BTreeMap<String, ClaudeScopeDebt>,
    /// The page total (each file once).
    pub(crate) debt: ClaudeScopeDebt,
}

/// Bytes `ClaudeLedgerScope::build` may allocate for `files` index keys of
/// total length `key_bytes`.
pub(crate) fn scope_bound(files: usize, key_bytes: usize) -> usize {
    files
        .saturating_mul(2 * (64 + std::mem::size_of::<GroupFile>()))
        .saturating_add(key_bytes.saturating_mul(3))
}

impl ClaudeLedgerScope {
    /// The groups and families of the page's `roots` and `groups`. None when
    /// the deadline passed.
    pub(crate) fn build(
        index: &ScanIndex,
        ledger: &ClaudeRequestCensus,
        page_groups: &BTreeSet<&str>,
        page_roots: &BTreeSet<&str>,
        deadline: Instant,
    ) -> Option<Self> {
        let mut scope = Self::default();
        let mut birth_stats = 0_usize;
        // Every indexed file, and every retained census record of a member
        // the index no longer lists (residue): its ids are no holder, so it
        // must count against the completeness it would otherwise break.
        let residue = index
            .claude_request_census
            .records()
            .map(|(key, _)| key)
            .filter(|key| !index.files.contains_key(*key));
        for key in index.files.keys().chain(residue) {
            if Instant::now() >= deadline {
                return None;
            }
            if index.confirmed_empty_files.contains(key) {
                continue;
            }
            let Some((root, _)) = claude_index_path_family_member(Path::new(key)) else {
                continue;
            };
            let group = claude_project_group(key);
            let in_group = group.is_some_and(|group| page_groups.contains(group));
            let in_family = page_roots.contains(root.as_str());
            if !in_group && !in_family {
                continue;
            }
            let FileDebt(debt) = file_debt(index, ledger, key);
            scope.debt.add(&debt);
            if let Some(group) = group.filter(|_| in_group) {
                // Births of unbuilt files, for the would-hold count only.
                let birth = (debt.new_unrecorded > 0 && birth_stats < UNBUILT_BIRTH_STATS)
                    .then(|| {
                        birth_stats += 1;
                        std::fs::metadata(key)
                            .and_then(|metadata| metadata.created())
                            .ok()
                            .and_then(|created| created.duration_since(UNIX_EPOCH).ok())
                            .and_then(|created| super::claude_birth_seconds(created.as_secs()))
                    })
                    .flatten();
                scope
                    .groups
                    .entry(group.to_owned())
                    .or_default()
                    .push((key.clone(), debt, birth));
            }
            if in_family {
                scope.families.entry(root).or_default().add(&debt);
            }
        }
        Some(scope)
    }

    /// The group of `own_key` blocks a negative claim (its own file aside).
    fn group_blocks(&self, own_key: &str, message: bool) -> Option<ClaudeUndecidedBy> {
        let group = claude_project_group(own_key)?;
        let files = self.groups.get(group)?;
        let mut message_unknown = false;
        for (key, debt, _) in files {
            if key == own_key {
                continue;
            }
            if debt.blocking() {
                return Some(ClaudeUndecidedBy::Scope);
            }
            message_unknown |= debt.message_unknown > 0;
        }
        (message && message_unknown).then_some(ClaudeUndecidedBy::MessageUnknown)
    }

    /// SOURCE's held-unbuilt-older rule, counted only: an unbuilt file of
    /// `own_key`'s group (its own file aside) has an unknown birth or one
    /// earlier than `holder_birth` (the winning holder's; None: unknown).
    fn unbuilt_older(&self, own_key: &str, holder_birth: Option<u64>) -> bool {
        let Some(files) = claude_project_group(own_key).and_then(|group| self.groups.get(group))
        else {
            return false;
        };
        files
            .iter()
            .filter(|(key, debt, _)| key != own_key && debt.new_unrecorded > 0)
            .any(|(_, _, birth)| match (birth, holder_birth) {
                (Some(birth), Some(holder)) => *birth < holder,
                _ => true,
            })
    }

    /// Every indexed file of `root`'s family is recorded (a new file aside):
    /// the side-call negative "no transcript in the family holds it" holds.
    pub(crate) fn family_complete(&self, root: &str) -> bool {
        self.families
            .get(root)
            .map_or(true, |debt| !debt.blocking())
    }
}

/// Per page: what the classifier knows about telemetry and traces.
pub(crate) struct ClaudeClassifyContext<'a, 'b> {
    pub(crate) index: &'a ScanIndex,
    /// The money ledger's records (telemetry, message-only).
    pub(crate) ledger: &'a ClaudeRequestCensus,
    pub(crate) holders: &'b ClaudeRequestHolders<'a>,
    pub(crate) scope: &'b ClaudeLedgerScope,
    /// Page roots' own telemetry claims (rows read this page), by hash:
    /// telemetry keys beside the ledger's records.
    pub(crate) page_claims: &'b BTreeMap<u64, Vec<&'b str>>,
    /// First event time (unix seconds) of the page roots' rows, per
    /// telemetry key (beside the ledger records' own).
    pub(crate) first_event: &'b BTreeMap<String, u64>,
    /// The page roots' session ids, per telemetry key (beside the session
    /// the ledger records' facts name).
    pub(crate) sessions: &'b BTreeMap<String, String>,
    /// Per root whose trace was read: request hash -> trace-named member.
    pub(crate) trace: &'b BTreeMap<String, BTreeMap<u64, String>>,
    /// The telemetry certificate: the sweep read everything written before
    /// this time (0 while any telemetry debt is open).
    pub(crate) telemetry_complete_through: u64,
    /// The page deadline: body building stops past it (the family fails).
    pub(crate) deadline: std::time::Instant,
    /// Whether the census sees every holder (else a unit no telemetry
    /// claims is held).
    pub(crate) holder_view: super::claude_request_money::coverage::ClaudeHolderView,
    /// T-empty units SOURCE's held-unbuilt-older rule would hold (counted,
    /// no verdict changes).
    pub(crate) unbuilt_older: Cell<u64>,
}

impl ClaudeClassifyContext<'_, '_> {
    pub(crate) fn late(&self) -> bool {
        std::time::Instant::now() >= self.deadline
    }

    /// Telemetry keys claiming `hash`, sorted and unique.
    pub(crate) fn telemetry_claimants(&self, hash: u64) -> Vec<&str> {
        let mut claimants = self
            .holders
            .telemetry_holders(hash)
            .iter()
            .copied()
            .chain(self.page_claims.get(&hash).into_iter().flatten().copied())
            .collect::<Vec<_>>();
        claimants.sort_unstable();
        claimants.dedup();
        claimants
    }

    /// The winning telemetry key among `claimants` (two or more): the
    /// earliest first event, then the smallest root session id (design v2
    /// §3). None when any time is unknown, or a tied root's session is.
    pub(crate) fn two_owner_winner<'c>(&self, claimants: &[&'c str]) -> Option<&'c str> {
        let mut ranked = Vec::with_capacity(claimants.len());
        for key in claimants {
            ranked.push((self.first_event_of(key)?, *key));
        }
        let earliest = ranked.iter().map(|(first, _)| *first).min()?;
        let mut tied = ranked
            .into_iter()
            .filter(|(first, _)| *first == earliest)
            .map(|(_, key)| key);
        let first = tied.next()?;
        let mut winner = (self.session_of(first)?, first);
        for key in tied {
            let session = self.session_of(key)?;
            if session == winner.0 {
                // One session spelled into two keys cannot be ordered.
                return None;
            }
            winner = winner.min((session, key));
        }
        Some(winner.1)
    }

    /// The earliest known event time of a telemetry key's rows (the
    /// ledger's record and this page's rows); None when unknown.
    fn first_event_of(&self, key: &str) -> Option<u64> {
        let stored = self
            .ledger
            .get(key)
            .and_then(ClaudeRequestCensusRecord::tail)
            .map(|tail| tail.first_event_unix)
            .filter(|time| *time > 0);
        let page = self.first_event.get(key).copied().filter(|time| *time > 0);
        match (stored, page) {
            (Some(stored), Some(page)) => Some(stored.min(page)),
            (stored, page) => stored.or(page),
        }
    }

    /// The root session id of a telemetry key: a page root's, else the one
    /// its ledger record's facts name.
    fn session_of(&self, key: &str) -> Option<String> {
        if let Some(session) = self.sessions.get(key) {
            return Some(session.clone());
        }
        let blob = self.ledger.get(key)?.facts()?;
        let header = super::claude_request_money::facts::ClaudeFacts::open(blob)?.header;
        (!header.session.is_empty()).then_some(header.session)
    }

    /// Count a T-empty verdict SOURCE's rule would hold: `winner` is the
    /// earliest-born holder that took (or kept) the id.
    fn note_unbuilt_older(&self, own_key: &str, winner: &str) {
        let birth = self
            .index
            .claude_request_census
            .get(winner)
            .and_then(ClaudeRequestCensusRecord::birth)
            .map(|birth| birth.unix_seconds);
        if self.scope.unbuilt_older(own_key, birth) {
            self.unbuilt_older.set(self.unbuilt_older.get() + 1);
        }
    }

    fn telemetry_swept(&self, clock: u64) -> bool {
        self.telemetry_complete_through > clock.saturating_add(TELEMETRY_WRITE_GRACE_SECONDS)
    }

    /// Classify one request-id (`R`) unit: hash `hash` with clock `clock`,
    /// seen in the file at census key `own_key` of family `own_root`.
    pub(crate) fn classify_request(
        &self,
        hash: u64,
        clock: u64,
        own_key: &str,
        own_root: &str,
    ) -> ClaudeRequestVerdict {
        if self.holders.overflowed(hash) {
            return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::Overflow);
        }
        let claimants = self.telemetry_claimants(hash);
        let own_telemetry = super::claude_request_census::telemetry_key(own_root);
        let (claimant, two_owner) = match claimants.as_slice() {
            [] => (None, false),
            [single] => (Some(*single), false),
            several => match self.two_owner_winner(several) {
                Some(winner) => (Some(winner), true),
                None => return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TelemetryOrder),
            },
        };
        let holders = holders_with(self.holders.transcript_holders(hash), own_key);
        let Some(claimant) = claimant else {
            // No telemetry owner: a negative claim about every root's
            // telemetry and every other file of the group.
            if !self.telemetry_swept(clock) {
                return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TelemetryUnswept);
            }
            if let Some(reason) = self.scope.group_blocks(own_key, false) {
                return ClaudeRequestVerdict::Undecided(reason);
            }
            if !self.holder_view.request {
                return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::HolderView);
            }
            return self.t_empty_verdict(&holders, own_key);
        };
        if claimant != own_telemetry {
            // Another root made the request: this file's copy is that
            // family's money (or a two-owner loser's).
            return ClaudeRequestVerdict::Removed(if two_owner {
                ClaudeRemovedBy::TwoOwnerLoser
            } else {
                ClaudeRemovedBy::Copy
            });
        }
        let counted = if two_owner {
            ClaudeCountedBy::TwoOwnerWinner
        } else {
            ClaudeCountedBy::TelemetryProven
        };
        // Inside the family: the only holder, else the trace-named member,
        // else birth policy. A negative claim about the other members needs
        // the family recorded.
        let in_family = holders
            .iter()
            .copied()
            .filter(|key| {
                claude_index_path_family_member(Path::new(key))
                    .is_some_and(|(root, _)| root == own_root)
            })
            .collect::<Vec<_>>();
        if !self.scope.family_complete(own_root) {
            return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::Scope);
        }
        if in_family.len() <= 1 {
            return ClaudeRequestVerdict::Counted(counted);
        }
        let Some(trace) = self.trace.get(own_root) else {
            return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::TraceUnavailable);
        };
        if let Some(named) = trace.get(&hash) {
            let named_keys = in_family
                .iter()
                .copied()
                .filter(|key| {
                    claude_index_path_family_member(Path::new(key))
                        .is_some_and(|(_, member)| member == *named)
                })
                .collect::<Vec<_>>();
            if let [winner] = named_keys.as_slice() {
                return if *winner == own_key {
                    ClaudeRequestVerdict::Counted(ClaudeCountedBy::PolicyOwned)
                } else {
                    ClaudeRequestVerdict::Removed(ClaudeRemovedBy::Copy)
                };
            }
        }
        match birth_policy(self.index, self.ledger, &in_family) {
            Ok(winner) if winner == own_key => {
                ClaudeRequestVerdict::Counted(ClaudeCountedBy::PolicyOwned)
            }
            Ok(_) => ClaudeRequestVerdict::Removed(ClaudeRemovedBy::Copy),
            Err(reason) => ClaudeRequestVerdict::Undecided(reason),
        }
    }

    /// Classify one message-only (`M`) unit. No telemetry row names a
    /// message id, so only the transcript holders decide.
    pub(crate) fn classify_message(&self, hash: u64, own_key: &str) -> ClaudeRequestVerdict {
        if self.holders.overflowed(hash) {
            return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::Overflow);
        }
        if let Some(reason) = self.scope.group_blocks(own_key, true) {
            return ClaudeRequestVerdict::Undecided(reason);
        }
        if !self.holder_view.message {
            return ClaudeRequestVerdict::Undecided(ClaudeUndecidedBy::HolderView);
        }
        let holders = holders_with(self.holders.message_holders(hash), own_key);
        self.t_empty_verdict(&holders, own_key)
    }

    /// No telemetry owner (T-empty): the only holder, else birth policy.
    fn t_empty_verdict(&self, holders: &[&str], own_key: &str) -> ClaudeRequestVerdict {
        let winner = match holders {
            [_] => Ok(own_key),
            holders => birth_policy(self.index, self.ledger, holders),
        };
        let winner = match winner {
            Ok(winner) => winner,
            Err(reason) => return ClaudeRequestVerdict::Undecided(reason),
        };
        self.note_unbuilt_older(own_key, winner);
        if holders.len() == 1 {
            ClaudeRequestVerdict::Counted(ClaudeCountedBy::Owned)
        } else if winner == own_key {
            ClaudeRequestVerdict::Counted(ClaudeCountedBy::PolicyOwned)
        } else {
            ClaudeRequestVerdict::Removed(ClaudeRemovedBy::Copy)
        }
    }
}

fn holders_with<'k>(holders: &[&'k str], own_key: &'k str) -> Vec<&'k str> {
    let mut holders = holders.to_vec();
    if !holders.contains(&own_key) {
        holders.push(own_key);
    }
    holders.sort_unstable();
    holders
}

/// Several holders: the earliest first-seen birth wins, then the member id
/// (then the key, for path twins). Every holder must be current at its
/// entry's fingerprint, and births all known or all unknown.
fn birth_policy<'k>(
    index: &ScanIndex,
    ledger: &ClaudeRequestCensus,
    holders: &[&'k str],
) -> Result<&'k str, ClaudeUndecidedBy> {
    let mut ranked = Vec::with_capacity(holders.len());
    for key in holders {
        let census = &index.claude_request_census;
        let record = index
            .files
            .get(*key)
            .zip(census.get(key))
            .filter(|(entry, record): &(_, &ClaudeRequestCensusRecord)| {
                record.current_holder_for(
                    &entry.source_file_fingerprint,
                    message_known(census, ledger, key),
                )
            })
            .map(|(_, record)| record)
            .ok_or(ClaudeUndecidedBy::StaleHolder)?;
        let member = claude_index_path_family_member(Path::new(key))
            .map(|(_, member)| member)
            .unwrap_or_default();
        ranked.push((record.birth().map(|birth| birth.unix_seconds), member, *key));
    }
    let known = ranked
        .iter()
        .filter(|(birth, _, _)| birth.is_some())
        .count();
    if known != 0 && known != ranked.len() {
        return Err(ClaudeUndecidedBy::Births);
    }
    ranked
        .into_iter()
        .min()
        .map(|(_, _, key)| key)
        .ok_or(ClaudeUndecidedBy::StaleHolder)
}

/// Roots (family root session ids) that hold at least one retired transcript
/// record: a counted unit there may have a retired copy.
pub(crate) fn roots_with_retired_records(census: &ClaudeRequestCensus) -> BTreeSet<String> {
    census
        .records()
        .filter(|(_, record)| record.retired().is_some())
        .filter_map(|(key, _)| {
            claude_index_path_family_member(Path::new(key)).map(|(root, _)| root)
        })
        .collect()
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ClaudeLedgerStateCounts {
    pub(crate) transcript_records: u64,
    pub(crate) transcript_retired_records: u64,
    pub(crate) transcript_retired_aged: u64,
    pub(crate) transcript_dropped_vanished: u64,
    /// Transcript records carrying a census `u` / without one (unknown).
    pub(crate) transcript_u_known: u64,
    pub(crate) transcript_u_unknown: u64,
    pub(crate) census_hashes: u64,
    pub(crate) census_serialized_bytes: u64,
    pub(crate) telemetry_records: u64,
    pub(crate) telemetry_retired_records: u64,
    pub(crate) telemetry_hashes: u64,
    pub(crate) message_records: u64,
    pub(crate) message_hashes: u64,
    pub(crate) family_memos: u64,
    /// The money ledger's own budget use and measured resident heap.
    pub(crate) ledger_hashes: u64,
    pub(crate) ledger_serialized_bytes: u64,
    pub(crate) ledger_resident_bytes: u64,
    /// The structural bound `ledger_resident_bytes` stays under.
    pub(crate) ledger_resident_bound_bytes: u64,
    pub(crate) ledger_dirty_shards: u64,
}

/// What the index's transcript records and the money ledger hold. The
/// ledger's resident heap is measured here, by walking it (the page line
/// refreshes this walk at most once a minute). None when `deadline` passes
/// during the walk (checked before every record).
pub(crate) fn ledger_state_counts(
    census: &ClaudeRequestCensus,
    ledger: Option<&ClaudeLedger>,
    deadline: Instant,
) -> Option<ClaudeLedgerStateCounts> {
    let late = || Instant::now() >= deadline;
    let (aged, vanished) = super::claude_request_census::transcript_retirements();
    let mut counts = ClaudeLedgerStateCounts {
        census_hashes: census.hash_total() as u64,
        census_serialized_bytes: census.serialized_total() as u64,
        transcript_retired_aged: aged,
        transcript_dropped_vanished: vanished,
        ..ClaudeLedgerStateCounts::default()
    };
    for (_, record) in census.records() {
        if late() {
            return None;
        }
        counts.transcript_records += 1;
        counts.transcript_retired_records += u64::from(record.retired().is_some());
        match record.old_path_usage() {
            Some(_) => counts.transcript_u_known += 1,
            None => counts.transcript_u_unknown += 1,
        }
    }
    let Some(ledger) = ledger else {
        return Some(counts);
    };
    let records = ledger.census();
    counts.ledger_hashes = records.hash_total() as u64;
    counts.ledger_serialized_bytes = records.serialized_total() as u64;
    counts.ledger_resident_bytes = records.resident_bytes(deadline)? as u64;
    counts.ledger_resident_bound_bytes =
        super::claude_request_money::store::LEDGER_RESIDENT_BOUND_BYTES as u64;
    counts.ledger_dirty_shards = ledger.dirty_shards() as u64;
    for (_, record) in records.records_with_prefix(TELEMETRY_KEY_PREFIX) {
        if late() {
            return None;
        }
        counts.telemetry_records += 1;
        counts.telemetry_retired_records += u64::from(record.retired().is_some());
        counts.telemetry_hashes += record.request_hashes().len() as u64;
    }
    for (_, record) in records.records_with_prefix(MESSAGE_KEY_PREFIX) {
        if late() {
            return None;
        }
        counts.message_records += 1;
        counts.message_hashes += record.request_hashes().len() as u64;
    }
    for _ in records.records_with_prefix(super::claude_request_census::FAMILY_KEY_PREFIX) {
        if late() {
            return None;
        }
        counts.family_memos += 1;
    }
    (!late()).then_some(counts)
}

/// Refresh the totals of cached state counts (the walked fields stay).
pub(crate) fn refresh_state_totals(
    counts: &mut ClaudeLedgerStateCounts,
    census: &ClaudeRequestCensus,
    ledger: Option<&ClaudeLedger>,
) {
    let (aged, vanished) = super::claude_request_census::transcript_retirements();
    counts.census_hashes = census.hash_total() as u64;
    counts.census_serialized_bytes = census.serialized_total() as u64;
    counts.transcript_retired_aged = aged;
    counts.transcript_dropped_vanished = vanished;
    if let Some(ledger) = ledger {
        counts.ledger_resident_bound_bytes =
            super::claude_request_money::store::LEDGER_RESIDENT_BOUND_BYTES as u64;
        counts.ledger_hashes = ledger.census().hash_total() as u64;
        counts.ledger_serialized_bytes = ledger.census().serialized_total() as u64;
        counts.ledger_dirty_shards = ledger.dirty_shards() as u64;
    }
}

/// The ledger is under pressure: its hashes or serialized bytes at `percent`
/// of their budgets.
fn pressure(ledger: &ClaudeLedger, percent: usize) -> bool {
    let census = ledger.census();
    census.hash_total().saturating_mul(100) >= MAX_CLAUDE_REQUEST_CENSUS_HASHES * percent
        || census.serialized_total().saturating_mul(100)
            >= MAX_CLAUDE_REQUEST_CENSUS_SERIALIZED_BYTES * percent
}

/// Telemetry retirement under budget pressure only: at 90% of the ledger's
/// hash or serialized budget, retire the telemetry records with the oldest
/// last append until both are under 80%. A retired telemetry record keeps
/// its tail (the reader never re-adds consumed rows), so its old ids lose
/// their telemetry claim and its money is unavailable: a later transcript
/// copy of one falls back to policy. Records are retired in place (taken and
/// reinserted without copying a hash). Returns how many; the caller drops
/// the telemetry certificate when any had claims.
pub(crate) fn retire_telemetry_under_pressure(ledger: &mut ClaudeLedger) -> u64 {
    if !pressure(ledger, PRESSURE_START_PERCENT) {
        return 0;
    }
    let mut candidates = ledger
        .census()
        .records_with_prefix(TELEMETRY_KEY_PREFIX)
        .filter(|(_, record)| !record.request_hashes().is_empty())
        .map(|(key, record)| {
            (
                record.tail().map_or(0, |tail| tail.last_append_unix),
                key.clone(),
            )
        })
        .collect::<Vec<_>>();
    candidates.sort_unstable();
    let mut retired = 0;
    for (_, key) in candidates {
        if !pressure(ledger, PRESSURE_TARGET_PERCENT) {
            break;
        }
        if let Some(mut record) = ledger.take(&key) {
            record.retire();
            let _ = ledger.insert(key, record);
            retired += 1;
        }
    }
    retired
}
