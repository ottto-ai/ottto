//! Freshness debt: each file's oldest change that no matched exact ACK covers
//! yet, kept as metadata of its Tail head and `tail.revision` rows so it
//! survives restarts, and reported per source on the `freshness_alarm` line.
//! Diagnostics only: it reads the index and the listing, stages debt-only
//! observations, and never grants, withholds or orders a read, upload or
//! settlement. One path for every source; sources differ only by the index
//! state the existing adapters already keep. The walk's own state rides in
//! `money_freshness::WalkFold`.
use super::money_freshness::{WalkFold, ALARM_AFTER};
use super::state_v2::{DebtSummary, NoUploadRequired, Observation, Representation, TailHead};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

// Reason bits this writer sets, bit 0 first. Every other bit is reserved for
// its own writer, kept as written, and counts as held.
const GROWTH_CLAIM_WAIT: u32 = 1 << 0;
const UNREAD: u32 = 1 << 1;
const HELD_REVISION: u32 = 1 << 2;
const OWN: u32 = GROWTH_CLAIM_WAIT | UNREAD | HELD_REVISION;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Extent {
    /// Source bytes `[start, end)` of the file's current object.
    Raw { start: u64, end: u64 },
    /// A whole archive, by its compressed size only.
    ArchiveWhole { compressed_bytes: u64 },
}
impl Extent {
    fn bounds(self) -> (u64, u64) {
        match self {
            Self::Raw { start, end } => (start, end),
            Self::ArchiveWhole { compressed_bytes } => (0, compressed_bytes),
        }
    }
}

/// One `tail.revision` value: an owed change and its first change time (Unix
/// milliseconds). `lower_bound`: the true change may be older.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Revision {
    extent: Extent,
    first_change_at: Option<u64>,
    lower_bound: bool,
    reason_bits: u32,
}

const REVISION_V1: u8 = 1;
const REVISION_BYTES: usize = 32;

impl Revision {
    fn end(&self) -> u64 {
        self.extent.bounds().1
    }
    fn bytes(&self) -> u64 {
        let (start, end) = self.extent.bounds();
        end.saturating_sub(start)
    }
    /// `[v1][kind][a u64][b u64][has first][first u64][lower bound][reasons u32]`.
    fn encode(&self) -> Vec<u8> {
        let (kind, a, b) = match self.extent {
            Extent::Raw { start, end } => (1_u8, start, end),
            Extent::ArchiveWhole { compressed_bytes } => (2, compressed_bytes, 0),
        };
        let mut out = Vec::with_capacity(REVISION_BYTES);
        out.extend_from_slice(&[REVISION_V1, kind]);
        out.extend_from_slice(&a.to_be_bytes());
        out.extend_from_slice(&b.to_be_bytes());
        out.push(u8::from(self.first_change_at.is_some()));
        out.extend_from_slice(&self.first_change_at.unwrap_or(0).to_be_bytes());
        out.push(u8::from(self.lower_bound));
        out.extend_from_slice(&self.reason_bits.to_be_bytes());
        out
    }
    /// `None`: another version or a damaged value, which this build leaves alone.
    fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != REVISION_BYTES
            || bytes[0] != REVISION_V1
            || bytes[18] > 1
            || bytes[27] > 1
        {
            return None;
        }
        let word = |at: usize| u64::from_be_bytes(bytes[at..at + 8].try_into().unwrap_or([0; 8]));
        let extent = match bytes[1] {
            1 if word(2) <= word(10) => Extent::Raw {
                start: word(2),
                end: word(10),
            },
            2 => Extent::ArchiveWhole {
                compressed_bytes: word(2),
            },
            _ => return None,
        };
        Some(Self {
            extent,
            first_change_at: (bytes[18] == 1).then(|| word(19)),
            lower_bound: bytes[27] == 1,
            reason_bits: u32::from_be_bytes(bytes[28..32].try_into().unwrap_or([0; 4])),
        })
    }
}

/// The earlier first change; an unknown one leaves the result unknown.
fn earlier(a: (Option<u64>, bool), b: (Option<u64>, bool)) -> (Option<u64>, bool) {
    match (a.0, b.0) {
        (Some(x), Some(y)) => (Some(x.min(y)), a.1 || b.1),
        _ => (None, true),
    }
}

/// The head's summary, derived from its surviving revisions only.
fn summary(owed: &[Revision], disposition: Option<NoUploadRequired>) -> DebtSummary {
    let (earliest, lower_bound) = match owed.split_first() {
        Some((first, rest)) => rest.iter().fold(
            (first.first_change_at, first.lower_bound),
            |found, revision| earlier(found, (revision.first_change_at, revision.lower_bound)),
        ),
        None => (None, false),
    };
    DebtSummary {
        earliest_unacked_change_at: earliest,
        lower_bound,
        reason_bits: owed
            .iter()
            .fold(0, |bits, revision| bits | revision.reason_bits),
        disposition,
    }
}

/// What the index and this listing prove about one file now.
#[derive(Clone, Copy, Debug)]
struct Live {
    len: u64,
    representation: Representation,
    /// `[0, accepted)` of the live object has a matched exact receipt.
    exact: bool,
    accepted: u64,
    /// `[0, read)` of the live object was read into the index.
    read: u64,
    /// The live object is not the one the stored state describes.
    replaced: bool,
    /// New messages wait on a growth claim.
    growth_wait: bool,
    /// Per-file evidence that nothing is owed.
    evidence: Option<NoUploadRequired>,
    /// A change first seen now: the live mtime, and whether it is a lower bound.
    change: (Option<u64>, bool),
    /// This observation adds no revision (outside the window, or a context change).
    quiet: bool,
}

/// One file's revisions after this observation.
#[derive(Debug, Default)]
struct Plan {
    resolved: BTreeSet<u64>,
    replaced: BTreeMap<u64, Revision>,
    added: Vec<Revision>,
    /// Every revision still owed, committed or new.
    owed: Vec<Revision>,
}

/// Retires only what the matched exact receipt covers, and only as a prefix:
/// a newer suffix keeps its own time and bytes. A replaced object never orphans
/// debt: its revisions fold into one of the new object with the earliest time.
fn reconcile(committed: &BTreeMap<u64, Revision>, live: &Live) -> Plan {
    let mut plan = Plan::default();
    if live.evidence.is_some() {
        plan.resolved = committed.keys().copied().collect();
        return plan;
    }
    let archive = live.representation == Representation::Archive;
    let extent = |start: u64, end: u64| {
        if archive {
            Extent::ArchiveWhole {
                compressed_bytes: end,
            }
        } else {
            Extent::Raw { start, end }
        }
    };
    let reasons = |extent: Extent, written: u32| {
        let (start, end) = extent.bounds();
        let mut bits = written & !OWN;
        if live.growth_wait {
            bits |= GROWTH_CLAIM_WAIT;
        }
        if end > live.read {
            bits |= UNREAD;
        }
        if start < live.read {
            bits |= HELD_REVISION;
        }
        bits
    };
    let covered = |end: u64| live.exact && end <= live.accepted;
    let collapse = live.replaced || committed.values().any(|revision| revision.end() > live.len);
    if collapse && !committed.is_empty() {
        let (first, written) =
            committed
                .values()
                .fold((live.change, 0), |(first, bits), revision| {
                    (
                        earlier(first, (revision.first_change_at, revision.lower_bound)),
                        bits | revision.reason_bits,
                    )
                });
        plan.resolved = committed.keys().copied().collect();
        if !covered(live.len) {
            let whole = extent(0, live.len);
            plan.added.push(Revision {
                extent: whole,
                first_change_at: first.0,
                lower_bound: first.1,
                reason_bits: reasons(whole, written),
            });
        }
        plan.owed = plan.added.clone();
        return plan;
    }
    let mut reach = if live.exact { live.accepted } else { 0 };
    for (&id, revision) in committed {
        if covered(revision.end()) {
            plan.resolved.insert(id);
            continue;
        }
        let mut kept = *revision;
        if let Extent::Raw { start, end } = kept.extent {
            if live.exact && start < live.accepted {
                kept.extent = Extent::Raw {
                    start: live.accepted,
                    end,
                };
            }
        }
        kept.reason_bits = reasons(kept.extent, kept.reason_bits);
        reach = reach.max(kept.end());
        if kept != *revision {
            plan.replaced.insert(id, kept);
        }
        plan.owed.push(kept);
    }
    if !live.quiet && live.len > reach {
        // Read-but-unaccepted bytes are held, the rest unread.
        let mut cuts = vec![reach];
        if !archive && live.read > reach && live.read < live.len {
            cuts.push(live.read);
        }
        cuts.push(live.len);
        for pair in cuts.windows(2) {
            let new = extent(pair[0], pair[1]);
            let revision = Revision {
                extent: new,
                first_change_at: live.change.0,
                lower_bound: live.change.1,
                reason_bits: reasons(new, 0),
            };
            plan.added.push(revision);
            plan.owed.push(revision);
        }
    }
    plan
}

/// One file's contribution to its source's aggregate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct FileDebt {
    owed: bool,
    /// `None` while owed: unknown age.
    earliest: Option<u64>,
    lower_bound: bool,
    held: bool,
    unread_bytes: u64,
    listed: bool,
}
impl FileDebt {
    /// A head this build cannot read: owed, age unknown. Never written over.
    const UNKNOWN: Self = Self {
        owed: true,
        earliest: None,
        lower_bound: true,
        held: false,
        unread_bytes: 0,
        listed: false,
    };
    fn of(owed: &[Revision]) -> Self {
        let summary = summary(owed, None);
        Self {
            owed: !owed.is_empty(),
            earliest: summary.earliest_unacked_change_at,
            lower_bound: summary.lower_bound,
            held: summary.reason_bits & !UNREAD != 0,
            unread_bytes: unread_bytes(owed.iter()),
            listed: false,
        }
    }
    /// A committed head the walk did not list: its stored summary, with the
    /// revisions decoded only when some are unread.
    fn committed(index: &ScanIndex, key: &str) -> Self {
        let head = match state_v2::load_head(index, key, u32::MAX) {
            Ok(Some(head)) => head,
            Ok(None) => return Self::default(),
            Err(_) => return Self::UNKNOWN,
        };
        let debt = head.common.debt;
        if debt.earliest_unacked_change_at.is_none() && !debt.lower_bound && debt.reason_bits == 0 {
            return Self::default();
        }
        let unread = if debt.reason_bits & UNREAD == 0 {
            0
        } else {
            match revisions(index, key, &head) {
                Some(owed) => unread_bytes(owed.values()),
                None => return Self::UNKNOWN,
            }
        };
        Self {
            owed: true,
            earliest: debt.earliest_unacked_change_at,
            lower_bound: debt.lower_bound,
            held: debt.reason_bits & !UNREAD != 0,
            unread_bytes: unread,
            listed: false,
        }
    }
}

fn unread_bytes<'a>(owed: impl Iterator<Item = &'a Revision>) -> u64 {
    owed.filter(|revision| revision.reason_bits & UNREAD != 0)
        .map(Revision::bytes)
        .sum()
}

/// A head's revisions by id; `None` when any is unreadable.
fn revisions(index: &ScanIndex, key: &str, head: &TailHead) -> Option<BTreeMap<u64, Revision>> {
    let (mut found, mut damaged) = (BTreeMap::new(), false);
    state_v2::load_revisions(index, key, head, |id, value| {
        match Revision::decode(&value) {
            Some(revision) => {
                found.insert(id, revision);
            }
            None => damaged = true,
        }
        Ok(())
    })
    .ok()?;
    (!damaged).then_some(found)
}

fn over_alarm_age(now_ms: u64, at: u64) -> bool {
    now_ms.saturating_sub(at) / 1000 > ALARM_AFTER
}

/// A source's persisted debt, as scalars. No cap: every owed file counts.
#[derive(Clone, Copy, Debug)]
pub(super) struct Report {
    available: bool,
    outstanding_files: u64,
    held_files: u64,
    unread_bytes: u64,
    /// Over the alarm age when counted.
    over_6h_files: u64,
    /// The oldest known first change, and whether it is a lower bound.
    oldest: Option<(u64, bool)>,
    unknown_age_files: u64,
    /// Owed files this walk listed that have no index entry (archives aside).
    never_indexed_files: u64,
    no_upload_required_files: u64,
    deleted_unaccepted_files: u64,
    /// Owed Listed history the gate holds: counted, but out of the age alarm.
    listed_history_held_files: u64,
    last_complete_discovery_at: Option<u64>,
}
impl Report {
    /// Storage could not be read, or this process has no aggregate yet: never fresh.
    pub(super) const UNAVAILABLE: Self = Self {
        available: false,
        outstanding_files: 0,
        held_files: 0,
        unread_bytes: 0,
        over_6h_files: 0,
        oldest: None,
        unknown_age_files: 0,
        never_indexed_files: 0,
        no_upload_required_files: 0,
        deleted_unaccepted_files: 0,
        listed_history_held_files: 0,
        last_complete_discovery_at: None,
    };
    fn add(&mut self, debt: FileDebt, now_ms: u64) {
        if !debt.owed {
            return;
        }
        self.outstanding_files += 1;
        self.held_files += u64::from(debt.held);
        self.unread_bytes += debt.unread_bytes;
        if debt.listed {
            self.listed_history_held_files += 1;
            return;
        }
        let Some(at) = debt.earliest else {
            self.unknown_age_files += 1;
            return;
        };
        self.over_6h_files += u64::from(over_alarm_age(now_ms, at));
        self.oldest = Some(match self.oldest {
            Some((old, lower)) if old < at => (old, lower),
            Some((old, lower)) if old == at => (old, lower || debt.lower_bound),
            _ => (at, debt.lower_bound),
        });
    }
    /// Over 6 h, unknown age, or no complete discovery within 6 h.
    pub(super) fn alarm(&self, now_ms: u64) -> bool {
        !self.available
            || self.over_6h_files > 0
            || self
                .oldest
                .is_some_and(|(at, _)| over_alarm_age(now_ms, at))
            || self.unknown_age_files > 0
            || self
                .last_complete_discovery_at
                .map_or(true, |at| over_alarm_age(now_ms, at))
    }
    /// The per-source fields; `null` when storage could not be read.
    pub(super) fn fields(&self, now_ms: u64) -> serde_json::Value {
        if !self.available {
            return serde_json::Value::Null;
        }
        serde_json::json!({
            "outstanding_files": self.outstanding_files,
            "held_files": self.held_files,
            "unread_bytes": self.unread_bytes,
            "over_6h_files": self.over_6h_files,
            "oldest_age_s": self.oldest.map(|(at, _)| now_ms.saturating_sub(at) / 1000),
            "oldest_age_lower_bound": self.oldest.is_some_and(|(_, lower)| lower)
                || self.unknown_age_files > 0,
            "never_indexed_files": self.never_indexed_files,
            "no_upload_required_files": self.no_upload_required_files,
            "deleted_unaccepted_files": self.deleted_unaccepted_files,
            "listed_history_held_files": self.listed_history_held_files,
            "last_complete_discovery_at": self.last_complete_discovery_at.map(|at| at / 1000),
            "alarm": self.alarm(now_ms),
        })
    }
}

/// One root walk's debt state, carried in its `WalkFold`. The debt itself is
/// persisted; this only knows which files the walk counted, so a walk resumed
/// after a restart is never complete.
#[derive(Debug)]
pub(super) struct Walk {
    /// Unix ms when this process saw the walk begin at the roots.
    started_at: Option<u64>,
    incomplete: bool,
    unavailable: bool,
    /// A symlink, unreadable entry, too-wide directory or disappearance on
    /// some page, or no Tail route: the roster proves nothing absent.
    issue: bool,
    /// The roster: every key the walk listed (excluded and out-of-window files
    /// too) with its mtime (unix seconds), each once.
    listed: BTreeMap<String, Option<u64>>,
    /// The walk's sums over `listed`.
    sums: Report,
}
impl Walk {
    pub(super) const EMPTY: Self = Self {
        started_at: None,
        incomplete: false,
        unavailable: false,
        issue: false,
        listed: BTreeMap::new(),
        sums: Report::UNAVAILABLE,
    };

    /// The roster of a complete walk begun in this process with no walk
    /// issue; `None` otherwise. Moves the roster out of the walk.
    pub(super) fn complete_roster(&mut self) -> Option<Roster> {
        let started_at_ms = self
            .started_at
            .filter(|_| !self.incomplete && !self.unavailable && !self.issue)?;
        Some(Roster {
            started_at_ms,
            listed: std::mem::take(&mut self.listed),
        })
    }
}

/// The source's root walk ends through the real walk end: `Some((started_at_ms,
/// listed))` a complete walk begun then that listed `listed`, `None` a walk
/// that was not complete (no roster).
#[cfg(test)]
pub(crate) fn walk_ended_for_test(
    source: SnapshotSource,
    roster: Option<(u64, BTreeMap<String, Option<u64>>)>,
) {
    let mut fold = WalkFold::EMPTY;
    if let Some((started_at_ms, listed)) = roster {
        fold.debt = Walk {
            started_at: Some(started_at_ms),
            listed,
            ..Walk::EMPTY
        };
    }
    fold.page_end(source, true, None);
}

/// Every file a complete root walk listed, and when that walk began.
pub(crate) struct Roster {
    pub(crate) started_at_ms: u64,
    pub(crate) listed: BTreeMap<String, Option<u64>>,
}

/// One listed file, as the walk saw it.
pub(super) struct Listing<'a> {
    pub(super) path: &'a Path,
    pub(super) metadata: &'a std::fs::Metadata,
    /// Inside the discovery window: outside it no new debt starts (the read
    /// filters, as for the never-indexed count).
    pub(super) in_window: bool,
}

/// One discovery page of one source.
pub(super) struct Page<'a> {
    source: SnapshotSource,
    /// `None`: a v1 graph, which has no Tail store and so no debt.
    route: Option<PathBuf>,
    root_walk: bool,
    fold: &'a mut WalkFold,
    /// This page's observations, staged together at its end.
    staged: Vec<(String, Observation)>,
    errors: (usize, usize),
    now_ms: u64,
    last_complete: Option<u64>,
}

fn listing_errors(counts: &ScanTraversalCounts) -> (usize, usize) {
    (
        counts.directory_entry_cap_exceeded_count,
        counts.unreadable_path_count,
    )
}

impl<'a> Page<'a> {
    /// A walk begins with exactly the configured roots pending, and then with a
    /// fresh fold.
    pub(super) fn begin(
        source: SnapshotSource,
        index: &ScanIndex,
        traversal: &ScanTraversalCheckpoint,
        root_walk: bool,
        fold: &'a mut WalkFold,
    ) -> Self {
        let now_ms = sampled_scan::now_seconds().saturating_mul(1000);
        let (route, unavailable) = match state_v2::tail_route_path(index) {
            Ok(route) => (route, false),
            Err(_) => (None, true),
        };
        let unmarked: Vec<&ScanTraversalPath> = traversal
            .pending_directories
            .iter()
            .filter(|directory| !directory.watcher_hint)
            .collect();
        let begins = !unmarked.is_empty()
            && unmarked.len() == traversal.scan_roots.len()
            && unmarked
                .iter()
                .zip(&traversal.scan_roots)
                .all(|(directory, root)| directory.path == *root && directory.scan_root == *root);
        if root_walk && begins {
            // A root that did not resolve, or failed to, is not listed: the
            // walk proves nothing absent under it.
            let counts = &traversal.counts;
            *fold = WalkFold::EMPTY;
            fold.debt.started_at = Some(now_ms);
            fold.debt.incomplete =
                listing_errors(counts) != (0, 0) || counts.disappeared_file_count > 0;
        }
        fold.debt.unavailable |= unavailable;
        Self {
            source,
            route,
            root_walk,
            fold,
            staged: Vec::new(),
            errors: listing_errors(&traversal.counts),
            now_ms,
            last_complete: index.tail_discovery.last_complete_discovery_at,
        }
    }

    /// A listing error or a too-wide directory leaves the walk incomplete. A
    /// re-listing pass restores its counts, so compare before that restore.
    pub(super) fn counts(
        &mut self,
        counts: &ScanTraversalCounts,
        before: Option<&ScanTraversalCounts>,
    ) {
        if listing_errors(counts) != before.map_or(self.errors, listing_errors) {
            self.fold.debt.incomplete = true;
        }
    }

    /// An entry the walk could not list, or a queued directory that is gone
    /// with no confirmed removal, proves nothing absent: no erasure this walk.
    pub(super) fn unlisted(&mut self) {
        self.fold.debt.incomplete = true;
    }

    /// Any walk issue on this page (symlink, unreadable, too wide, gone).
    pub(super) fn walk_issue(&mut self) {
        self.fold.debt.issue = true;
    }

    /// Enter `path` in the roster once per walk; false when already listed.
    fn roster(&mut self, path: &Path, metadata: Option<&std::fs::Metadata>) -> bool {
        let mtime = metadata
            .and_then(|metadata| metadata.modified().ok())
            .and_then(unix_seconds);
        self.fold
            .debt
            .listed
            .insert(local_index_key(path), mtime)
            .is_none()
    }

    /// A file excluded from upload by the daemon's own snapshot rule is never
    /// upload-required: no debt, counted as no upload required.
    pub(super) fn excluded(&mut self, path: &Path, metadata: Option<&std::fs::Metadata>) {
        if self.roster(path, metadata) && self.route.is_some() {
            self.fold.debt.sums.no_upload_required_files += 1;
        }
    }

    /// No complete discovery yet, or a change older than the last one that
    /// would have recorded it: its first change can only be a lower bound.
    fn bootstrap(&self, mtime: Option<u64>) -> bool {
        match (self.last_complete, mtime) {
            (Some(complete), Some(mtime)) => mtime <= complete,
            _ => true,
        }
    }

    fn live(&self, index: &ScanIndex, key: &str, listing: &Listing<'_>) -> Live {
        let metadata = listing.metadata;
        let len = metadata.len();
        // A future mtime is a regressed clock: unknown, never fresh.
        let mtime = metadata
            .modified()
            .ok()
            .and_then(unix_nanos)
            .map(|nanos| nanos / 1_000_000)
            .filter(|ms| ms / 1000 <= self.now_ms / 1000);
        // Never indexed: no stored state, so its age is a lower bound.
        let mut live = Live {
            len,
            representation: Representation::Tail,
            exact: false,
            accepted: 0,
            read: 0,
            replaced: false,
            growth_wait: sampled_audit::growth_selectable(
                self.source,
                listing.path,
                Some(&index.v2().growth_retention),
            ),
            evidence: None,
            change: (mtime, true),
            quiet: !listing.in_window,
        };
        let compressed = codex_archive_path(listing.path);
        if compressed {
            // The extent is physical compressed bytes; the reduction-bearing
            // head retains Tail representation and logical decoded progress.
            live.representation = Representation::Archive;
        }
        let Some(entry) = index.files.get(key) else {
            return live;
        };
        let unchanged = index.listing_stamp_matches(listing.path, metadata);
        let len = if unchanged { entry.size_bytes } else { len };
        live.len = len;
        if unchanged {
            live.representation = Representation::Tail;
        }

        let birth = metadata.created().ok().and_then(unix_nanos);
        let same_object = entry.opened_birth_nanos == 0 || birth == Some(entry.opened_birth_nanos);
        let grown = !compressed && !unchanged && same_object && len > entry.size_bytes;
        live.exact = index.file_upload_context_enabled()
            && !index.file_upload_context_requires_adoption(key)
            && (unchanged || grown);
        // The stored size, never the live one: a matching Codex fragment's
        // entry records only its certified prefix.
        live.read = if unchanged || grown {
            entry.size_bytes.min(len)
        } else {
            0
        };
        live.accepted = if live.exact { live.read } else { 0 };
        live.replaced = !unchanged && !grown;
        if unchanged && index.confirmed_empty_files.contains(key) {
            live.evidence = Some(NoUploadRequired::ZeroUsageLines);
        }
        live.change.1 = self.bootstrap(mtime);
        // Unchanged, unaccepted and older than the last complete discovery,
        // which recorded no debt for it: a context change, not a byte change.
        let seen_whole = self
            .last_complete
            .zip(mtime)
            .is_some_and(|(complete, mtime)| mtime <= complete);
        live.quiet = !listing.in_window || (unchanged && !live.exact && seen_whole);
        live
    }

    /// Reconcile one listed file, once per walk, and stage what changed. A head
    /// this build cannot read is counted unknown and never written.
    pub(super) fn listed(&mut self, index: &ScanIndex, listing: Listing<'_>) {
        if !self.roster(listing.path, Some(listing.metadata)) || self.route.is_none() {
            return;
        }
        let key = local_index_key(listing.path);
        let live = self.live(index, &key, &listing);
        // One keyed read per listed file; an absent head is `None`.
        let head = match state_v2::load_head(index, &key, u32::MAX) {
            Ok(head) => head,
            Err(_) => return self.count(index, listing.path, key, FileDebt::UNKNOWN, false),
        };
        let committed = match &head {
            Some(head) => match revisions(index, &key, head) {
                Some(committed) => committed,
                None => return self.count(index, listing.path, key, FileDebt::UNKNOWN, false),
            },
            None => BTreeMap::new(),
        };
        let plan = reconcile(&committed, &live);
        let summary = summary(&plan.owed, live.evidence);
        let changed = !plan.resolved.is_empty()
            || !plan.replaced.is_empty()
            || !plan.added.is_empty()
            || head
                .as_ref()
                .is_some_and(|head| head.common.debt != summary);
        if changed {
            // The head's own representation and the full recomputed summary.
            let observation = Observation {
                representation: head
                    .as_ref()
                    .map_or(live.representation, |head| head.common.representation),
                summary,
                added: plan.added.iter().map(Revision::encode).collect(),
                replaced: plan
                    .replaced
                    .iter()
                    .map(|(id, revision)| (*id, revision.encode()))
                    .collect(),
                resolved: plan.resolved.clone(),
                inventory: None,
            };
            self.staged.push((key.clone(), observation));
        }
        if head.is_some() || !plan.owed.is_empty() || live.evidence.is_some() {
            let mut debt = FileDebt::of(&plan.owed);
            debt.listed = debt.owed && listed_history_held(index, &key, &listing);
            self.count(index, listing.path, key, debt, live.evidence.is_some());
        }
    }

    fn count(
        &mut self,
        index: &ScanIndex,
        path: &Path,
        key: String,
        debt: FileDebt,
        no_upload_required: bool,
    ) {
        // The one never-indexed count, for every ordinary input encoding.
        let never_indexed = debt.owed && !index.files.contains_key(&key);
        let walk = &mut self.fold.debt;
        walk.sums.never_indexed_files += u64::from(never_indexed);
        walk.sums.add(debt, self.now_ms);
        walk.sums.no_upload_required_files += u64::from(no_upload_required);
        if debt.owed && index.authority_terminal_member(path) {
            let age_ms = debt.earliest.map_or(0, |at| self.now_ms.saturating_sub(at));
            self.fold.authority_terminal_file(age_ms / 1000);
        }
    }

    /// The page's end: its observations are staged for the next save. When a
    /// root walk ends, a complete walk begun in this process erases every head
    /// it did not list whose index entry is gone (counted as deleted unaccepted
    /// when owed) and records its start as the last complete discovery; then
    /// the source's whole persisted debt is aggregated. `None`: a page that is
    /// not a walk's end, or a v1 graph.
    pub(super) fn end(self, index: &mut ScanIndex, walk_ended: bool) -> Option<Report> {
        let Self {
            route,
            root_walk,
            fold,
            staged,
            now_ms,
            ..
        } = self;
        let walk = &mut fold.debt;
        walk.issue |= route.is_none();
        if let Some(route) = route.as_deref().filter(|_| !staged.is_empty()) {
            walk.unavailable |= state_v2::observe_tails(route, staged).is_err();
        }
        if !root_walk || !walk_ended {
            return None;
        }
        match route {
            Some(route) => Some(aggregate(index, &route, walk, now_ms)),
            None if walk.unavailable => Some(Report::UNAVAILABLE),
            None => None,
        }
    }
}

/// Claude history the gate holds as Listed (`decide` or stricter), not refused.
/// No source guard: the list loads only for Claude, so it is empty elsewhere.
fn listed_history_held(index: &ScanIndex, key: &str, listing: &Listing<'_>) -> bool {
    let refused = &index.quarantined_snapshot_fingerprints;
    let owned = index.file_snapshot_fingerprints.get(key);
    claude_history_upgrade::revision_policy(index.active_effective_upload_body_witness_revision)
        .is_some()
        && index.listing_stamp_matches(listing.path, listing.metadata)
        && index.effective_upload_body_witness_revision_requires_adoption(key)
        && !index.claude_reemission_exclusions.pauses_adoption()
        && index.claude_family_listed(listing.path)
        && !owned.is_some_and(|owned| owned.iter().any(|fp| refused.contains_key(fp)))
}

fn aggregate(index: &mut ScanIndex, route: &Path, walk: &Walk, now_ms: u64) -> Report {
    if walk.unavailable {
        return Report::UNAVAILABLE;
    }
    let Ok(keys) = state_v2::tail_head_keys(index) else {
        return Report::UNAVAILABLE;
    };
    let complete = walk.started_at.filter(|_| !walk.incomplete);
    let mut report = walk.sums;
    let mut gone = Vec::new();
    for key in keys
        .into_iter()
        .filter(|key| !walk.listed.contains_key(key))
    {
        if complete.is_some() && !index.files.contains_key(&key) {
            gone.push(key);
        } else {
            report.add(FileDebt::committed(index, &key), now_ms);
        }
    }
    if let Some(started_at) = complete {
        if state_v2::erase_tail(route, index, gone).is_err() {
            return Report::UNAVAILABLE;
        }
        index.tail_discovery.last_complete_discovery_at = Some(started_at);
    }
    report.available = true;
    report.deleted_unaccepted_files = index.tail_discovery.deleted_unaccepted_files;
    report.last_complete_discovery_at = index.tail_discovery.last_complete_discovery_at;
    report
}

#[cfg(test)]
#[path = "g7_debt_tests.rs"]
pub(super) mod tests;
