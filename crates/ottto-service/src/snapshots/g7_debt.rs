//! G7 (D145) freshness debt: each file's oldest change that no matched exact
//! ACK covers yet, kept as metadata of its Tail head and `tail.revision` rows so
//! it survives restarts, and reported per source on the `freshness_alarm` line.
//! Diagnostics only: it reads the index and the listing, stages debt-only
//! observations, and never grants, withholds or orders a read, upload or
//! settlement. One path for every source; sources differ only by the index
//! state the existing adapters already keep.
use super::codex_compressed_input::ArchiveDisposition;
use super::state_v2::{DebtSummary, NoUploadRequired, Observation, Representation, TailHead};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

const ALARM_AFTER_MS: u64 = 6 * 60 * 60 * 1000;

// Reason bits, bit 0 first. Bits 9 and up are free: reserve them here first.
const GROWTH_CLAIM_WAIT: u32 = 1 << 0;
const UNREAD: u32 = 1 << 1;
const HELD_REVISION: u32 = 1 << 2;
const RETRY_PENDING: u32 = 1 << 3;
const QUARANTINE: u32 = 1 << 4;
const SET_ASIDE: u32 = 1 << 5;
const AUTHORITY_TERMINAL: u32 = 1 << 6;
const CENSUS_HELD: u32 = 1 << 7;
/// RF1's delivery debt (D177 design A). Never set here; kept as written and
/// counted as held.
const DELIVERY_DEBT: u32 = 1 << 8;
/// The bits this writer recomputes on every observation; others stay as written.
const OWN: u32 = GROWTH_CLAIM_WAIT
    | UNREAD
    | HELD_REVISION
    | RETRY_PENDING
    | QUARANTINE
    | SET_ASIDE
    | AUTHORITY_TERMINAL
    | CENSUS_HELD;
/// Owed but not waiting for a read.
const HELD: u32 = (OWN & !UNREAD) | DELIVERY_DEBT;

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
    /// Reasons that hold the whole file.
    holds: u32,
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
fn reconcile(committed: &BTreeMap<u64, Revision>, live: &Live, set_aside: bool) -> Plan {
    let mut plan = Plan::default();
    if live.evidence.is_some() {
        plan.resolved = committed.keys().copied().collect();
        return plan;
    }
    let holds = live.holds | if set_aside { SET_ASIDE } else { 0 };
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
        let mut bits = holds | (written & !OWN);
        if end > live.read {
            bits |= UNREAD;
        }
        if start < live.read {
            bits |= HELD_REVISION;
        }
        bits
    };
    let covered = |end: u64| live.exact && end <= live.accepted;
    let collapse = live.replaced
        || committed.values().any(|revision| {
            revision.end() > live.len
                || matches!(revision.extent, Extent::ArchiveWhole { .. }) != archive
        });
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
}
impl FileDebt {
    /// A head this build cannot read: owed, age unknown. Never written over.
    const UNKNOWN: Self = Self {
        owed: true,
        earliest: None,
        lower_bound: true,
        held: false,
        unread_bytes: 0,
    };
    fn of(owed: &[Revision]) -> Self {
        let summary = summary(owed, None);
        Self {
            owed: !owed.is_empty(),
            earliest: summary.earliest_unacked_change_at,
            lower_bound: summary.lower_bound,
            held: summary.reason_bits & HELD != 0,
            unread_bytes: owed
                .iter()
                .filter(|revision| revision.reason_bits & UNREAD != 0)
                .map(Revision::bytes)
                .sum(),
        }
    }
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

/// A source's persisted debt, as of one walk's end. No cap: every owed file.
#[derive(Clone, Debug, Default)]
pub(super) struct Report {
    available: bool,
    outstanding_files: u64,
    held_files: u64,
    unread_bytes: u64,
    /// Each owed file of known age: (earliest change, lower bound).
    dated: Vec<(u64, bool)>,
    unknown_age_files: u64,
    no_upload_required_files: u64,
    deleted_unaccepted_files: u64,
    last_complete_discovery_at: Option<u64>,
}
impl Report {
    /// Storage could not be read, or this process has no aggregate yet: never fresh.
    pub(super) fn unavailable() -> Self {
        Self::default()
    }
    fn add(&mut self, debt: FileDebt) {
        if !debt.owed {
            return;
        }
        self.outstanding_files += 1;
        self.held_files += u64::from(debt.held);
        self.unread_bytes += debt.unread_bytes;
        match debt.earliest {
            Some(at) => self.dated.push((at, debt.lower_bound)),
            None => self.unknown_age_files += 1,
        }
    }
    fn over_6h_files(&self, now_ms: u64) -> u64 {
        self.dated
            .iter()
            .filter(|(at, _)| now_ms.saturating_sub(*at) > ALARM_AFTER_MS)
            .count() as u64
    }
    /// Over 6 h, unknown age, or no complete discovery within 6 h.
    pub(super) fn alarm(&self, now_ms: u64) -> bool {
        !self.available
            || self.over_6h_files(now_ms) > 0
            || self.unknown_age_files > 0
            || self
                .last_complete_discovery_at
                .map_or(true, |at| now_ms.saturating_sub(at) > ALARM_AFTER_MS)
    }
    /// The ten per-source fields; `null` when storage could not be read.
    pub(super) fn fields(&self, now_ms: u64) -> serde_json::Value {
        if !self.available {
            return serde_json::Value::Null;
        }
        let oldest = self
            .dated
            .iter()
            .fold(None, |found, &(at, lower)| match found {
                Some((old, old_lower)) if old < at => Some((old, old_lower)),
                Some((old, old_lower)) if old == at => Some((old, old_lower || lower)),
                _ => Some((at, lower)),
            });
        serde_json::json!({
            "outstanding_files": self.outstanding_files,
            "held_files": self.held_files,
            "unread_bytes": self.unread_bytes,
            "over_6h_files": self.over_6h_files(now_ms),
            "oldest_age_s": oldest.map(|(at, _)| now_ms.saturating_sub(at) / 1000),
            "oldest_age_lower_bound": oldest.is_some_and(|(_, lower)| lower)
                || self.unknown_age_files > 0,
            "no_upload_required_files": self.no_upload_required_files,
            "deleted_unaccepted_files": self.deleted_unaccepted_files,
            "last_complete_discovery_at": self.last_complete_discovery_at.map(|at| at / 1000),
            "alarm": self.alarm(now_ms),
        })
    }
}

/// One root walk's process-local state. Debt itself is persisted; this only
/// knows which heads the walk listed, so a walk resumed after a restart is
/// never complete.
#[derive(Debug, Default)]
struct Walk {
    /// Unix ms when this process saw the walk begin at the roots.
    started_at: Option<u64>,
    incomplete: bool,
    unavailable: bool,
    /// Listed keys with a committed head.
    seen: BTreeSet<String>,
    /// This walk's view of every file it observed with a head or with debt.
    files: BTreeMap<String, FileDebt>,
    no_upload_required: u64,
}

#[derive(Default)]
struct Walks {
    walks: [Option<Walk>; 3],
    last: [Option<Report>; 3],
}

#[cfg(not(test))]
static WALKS: std::sync::Mutex<Walks> = std::sync::Mutex::new(Walks {
    walks: [None, None, None],
    last: [None, None, None],
});

#[cfg(test)]
thread_local! {
    static WALKS_FOR_TEST: std::cell::RefCell<Walks> = std::cell::RefCell::new(Walks::default());
}

#[cfg(not(test))]
fn with_walks<T>(body: impl FnOnce(&mut Walks) -> T) -> T {
    let mut walks = WALKS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body(&mut walks)
}

#[cfg(test)]
fn with_walks<T>(body: impl FnOnce(&mut Walks) -> T) -> T {
    WALKS_FOR_TEST.with(|walks| body(&mut walks.borrow_mut()))
}

/// The aggregate of the source's last walk, for a pass that failed before one.
pub(super) fn last_report(source: SnapshotSource) -> Option<Report> {
    with_walks(|walks| walks.last[source as usize].clone())
}

/// One listed file, as the walk saw it.
pub(super) struct Listing<'a> {
    pub(super) path: &'a Path,
    pub(super) metadata: &'a std::fs::Metadata,
    /// Inside the discovery window: outside it no new debt starts (the read
    /// filters, as for the old never-indexed count).
    pub(super) in_window: bool,
    /// Excluded from snapshots by design (a Claude subagent journal): owed
    /// until per-file evidence exists, which no read records yet.
    pub(super) excluded: bool,
}

/// One discovery page of one source.
pub(super) struct Page {
    source: SnapshotSource,
    /// `None`: a v1 graph, which has no Tail store and so no debt.
    route: Option<PathBuf>,
    root_walk: bool,
    walk: Walk,
    /// Keys whose observation is staged and not yet committed, this page's
    /// included: each is a delta from the committed rows, so none is staged
    /// twice before the save.
    pending: BTreeSet<String>,
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

impl Page {
    pub(super) fn begin(
        source: SnapshotSource,
        index: &ScanIndex,
        traversal: &ScanTraversalCheckpoint,
        root_walk: bool,
    ) -> Self {
        let now_ms = sampled_scan::now_seconds().saturating_mul(1000);
        let (route, pending, unavailable) = match state_v2::tail_route_path(index) {
            Ok(Some(route)) => match state_v2::tail_observed_keys(&route) {
                Ok(pending) => (Some(route), pending, false),
                Err(_) => (None, BTreeSet::new(), true),
            },
            Ok(None) => (None, BTreeSet::new(), false),
            Err(_) => (None, BTreeSet::new(), true),
        };
        // A walk begins with exactly the configured roots pending.
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
        let mut walk = if !root_walk {
            Walk::default()
        } else if begins {
            // A root that did not resolve, or failed to, is not listed: the
            // walk proves nothing absent under it.
            let counts = &traversal.counts;
            Walk {
                started_at: Some(now_ms),
                incomplete: listing_errors(counts) != (0, 0) || counts.disappeared_file_count > 0,
                ..Walk::default()
            }
        } else {
            with_walks(|walks| walks.walks[source as usize].take()).unwrap_or_default()
        };
        walk.unavailable |= unavailable;
        Self {
            source,
            route,
            root_walk,
            walk,
            pending,
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
            self.walk.incomplete = true;
        }
    }

    /// A configured root that is not there proves nothing absent.
    pub(super) fn root_missing(&mut self) {
        self.walk.incomplete = true;
    }

    /// No complete discovery yet, or a change older than the last one that
    /// would have recorded it: its first change can only be a lower bound.
    fn bootstrap(&self, mtime: Option<u64>) -> bool {
        match (self.last_complete, mtime) {
            (Some(complete), Some(mtime)) => mtime <= complete,
            _ => true,
        }
    }

    fn live(
        &self,
        index: &ScanIndex,
        traversal: &ScanTraversalCheckpoint,
        key: &str,
        listing: &Listing<'_>,
    ) -> Live {
        let metadata = listing.metadata;
        let len = metadata.len();
        // A future mtime is a regressed clock: unknown, never fresh.
        let mtime = metadata
            .modified()
            .ok()
            .and_then(unix_nanos)
            .map(|nanos| nanos / 1_000_000)
            .filter(|ms| ms / 1000 <= self.now_ms / 1000);
        let mut holds = 0;
        if sampled_audit::growth_selectable(
            self.source,
            listing.path,
            Some(&index.v2().growth_retention),
        ) {
            holds |= GROWTH_CLAIM_WAIT;
        }
        if index.authority_terminal_member(listing.path) {
            holds |= AUTHORITY_TERMINAL;
        } else if claude_index_path_member_ref(listing.path).is_some_and(|member| {
            index
                .claude_usage_authority_quarantine
                .contains_key(member.root)
        }) {
            holds |= RETRY_PENDING;
        }
        if index.decode_holds_file(key) {
            holds |= QUARANTINE;
        }
        if traversal
            .residue
            .codex_inventory_hold
            .as_ref()
            .is_some_and(|hold| hold.owed.contains(key))
        {
            holds |= CENSUS_HELD;
        }
        // Never indexed: no stored state, so its age is a lower bound.
        let mut live = Live {
            len,
            representation: Representation::Tail,
            exact: false,
            accepted: 0,
            read: 0,
            replaced: false,
            holds,
            evidence: None,
            change: (mtime, true),
            quiet: !listing.in_window,
        };
        if listing.excluded {
            live.representation = Representation::NonTail;
            return live;
        }
        if codex_archive_path(listing.path) {
            live.representation = Representation::Archive;
            let Some(archive) = index.archives.get(key) else {
                return live;
            };
            live.change.1 = self.bootstrap(mtime);
            if !archive.matches_metadata(metadata) {
                live.replaced = true;
                return live;
            }
            match &archive.disposition {
                ArchiveDisposition::Acquired => {
                    (live.exact, live.accepted, live.read) = (true, len, len);
                }
                ArchiveDisposition::Empty => {
                    live.evidence = Some(NoUploadRequired::ZeroUsageLines);
                }
                ArchiveDisposition::Held { .. } => live.read = len,
                ArchiveDisposition::HeaderValidated | ArchiveDisposition::Pending => {}
            }
            return live;
        }
        let Some(entry) = index.files.get(key) else {
            return live;
        };
        let unchanged = entry.same_listing_stamp_as(metadata);
        let birth = metadata.created().ok().and_then(unix_nanos);
        let same_object = entry.opened_birth_nanos == 0 || birth == Some(entry.opened_birth_nanos);
        let grown = !unchanged && same_object && len > entry.size_bytes;
        live.exact = index.file_upload_context_enabled()
            && !index.file_upload_context_requires_adoption(key)
            && (unchanged || grown);
        live.read = match (unchanged, grown) {
            (true, _) => len,
            (false, true) => entry.size_bytes,
            (false, false) => 0,
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

    /// Reconcile one listed file and stage what changed. A head this build
    /// cannot read is counted unknown and never written (F2, F4).
    pub(super) fn listed(
        &mut self,
        index: &ScanIndex,
        traversal: &ScanTraversalCheckpoint,
        listing: Listing<'_>,
    ) {
        if self.route.is_none() {
            return;
        }
        let key = local_index_key(listing.path);
        let live = self.live(index, traversal, &key, &listing);
        if live.evidence.is_some() {
            self.walk.no_upload_required += 1;
        }
        // One keyed read per listed file; an absent head is `None`.
        let head = match state_v2::load_head(index, &key, u32::MAX) {
            Ok(head) => head,
            Err(_) => {
                self.walk.seen.insert(key.clone());
                self.walk.files.insert(key, FileDebt::UNKNOWN);
                return;
            }
        };
        if head.is_some() {
            self.walk.seen.insert(key.clone());
        }
        let committed = match &head {
            Some(head) => match revisions(index, &key, head) {
                Some(committed) => committed,
                None => {
                    self.walk.files.insert(key, FileDebt::UNKNOWN);
                    return;
                }
            },
            None => BTreeMap::new(),
        };
        let mut plan = reconcile(&committed, &live, false);
        if !plan.owed.is_empty() && matches!(state_v2::tail_set_aside(index, &key), Ok(Some(_))) {
            plan = reconcile(&committed, &live, true);
        }
        let summary = summary(&plan.owed, live.evidence);
        let changed = !plan.resolved.is_empty()
            || !plan.replaced.is_empty()
            || !plan.added.is_empty()
            || head
                .as_ref()
                .is_some_and(|head| head.common.debt != summary);
        if changed && self.pending.insert(key.clone()) {
            // F1: the head's own representation and the full recomputed summary.
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
        if head.is_some() || !plan.owed.is_empty() {
            self.walk.files.insert(key, FileDebt::of(&plan.owed));
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
            source,
            route,
            root_walk,
            mut walk,
            staged,
            ..
        } = self;
        if let Some(route) = route.as_deref().filter(|_| !staged.is_empty()) {
            walk.unavailable |= state_v2::observe_tails(route, staged).is_err();
        }
        if !root_walk {
            return None;
        }
        if !walk_ended {
            with_walks(|walks| walks.walks[source as usize] = Some(walk));
            return None;
        }
        let report = match route {
            Some(route) => aggregate(index, &route, walk),
            None if walk.unavailable => Report::unavailable(),
            None => return None,
        };
        with_walks(|walks| walks.last[source as usize] = Some(report.clone()));
        Some(report)
    }
}

fn aggregate(index: &mut ScanIndex, route: &Path, walk: Walk) -> Report {
    if walk.unavailable {
        return Report::unavailable();
    }
    let Ok(keys) = state_v2::tail_head_keys(index) else {
        return Report::unavailable();
    };
    let unlisted = |key: &&String| !walk.seen.contains(*key) && !walk.files.contains_key(*key);
    let mut erased = BTreeSet::new();
    if let (Some(started_at), false) = (walk.started_at, walk.incomplete) {
        let gone: Vec<String> = keys
            .iter()
            .filter(unlisted)
            .filter(|key| index.files.get(key.as_str()).is_none())
            .cloned()
            .collect();
        if state_v2::erase_tail(route, index, gone.iter().cloned()).is_err() {
            return Report::unavailable();
        }
        erased.extend(gone);
        index.tail_discovery.last_complete_discovery_at = Some(started_at);
    }
    let mut report = Report {
        available: true,
        no_upload_required_files: walk.no_upload_required,
        deleted_unaccepted_files: index.tail_discovery.deleted_unaccepted_files,
        last_complete_discovery_at: index.tail_discovery.last_complete_discovery_at,
        ..Report::default()
    };
    for key in keys
        .iter()
        .filter(unlisted)
        .filter(|key| !erased.contains(*key))
    {
        report.add(match state_v2::load_head(index, key, u32::MAX) {
            Ok(Some(head)) => revisions(index, key, &head).map_or(FileDebt::UNKNOWN, |owed| {
                FileDebt::of(&owed.into_values().collect::<Vec<_>>())
            }),
            Ok(None) => FileDebt::default(),
            Err(_) => FileDebt::UNKNOWN,
        });
    }
    for debt in walk.files.values() {
        report.add(*debt);
    }
    report
}

#[cfg(test)]
#[path = "g7_debt_tests.rs"]
mod tests;
