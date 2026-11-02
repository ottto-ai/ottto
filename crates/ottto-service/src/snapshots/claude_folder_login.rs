//! Names a Claude request from its own session's recorded login.
//!
//! A transcript records the signed-in email and organization. A request with no
//! telemetry is named only when its own file records the folder's known login:
//! the proven owner of a folder that has only ever held one login, or the
//! account a registered slot is bound to. Everything else stays untagged.
//!
//! The email stays in memory: only the comparison result is persisted, as a
//! file location in `FolderRecord::matched`, so a file resumed from its tail keeps
//! its result without the sentence. The whole path stays off until the server
//! advertises `SOLE_LOGIN_WITNESS_CONTRACT`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::claude_money_birth_store::location_key;
use super::claude_request_identity::{
    complete_org, marker_email_digest, marker_org_hash, valid_login, AcceptedBuckets,
};
use super::{local_index_key, ScanIndex, SnapshotItem, SoleLoginWitness};
use crate::claude_local_otel::ClaudeLocalOtelLoadReport;
use crate::claude_status_coverage as coverage;

/// Exact activity-hint capability; anything else leaves the path off.
pub(crate) const SOLE_LOGIN_WITNESS_CONTRACT: &str = "session_request_sole_login_witness:v1";
/// Default folder plus every registered and every previously registered slot.
/// A folder past this bound is never recorded, so it never qualifies.
pub(crate) const MAX_FOLDERS: usize = 1 + 2 * ottto_core::MAX_CLAUDE_ACCOUNT_SLOTS;
/// A folder holding more own files than this stops recording them: the rest
/// stay owed. 160 KiB per folder at most.
const MAX_MATCHED_FILES: usize = 20_000;
/// One folder's re-offer, whole. A bigger folder stays owed.
const MAX_REOFFER_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// One re-offer step; the history gate then paces it page by page. Stepping is
/// what lets a sticky verdict stop the rest of a folder's read.
const REOFFER_STEP_FILES: usize = 2_000;
const HOUR_SECONDS: i64 = 3_600;
const MAX_HASH_TEXT: usize = 128;

/// No re-offer started.
const REOFFER_IDLE: u8 = 0;
/// Re-reading history this folder uploaded before its record existed. Unchanged
/// bodies re-upload nothing.
const REOFFER_CENSUS: u8 = 1;
/// Re-reading this folder's own matched files, so their bodies carry the tag.
const REOFFER_TAG: u8 = 2;
const REOFFER_DONE: u8 = 3;
const REOFFER_TOO_BIG: u8 = 4;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The ledger and status key of one config folder.
pub(crate) fn folder_key(config_dir: &Path) -> String {
    hex(&coverage::home_key(config_dir))
}

/// The one address a recorded `userEmail` sentence names, lowercased. The
/// wording belongs to another program: anything but exactly one well-formed
/// address is no answer.
fn recorded_address(text: &str) -> Option<String> {
    let mut words = text.split_whitespace().filter(|word| word.contains('@'));
    let word = words.next()?;
    if words.next().is_some() {
        return None;
    }
    let address = word.trim_matches(|c: char| ".,;:!?()<>[]\"'`".contains(c));
    let (local, domain) = address.split_once('@')?;
    let well_formed = !local.is_empty()
        && domain.contains('.')
        && !domain.contains('@')
        && !domain.starts_with('.')
        && !domain.ends_with('.');
    well_formed.then(|| address.to_ascii_lowercase())
}

/// The in-memory form of an address: both sides of the comparison use it.
pub(crate) fn address_digest(address: &str) -> String {
    marker_email_digest(&address.trim().to_ascii_lowercase())
}

/// What one transcript read saw. Never serialized, never logged.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct FolderTrace {
    org: Option<String>,
    other_org: bool,
    bad_org: bool,
    email: Option<String>,
    other_email: bool,
    /// A sentence without exactly one address: untagged, no verdict on the folder.
    unreadable_email: bool,
    forked: bool,
    /// The read started at the first byte, so it saw any fork reference.
    whole: bool,
    home: Option<String>,
    location: Option<u64>,
    /// Set for this page only, on a matched own file of a qualified folder.
    qualified: Option<Box<QualifiedFolder>>,
}
crate::heap_layout_bound::fields!(FolderTrace; org, other_org, bad_org, email, other_email, unreadable_email, forked, whole, home, location, qualified);

impl std::fmt::Debug for FolderTrace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderTrace").finish_non_exhaustive()
    }
}

/// Whether this line can change a trace, checked before any allocation.
pub(crate) fn line_matters(value: &Value, inherited: bool) -> bool {
    inherited
        || match value.get("type").and_then(Value::as_str) {
            Some("fork-context-ref") => true,
            Some("attachment") => matches!(
                value.pointer("/attachment/type").and_then(Value::as_str),
                Some("credential_org" | "session_context")
            ),
            _ => false,
        }
}

impl FolderTrace {
    /// Called above the inherited-line return: a copied marker is still a trace.
    pub(crate) fn note_line(&mut self, value: &Value, inherited: bool) {
        let kind = value.get("type").and_then(Value::as_str);
        self.forked |= inherited || kind == Some("fork-context-ref");
        let Some(attachment) = value
            .get("attachment")
            .filter(|_| kind == Some("attachment"))
        else {
            return;
        };
        match attachment.get("type").and_then(Value::as_str) {
            Some("credential_org") => match marker_org_hash(attachment) {
                None => self.bad_org = true,
                Some(org) => note_value(&mut self.org, &mut self.other_org, org),
            },
            Some("session_context") => {
                let text = attachment
                    .pointer("/context/userEmail")
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if text.trim().is_empty() {
                    return;
                }
                match recorded_address(text) {
                    Some(address) => note_value(
                        &mut self.email,
                        &mut self.other_email,
                        address_digest(&address),
                    ),
                    None => self.unreadable_email = true,
                }
            }
            _ => {}
        }
    }

    pub(crate) fn qualified(&self) -> Option<&QualifiedFolder> {
        self.qualified.as_deref()
    }

    /// What `attach_trace` adds to a finished fold: the box and three hashes.
    pub(crate) fn finish_heap_bound() -> usize {
        std::mem::size_of::<Self>() + std::mem::align_of::<Self>() + 3 * MAX_HASH_TEXT
    }
}

fn note_value(first: &mut Option<String>, other: &mut bool, value: String) {
    match first {
        None => *first = Some(value),
        Some(known) if *known == value => {}
        Some(_) => *other = true,
    }
}

/// The ledger's key for one file: the existing location digest, cut to 8 bytes.
fn file_location(index_key: &str) -> u64 {
    let bytes = location_key(index_key).to_bytes();
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Hands the read's trace to the finished Claude items. `whole`: the read began
/// at the file's first byte.
pub(crate) fn attach_trace(
    items: &mut [SnapshotItem],
    path: &Path,
    trace: Option<Box<FolderTrace>>,
    whole: bool,
) {
    let mut trace = trace.unwrap_or_default();
    trace.home = coverage::transcript_home_key(path).map(|home| hex(&home));
    trace.location = Some(file_location(&local_index_key(path)));
    trace.whole = whole;
    for item in items {
        if let Some(fold) = item.claude_money.as_deref_mut() {
            fold.folder_trace = Some(trace.clone());
        }
    }
}

/// One folder's durable evidence: hashes, flags and file digests, no email.
/// Absent members default to "not qualified".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FolderRecord {
    /// The record predates this folder's first read, or that read's login was
    /// knowable. False: its history needs a census read.
    fresh: bool,
    /// Sticky: this folder held another login, so it never names again.
    mixed: bool,
    login: Option<String>,
    org: Option<String>,
    /// A completed proof named `login` for this folder's token.
    owner_proven: bool,
    census_complete: bool,
    /// Earliest request read as unix seconds, floored to the hour.
    covered_from: Option<i64>,
    /// Sorted. Own files whose own marker matched `login` and `org`.
    matched: Vec<u64>,
    reoffer: u8,
    reoffer_cursor: Option<String>,
    /// Contradictions after names were possible. Earlier names stay inferred.
    late_contradictions: u64,
}
crate::heap_layout_bound::fields!(FolderRecord; fresh, mixed, login, org, owner_proven, census_complete, covered_from, matched, reoffer, reoffer_cursor, late_contradictions);

impl FolderRecord {
    fn set_mixed(&mut self) {
        if !self.mixed && (self.census_complete || self.fresh) {
            self.late_contradictions = self.late_contradictions.saturating_add(1);
        }
        self.mixed = true;
        self.matched = Vec::new();
        self.reoffer_cursor = None;
    }

    fn note_pair(&mut self, login: Option<&str>, org: Option<&str>) {
        let other = |known: &Option<String>, seen: Option<&str>| matches!((known.as_deref(), seen), (Some(known), Some(seen)) if known != seen);
        if other(&self.login, login) || other(&self.org, org) {
            self.set_mixed();
        }
    }

    /// One status report. No proof yet only means "not yet".
    fn absorb_owner(&mut self, report: &OwnerReport) {
        if report.other_account {
            self.set_mixed();
        }
        let Some((login, org)) = &report.pair else {
            return;
        };
        self.note_pair(Some(login), Some(org));
        self.login.get_or_insert_with(|| login.clone());
        self.org.get_or_insert_with(|| org.clone());
        if let Some(proven) = &report.proven {
            if proven != report.pair.as_ref().unwrap_or(proven) {
                self.set_mixed();
            } else {
                self.owner_proven = true;
            }
        }
    }

    fn matches_file(&self, location: u64) -> bool {
        self.matched.binary_search(&location).is_ok()
    }

    fn set_matched(&mut self, location: u64, matched: bool) {
        match (self.matched.binary_search(&location), matched) {
            (Err(at), true) if self.matched.len() < MAX_MATCHED_FILES => {
                self.matched.insert(at, location);
            }
            (Ok(at), false) => {
                self.matched.remove(at);
            }
            _ => {}
        }
    }

    /// An empty census completes with nothing covered: the folder's first
    /// request then sets the floor.
    fn note_requests(&mut self, item: &SnapshotItem) {
        if self.census_complete && self.covered_from.is_some() {
            return;
        }
        // Request-owned hours are built after this point; the occurrences are
        // the same requests.
        let earliest = item
            .claude_usage_occurrences
            .values()
            .filter(|occurrence| !occurrence.usage.is_zero())
            .filter_map(|occurrence| occurrence.timestamp.as_deref())
            .filter_map(|at| OffsetDateTime::parse(at, &Rfc3339).ok())
            .map(|at| at.unix_timestamp().div_euclid(HOUR_SECONDS) * HOUR_SECONDS)
            .min();
        self.covered_from = match (self.covered_from, earliest) {
            (Some(known), Some(at)) => Some(known.min(at)),
            (known, at) => known.or(at),
        };
    }
}

/// What this process's status pass last established for one folder. In memory.
#[derive(Clone, Default, PartialEq, Eq)]
pub(crate) struct OwnerReport {
    pub(crate) slot: bool,
    /// The strong pair: a slot's registered account, or what the default
    /// folder's `.claude.json` names.
    pub(crate) pair: Option<(String, String)>,
    /// The pair a completed proof named for the default folder's current token.
    pub(crate) proven: Option<(String, String)>,
    /// `address_digest` of the login's own email.
    pub(crate) email: Option<String>,
    /// A registered slot now holds another account.
    pub(crate) other_account: bool,
}

/// A folder's verdict, handed to the classifier through its own files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QualifiedFolder {
    pub(crate) login: String,
    pub(crate) org: String,
    pub(crate) witness: SoleLoginWitness,
}
crate::heap_layout_bound::fields!(QualifiedFolder; login, org, witness);

/// The (login, org, covered_from, kind) a folder may name, or `None` while any
/// condition is unmet. A slot's account is its registration, so a slot the
/// record saw from its first read needs no census; an upgraded slot does.
pub(crate) fn qualify<'r>(
    record: &'r FolderRecord,
    report: &OwnerReport,
) -> Option<(&'r str, &'r str, i64, &'static str)> {
    let login = record.login.as_deref()?;
    let org = record.org.as_deref()?;
    let (known_login, known_org) = report.pair.as_ref()?;
    let eligible = if report.slot {
        record.fresh || record.census_complete
    } else {
        record.census_complete && record.owner_proven
    };
    (eligible
        && !record.mixed
        && !report.other_account
        && report.email.is_some()
        && known_login == login
        && known_org == org)
        .then_some(record.covered_from)
        .flatten()
        .map(|covered_from| {
            let kind = if report.slot { "slot" } else { "folder" };
            (login, org, covered_from, kind)
        })
}

#[derive(Default)]
struct Feed {
    enabled: bool,
    /// Sticky folders: no profile call is worth making.
    stopped: BTreeSet<String>,
    reports: BTreeMap<String, OwnerReport>,
}

#[cfg(not(test))]
static FEED: std::sync::Mutex<Option<Feed>> = std::sync::Mutex::new(None);

#[cfg(not(test))]
fn with_feed<R>(use_feed: impl FnOnce(&mut Feed) -> R) -> R {
    use_feed(
        FEED.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert_with(Feed::default),
    )
}

#[cfg(test)]
thread_local! {
    static FEED: std::cell::RefCell<Feed> = std::cell::RefCell::new(Feed::default());
}

#[cfg(test)]
fn with_feed<R>(use_feed: impl FnOnce(&mut Feed) -> R) -> R {
    FEED.with(|feed| use_feed(&mut feed.borrow_mut()))
}

/// Status pass: whether a profile call could still help this folder.
pub(crate) fn proof_wanted(home: &str) -> bool {
    with_feed(|feed| feed.enabled && !feed.stopped.contains(home))
}

/// Status pass: the folder's latest report. A slot's other account stays
/// reported until a sync pass absorbs it into the sticky ledger.
pub(crate) fn observe_owner(home: String, mut report: OwnerReport) {
    with_feed(|feed| {
        report.other_account |= feed
            .reports
            .get(&home)
            .is_some_and(|known| known.other_account);
        feed.reports.insert(home, report);
    });
}

/// Sync pass, before this page's evidence: records each folder the first time
/// it is seen. Off, it writes nothing.
pub(crate) fn begin_page(
    index: &mut ScanIndex,
    committed: &ScanIndex,
    roots: &[PathBuf],
    enabled: bool,
) {
    with_feed(|feed| feed.enabled = enabled);
    if !enabled {
        return;
    }
    for root in roots {
        let Some(config) = root.parent() else {
            continue;
        };
        let key = folder_key(config);
        if index.claude_folder_login_ledger.contains_key(&key)
            || index.claude_folder_login_ledger.len() >= MAX_FOLDERS
        {
            continue;
        }
        // The committed index predates this page's reads.
        let prefix = format!("{}/", root.to_string_lossy());
        let fresh = !committed
            .files
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .next()
            .is_some_and(|(path, _)| path.starts_with(prefix.as_str()));
        index.claude_folder_login_ledger.insert(
            key,
            FolderRecord {
                fresh,
                ..FolderRecord::default()
            },
        );
    }
    let stopped = index
        .claude_folder_login_ledger
        .iter()
        .filter(|(_, record)| record.mixed)
        .map(|(home, _)| home.clone())
        .collect();
    with_feed(|feed| feed.stopped = stopped);
}

/// Whether this read's own lines record exactly the folder's known login.
fn read_matches(trace: &FolderTrace, report: &OwnerReport) -> bool {
    let Some((_, org)) = report.pair.as_ref() else {
        return false;
    };
    !trace.other_email
        && !trace.other_org
        && !trace.bad_org
        && !trace.unreadable_email
        && trace.email.is_some()
        && trace.email == report.email
        && trace.org.as_ref() == Some(org)
}

/// One read's evidence on its folder. Sticky on any mismatch; a read of a folder
/// with no known login leaves that history for a census read.
fn note_read(
    record: &mut FolderRecord,
    item: &SnapshotItem,
    trace: &FolderTrace,
    report: Option<&OwnerReport>,
    own: bool,
) {
    let names_someone = trace.email.is_some() || trace.org.is_some();
    if trace.bad_org || trace.other_org || trace.other_email {
        record.set_mixed();
    }
    let Some(report) = report.filter(|report| report.pair.is_some() && report.email.is_some())
    else {
        if names_someone && !record.census_complete {
            record.fresh = false;
        }
        return;
    };
    let org_differs = trace.org.is_some()
        && trace.org.as_deref() != report.pair.as_ref().map(|(_, org)| org.as_str());
    let email_differs = trace.email.is_some() && trace.email != report.email;
    if org_differs || email_differs {
        record.set_mixed();
    }
    let matches = read_matches(trace, report);
    // An upgraded slot has no history of its own, so every session must carry
    // the matching login. A subagent file stands on its own record.
    let root_file = super::claude_snapshot_family_root_ref(item) == item.source_session_id;
    if report.slot && !record.fresh && !record.census_complete && root_file && !matches {
        record.set_mixed();
    }
    if record.mixed {
        return;
    }
    record.note_requests(item);
    let Some(location) = trace.location else {
        return;
    };
    if !own {
        record.set_matched(location, false);
    } else if trace.whole {
        // A tail read carries the earlier result: it never saw the file's start.
        record.set_matched(location, matches);
    }
}

/// Sync pass, once this page's sidecar rows are loaded: each re-parsed file feeds
/// its folder, then a clean terminal traversal completes the census.
pub(crate) fn note_page(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    census_clean: bool,
) {
    let reports = with_feed(|feed| feed.reports.clone());
    let mut ledger = std::mem::take(&mut index.claude_folder_login_ledger);
    for (home, record) in &mut ledger {
        if let Some(report) = reports.get(home) {
            record.absorb_owner(report);
        }
    }
    for item in items {
        let Some(trace) = item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.folder_trace.as_deref())
        else {
            continue;
        };
        let Some(record) = trace.home.as_deref().and_then(|home| ledger.get_mut(home)) else {
            continue;
        };
        let own = own_session(item, index, api);
        let report = trace.home.as_deref().and_then(|home| reports.get(home));
        note_read(record, item, trace, report, own);
        let root = super::claude_snapshot_family_root_ref(item);
        for row in api.evidence.get(root).into_iter().flatten() {
            if let Some(login) = valid_login(row, root) {
                record.note_pair(Some(login), complete_org(row));
            }
        }
    }
    for record in ledger.values_mut().filter(|_| census_clean) {
        record.census_complete |= record.fresh;
    }
    index.claude_folder_login_ledger = ledger;
}

/// Sync pass, before the walk, in the same save as the ledger: moves each
/// folder's single re-offer one step. History already uploaded untagged reaches
/// the tag only through one more read of the file. Each file goes through the
/// history gate like any owed file, once. Files of a sticky folder are never
/// offered, so a mixed folder stops at its first step that sees the mismatch.
pub(crate) fn step_reoffers(index: &mut ScanIndex, enabled: bool) {
    if !enabled {
        return;
    }
    let reports = with_feed(|feed| feed.reports.clone());
    let mut due = BTreeSet::new();
    for (home, record) in &mut index.claude_folder_login_ledger {
        if record.mixed {
            continue;
        }
        if record.reoffer == REOFFER_IDLE {
            let report = reports.get(home);
            if !record.fresh && !record.census_complete {
                record.reoffer = REOFFER_CENSUS;
            } else if report.is_some_and(|report| report.slot) && record.fresh {
                record.reoffer = REOFFER_DONE;
            } else if report.is_some_and(|report| qualify(record, report).is_some()) {
                record.reoffer = REOFFER_TAG;
            }
        }
        if matches!(record.reoffer, REOFFER_CENSUS | REOFFER_TAG) {
            due.insert(home.clone());
        }
    }
    if due.is_empty() {
        return;
    }
    let mut files = BTreeMap::<&str, Vec<(&str, u64, bool)>>::new();
    for (key, entry) in &index.files {
        let Some(home) = coverage::transcript_home_key(Path::new(key)).map(|home| hex(&home))
        else {
            continue;
        };
        let Some(home) = due.get(&home) else {
            continue;
        };
        let owed = index.effective_upload_body_witness_revision_requires_adoption(key);
        files
            .entry(home.as_str())
            .or_default()
            .push((key.as_str(), entry.size_bytes, owed));
    }
    let mut owe = Vec::new();
    let mut steps = Vec::new();
    for home in &due {
        let Some(record) = index.claude_folder_login_ledger.get(home) else {
            continue;
        };
        let held = files.get(home.as_str()).map_or(&[][..], Vec::as_slice);
        // Earlier steps settle first: a verdict they reach can stop this one.
        if held.iter().any(|(.., owed)| *owed) {
            continue;
        }
        let tag = record.reoffer == REOFFER_TAG;
        let offered = held
            .iter()
            .filter(|(key, ..)| !tag || record.matches_file(file_location(key)))
            .collect::<Vec<_>>();
        if record.reoffer_cursor.is_none()
            && offered.iter().map(|(_, bytes, _)| *bytes).sum::<u64>() > MAX_REOFFER_BYTES
        {
            steps.push((home.clone(), REOFFER_TOO_BIG, None));
            continue;
        }
        let cursor = record.reoffer_cursor.as_deref();
        let step = offered
            .iter()
            .filter(|(key, ..)| cursor < Some(*key))
            .take(REOFFER_STEP_FILES)
            .map(|(key, ..)| (*key).to_owned())
            .collect::<Vec<_>>();
        let last = step.last().cloned();
        // A census whose every read has settled is complete: a file that never
        // settles stays owed above, and so does the folder.
        let next = match (last.is_some(), tag) {
            (true, _) => record.reoffer,
            (false, true) => REOFFER_DONE,
            (false, false) => REOFFER_IDLE,
        };
        owe.extend(step);
        steps.push((home.clone(), next, last));
    }
    drop(files);
    let to = index
        .active_effective_upload_body_witness_revision
        .saturating_sub(1);
    for key in owe {
        index.re_owe_effective_upload_body_witness_revision(&key, to);
    }
    for (home, reoffer, cursor) in steps {
        if let Some(record) = index.claude_folder_login_ledger.get_mut(&home) {
            record.census_complete |= reoffer == REOFFER_IDLE;
            record.reoffer = reoffer;
            record.reoffer_cursor = cursor;
        }
    }
}

/// Hour-floored RFC 3339, as the witness carries it.
fn covered_from_text(covered_from: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(covered_from)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

/// The own-session gate for one transcript. Every condition is per file: a
/// forked or copied session, or one with any telemetry row of its own, keeps its
/// existing path.
fn own_session(item: &SnapshotItem, index: &ScanIndex, api: &ClaudeLocalOtelLoadReport) -> bool {
    let Some(fold) = item.claude_money.as_deref() else {
        return false;
    };
    if fold
        .folder_trace
        .as_deref()
        .map_or(true, |trace| trace.forked)
        || item.claude_context_curve_owned_start_proven
        || fold.copied_or_moved(item.claude_usage_occurrences.values())
        || index.claude_duplicate_request_witness_overflowed
    {
        return false;
    }
    let root = super::claude_snapshot_family_root_ref(item);
    let has_telemetry = api.evidence.get(root).is_some_and(|rows| {
        rows.iter()
            .any(|row| item.claude_usage_request_ids.contains(&row.request_id))
    });
    if has_telemetry {
        return false;
    }
    let duplicates = &index.claude_duplicate_request_owners;
    duplicates.is_empty()
        || !item.claude_usage_request_ids.iter().any(|request| {
            duplicates.contains_key(&format!("{:x}", sha2::Sha256::digest(request.as_bytes())))
        })
}

/// Sync pass, before request accounts reconcile: stamps each matched own file of
/// a qualified folder, which is the classifier's only way to reach this basis.
pub(crate) fn stamp_page(
    items: &mut [SnapshotItem],
    index: &ScanIndex,
    api: &ClaudeLocalOtelLoadReport,
    accepted: &AcceptedBuckets,
) {
    let reports = with_feed(|feed| feed.reports.clone());
    let mut verdicts = BTreeMap::<String, Option<QualifiedFolder>>::new();
    for item in items {
        let Some((home, location)) = item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.folder_trace.as_deref())
            .and_then(|trace| Some((trace.home.clone()?, trace.location?)))
        else {
            continue;
        };
        let verdict = verdicts.entry(home.clone()).or_insert_with(|| {
            let record = index.claude_folder_login_ledger.get(&home)?;
            let (login, org, covered_from, kind) = qualify(record, reports.get(&home)?)?;
            Some(QualifiedFolder {
                login: login.to_owned(),
                org: org.to_owned(),
                witness: SoleLoginWitness {
                    v: 1,
                    kind: kind.to_owned(),
                    folder: accepted.folder_token(&home)?,
                    covered_from: covered_from_text(covered_from)?,
                },
            })
        });
        let matched = index
            .claude_folder_login_ledger
            .get(&home)
            .is_some_and(|record| record.matches_file(location));
        let verdict = verdict
            .clone()
            .filter(|_| matched && own_session(item, index, api));
        if let Some(trace) = item
            .claude_money
            .as_deref_mut()
            .and_then(|fold| fold.folder_trace.as_deref_mut())
        {
            trace.qualified = verdict.map(Box::new);
        }
    }
}

#[cfg(test)]
#[path = "claude_folder_login_tests.rs"]
mod tests;
