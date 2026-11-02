//! Per-folder sole-login evidence for one Claude config folder.
//!
//! A request with no telemetry can be named only when its folder has only ever
//! held one login. The status pass proves the token's owner, the transcript
//! read reports every organization and email a file names (inherited lines
//! included), and this ledger keeps what both saw across restarts. A contradiction
//! is sticky; a failed or skipped proof only means "not yet". The whole path stays
//! off until the server advertises `SOLE_LOGIN_WITNESS_CONTRACT`.
//!
//! The ledger holds hashes and counts only. Its size is bounded by `MAX_FOLDERS`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Digest;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::claude_request_identity::{
    complete_org, marker_email_digest, marker_org_hash, valid_login, AcceptedBuckets, OrgMarkers,
};
use super::{ScanIndex, SessionAccountEvidence, SnapshotItem, SoleLoginWitness};
use crate::claude_local_otel::ClaudeLocalOtelLoadReport;
use crate::claude_status_coverage as coverage;

/// Exact activity-hint capability; anything else leaves the path off.
pub(crate) const SOLE_LOGIN_WITNESS_CONTRACT: &str = "session_request_sole_login_witness:v1";
/// Default folder plus every registered and every previously registered slot.
/// A folder past this bound is never recorded, so it never qualifies.
pub(crate) const MAX_FOLDERS: usize = 1 + 2 * ottto_core::MAX_CLAUDE_ACCOUNT_SLOTS;
const HOUR_SECONDS: i64 = 3_600;
const MAX_HASH_TEXT: usize = 128;

const SPLIT_LOGIN: u16 = 1 << 0;
const OTHER_OWNER: u16 = 1 << 1;
const OTHER_SLOT: u16 = 1 << 2;
const OTHER_ORG: u16 = 1 << 3;
const BAD_ORG: u16 = 1 << 4;
const OTHER_LOGIN: u16 = 1 << 5;
const OTHER_EMAIL: u16 = 1 << 6;
const OTHER_BACKUP: u16 = 1 << 7;

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The ledger and status key of one config folder.
pub(crate) fn folder_key(config_dir: &Path) -> String {
    hex(&coverage::home_key(config_dir))
}

pub(crate) fn slot_key(slot_id: &str) -> String {
    hex(&coverage::slot_digest(slot_id))
}

/// What one transcript read saw for the ledger. Never serialized.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FolderTrace {
    org: Option<String>,
    other_org: bool,
    bad_org: bool,
    email: Option<String>,
    other_email: bool,
    forked: bool,
    home: Option<String>,
    /// Set for this page only, on an own-session file of a qualified folder.
    sole: Option<Box<QualifiedFolder>>,
}
crate::heap_layout_bound::fields!(FolderTrace; org, other_org, bad_org, email, other_email, forked, home, sole);

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
                    .get("context")
                    .and_then(|context| context.get("userEmail"))
                    .and_then(Value::as_str)
                    .map(|text| text.trim().to_ascii_lowercase())
                    .unwrap_or_default();
                if !text.is_empty() {
                    note_value(
                        &mut self.email,
                        &mut self.other_email,
                        marker_email_digest(&text),
                    );
                }
            }
            _ => {}
        }
    }

    pub(crate) fn sole(&self) -> Option<&QualifiedFolder> {
        self.sole.as_deref()
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

/// Hands the read's trace to the finished Claude items.
pub(crate) fn attach_trace(
    items: &mut [SnapshotItem],
    path: &Path,
    trace: Option<Box<FolderTrace>>,
) {
    let mut trace = trace.unwrap_or_default();
    trace.home = coverage::transcript_home_key(path).map(|home| hex(&home));
    for item in items {
        if let Some(fold) = item.claude_money.as_deref_mut() {
            fold.folder_trace = Some(trace.clone());
        }
    }
}

/// One folder's durable evidence. Absent members default to "not qualified".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FolderRecord {
    /// The record predates this folder's first read, so the normal traversal
    /// is its census. False: history was read before the ledger existed.
    fresh: bool,
    /// Sticky. Any bit, known or not, disqualifies.
    disqualified: u16,
    sole_login: Option<String>,
    sole_org: Option<String>,
    first_slot_digest: Option<String>,
    census_complete: bool,
    /// Earliest request of the census as unix seconds, floored to the hour.
    covered_from: Option<i64>,
    email_digest: Option<String>,
    seen_login: Option<String>,
    seen_org: Option<String>,
    /// Contradictions after the census finished. Earlier names stay inferred.
    late_contradictions: u64,
}
crate::heap_layout_bound::fields!(FolderRecord; fresh, disqualified, sole_login, sole_org, first_slot_digest, census_complete, covered_from, email_digest, seen_login, seen_org, late_contradictions);

impl FolderRecord {
    fn disqualify(&mut self, bit: u16) {
        if self.disqualified == 0 && self.census_complete {
            self.late_contradictions = self.late_contradictions.saturating_add(1);
        }
        self.disqualified |= bit;
    }

    fn note_pair(&mut self, login: Option<&str>, org: Option<&str>) {
        if let Some(login) = login {
            let mut other = false;
            note_value(&mut self.seen_login, &mut other, login.to_owned());
            if other {
                self.disqualify(OTHER_LOGIN);
            }
        }
        if let Some(org) = org {
            let mut other = false;
            note_value(&mut self.seen_org, &mut other, org.to_owned());
            if other {
                self.disqualify(OTHER_ORG);
            }
        }
    }

    fn note_trace(&mut self, trace: &FolderTrace) {
        if trace.bad_org {
            self.disqualify(BAD_ORG);
        }
        if trace.other_org {
            self.disqualify(OTHER_ORG);
        }
        if trace.other_email {
            self.disqualify(OTHER_EMAIL);
        }
        self.note_pair(None, trace.org.as_deref());
        if let Some(email) = &trace.email {
            let mut other = false;
            note_value(&mut self.email_digest, &mut other, email.clone());
            if other {
                self.disqualify(OTHER_EMAIL);
            }
        }
    }

    /// Own markers survive a tail resume that dropped the read's trace.
    fn note_markers(&mut self, markers: &OrgMarkers) {
        for org in markers.folder_orgs() {
            match org {
                Some(org) => self.note_pair(None, Some(org)),
                None => self.disqualify(BAD_ORG),
            }
        }
    }

    /// An empty census completes with nothing covered: the folder's first
    /// request then sets the floor.
    fn note_requests(&mut self, item: &SnapshotItem) {
        if self.census_complete && self.covered_from.is_some() {
            return;
        }
        let earliest = item
            .usage_buckets
            .iter()
            .filter_map(|bucket| OffsetDateTime::parse(&bucket.bucket_start, &Rfc3339).ok())
            .map(|at| at.unix_timestamp().div_euclid(HOUR_SECONDS) * HOUR_SECONDS)
            .min();
        self.covered_from = match (self.covered_from, earliest) {
            (Some(known), Some(at)) => Some(known.min(at)),
            (known, at) => known.or(at),
        };
    }

    fn absorb_owner(&mut self, report: &OwnerReport) {
        let mut other_slot = false;
        note_value(
            &mut self.first_slot_digest,
            &mut other_slot,
            report.slot_digest.clone(),
        );
        if other_slot {
            self.disqualify(OTHER_SLOT);
        }
        if report.foreign_backup {
            self.disqualify(OTHER_BACKUP);
        }
        if let Some((login, org)) = &report.proven {
            if report.cached.as_ref() != report.proven.as_ref() {
                self.disqualify(SPLIT_LOGIN);
            }
            match (&self.sole_login, &self.sole_org) {
                (Some(known_login), Some(known_org)) => {
                    if known_login != login || known_org != org {
                        self.disqualify(OTHER_OWNER);
                    }
                }
                _ => {
                    self.sole_login = Some(login.clone());
                    self.sole_org = Some(org.clone());
                }
            }
        }
        if let (Some(seen), Some(cached)) = (&self.email_digest, &report.email_digest) {
            if seen != cached {
                self.disqualify(OTHER_EMAIL);
            }
        }
        if self.sole_login.is_some()
            && self.seen_login.is_some()
            && self.seen_login != self.sole_login
        {
            self.disqualify(OTHER_LOGIN);
        }
        if self.sole_org.is_some() && self.seen_org.is_some() && self.seen_org != self.sole_org {
            self.disqualify(OTHER_ORG);
        }
    }
}

/// What this process's status pass last established for one folder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OwnerReport {
    pub(crate) slot_digest: String,
    /// The strong pair `.claude.json` names.
    pub(crate) cached: Option<(String, String)>,
    /// The pair a completed proof named for the current token. `None`: no call
    /// was allowed or it failed, which never disqualifies.
    pub(crate) proven: Option<(String, String)>,
    pub(crate) email_digest: Option<String>,
    pub(crate) foreign_backup: bool,
}

/// A folder's verdict, handed to the classifier through its own files.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QualifiedFolder {
    pub(crate) login: String,
    pub(crate) org: String,
    pub(crate) witness: SoleLoginWitness,
}
crate::heap_layout_bound::fields!(QualifiedFolder; login, org, witness);

/// The (login, org, covered_from) a folder may name, or `None` while any
/// condition is unmet. Pure: the caller supplies the key-derived token.
pub(crate) fn qualify<'r>(
    record: &'r FolderRecord,
    registered: bool,
    owner: Option<&OwnerReport>,
) -> Option<(&'r str, &'r str, i64)> {
    let owner = owner?;
    let login = record.sole_login.as_deref()?;
    let org = record.sole_org.as_deref()?;
    let proven = owner.proven.as_ref()?;
    let current = proven.0 == login && proven.1 == org && owner.cached.as_ref() == Some(proven);
    let floor =
        record.seen_org.as_deref() == Some(org) || record.seen_login.as_deref() == Some(login);
    (registered
        && current
        && floor
        && record.fresh
        && record.census_complete
        && record.disqualified == 0)
        .then_some(record.covered_from)
        .flatten()
        .map(|covered_from| (login, org, covered_from))
}

#[derive(Default)]
struct Feed {
    /// `None` until a capability-on sync pass says otherwise: no status work.
    candidates: Option<BTreeSet<String>>,
    registered: BTreeSet<String>,
    reports: BTreeMap<String, OwnerReport>,
    backups_checked: BTreeMap<String, String>,
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

/// Status pass: whether this folder may still qualify, so may be asked about.
pub(crate) fn is_candidate(home: &str) -> bool {
    with_feed(|feed| {
        feed.candidates
            .as_ref()
            .is_some_and(|candidates| candidates.contains(home))
    })
}

/// Status pass: true once per folder and token, for the identity backup check.
pub(crate) fn backups_due(home: &str, fingerprint: &str) -> bool {
    with_feed(|feed| {
        if feed.backups_checked.get(home).map(String::as_str) == Some(fingerprint) {
            return false;
        }
        feed.backups_checked
            .insert(home.to_owned(), fingerprint.to_owned());
        true
    })
}

/// Status pass: replaces the folder's report. A foreign backup stays reported
/// until a sync pass absorbs it into the sticky ledger.
pub(crate) fn observe_owner(home: String, mut report: OwnerReport) {
    with_feed(|feed| {
        report.foreign_backup |= feed
            .reports
            .get(&home)
            .is_some_and(|known| known.foreign_backup);
        feed.reports.insert(home, report);
    });
}

/// Sync pass, before this page's evidence: records each folder the first time
/// it is seen and tells the status pass what to prove. Off, it clears that list
/// and writes nothing.
pub(crate) fn begin_page(
    index: &mut ScanIndex,
    committed: &ScanIndex,
    roots: &[PathBuf],
    enabled: bool,
) {
    if !enabled {
        with_feed(|feed| {
            feed.candidates = None;
            feed.registered.clear();
        });
        return;
    }
    let mut registered = BTreeSet::new();
    for root in roots {
        let Some(config) = root.parent() else {
            continue;
        };
        let key = folder_key(config);
        registered.insert(key.clone());
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
    let candidates = registered
        .iter()
        .filter(|home| {
            index
                .claude_folder_login_ledger
                .get(home.as_str())
                .is_some_and(|record| record.fresh && record.disqualified == 0)
        })
        .cloned()
        .collect();
    with_feed(|feed| {
        feed.candidates = Some(candidates);
        feed.registered = registered;
    });
}

/// Sync pass, once this page's sidecar rows are loaded: every re-parsed file
/// feeds its folder, then the status reports are absorbed, then a clean
/// terminal traversal completes the census of each fresh folder.
pub(crate) fn note_page(
    index: &mut ScanIndex,
    items: &[SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    originals: &BTreeMap<String, SessionAccountEvidence>,
    census_clean: bool,
) {
    let ledger = &mut index.claude_folder_login_ledger;
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
        record.note_trace(trace);
        if let Some(markers) = item.claude_org_markers.as_deref() {
            record.note_markers(markers);
        }
        record.note_requests(item);
        let root = super::claude_snapshot_family_root_ref(item);
        for row in api.evidence.get(root).into_iter().flatten() {
            if let Some(login) = valid_login(row, root) {
                record.note_pair(Some(login), complete_org(row));
            }
        }
        if let Some(original) = originals
            .get(&item.source_session_id)
            .filter(|original| original.evidence_source == "claude_desktop_original:v1")
        {
            record.note_pair(
                original.account_identifier_hash.as_deref(),
                original.provider_workspace_hash.as_deref(),
            );
        }
    }
    with_feed(|feed| {
        for (home, report) in &feed.reports {
            if let Some(record) = ledger.get_mut(home) {
                record.absorb_owner(report);
            }
        }
        if census_clean {
            for home in &feed.registered {
                if let Some(record) = ledger.get_mut(home) {
                    record.census_complete |= record.fresh;
                }
            }
        }
    });
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

/// Sync pass, before request accounts reconcile: stamps each own-session file of
/// a qualified folder, which is the classifier's only way to reach this basis.
pub(crate) fn stamp_page(
    items: &mut [SnapshotItem],
    index: &ScanIndex,
    api: &ClaudeLocalOtelLoadReport,
    accepted: &AcceptedBuckets,
) {
    let (registered, reports) = with_feed(|feed| (feed.registered.clone(), feed.reports.clone()));
    let mut verdicts = BTreeMap::<String, Option<QualifiedFolder>>::new();
    for item in items {
        let Some(home) = item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.folder_trace.as_deref())
            .and_then(|trace| trace.home.clone())
        else {
            continue;
        };
        let verdict = verdicts.entry(home.clone()).or_insert_with(|| {
            let record = index.claude_folder_login_ledger.get(&home)?;
            let (login, org, covered_from) =
                qualify(record, registered.contains(&home), reports.get(&home))?;
            Some(QualifiedFolder {
                login: login.to_owned(),
                org: org.to_owned(),
                witness: SoleLoginWitness {
                    v: 1,
                    folder: accepted.folder_token(&home)?,
                    covered_from: covered_from_text(covered_from)?,
                },
            })
        });
        let verdict = verdict.clone().filter(|_| own_session(item, index, api));
        if let Some(trace) = item
            .claude_money
            .as_deref_mut()
            .and_then(|fold| fold.folder_trace.as_deref_mut())
        {
            trace.sole = verdict.map(Box::new);
        }
    }
}

#[cfg(test)]
#[path = "claude_folder_login_tests.rs"]
mod tests;
