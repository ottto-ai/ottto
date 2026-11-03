//! Names a Claude request from its own session's recorded login.
//!
//! A transcript records the signed-in email and organization. A request with no
//! telemetry is named only when its own file records the folder's known login:
//! the proven owner of a folder that has only ever held one login, or the
//! account a registered slot is bound to. Everything else stays untagged.
//!
//! The evidence is the Claude applier's own accumulators (`OrgMarkers`, the fork
//! flags). Only the comparison result is persisted, as a file location in
//! `FolderRecord::matched`. The whole path stays off until the server advertises
//! `SOLE_LOGIN_WITNESS_CONTRACT`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::Digest;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::claude_money_birth_store::location_key;
use super::claude_request_identity::{
    complete_org, digest_hex, valid_login, AcceptedBuckets, RecordedLogin,
};
use super::{local_index_key, ScanIndex, SnapshotItem, SoleLoginWitness};
use crate::claude_local_otel::ClaudeLocalOtelLoadReport;
use crate::claude_status_coverage as coverage;
pub(crate) use crate::claude_status_coverage::OwnerReport;

/// Exact activity-hint capability; anything else leaves the path off.
pub(crate) const SOLE_LOGIN_WITNESS_CONTRACT: &str = "session_request_sole_login_witness:v1";
const HOUR_SECONDS: i64 = 3_600;
const MAX_HASH_TEXT: usize = 128;
/// Marks a ledger that decoded as damaged: it may have held a sticky verdict, so
/// every folder first seen after it starts sticky.
const DAMAGED_LEDGER: &str = "damaged";

/// The ledger and status key of one config folder.
pub(crate) fn folder_key(config_dir: &Path) -> String {
    digest_hex::encode(&coverage::home_key(config_dir))
}

/// Which file a fold read and whether it is its session's own, set when the
/// finished fold becomes an item. Never serialized, never logged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct FolderTrace {
    forked: bool,
    home: Option<String>,
    location: Option<u64>,
    /// Set for this page only, on a matched own file of a qualified folder.
    qualified: Option<Box<QualifiedFolder>>,
}
crate::heap_layout_bound::fields!(FolderTrace; forked, home, location, qualified);

impl FolderTrace {
    pub(crate) fn of_file(path: &Path, forked: bool) -> Self {
        Self {
            forked,
            home: coverage::transcript_home_key(path).map(|home| digest_hex::encode(&home)),
            location: Some(file_location(&local_index_key(path))),
            qualified: None,
        }
    }

    pub(crate) fn qualified(&self) -> Option<&QualifiedFolder> {
        self.qualified.as_deref()
    }

    /// What `of_file` adds to a finished fold: the box and one hash.
    pub(crate) fn finish_heap_bound() -> usize {
        std::mem::size_of::<Self>() + std::mem::align_of::<Self>() + MAX_HASH_TEXT
    }
}

/// The ledger's key for one file: the existing location digest, cut to 8 bytes.
fn file_location(index_key: &str) -> u64 {
    let bytes = location_key(index_key).to_bytes();
    u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// One folder's durable evidence: hashes, flags and file digests, no email.
/// Absent members default to "not qualified", and nothing re-reads history to
/// change that: a folder whose history was read before its record never names.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub(crate) struct FolderRecord {
    /// The record predates this folder's first read, and every read since knew
    /// the login. False: some history went unchecked, so the folder never names.
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
}
crate::heap_layout_bound::fields!(FolderRecord; fresh, mixed, login, org, owner_proven, census_complete, covered_from, matched);

// Admission classes: flags and times are N; `login`/`org` are identity hashes
// (H); `matched` holds location digests truncated to u64, so it is N-typed, not
// H's fixed 32 bytes. Not part of any retained body.
crate::durable_tail_codec::durable_struct!(FolderRecord {
    N fresh: bool,
    N mixed: bool,
    H login: Option<String>,
    H org: Option<String>,
    N owner_proven: bool,
    N census_complete: bool,
    N covered_from: Option<i64>,
    N matched: Vec<u64>,
});

impl FolderRecord {
    /// Whether this folder can still ever name: it saw its whole history and
    /// never held another login.
    fn can_name(&self) -> bool {
        !self.mixed && (self.fresh || self.census_complete)
    }

    fn set_mixed(&mut self) {
        self.mixed = true;
        self.matched = Vec::new();
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
            (Err(at), true) => self.matched.insert(at, location),
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
/// record saw from its first read needs no census. A folder whose history was
/// read before its record never qualifies.
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

/// Sync pass, before this page's evidence: records each folder the first time
/// it is seen. A folder with indexed history is recorded as not fresh, so it
/// never names; nothing re-reads that history. Off, it writes nothing.
pub(crate) fn begin_page(
    index: &mut ScanIndex,
    committed: &ScanIndex,
    roots: &[PathBuf],
    enabled: bool,
) {
    if !enabled {
        coverage::set_wanted(false, BTreeSet::new());
        return;
    }
    let damaged = index
        .claude_folder_login_ledger
        .contains_key(DAMAGED_LEDGER);
    for root in roots {
        let Some(config) = root.parent() else {
            continue;
        };
        let key = folder_key(config);
        if index.claude_folder_login_ledger.contains_key(&key) {
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
                mixed: damaged,
                ..FolderRecord::default()
            },
        );
    }
    // No profile call can help a folder that can never name.
    let stopped = index
        .claude_folder_login_ledger
        .iter()
        .filter(|(_, record)| !record.can_name())
        .map(|(home, _)| home.clone())
        .collect();
    coverage::set_wanted(true, stopped);
}

/// What a ledger that failed to decode becomes: sticky, never empty.
pub(crate) fn damaged_ledger() -> BTreeMap<String, FolderRecord> {
    BTreeMap::from([(
        DAMAGED_LEDGER.to_owned(),
        FolderRecord {
            mixed: true,
            ..FolderRecord::default()
        },
    )])
}

/// Whether this file's own lines record exactly the folder's known login.
fn read_matches(seen: &RecordedLogin<'_>, report: &OwnerReport) -> bool {
    let Some((_, org)) = report.pair.as_ref() else {
        return false;
    };
    !seen.contradicted
        && seen.email.is_some()
        && seen.email == report.email.as_deref()
        && seen.org == Some(org.as_str())
}

/// One read's evidence on its folder. Sticky on any mismatch; a read of a folder
/// with no known login leaves that history unchecked, so the folder never names.
fn note_read(
    record: &mut FolderRecord,
    item: &SnapshotItem,
    location: Option<u64>,
    report: Option<&OwnerReport>,
    own: bool,
) {
    let seen = item
        .claude_org_markers
        .as_deref()
        .map(|markers| markers.recorded_login())
        .unwrap_or_default();
    if seen.contradicted {
        record.set_mixed();
    }
    let Some(report) = report.filter(|report| report.pair.is_some() && report.email.is_some())
    else {
        if (seen.email.is_some() || seen.org.is_some()) && !record.census_complete {
            record.fresh = false;
        }
        return;
    };
    let org_differs =
        seen.org.is_some() && seen.org != report.pair.as_ref().map(|(_, org)| org.as_str());
    let email_differs = seen.email.is_some() && seen.email != report.email.as_deref();
    if org_differs || email_differs {
        record.set_mixed();
    }
    let matches = read_matches(&seen, report);
    if record.mixed {
        return;
    }
    record.note_requests(item);
    if let Some(location) = location {
        record.set_matched(location, own && matches);
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
    let reports = coverage::snapshot();
    let mut ledger = std::mem::take(&mut index.claude_folder_login_ledger);
    let mixed_before = ledger
        .iter()
        .filter(|(_, record)| record.mixed)
        .map(|(home, _)| home.clone())
        .collect::<BTreeSet<_>>();
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
        note_read(record, item, trace.location, report, own);
        let root = super::claude_snapshot_family_root_ref(item);
        for row in api.evidence.get(root).into_iter().flatten() {
            if let Some(login) = valid_login(row, root) {
                record.note_pair(Some(login), complete_org(row));
            }
        }
    }
    for (home, record) in &mut ledger {
        record.census_complete |= census_clean && record.fresh;
        if record.mixed && !mixed_before.contains(home) {
            eprintln!(
                "ottto-service: claude folder login contradicted folder={} names_were_possible={}",
                short_key(home),
                record.census_complete || record.fresh,
            );
        }
    }
    index.claude_folder_login_ledger = ledger;
}

fn short_key(home: &str) -> &str {
    home.get(..8).unwrap_or(home)
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
    let reports = coverage::snapshot();
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
