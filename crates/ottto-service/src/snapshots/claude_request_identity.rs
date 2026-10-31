//! Wire contract 5: per-request Claude identity on unchanged usage rows.
//!
//! Usage rows keep today's grain, key and totals. A bucket row whose requests
//! share one authority key carries it (`account_identifier_hash` plus
//! `evidence_ref` into the item's `request_evidence`); a row that mixes keys
//! carries no row-level identity and exact `identity_parts` instead. The
//! authority key is (login, organization, full basis): different bases never
//! merge before the server resolves them. Old collectors keep their bytes.
//!
//! Tagging runs after rows are built and only when the per-request regrouping
//! reproduces every row exactly; otherwise the item keeps today's path. It adds
//! no transcript read or parse. Legacy transcript markers never authorize
//! emitted tags; login-only telemetry keeps its login without a marker org.
//! E2 partitions counted requests using bounded native marker runs before
//! aggregation, then feeds those exact final shares to this same tag installer.

use super::claude_request_accounts::{local_subscription, normalize_activity};
use super::{
    activity_bucket_from_timestamp, build_row_identity, claude_snapshot_request_id_hashes,
    codex_identity_is_uuid_shaped, rfc3339_unix_seconds, row_key_from_model_usage,
    snapshot_fingerprint, usd_picos_string, RowKey, ScanIndex, SelectorCapture,
    SnapshotIdentityPart, SnapshotItem, SnapshotModelUsage, SnapshotRequestEvidence,
    SnapshotSource, UsageTotals, USD_PICO_SCALE,
};
use crate::claude_local_otel::{
    ClaudeIdentityAttributeEvidence, ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition,
    ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport, ClaudeRequestIdentityEvidence,
    ClaudeTraceOwnershipEvidence, ClaudeTraceOwnershipLoadReport,
};
use ottto_protocol::{ActiveSessionAccountUse, ActiveSessionCurrentAccount};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

mod accepted;
mod budget;
pub(crate) use accepted::AcceptedBuckets;
pub(crate) use budget::Measurement as CapMeasurement;

pub(crate) const COLLECTOR: &str = "claude_code_jsonl:own_request_identity_rows:v1";
/// Option (ii) activation: the exact activity-hint capability token
/// (`session_request_identity_retained_contract`). Any other value keeps
/// `identity_retained` off and the #909 accepted-priority body byte-identical.
pub(crate) const IDENTITY_RETAINED_CONTRACT: &str = "session_request_identity_retained:v1";
pub(crate) const E2_GROUPING: &str =
    "claude_code_jsonl:own_request_identity_rows:v1/e2_grouping:v1";

/// The contract a scan builds Claude bodies under: the full collector token,
/// which names its version, when it captures (every Claude cycle), and `""`
/// otherwise (records written by permit-era builds without a permit).
#[cfg(not(test))]
pub(crate) const fn cycle_contract(captured: bool) -> &'static str {
    compiled_cycle_contract(captured, true)
}

// Durable grouping version shares the existing identity-contract rearm. The
// wire collector stays v1; gate-off contracts and uploads stay byte-identical.
const fn compiled_cycle_contract(captured: bool, request_owned: bool) -> &'static str {
    if !captured {
        ""
    } else if request_owned {
        E2_GROUPING
    } else {
        COLLECTOR
    }
}

// Exercise future collector versions through the real scan/fold/tag pipeline
// without changing the released collector or other tests' contract.
#[cfg(test)]
std::thread_local! {
    static TEST_CYCLE_CONTRACT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn cycle_contract(captured: bool) -> &'static str {
    if captured {
        TEST_CYCLE_CONTRACT.with(|contract| contract.get().unwrap_or(COLLECTOR))
    } else {
        ""
    }
}

#[cfg(test)]
pub(crate) fn with_cycle_contract_for_test<T>(
    contract: &'static str,
    run: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<&'static str>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_CYCLE_CONTRACT.with(|contract| contract.set(self.0));
        }
    }
    let _restore = Restore(TEST_CYCLE_CONTRACT.with(|current| current.replace(Some(contract))));
    run()
}

/// Contract 5 is always on for Claude Code: every Claude sync cycle captures
/// markers and builds identity evidence. The activity hint's
/// `session_request_identity_contract` is still decoded for compatibility
/// but never read. Codex and Pi cycles never capture, so their sampled scope
/// and durable bindings keep their bytes. Outside a cycle the flag only
/// gates the Claude marker parser and is always on.
pub(crate) const fn captures(source: SnapshotSource) -> bool {
    matches!(source, SnapshotSource::ClaudeCode)
}

/// Every Claude sync cycle builds contract-5 evidence. A test may model a
/// pre-cutover daemon's unpermitted page, or pin the legacy account path
/// (D1 qualification, mixed bodies, owner holds) that production now
/// reaches only for bodies contract 5 leaves untagged.
pub(crate) fn builds_evidence() -> bool {
    #[cfg(test)]
    if PRE_CUTOVER.with(std::cell::Cell::get) {
        return false;
    }
    true
}
#[cfg(test)]
thread_local! { static PRE_CUTOVER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
/// Runs this thread's sync evidence stage without contract-5 evidence until
/// dropped, as every unpermitted cycle did before the cutover. Only for
/// fixtures that model that daemon or whose subject is the legacy path.
#[cfg(test)]
pub(crate) struct PreCutoverEvidenceForTest(bool);
#[cfg(test)]
impl PreCutoverEvidenceForTest {
    pub(crate) fn enter() -> Self {
        Self(PRE_CUTOVER.with(|v| v.replace(true)))
    }
}
#[cfg(test)]
impl Drop for PreCutoverEvidenceForTest {
    fn drop(&mut self) {
        PRE_CUTOVER.with(|v| v.set(self.0));
    }
}

/// `transcript_email` (and its status-coverage feed) needs its own review and
/// receiver acceptance on top of contract-5 emission. Flipping this is a
/// separate, parent-owned change.
pub(crate) const TRANSCRIPT_EMAIL_ENABLED: bool = false;

pub(crate) const fn transcript_email_enabled() -> bool {
    TRANSCRIPT_EMAIL_ENABLED || cfg!(test)
}

/// `transcript_sole_login` needs the receiver's time-scoped sole-login body
/// veto verified as deployed, on top of contract-5 emission. Until then a
/// qualifying Desktop census still yields org-only (`transcript_org`); the
/// email gate does not cover this basis. Flipping this is a separate,
/// parent-owned change.
pub(crate) const TRANSCRIPT_SOLE_LOGIN_ENABLED: bool = false;

pub(crate) const MAX_EVIDENCE_ENTRIES: usize = 16;
pub(crate) const MAX_AUTHORITY_KEYS: usize = 16;
pub(crate) const MAX_PARTS_PER_ROW: usize = MAX_AUTHORITY_KEYS + 1;
/// Declared bound (W0 `bounds.total_parts`, P1 `MAX_IDENTITY_PARTS_PER_ITEM`).
/// The byte cap is the real limit; this stops construction early.
pub(crate) const MAX_PARTS_PER_ITEM: usize = 2_048;
pub(crate) const MAX_ROWS: usize = 100;
/// Receiver `MAX_SNAPSHOT_ITEM_BYTES`, measured on sorted compact JSON.
pub(crate) const MAX_ITEM_BYTES: usize = 640 * 1024;
const MICRO_PICOS: u128 = USD_PICO_SCALE / 1_000_000;
const MAX_MONEY_PICOS: u128 = 1_000_000_000 * USD_PICO_SCALE;

pub(crate) const TELEMETRY: &str = "telemetry";
pub(crate) const TELEMETRY_LOGIN: &str = "telemetry_login";
pub(crate) const TRANSCRIPT_SOLE_LOGIN: &str = "transcript_sole_login";
pub(crate) const TRANSCRIPT_ORG: &str = "transcript_org";

/// (login, org, full basis). Derived order is the contract order: absent before
/// present for login and org, then the basis token bytewise.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AuthorityKey {
    pub(crate) login: Option<String>,
    pub(crate) org: Option<String>,
    pub(crate) basis: &'static str,
}

impl AuthorityKey {
    fn evidence(&self) -> EvidenceKey {
        EvidenceKey {
            org: self.org.clone(),
            basis: self.basis,
        }
    }
}

/// `request_evidence` total order: org absent first, org hash, then basis.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EvidenceKey {
    org: Option<String>,
    basis: &'static str,
}

/// Why a request's usage is left untagged. Only refused-versus-missing reaches
/// the wire (`request_identity_refusals`); the reason stays local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Refusal {
    /// Telemetry for this request is genuinely forthcoming.
    Pending,
    ConflictingDuplicate,
    ForeignOwner,
    InvalidEvidence,
    ContradictoryOrg,
    BadClock,
    MarkerOverflow,
    UntrustedFlip,
    /// Stronger evidence exists but is unreadable or incomplete.
    IncompleteEvidence,
    /// A recorded email in a registered folder with no usable status history
    /// for its window (feed failed, never observed, gap, restart, eviction).
    CoverageUnavailable,
    /// Status samples span the window but cannot prove continuity, and the
    /// email is never joined to a login: nothing qualifies `transcript_email`.
    CoverageUnqualified,
}

/// Why a root's strict sidecar evidence was unhealthy this pass. Local counter
/// label only; declaration order is precedence when several causes apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum UnhealthyRootReason {
    /// The strict trace read was discarded (it grew or was replaced mid-read).
    /// The family is also withheld (`e2::hold_trace_discarded`).
    Discarded,
    Oversized,
    Unreadable,
    Malformed,
    /// A missing pair member, failed permissive read, invalid or missing
    /// request ids, or conflicting ids.
    Incomplete,
}

impl UnhealthyRootReason {
    /// The strongest cause among one read's health counters.
    pub(crate) fn of(oversized: u64, unreadable: u64, malformed: u64) -> Self {
        if oversized > 0 {
            Self::Oversized
        } else if unreadable > 0 {
            Self::Unreadable
        } else if malformed > 0 {
            Self::Malformed
        } else {
            Self::Incomplete
        }
    }
}

/// Owned form of `IdentityRef`, for tests and the W0 builder oracle.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RequestIdentity {
    Tagged(AuthorityKey),
    Missing,
    Refused(Refusal),
}

/// One counted request: where today's code bucketed it and what it carried.
/// Test oracle only: production folds requests into a `Grouping` as they come.
#[cfg(test)]
#[derive(Clone, Debug)]
pub(crate) struct Contribution {
    pub(super) bucket_start: String,
    pub(super) row_key: RowKey,
    pub(super) usage: UsageTotals,
    pub(super) identity: RequestIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Ineligible {
    /// The regrouped requests do not reproduce today's rows exactly.
    RowsNotReproduced,
    /// Money that contract 5 cannot carry exactly (more than 6 decimals or over $1e9).
    MoneyNotMicroExact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum OverCap {
    EvidenceEntries,
    AuthorityKeys,
    PartsPerRow,
    PartsPerItem,
    Rows,
    Bytes,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Tagged {
    /// Tagged body (possibly with every row untagged).
    Sent { refusals: u64 },
    /// Today's untagged shape under the new collector with refusals.
    Fallback {
        over_cap: Vec<OverCap>,
        refusals: u64,
    },
}

/// Exact per-key amounts: the 8 counts plus money folded exactly as
/// `UsageCosts::add` folds it for today's rows. A request without observed
/// money leaves the row's money unchanged but makes it unsplittable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Amounts {
    counts: [u64; 8],
    costs: [Option<u128>; 5],
    observed: bool,
    /// Observed but unreported or partial money: today's row omits the field.
    poisoned: [bool; 5],
    /// Some request carried no observed money at all.
    cost_missing: bool,
    /// Local display only: the newest own transcript request folded here.
    /// Never on the wire and never compared with a row.
    last_at: Option<OffsetDateTime>,
}

impl Amounts {
    fn add(&mut self, usage: &UsageTotals) -> Option<()> {
        for (total, value) in self.counts.iter_mut().zip(usage_counts(usage)) {
            *total = total.checked_add(value)?;
        }
        if !usage.costs.observed {
            self.cost_missing = true;
            return Some(());
        }
        self.observed = true;
        for (index, value) in usage_costs(usage).into_iter().enumerate() {
            match value {
                Some(value) if usage.costs.reported => {
                    self.costs[index] = Some(self.costs[index].unwrap_or(0).checked_add(value)?);
                }
                _ => self.poisoned[index] = true,
            }
        }
        Some(())
    }

    fn merge(&mut self, other: &Amounts) -> Option<()> {
        for (total, value) in self.counts.iter_mut().zip(other.counts) {
            *total = total.checked_add(value)?;
        }
        self.observed |= other.observed;
        self.cost_missing |= other.cost_missing;
        self.last_at = self.last_at.max(other.last_at);
        for index in 0..5 {
            self.poisoned[index] |= other.poisoned[index];
            if let Some(value) = other.costs[index] {
                self.costs[index] = Some(self.costs[index].unwrap_or(0).checked_add(value)?);
            }
        }
        Some(())
    }

    /// Merge already emitted contributions with receiver presence arithmetic.
    fn merge_wire(&mut self, other: &Amounts) -> Option<()> {
        let costs = std::array::from_fn::<_, 5, _>(|field| other.wire(field));
        for (total, value) in self.counts.iter_mut().zip(other.counts) {
            *total = total.checked_add(value)?;
        }
        self.observed = true;
        self.last_at = self.last_at.max(other.last_at);
        for (field, cost) in costs.into_iter().enumerate() {
            if let Some(value) = cost {
                self.costs[field] = Some(self.costs[field].unwrap_or(0).checked_add(value)?);
            }
        }
        Some(())
    }

    /// The money today's row carries for this field.
    fn wire(&self, index: usize) -> Option<u128> {
        (self.observed && !self.poisoned[index])
            .then_some(self.costs[index])
            .flatten()
    }
}

fn usage_counts(usage: &UsageTotals) -> [u64; 8] {
    [
        usage.input_tokens,
        usage.output_tokens,
        usage.cache_read_tokens,
        usage.cache_creation_5m_tokens,
        usage.cache_creation_1h_tokens,
        usage.reasoning_output_tokens,
        usage.unattributed_total_tokens,
        usage.request_count,
    ]
}

fn usage_costs(usage: &UsageTotals) -> [Option<u128>; 5] {
    let costs = &usage.costs;
    [
        costs.total,
        costs.input,
        costs.output,
        costs.cache_read,
        costs.cache_creation,
    ]
}

fn row_counts(row: &SnapshotModelUsage) -> [u64; 8] {
    [
        row.input_tokens,
        row.output_tokens,
        row.cache_read_tokens,
        row.cache_creation_5m_tokens,
        row.cache_creation_1h_tokens,
        row.reasoning_output_tokens,
        row.unattributed_total_tokens,
        row.request_count,
    ]
}

fn row_costs(row: &SnapshotModelUsage) -> [&Option<String>; 5] {
    [
        &row.cost_usd,
        &row.input_cost_usd,
        &row.output_cost_usd,
        &row.cache_read_cost_usd,
        &row.cache_creation_cost_usd,
    ]
}

/// A row's money as contract 5 carries it: every present value micro-exact and
/// at most $1e9. `None` when it is not.
fn micro_exact(picos: u128) -> bool {
    picos % MICRO_PICOS == 0 && picos <= MAX_MONEY_PICOS
}

/// Per bucket row: amounts per authority key (`None` = untagged) and whether
/// any untagged usage was refused or pending.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RowGroup {
    total: Amounts,
    by_key: BTreeMap<Option<AuthorityKey>, Amounts>,
    refused: bool,
    truncated: bool,
}

/// Per-item aggregation at today's (bucket, row key) x authority-key grain,
/// fed one request at a time so nothing grows with the request count. Groups
/// are capped by the rows the item can carry (more could never reproduce), and
/// each group by `MAX_AUTHORITY_KEYS` plus the untagged entry. A truncated
/// row never qualifies for the sticky budget; independent later rows can
/// still retain their proof. The emitted item keeps the global key cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grouping {
    groups: BTreeMap<String, BTreeMap<RowKey, RowGroup>>,
    group_count: usize,
    max_groups: usize,
    keys: BTreeSet<AuthorityKey>,
    keys_over_cap: bool,
    upstream_proof_lost: bool,
    /// Additional cache-reconciliation wire bytes, projected once before tags.
    extra_wire_bytes: usize,
    accepted_share_changed: BTreeSet<String>,
    /// Frozen tagged rows absent from their present accepted bucket.
    accepted_rows_vanished: u64,
    /// Why the caller found no accepted state, when it found none.
    accepted_miss: accepted::UnknownCause,
    failed: Option<Ineligible>,
    /// Requests a `RequestSink` admitted: those the item's transcript holds,
    /// and telemetry-only (auxiliary) ones the reported rebuild added.
    transcript_requests: u64,
    telemetry_only_requests: u64,
    /// The item's transcript requests the reported rebuild excluded as
    /// another root's (a legacy fork's inherited prefix); `None` when an
    /// exclusion is not one of the item's transcript requests.
    excluded_requests: Option<u64>,
    /// An admitted request was excluded, or its transcript membership
    /// disagrees with its occurrence: such a grouping is never tagged.
    unowned_request: bool,
    desktop_recent: crate::desktop_recent::RecentActivity,
    /// Local display only: the item's newest own transcript requests.
    latest: LatestRequests,
}

/// At most this many distinct (row, key) requests share the newest time;
/// more makes the current account unknown rather than growing.
const MAX_LATEST_TIES: usize = 4;

/// The newest own transcript requests, by their own full-precision time (not
/// their hour bucket), folded in any order: every distinct (bucket row, key)
/// at that instant, bounded by `MAX_LATEST_TIES`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct LatestRequests {
    at: Option<OffsetDateTime>,
    ties: Vec<(String, RowKey, Option<AuthorityKey>)>,
    ties_overflowed: bool,
    /// A transcript request's time did not parse: no request is provably newest.
    unordered: bool,
}

impl LatestRequests {
    fn note(
        &mut self,
        at: OffsetDateTime,
        bucket_start: &str,
        row_key: &RowKey,
        key: Option<KeyRef<'_>>,
    ) {
        let same = |(bucket, row, known): &(String, RowKey, Option<AuthorityKey>)| {
            bucket == bucket_start
                && row == row_key
                && match (known, key) {
                    (None, None) => true,
                    (Some(known), Some(key)) => key.matches(known),
                    _ => false,
                }
        };
        match self.at.cmp(&Some(at)) {
            std::cmp::Ordering::Greater => return,
            std::cmp::Ordering::Less => {
                self.at = Some(at);
                self.ties_overflowed = false;
                // Reuse a retained tie, including its string buffers, when a
                // newer request replaces the previous newest set. Alternating
                // accounts must not allocate copies on every request.
                if let Some(index) = self.ties.iter().position(same) {
                    self.ties.swap(0, index);
                    self.ties.truncate(1);
                    return;
                }
                if let Some((bucket, row, known)) = self.ties.first_mut() {
                    bucket_start.clone_into(bucket);
                    if *row != *row_key {
                        *row = row_key.clone();
                    }
                    match (known.as_mut(), key) {
                        (Some(known), Some(key)) => {
                            for (stored, incoming) in
                                [(&mut known.login, key.login), (&mut known.org, key.org)]
                            {
                                match (stored.as_mut(), incoming) {
                                    (Some(stored), Some(incoming)) => incoming.clone_into(stored),
                                    (_, incoming) => *stored = incoming.map(str::to_string),
                                }
                            }
                            known.basis = key.basis;
                        }
                        (_, key) => *known = key.map(KeyRef::to_key),
                    }
                    self.ties.truncate(1);
                    return;
                }
            }
            std::cmp::Ordering::Equal => {
                if self.ties.iter().any(same) {
                    return;
                }
                if self.ties.len() == MAX_LATEST_TIES {
                    self.ties_overflowed = true;
                    return;
                }
            }
        }
        self.ties.push((
            bucket_start.to_string(),
            row_key.clone(),
            key.map(KeyRef::to_key),
        ));
    }
}

impl Grouping {
    #[cfg(test)]
    pub(crate) fn lose_upstream_proof_for_test(&mut self) {
        self.upstream_proof_lost = true;
        self.keys_over_cap = true;
    }

    #[cfg(test)]
    pub(super) fn desktop_recent(&self) -> &crate::desktop_recent::RecentActivity {
        &self.desktop_recent
    }

    pub(crate) fn new(max_groups: usize) -> Self {
        Self {
            groups: BTreeMap::new(),
            group_count: 0,
            max_groups,
            keys: BTreeSet::new(),
            keys_over_cap: false,
            upstream_proof_lost: false,
            extra_wire_bytes: 0,
            accepted_share_changed: BTreeSet::new(),
            accepted_rows_vanished: 0,
            accepted_miss: accepted::UnknownCause::NoKey,
            failed: None,
            transcript_requests: 0,
            telemetry_only_requests: 0,
            excluded_requests: Some(0),
            unowned_request: false,
            desktop_recent: crate::desktop_recent::RecentActivity::default(),
            latest: LatestRequests::default(),
        }
    }

    fn item_bytes(&self, item: &SnapshotItem) -> usize {
        item_bytes(item).saturating_add(self.extra_wire_bytes)
    }

    #[cfg(test)]
    pub(super) fn add(
        &mut self,
        bucket_start: &str,
        row_key: &RowKey,
        usage: &UsageTotals,
        identity: IdentityRef<'_>,
    ) {
        self.add_at(bucket_start, row_key, usage, identity, None);
    }

    /// `add` for an own transcript request at its own time (`Some`), which
    /// orders it for local display. Auxiliary telemetry-only requests pass
    /// `None`: their clock may be the observer's, so they never decide the
    /// current account or a last use.
    pub(super) fn add_at(
        &mut self,
        bucket_start: &str,
        row_key: &RowKey,
        usage: &UsageTotals,
        identity: IdentityRef<'_>,
        transcript_at: Option<&str>,
    ) {
        if self.failed.is_some() {
            return;
        }
        let at = transcript_at.and_then(|text| {
            let at = OffsetDateTime::parse(text, &Rfc3339).ok();
            self.latest.unordered |= at.is_none();
            at
        });
        if !self
            .groups
            .get(bucket_start)
            .is_some_and(|rows| rows.contains_key(row_key))
        {
            if self.group_count == self.max_groups {
                self.failed = Some(Ineligible::RowsNotReproduced);
                return;
            }
            self.group_count += 1;
            self.groups
                .entry(bucket_start.to_string())
                .or_default()
                .insert(row_key.clone(), RowGroup::default());
        }
        let group = self
            .groups
            .get_mut(bucket_start)
            .and_then(|rows| rows.get_mut(row_key))
            .expect("group was just ensured");
        if group.total.add(usage).is_none() {
            self.failed = Some(Ineligible::RowsNotReproduced);
            return;
        }
        group.total.last_at = group.total.last_at.max(at);
        let key = match identity {
            // Only a strictly lowercase-hex login reaches the wire; anything
            // else is refused here, never transformed into another identity.
            IdentityRef::Tagged(key) if !key.login.map_or(true, wire_login_is_valid) => {
                group.refused = true;
                None
            }
            IdentityRef::Tagged(key) => {
                if !self.keys_over_cap && !self.keys.iter().any(|known| key.matches(known)) {
                    if self.keys.len() == MAX_AUTHORITY_KEYS {
                        self.keys_over_cap = true;
                    } else {
                        self.keys.insert(key.to_key());
                    }
                }
                // Bound construction per row, so an old global key does not
                // prevent a later bucket's independent proof from surviving.
                let known = group
                    .by_key
                    .keys()
                    .flatten()
                    .any(|known| key.matches(known));
                if known || group.by_key.keys().flatten().count() < MAX_AUTHORITY_KEYS {
                    Some(key)
                } else {
                    group.truncated = true;
                    group.refused = true;
                    None
                }
            }
            IdentityRef::Missing => None,
            IdentityRef::Refused(_) => {
                group.refused = true;
                None
            }
        };
        let amounts = match group
            .by_key
            .iter_mut()
            .find(|(existing, _)| match (existing, key) {
                (None, None) => true,
                (Some(existing), Some(key)) => key.matches(existing),
                _ => false,
            }) {
            Some((_, amounts)) => amounts,
            None => group.by_key.entry(key.map(KeyRef::to_key)).or_default(),
        };
        if amounts.add(usage).is_none() {
            self.failed = Some(Ineligible::RowsNotReproduced);
            return;
        }
        amounts.last_at = amounts.last_at.max(at);
        if let Some(at) = at {
            self.latest.note(at, bucket_start, row_key, key);
        }
    }

    fn get(&self, bucket_start: &str, row_key: &RowKey) -> Option<&RowGroup> {
        self.groups.get(bucket_start)?.get(row_key)
    }

    /// Drops every tag that rests on transcript markers: the org-only and
    /// sole-login bases, and a marker org joined to login-only telemetry. Their
    /// usage stays on its row, untagged or login-only; refusals stay.
    fn withdraw_transcript_tags(&mut self) {
        for group in self.groups.values_mut().flat_map(BTreeMap::values_mut) {
            let mut kept: BTreeMap<Option<AuthorityKey>, Amounts> = BTreeMap::new();
            for (key, amounts) in std::mem::take(&mut group.by_key) {
                if kept
                    .entry(key.and_then(withdrawn))
                    .or_default()
                    .merge(&amounts)
                    .is_none()
                {
                    self.failed = Some(Ineligible::RowsNotReproduced);
                }
            }
            group.by_key = kept;
        }
        // The newest requests' keys withdraw the same way; ties that now
        // agree stay separate entries naming one triple.
        for (_, _, key) in &mut self.latest.ties {
            *key = key.take().and_then(withdrawn);
        }
    }

    fn rows(&self) -> impl Iterator<Item = (&RowKey, &RowGroup)> {
        self.groups.values().flatten()
    }

    /// The reported rebuild counted exactly the item's own requests, each
    /// once (the ledger holds one row per request id): every transcript
    /// request except those it excluded as another root's, plus telemetry-only
    /// requests. Each exclusion is one of the item's transcript requests and
    /// none was admitted, so excluded requests are outside the item's count
    /// and usage. Telemetry-only requests are classified on their own rows;
    /// the transcript request-id set itself is not widened.
    pub(super) fn owned_reported_requests(&self, item: &SnapshotItem) -> bool {
        let owned = self.excluded_requests.and_then(|excluded| {
            u64::try_from(item.claude_usage_request_ids.len())
                .ok()?
                .checked_sub(excluded)
        });
        !self.unowned_request
            && owned.is_some_and(|owned| owned > 0 && self.transcript_requests == owned)
            && self
                .transcript_requests
                .checked_add(self.telemetry_only_requests)
                == Some(item.request_count)
    }

    /// Whether a reported item may be tagged from this grouping: exact
    /// owned-request accounting or, failing that, the request-id count guard
    /// the transcript path keeps, so no item that guard admitted is refused.
    /// A grouping that admitted an excluded or non-member request never is.
    pub(super) fn reported_requests_admissible(&self, item: &SnapshotItem) -> bool {
        !self.unowned_request
            && (self.owned_reported_requests(item)
                || claude_snapshot_request_id_hashes(item).is_some())
    }
}

/// The bucket rows an item carries: the most groups that could reproduce it.
fn bucket_row_count(item: &SnapshotItem) -> usize {
    item.usage_buckets
        .iter()
        .map(|bucket| bucket.model_usage.len())
        .sum()
}

/// Tag `item` from materialized requests: the W0 builder oracle (tests only).
#[cfg(test)]
pub(crate) fn apply(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
) -> Result<Tagged, Ineligible> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    for contribution in contributions {
        grouping.add(
            &contribution.bucket_start,
            &contribution.row_key,
            &contribution.usage,
            contribution.identity.as_ref(),
        );
    }
    apply_grouped(item, grouping)
}

#[cfg(test)]
pub(crate) fn apply_with_accepted_for_test(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
    accepted: &AcceptedBuckets,
) -> Result<Tagged, Ineligible> {
    apply_with_reserved_bytes_for_test(item, contributions, accepted, 0)
}

#[cfg(test)]
pub(crate) fn apply_with_reserved_bytes_for_test(
    item: &mut SnapshotItem,
    contributions: &[Contribution],
    accepted: &AcceptedBuckets,
    extra_wire_bytes: usize,
) -> Result<Tagged, Ineligible> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    grouping.extra_wire_bytes = extra_wire_bytes;
    for c in contributions {
        grouping.add_at(
            &c.bucket_start,
            &c.row_key,
            &c.usage,
            c.identity.as_ref(),
            Some(&c.bucket_start),
        );
    }
    let known = accepted.get(&item.source_session_id);
    grouping.accepted_miss = accepted.miss_cause();
    apply_grouped_with_accepted(item, grouping, known, accepted.retained_enabled())
}

/// `apply` with each request's own transcript time (`None`: auxiliary),
/// withdrawing transcript tags first exactly as `tag_item` does.
#[cfg(test)]
pub(crate) fn apply_timed(
    item: &mut SnapshotItem,
    requests: &[(Contribution, Option<&str>)],
) -> Result<Tagged, Ineligible> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    for (contribution, at) in requests {
        grouping.add_at(
            &contribution.bucket_start,
            &contribution.row_key,
            &contribution.usage,
            contribution.identity.as_ref(),
            *at,
        );
    }
    grouping.withdraw_transcript_tags();
    apply_grouped(item, grouping)
}

/// Tag `item` from its aggregated requests. Returns `Err` when the item must
/// stay on today's path (it is left unchanged). On success the item carries the
/// new collector, the tagged or fallback shape, and a fresh fingerprint.
#[cfg(test)]
pub(crate) fn apply_grouped(
    item: &mut SnapshotItem,
    grouping: Grouping,
) -> Result<Tagged, Ineligible> {
    apply_grouped_with_accepted(item, grouping, None, false)
}

/// `retained` is option (ii): the server retains proof per bucket row, so the
/// accepted set is the witnessed proved-row ledger (markers) instead of an
/// allocation priority, and fresh tags use the plain newest-first order.
fn apply_grouped_with_accepted(
    item: &mut SnapshotItem,
    mut grouping: Grouping,
    known: Option<&accepted::AcceptedSession>,
    retained: bool,
) -> Result<Tagged, Ineligible> {
    let retained = retained && super::claude_history_upgrade::is_request_owned_literal(item);
    let (accepted, proved) = if retained {
        (None, known)
    } else {
        (known, None)
    };
    if let Some(ineligible) = grouping.failed {
        return Err(ineligible);
    }
    // Every bucket row must be reproduced exactly, and nothing may be left over.
    let mut matched = 0_usize;
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let group = grouping
                .get(&bucket.bucket_start, &key)
                .ok_or(Ineligible::RowsNotReproduced)?;
            reproduces(row, &group.total)?;
            matched += 1;
        }
    }
    if matched != grouping.group_count {
        return Err(Ineligible::RowsNotReproduced);
    }
    let keys_over_cap = grouping.keys_over_cap;
    // Top-level rows must equal the per-key sum of their bucket rows.
    let mut top_groups: BTreeMap<&RowKey, Amounts> = BTreeMap::new();
    for (row_key, group) in grouping.rows() {
        top_groups
            .entry(row_key)
            .or_default()
            .merge_wire(&group.total)
            .ok_or(Ineligible::RowsNotReproduced)?;
    }
    if item.model_usage.len() != top_groups.len() {
        return Err(Ineligible::RowsNotReproduced);
    }
    for row in &item.model_usage {
        let key = row_key_from_model_usage(row);
        reproduces(
            row,
            top_groups.get(&key).ok_or(Ineligible::RowsNotReproduced)?,
        )?;
    }

    protect_accepted_shares(&mut grouping, accepted);
    let prior_refusals = item.request_identity_refusals;
    let mut refusals = prior_refusals;
    let mut over_cap = BTreeSet::new();
    if keys_over_cap {
        over_cap.insert(OverCap::AuthorityKeys);
    }

    // A row whose app-reported money cannot be split per request stays untagged.
    for group in grouping.groups.values_mut().flat_map(BTreeMap::values_mut) {
        let unsplittable =
            (0..5).any(|index| group.total.wire(index).is_some()) && group.total.cost_missing;
        if unsplittable && group.by_key.keys().any(Option::is_some) {
            let total = group.total.clone();
            group.by_key = BTreeMap::from([(None, total)]);
            group.refused = true;
        }
    }
    let mut deferred = defer_retained_rows(item, &mut grouping, proved);
    // Marker bytes are constant across every tag selection; markers go on
    // the item only after measurement, as the last change before hashing.
    grouping.extra_wire_bytes = grouping
        .extra_wire_bytes
        .saturating_add(deferred.marker_bytes());

    let evidence = grouping
        .rows()
        .flat_map(|(_, group)| group.by_key.keys().flatten())
        .map(AuthorityKey::evidence)
        .collect::<BTreeSet<_>>();
    if evidence.len() > MAX_EVIDENCE_ENTRIES {
        over_cap.insert(OverCap::EvidenceEntries);
    }
    let used_keys = grouping
        .rows()
        .flat_map(|(_, group)| group.by_key.keys().flatten())
        .collect::<BTreeSet<_>>();
    if used_keys.len() > MAX_AUTHORITY_KEYS {
        over_cap.insert(OverCap::AuthorityKeys);
    }
    let evidence_index = evidence
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.clone(), index as u16))
        .collect::<BTreeMap<_, _>>();

    let mut total_parts = 0_usize;
    let mut bucket_identities = Vec::with_capacity(item.usage_buckets.len());
    for bucket in &item.usage_buckets {
        let mut rows = Vec::with_capacity(bucket.model_usage.len());
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let group = grouping
                .get(&bucket.bucket_start, &key)
                .expect("every bucket row was matched");
            if group.refused {
                refusals = refusals.saturating_add(1);
            }
            let identity = row_identity(row, &group.by_key, &evidence_index)?;
            if let RowIdentity::Parts(parts) = &identity {
                if parts.len() > MAX_PARTS_PER_ROW {
                    over_cap.insert(OverCap::PartsPerRow);
                }
                total_parts += parts.len();
            }
            rows.push(identity);
        }
        bucket_identities.push(rows);
    }
    let mut top_identities = Vec::with_capacity(item.model_usage.len());
    for row in &item.model_usage {
        let key = row_key_from_model_usage(row);
        let mut by_key: BTreeMap<Option<AuthorityKey>, Amounts> = BTreeMap::new();
        for (row_key, group) in grouping.rows() {
            if *row_key == key {
                for (authority, amounts) in &group.by_key {
                    let mut wire_amount = amounts.clone();
                    for field in 0..5 {
                        if group.total.wire(field).is_none() {
                            wire_amount.poisoned[field] = true;
                        }
                    }
                    by_key
                        .entry(authority.clone())
                        .or_default()
                        .merge_wire(&wire_amount)
                        .ok_or(Ineligible::RowsNotReproduced)?;
                }
            }
        }
        let identity = row_identity(row, &by_key, &evidence_index)?;
        if let RowIdentity::Parts(parts) = &identity {
            if parts.len() > MAX_PARTS_PER_ROW {
                over_cap.insert(OverCap::PartsPerRow);
            }
            total_parts += parts.len();
        }
        top_identities.push(identity);
    }
    if total_parts > MAX_PARTS_PER_ITEM {
        over_cap.insert(OverCap::PartsPerItem);
    }
    if item.model_usage.len() > MAX_ROWS
        || item
            .usage_buckets
            .iter()
            .any(|bucket| bucket.model_usage.len() > MAX_ROWS)
    {
        over_cap.insert(OverCap::Rows);
    }

    let lost = item
        .usage_buckets
        .iter()
        .zip(&bucket_identities)
        .map(|(bucket, identities)| {
            bucket
                .model_usage
                .iter()
                .zip(identities)
                .filter(|(row, identity)| {
                    !matches!(identity, RowIdentity::Untagged)
                        || grouping
                            .get(&bucket.bucket_start, &row_key_from_model_usage(row))
                            .is_some_and(|group| group.refused)
                })
                .count() as u64
        })
        .sum::<u64>();
    // Measure the attempted tagged body even when another cap failed. Only
    // byte counts and closed reason labels enter local diagnostics. Recovery
    // below must satisfy the same wire bounds and reconciliation rules.
    install(item, &evidence, top_identities, bucket_identities, refusals);
    let attempted_bytes = grouping.item_bytes(item);
    if attempted_bytes > MAX_ITEM_BYTES {
        over_cap.insert(OverCap::Bytes);
    }
    let unpriced = over_cap
        .is_empty()
        .then(|| untag_unpriced_parts(item, &grouping, accepted))
        .flatten();
    if let Some(unpriced) = unpriced {
        // Stripping only removes tags; the wire bound is still re-checked.
        if grouping.item_bytes(item) <= MAX_ITEM_BYTES {
            let mut counts = cap_counts(item, &grouping, accepted, None);
            unpriced.count(&mut counts);
            deferred.drop_stripped(item, &unpriced.keys);
            deferred.mark(item);
            deferred.count(item, retained, &mut counts);
            budget::record(&counts);
            untag_groups(&mut grouping, &unpriced.keys);
            deferred.restore(&mut grouping);
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            item.claude_account_display = Some(Box::new(account_display(
                &grouping,
                grouping.unowned_request,
            )));
            return Ok(Tagged::Sent {
                refusals: item.request_identity_refusals,
            });
        }
        over_cap.insert(OverCap::Bytes);
    }
    crate::local_resource_diagnostics::claude_identity_over_cap(&over_cap, attempted_bytes);
    let attempted_counts = cap_counts(item, &grouping, accepted, None);
    let accepted_tagged_attempted = item
        .usage_buckets
        .iter()
        .filter(|bucket| {
            accepted::bucket_key(&bucket.bucket_start)
                .is_some_and(|key| accepted.is_some_and(|known| known.binary_search(&key).is_ok()))
                && bucket.model_usage.iter().any(|row| {
                    row.evidence_ref.is_some()
                        || row.identity_parts.as_ref().is_some_and(|parts| {
                            parts.iter().any(|part| part.evidence_ref.is_some())
                        })
                })
        })
        .count() as u64;
    let selected = (!grouping.upstream_proof_lost)
        .then(|| budget::select(item, &grouping, prior_refusals, accepted))
        .flatten()
        .and_then(|(kept, mut measurement)| {
            let unpriced = untag_unpriced_parts(item, &grouping, accepted)?;
            if !unpriced.keys.is_empty() {
                // Kept buckets left without any tag are no longer retained.
                measurement.accepted_retained =
                    cap_counts(item, &grouping, accepted, None).retained_buckets;
            }
            (grouping.item_bytes(item) <= MAX_ITEM_BYTES).then_some((kept, measurement, unpriced))
        });
    if let Some((kept, measurement, unpriced)) = selected {
        let mut counts = cap_counts(item, &grouping, accepted, Some(&measurement));
        unpriced.count(&mut counts);
        deferred.drop_stripped(item, &unpriced.keys);
        deferred.mark(item);
        deferred.count(item, retained, &mut counts);
        budget::record(&counts);
        let mut visible = grouping;
        untag_groups(&mut visible, &unpriced.keys);
        for (bucket, keep) in item.usage_buckets.iter().zip(&kept) {
            if !keep {
                for group in visible
                    .groups
                    .get_mut(&bucket.bucket_start)
                    .into_iter()
                    .flat_map(BTreeMap::values_mut)
                {
                    group.by_key = BTreeMap::from([(None, group.total.clone())]);
                }
            }
        }
        deferred.restore(&mut visible);
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        // account_display checks the newest request against the filtered rows.
        // Withholding only that request must not anonymize retained history.
        item.claude_account_display =
            Some(Box::new(account_display(&visible, visible.unowned_request)));
        return Ok(Tagged::Sent {
            refusals: item.request_identity_refusals,
        });
    }
    let mut counts = attempted_counts;
    counts.accepted_overflow.differs = accepted_tagged_attempted;
    counts.retained_buckets = 0;
    counts.refused_new_buckets = grouping
        .groups
        .iter()
        .filter(|(bucket, rows)| {
            !accepted::bucket_key(bucket)
                .is_some_and(|key| accepted.is_some_and(|known| known.binary_search(&key).is_ok()))
                && rows
                    .values()
                    .any(|group| group.by_key.keys().any(Option::is_some))
        })
        .count() as u64;
    let refusals = lost.max(1).saturating_add(prior_refusals);
    strip(item);
    item.provenance.collector = COLLECTOR.to_string();
    #[cfg(test)]
    {
        item.provenance.collector = cycle_contract(true).to_owned();
    }
    // Markers must fit beside the stripped body; the newest ones are kept.
    // A dropped marker is a stripped proved row, so it counts as a refusal.
    // Measured at the largest refusal count, so the final digits never grow,
    // and with a final-length fingerprint.
    let dropped = if deferred.rows.is_empty() {
        0
    } else {
        item.request_identity_refusals = refusals.saturating_add(deferred.rows.len() as u64);
        item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        let unmarked = grouping
            .item_bytes(item)
            .saturating_sub(deferred.marker_bytes());
        deferred.keep_newest(MAX_ITEM_BYTES.saturating_sub(unmarked))
    };
    let refusals = refusals.saturating_add(dropped);
    deferred.mark(item);
    deferred.count(item, retained, &mut counts);
    budget::record(&counts);
    item.request_identity_refusals = refusals;
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    // The rows carry no identity, so neither may the display.
    item.claude_account_display = Some(Box::new(account_display(&grouping, true)));
    Ok(Tagged::Fallback {
        over_cap: over_cap.into_iter().collect(),
        refusals,
    })
}

/// Bytes one `identity_retained` member adds to a compact wire row.
const MARKER_BYTES: usize = r#","identity_retained":true"#.len();

/// One marked bucket row with today's identities, restored only for display.
struct DeferredRow {
    bucket: String,
    row: RowKey,
    by_key: BTreeMap<Option<AuthorityKey>, Amounts>,
    refused: bool,
    account: Option<String>,
}

/// Option (ii) bucket rows that defer to server-retained proof. Each is sent
/// untagged with its full amounts plus the marker, and is not a refusal.
#[derive(Default)]
struct Deferred {
    rows: Vec<DeferredRow>,
    /// Buckets reported `retained_proof_missing` that hold fresh proof now.
    missing: BTreeSet<String>,
}

impl Deferred {
    fn marker_bytes(&self) -> usize {
        self.rows
            .iter()
            .map(|row| {
                MARKER_BYTES
                    + row.account.as_ref().map_or(0, |hash| {
                        r#","account_identifier_hash":"""#.len() + hash.len()
                    })
            })
            .sum()
    }

    /// Keep newest markers while their complete wire members fit.
    fn keep_newest(&mut self, mut available: usize) -> u64 {
        let before = self.rows.len();
        self.rows
            .sort_by(|left, right| right.bucket.cmp(&left.bucket));
        self.rows.retain(|row| {
            let bytes = MARKER_BYTES
                + row.account.as_ref().map_or(0, |hash| {
                    r#","account_identifier_hash":"""#.len() + hash.len()
                });
            if bytes > available {
                return false;
            }
            available -= bytes;
            true
        });
        before.saturating_sub(self.rows.len()) as u64
    }

    fn drop_stripped(&mut self, item: &mut SnapshotItem, keys: &BTreeSet<RowKey>) {
        let before = self.rows.len();
        self.rows.retain(|row| !keys.contains(&row.row));
        item.request_identity_refusals = item
            .request_identity_refusals
            .saturating_add((before - self.rows.len()) as u64);
    }

    fn mark(&self, item: &mut SnapshotItem) {
        if self.rows.is_empty() {
            return;
        }
        let marked = self
            .rows
            .iter()
            .map(|deferred| ((deferred.bucket.as_str(), &deferred.row), &deferred.account))
            .collect::<BTreeMap<_, _>>();
        for bucket in &mut item.usage_buckets {
            for row in &mut bucket.model_usage {
                if let Some(account) =
                    marked.get(&(bucket.bucket_start.as_str(), &row_key_from_model_usage(row)))
                {
                    if row.evidence_ref.is_some() || row.identity_parts.is_some() {
                        continue;
                    }
                    row.identity_retained = true;
                    row.account_identifier_hash = (*account).clone();
                }
            }
        }
    }

    fn restore(&self, grouping: &mut Grouping) {
        for deferred in &self.rows {
            if let Some(group) = grouping
                .groups
                .get_mut(&deferred.bucket)
                .and_then(|rows| rows.get_mut(&deferred.row))
            {
                group.by_key = deferred.by_key.clone();
                group.refused = deferred.refused;
            }
        }
    }

    /// Option (ii) counters on the final body. #909's accepted-priority
    /// ledger state is not an input in this mode.
    fn count(&self, item: &SnapshotItem, retained: bool, counts: &mut budget::Counts) {
        if !retained {
            return;
        }
        counts.accepted_state_unknown = 0;
        counts.accepted_state_unknown_cause = Default::default();
        counts.retained_marker_rows = self.rows.len() as u64;
        counts.retained_missing_unfit = item
            .usage_buckets
            .iter()
            .filter(|bucket| {
                self.missing.contains(&bucket.bucket_start)
                    && !bucket.model_usage.iter().any(|row| {
                        row.evidence_ref.is_some()
                            || row.identity_parts.as_ref().is_some_and(|parts| {
                                parts.iter().any(|part| part.evidence_ref.is_some())
                            })
                    })
            })
            .count() as u64;
    }
}

/// A row's fresh-tag wire form and its evidence list, exactly as `install`
/// would emit them, so today's proof digest matches an ACKed body's.
fn fresh_row_value(
    row: &SnapshotModelUsage,
    by_key: &BTreeMap<Option<AuthorityKey>, Amounts>,
) -> Option<(Value, Value)> {
    let evidence = by_key
        .keys()
        .flatten()
        .map(AuthorityKey::evidence)
        .collect::<BTreeSet<_>>();
    let index = evidence
        .iter()
        .enumerate()
        .map(|(position, entry)| (entry.clone(), position as u16))
        .collect();
    let identity = row_identity(row, by_key, &index).ok()?;
    let mut fresh = row.clone();
    set_row(&mut fresh, identity, &index);
    let evidence = evidence
        .into_iter()
        .map(|entry| SnapshotRequestEvidence {
            identity_basis: entry.basis.to_string(),
            provider_workspace_hash: entry.org,
        })
        .collect::<Vec<_>>();
    Some((
        serde_json::to_value(fresh).ok()?,
        serde_json::to_value(evidence).ok()?,
    ))
}

/// SOURCE option (ii), per bucket row, against the witnessed proved ledger:
/// - today's proof equals the ACKed proof in a closed hour: marker;
/// - today's transcript no longer proves the row (none, refused): marker;
/// - different proof: fresh tags, counted `accepted_share_changed`;
/// - the open hour with proof, and rows never proved: fresh tags.
///
/// A row is never both tagged and marked. Runs after the unsplittable-money
/// strip, so a row that cannot carry tags today defers instead.
fn defer_retained_rows(
    item: &SnapshotItem,
    grouping: &mut Grouping,
    proved: Option<&accepted::AcceptedSession>,
) -> Deferred {
    let mut deferred = Deferred::default();
    let Some(proved) = proved else {
        return deferred;
    };
    let open_hour = accepted::bucket_key(&item.collected_at).map(|at| at.div_euclid(3600));
    let mut changed = BTreeSet::new();
    for bucket in &item.usage_buckets {
        let Some(start) = accepted::bucket_key(&bucket.bucket_start) else {
            continue;
        };
        let open = open_hour == Some(start.div_euclid(3600));
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let Some(group) = grouping
                .groups
                .get_mut(&bucket.bucket_start)
                .and_then(|rows| rows.get_mut(&key))
            else {
                continue;
            };
            let proves = !group.refused
                && !group.truncated
                && group
                    .by_key
                    .iter()
                    .any(|(key, amount)| key.is_some() && amount.counts != [0; 8]);
            if proves && proved.proof_missing(start) {
                deferred.missing.insert(bucket.bucket_start.clone());
            }
            let Some(prior) = proved.proved_row(start, &key) else {
                // A lost replacement ACK must not erase proof the server may
                // still hold when today's transcript can no longer prove it.
                if !proves
                    && (proved.replacement_unsettled(start, &key)
                        || proved.row_shares(start, &key).iter().any(Option::is_some))
                {
                    group.refused = true;
                }
                continue;
            };
            if proves {
                let today = fresh_row_value(row, &group.by_key)
                    .and_then(|(fresh, evidence)| proved.row_proof(&fresh, &evidence));
                if today != Some(prior) {
                    changed.insert(bucket.bucket_start.clone());
                    continue;
                }
                if open {
                    continue;
                }
            }
            let account = proved.proved_account(start, &key);
            let by_key = std::mem::replace(
                &mut group.by_key,
                BTreeMap::from([(None, group.total.clone())]),
            );
            let refused = std::mem::replace(&mut group.refused, false);
            deferred.rows.push(DeferredRow {
                bucket: bucket.bucket_start.clone(),
                row: key,
                account,
                by_key,
                refused,
            });
        }
    }
    grouping.accepted_share_changed.extend(changed);
    deferred
}

fn protect_accepted_shares(grouping: &mut Grouping, accepted: Option<&accepted::AcceptedSession>) {
    let Some(accepted) = accepted else {
        return;
    };
    for (bucket, rows) in &mut grouping.groups {
        let Some(start) = accepted::bucket_key(bucket) else {
            continue;
        };
        if accepted.binary_search(&start).is_err() {
            continue;
        }
        // Counts only: a frozen row whose usage moved to a new key bypasses
        // the gate (no money or tagging change).
        grouping.accepted_rows_vanished += accepted.vanished_rows(start, rows.keys());
        for (row, group) in rows {
            let prior = accepted.row_shares(start, row);
            let current = group
                .by_key
                .iter()
                .filter(|(_, amount)| amount.counts != [0; 8])
                .map(|(key, _)| key.as_ref().map(|key| accepted.authority_hash(key)))
                .collect::<BTreeSet<_>>();
            // Only a row frozen with tagged proof can constrain later proof.
            // New rows and rows previously ACKed untagged remain admissible.
            if prior.is_empty() {
                continue;
            }
            // Resolving an untagged share to the same surviving tagged set is
            // new proof, not a retag. Missing prior tagged keys still count changed.
            let resolved_missing = prior.contains(&None)
                && current == prior.iter().filter(|key| key.is_some()).copied().collect();
            let changed = current != prior && !resolved_missing;
            if !changed {
                continue;
            }
            grouping.accepted_share_changed.insert(bucket.clone());
            let mut kept = BTreeMap::<Option<AuthorityKey>, Amounts>::new();
            for (key, amount) in std::mem::take(&mut group.by_key) {
                let key = key.filter(|key| prior.contains(&Some(accepted.authority_hash(key))));
                // Never reconstruct missing proof from the ledger.
                kept.entry(key)
                    .or_default()
                    .merge_wire(&amount)
                    .expect("subset of checked row");
            }
            group.by_key = kept;
            group.refused = true;
        }
    }
}

fn cap_counts(
    item: &SnapshotItem,
    grouping: &Grouping,
    accepted: Option<&accepted::AcceptedSession>,
    measurement: Option<&CapMeasurement>,
) -> budget::Counts {
    let unknown = match accepted {
        None => Some(grouping.accepted_miss),
        Some(known) => known
            .incomplete
            .then_some(accepted::UnknownCause::Incomplete),
    };
    let retained = item
        .usage_buckets
        .iter()
        .filter(|bucket| {
            accepted::bucket_key(&bucket.bucket_start)
                .is_some_and(|key| accepted.is_some_and(|known| known.binary_search(&key).is_ok()))
                && !grouping
                    .accepted_share_changed
                    .contains(&bucket.bucket_start)
                && bucket.model_usage.iter().any(|row| {
                    row.evidence_ref.is_some()
                        || row.identity_parts.as_ref().is_some_and(|parts| {
                            parts.iter().any(|part| part.evidence_ref.is_some())
                        })
                })
        })
        .count() as u64;
    budget::Counts {
        retained_buckets: measurement.map_or(retained, |m| m.accepted_retained),
        refused_new_buckets: measurement.map_or(0, |m| m.refused_recent_buckets),
        accepted_state_evicted: 0,
        accepted_state_unknown: u64::from(unknown.is_some()),
        accepted_share_changed: grouping.accepted_share_changed.len() as u64,
        accepted_overflow: measurement
            .map_or_else(Default::default, |m| m.accepted_overflow.clone()),
        unpriced_part_untagged: 0,
        accepted_row_vanished: grouping.accepted_rows_vanished,
        accepted_state_unknown_cause: unknown.map(budget::UnknownCauses::one).unwrap_or_default(),
        ..Default::default()
    }
}

/// Pure measurement over a request-owned item's currently held native proof.
/// It never reads accounts/transcripts, emits diagnostics or uploads a body.
#[allow(dead_code)] // Side-run/debug hook; deliberately not a runtime decision input.
pub(crate) fn measure_identity_cap(
    item: &SnapshotItem,
    accepted: &AcceptedBuckets,
) -> Option<CapMeasurement> {
    let mut grouping = request_owned_grouping(item).or_else(|| wire_grouping(item))?;
    let mut output = item.clone();
    let known = accepted.get(&item.source_session_id);
    protect_accepted_shares(&mut grouping, known);
    let selected = (!grouping.upstream_proof_lost)
        .then(|| {
            budget::select(
                &mut output,
                &grouping,
                item.request_identity_refusals,
                known,
            )
        })
        .flatten();
    if let Some((_, measured)) = selected {
        return Some(measured);
    }
    let mut measured = CapMeasurement::default();
    let mut refused_rows = 0u64;
    for bucket in &item.usage_buckets {
        let remembered = accepted::bucket_key(&bucket.bucket_start)
            .is_some_and(|key| known.is_some_and(|set| set.binary_search(&key).is_ok()));
        let mut tagged = false;
        for row in &bucket.model_usage {
            let group = grouping.get(&bucket.bucket_start, &row_key_from_model_usage(row))?;
            let proved = group.by_key.keys().any(Option::is_some);
            tagged |= proved;
            refused_rows += u64::from(proved || group.refused || remembered);
        }
        if tagged {
            if remembered {
                measured.accepted_overflow.differs += 1;
            } else {
                measured.refused_recent_buckets += 1;
            }
        }
    }
    strip(&mut output);
    output.request_identity_refusals = item
        .request_identity_refusals
        .saturating_add(refused_rows.max(1));
    measured.item_bytes = item_bytes(&output);
    Some(measured)
}

fn wire_usage(row: &SnapshotModelUsage) -> Option<UsageTotals> {
    let mut amounts = [None; 5];
    for (slot, text) in amounts.iter_mut().zip(row_costs(row)) {
        if let Some(text) = text {
            let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
            if whole.is_empty()
                || fraction.len() > 12
                || !whole
                    .bytes()
                    .chain(fraction.bytes())
                    .all(|byte| byte.is_ascii_digit())
            {
                return None;
            }
            let picos = whole
                .parse::<u128>()
                .ok()?
                .checked_mul(USD_PICO_SCALE)?
                .checked_add(if fraction.is_empty() {
                    0
                } else {
                    fraction
                        .parse::<u128>()
                        .ok()?
                        .checked_mul(10u128.pow((12 - fraction.len()) as u32))?
                })?;
            if !micro_exact(picos) || usd_picos_string(picos) != *text {
                return None;
            }
            *slot = Some(picos);
        }
    }
    let reported = amounts.iter().any(Option::is_some);
    let [total, input, output, cache_read, cache_creation] = amounts;
    let mut usage = super::usage_totals_from_model_usage(row);
    usage.costs = super::UsageCosts {
        observed: true,
        reported,
        total,
        input,
        output,
        cache_read,
        cache_creation,
    };
    Some(usage)
}

// A side-run may have a tagged item without the native fold. Use only its
// explicit current shares, never reconstruct lost proof from an account hint.
fn wire_grouping(item: &SnapshotItem) -> Option<Grouping> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let mut add =
                |login: Option<&str>, reference: Option<u16>, usage: UsageTotals| -> Option<()> {
                    let identity = match reference {
                        None => IdentityRef::Missing,
                        Some(reference) => {
                            let evidence = item.request_evidence.get(usize::from(reference))?;
                            let basis = match evidence.identity_basis.as_str() {
                                TELEMETRY => TELEMETRY,
                                TELEMETRY_LOGIN => TELEMETRY_LOGIN,
                                TRANSCRIPT_ORG => TRANSCRIPT_ORG,
                                TRANSCRIPT_SOLE_LOGIN => TRANSCRIPT_SOLE_LOGIN,
                                _ => return None,
                            };
                            IdentityRef::Tagged(KeyRef {
                                login,
                                org: evidence.provider_workspace_hash.as_deref(),
                                basis,
                            })
                        }
                    };
                    grouping.add_at(
                        &bucket.bucket_start,
                        &row_key_from_model_usage(row),
                        &usage,
                        identity,
                        None,
                    );
                    Some(())
                };
            if let Some(parts) = &row.identity_parts {
                for part in parts {
                    let mut share = row.clone();
                    share.input_tokens = part.input_tokens;
                    share.output_tokens = part.output_tokens;
                    share.cache_read_tokens = part.cache_read_tokens;
                    share.cache_creation_5m_tokens = part.cache_creation_5m_tokens;
                    share.cache_creation_1h_tokens = part.cache_creation_1h_tokens;
                    share.reasoning_output_tokens = part.reasoning_output_tokens;
                    share.unattributed_total_tokens = part.unattributed_total_tokens;
                    share.request_count = part.request_count;
                    share.cost_usd = part.cost_usd.clone();
                    share.input_cost_usd = part.input_cost_usd.clone();
                    share.output_cost_usd = part.output_cost_usd.clone();
                    share.cache_read_cost_usd = part.cache_read_cost_usd.clone();
                    share.cache_creation_cost_usd = part.cache_creation_cost_usd.clone();
                    add(
                        part.account_identifier_hash.as_deref(),
                        part.evidence_ref,
                        wire_usage(&share)?,
                    )?;
                }
            } else {
                add(
                    row.account_identifier_hash.as_deref(),
                    row.evidence_ref,
                    wire_usage(row)?,
                )?;
            }
        }
    }
    Some(grouping)
}

fn withdrawn(key: AuthorityKey) -> Option<AuthorityKey> {
    match key.basis {
        TELEMETRY => Some(key),
        TELEMETRY_LOGIN => Some(AuthorityKey { org: None, ..key }),
        _ => None,
    }
}

/// Local display evidence of a tagged item's accounts, read from the same
/// final grouping its wire rows are: usage per (account, workspace,
/// subscription) and the account of its newest own transcript request. Never
/// serialized or uploaded, and never account evidence for anything else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AccountDisplay {
    pub(crate) current: ActiveSessionCurrentAccount,
    pub(crate) history: Vec<ActiveSessionAccountUse>,
}

pub(crate) const CURRENT_KNOWN: &str = "known";
pub(crate) const CURRENT_UNKNOWN: &str = "unknown";
const LATEST_UNIDENTIFIED: &str = "latest_request_unidentified";
const LATEST_CONFLICTING: &str = "conflicting_latest_requests";
const ORDER_UNAVAILABLE: &str = "request_order_unavailable";
pub(crate) const IDENTITY_WITHHELD: &str = "identity_withheld";

/// (account, workspace, subscription), compared whole.
type AccountTriple = (Option<String>, Option<String>, Option<String>);

fn account_triple(key: Option<&AuthorityKey>, row_key: &RowKey) -> AccountTriple {
    (
        key.and_then(|key| key.login.clone()),
        key.and_then(|key| key.org.clone()),
        row_key.subscription_product.clone(),
    )
}

fn display_time(at: Option<OffsetDateTime>) -> Option<String> {
    at?.to_offset(time::UtcOffset::UTC).format(&Rfc3339).ok()
}

/// `withheld`: the rows carry no identity, so every use is unnamed and the
/// current account is unknown.
fn account_display(grouping: &Grouping, withheld: bool) -> AccountDisplay {
    let mut uses: BTreeMap<AccountTriple, ([u64; 8], Option<OffsetDateTime>)> = BTreeMap::new();
    for (row_key, group) in grouping.rows() {
        let named = (!withheld).then_some(&group.by_key);
        let entries = named
            .into_iter()
            .flatten()
            .map(|(key, amounts)| (key.as_ref(), amounts));
        let unnamed = withheld.then_some((None, &group.total));
        for (key, amounts) in entries.chain(unnamed) {
            if amounts.counts == [0; 8] {
                continue;
            }
            let (counts, last_at) = uses.entry(account_triple(key, row_key)).or_default();
            for (total, value) in counts.iter_mut().zip(amounts.counts) {
                *total = total.saturating_add(value);
            }
            *last_at = (*last_at).max(amounts.last_at);
        }
    }

    let latest = &grouping.latest;
    let current = if withheld {
        Err(IDENTITY_WITHHELD)
    } else if latest.unordered || latest.at.is_none() {
        Err(ORDER_UNAVAILABLE)
    } else if latest.ties_overflowed {
        Err(LATEST_CONFLICTING)
    } else {
        // A newest request's key counts only while its row still carries it
        // (an unsplittable row was untagged after the request was noted).
        let triples = latest
            .ties
            .iter()
            .map(|(bucket_start, row_key, key)| {
                let carried = key.as_ref().filter(|key| {
                    grouping
                        .get(bucket_start, row_key)
                        .and_then(|group| group.by_key.get(&Some((*key).clone())))
                        .is_some_and(|amounts| amounts.counts != [0; 8])
                });
                account_triple(carried, row_key)
            })
            .collect::<BTreeSet<_>>();
        if triples.iter().any(|(account, _, _)| account.is_none()) {
            Err(LATEST_UNIDENTIFIED)
        } else if triples.len() != 1 {
            Err(LATEST_CONFLICTING)
        } else {
            Ok(triples.into_iter().next().expect("one triple"))
        }
    };

    let mut history = uses
        .into_iter()
        .map(|(triple, (counts, last_at))| {
            let current = current.as_ref().is_ok_and(|current| *current == triple);
            let (account, organization, subscription) = triple;
            (
                last_at,
                ActiveSessionAccountUse {
                    account_identifier_hash: account,
                    organization_identifier_hash: organization,
                    subscription_product: subscription,
                    input_tokens: counts[0],
                    output_tokens: counts[1],
                    cache_read_tokens: counts[2],
                    cache_creation_5m_tokens: counts[3],
                    cache_creation_1h_tokens: counts[4],
                    request_count: counts[7],
                    last_used_at: display_time(last_at),
                    current,
                },
            )
        })
        .collect::<Vec<_>>();
    // Newest use first, uses without a provable time last; ties keep triple order.
    history.sort_by(|(left, _), (right, _)| match (left, right) {
        (Some(left), Some(right)) => right.cmp(left),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });
    let latest_request_at = display_time(latest.at);
    let current = match current {
        Ok((account, organization, subscription)) => ActiveSessionCurrentAccount {
            status: CURRENT_KNOWN.to_string(),
            account_identifier_hash: account,
            organization_identifier_hash: organization,
            subscription_product: subscription,
            latest_request_at,
            unknown_reason: None,
        },
        Err(reason) => ActiveSessionCurrentAccount {
            status: CURRENT_UNKNOWN.to_string(),
            account_identifier_hash: None,
            organization_identifier_hash: None,
            subscription_product: None,
            latest_request_at,
            unknown_reason: Some(reason.to_string()),
        },
    };
    AccountDisplay {
        current,
        history: history.into_iter().map(|(_, entry)| entry).collect(),
    }
}

fn reproduces(row: &SnapshotModelUsage, amounts: &Amounts) -> Result<(), Ineligible> {
    if row_counts(row) != amounts.counts {
        return Err(Ineligible::RowsNotReproduced);
    }
    for (index, wire) in row_costs(row).into_iter().enumerate() {
        match (wire, amounts.wire(index)) {
            (None, None) => {}
            (Some(wire), Some(picos)) if *wire == usd_picos_string(picos) => {
                if !micro_exact(picos) {
                    return Err(Ineligible::MoneyNotMicroExact);
                }
            }
            _ => return Err(Ineligible::RowsNotReproduced),
        }
    }
    Ok(())
}

#[derive(Clone)]
enum RowIdentity {
    Untagged,
    Single(AuthorityKey),
    Parts(Vec<(Option<AuthorityKey>, Amounts)>),
}

fn row_identity(
    row: &SnapshotModelUsage,
    by_key: &BTreeMap<Option<AuthorityKey>, Amounts>,
    evidence_index: &BTreeMap<EvidenceKey, u16>,
) -> Result<RowIdentity, Ineligible> {
    let mut entries = by_key
        .iter()
        .filter(|(_, amounts)| amounts.counts != [0; 8]);
    let identity = match (entries.next(), entries.next()) {
        (None, _) | (Some((None, _)), None) => RowIdentity::Untagged,
        (Some((Some(key), _)), None) => RowIdentity::Single(key.clone()),
        _ => RowIdentity::Parts(
            by_key
                .iter()
                .filter(|(_, amounts)| amounts.counts != [0; 8])
                .map(|(key, amounts)| (key.clone(), amounts.clone()))
                .collect(),
        ),
    };
    if let RowIdentity::Parts(parts) = &identity {
        for (key, amounts) in parts {
            if let Some(key) = key {
                debug_assert!(evidence_index.contains_key(&key.evidence()));
            }
            for (index, wire) in row_costs(row).into_iter().enumerate() {
                if wire.is_some() && amounts.wire(index).is_some_and(|value| !micro_exact(value)) {
                    return Err(Ineligible::MoneyNotMicroExact);
                }
            }
        }
    }
    Ok(identity)
}

fn install(
    item: &mut SnapshotItem,
    evidence: &BTreeSet<EvidenceKey>,
    top: Vec<RowIdentity>,
    buckets: Vec<Vec<RowIdentity>>,
    refusals: u64,
) {
    let index = evidence
        .iter()
        .enumerate()
        .map(|(position, entry)| (entry.clone(), position as u16))
        .collect::<BTreeMap<_, _>>();
    item.request_evidence = evidence
        .iter()
        .map(|entry| SnapshotRequestEvidence {
            identity_basis: entry.basis.to_string(),
            provider_workspace_hash: entry.org.clone(),
        })
        .collect();
    item.request_identity_refusals = refusals;
    for (row, identity) in item.model_usage.iter_mut().zip(top) {
        set_row(row, identity, &index);
    }
    for (bucket, identities) in item.usage_buckets.iter_mut().zip(buckets) {
        for (row, identity) in bucket.model_usage.iter_mut().zip(identities) {
            set_row(row, identity, &index);
        }
    }
    item.provenance.collector = COLLECTOR.to_string();
    #[cfg(test)]
    {
        item.provenance.collector = cycle_contract(true).to_owned();
    }
}

fn set_row(
    row: &mut SnapshotModelUsage,
    identity: RowIdentity,
    index: &BTreeMap<EvidenceKey, u16>,
) {
    row.account_identifier_hash = None;
    row.evidence_ref = None;
    row.identity_parts = None;
    row.identity_retained = false;
    match identity {
        RowIdentity::Untagged => {}
        RowIdentity::Single(key) => {
            row.evidence_ref = Some(index[&key.evidence()]);
            row.account_identifier_hash = key.login;
        }
        RowIdentity::Parts(parts) => {
            let has_cost = row_costs(row).map(Option::is_some);
            row.identity_parts = Some(
                parts
                    .into_iter()
                    .map(|(key, amounts)| {
                        let cost = |field: usize| {
                            has_cost[field]
                                .then(|| amounts.wire(field).map(usd_picos_string))
                                .flatten()
                        };
                        let [input, output, cache_read, cache_5m, cache_1h, reasoning, unattributed, requests] =
                            amounts.counts;
                        SnapshotIdentityPart {
                            evidence_ref: key.as_ref().map(|key| index[&key.evidence()]),
                            account_identifier_hash: key.and_then(|key| key.login),
                            input_tokens: input,
                            output_tokens: output,
                            cache_read_tokens: cache_read,
                            cache_creation_5m_tokens: cache_5m,
                            cache_creation_1h_tokens: cache_1h,
                            reasoning_output_tokens: reasoning,
                            unattributed_total_tokens: unattributed,
                            request_count: requests,
                            cost_usd: cost(0),
                            input_cost_usd: cost(1),
                            output_cost_usd: cost(2),
                            cache_read_cost_usd: cost(3),
                            cache_creation_cost_usd: cost(4),
                        }
                    })
                    .collect(),
            );
        }
    }
}

/// Today's untagged shape: the same rows with every identity removed.
fn strip(item: &mut SnapshotItem) {
    item.request_evidence.clear();
    item.request_identity_refusals = 0;
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|bucket| bucket.model_usage.iter_mut()),
    ) {
        row.account_identifier_hash = None;
        row.evidence_ref = None;
        row.identity_parts = None;
        row.identity_retained = false;
    }
}

fn row_tagged(row: &SnapshotModelUsage) -> bool {
    row.evidence_ref.is_some()
        || row
            .identity_parts
            .iter()
            .flatten()
            .any(|part| part.evidence_ref.is_some())
}

/// Receiver `_validate_identity_parts` money presence
/// (backend/app/schemas/agent_session_snapshots.py:634-641): per cost field, a
/// row carrying it needs it on every part and a row without it allows none.
fn parts_presence_holds(row: &SnapshotModelUsage) -> bool {
    let row_present = row_costs(row).map(Option::is_some);
    row.identity_parts.iter().flatten().all(|part| {
        [
            &part.cost_usd,
            &part.input_cost_usd,
            &part.output_cost_usd,
            &part.cache_read_cost_usd,
            &part.cache_creation_cost_usd,
        ]
        .map(Option::is_some)
            == row_present
    })
}

/// Model rows the final body stripped because a share had no value for a cost
/// field its priced row carries.
#[derive(Default)]
struct UnpricedStrip {
    keys: BTreeSet<RowKey>,
    /// Stripped rows with a frozen tagged share set in an accepted bucket.
    accepted_rows: u64,
}

impl UnpricedStrip {
    fn count(&self, counts: &mut budget::Counts) {
        counts.unpriced_part_untagged = self.keys.len() as u64;
        // Losing accepted tags can move dollars to the starting binding.
        counts.accepted_overflow.differs = counts
            .accepted_overflow
            .differs
            .saturating_add(self.accepted_rows);
    }
}

/// Fail closed on the final derived rows: a share whose contributing buckets
/// all lack a cost its priced parent carries has no exact value, and neither a
/// zero nor a guessed identity may stand in. The whole model row (top and
/// every bucket row) goes out untagged with its unchanged money, one refusal
/// per newly untagged bucket row; orphaned evidence is pruned and remapped.
/// `None` when the stripped body no longer reconciles (never expected).
fn untag_unpriced_parts(
    item: &mut SnapshotItem,
    grouping: &Grouping,
    accepted: Option<&accepted::AcceptedSession>,
) -> Option<UnpricedStrip> {
    let keys = item
        .model_usage
        .iter()
        .chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
        .filter(|row| !parts_presence_holds(row))
        .map(row_key_from_model_usage)
        .collect::<BTreeSet<_>>();
    let mut stripped = UnpricedStrip::default();
    if keys.is_empty() {
        return Some(stripped);
    }
    let mut refusals = 0_u64;
    let mut accepted_keys = BTreeSet::new();
    for bucket in &mut item.usage_buckets {
        let start = accepted::bucket_key(&bucket.bucket_start)
            .filter(|key| accepted.is_some_and(|known| known.binary_search(key).is_ok()));
        for row in &mut bucket.model_usage {
            let key = row_key_from_model_usage(row);
            if !keys.contains(&key) || !row_tagged(row) {
                continue;
            }
            let group = grouping.get(&bucket.bucket_start, &key)?;
            refusals += u64::from(!group.refused);
            if let (Some(start), Some(known)) = (start, accepted) {
                if known.row_shares(start, &key).iter().any(Option::is_some) {
                    accepted_keys.insert(key);
                }
            }
            row.account_identifier_hash = None;
            row.evidence_ref = None;
            row.identity_parts = None;
        }
    }
    for row in &mut item.model_usage {
        if keys.contains(&row_key_from_model_usage(row)) {
            row.account_identifier_hash = None;
            row.evidence_ref = None;
            row.identity_parts = None;
        }
    }
    item.request_identity_refusals = item.request_identity_refusals.saturating_add(refusals);
    prune_evidence(item);
    if !wire_reconciles(item) {
        return None;
    }
    stripped.accepted_rows = accepted_keys.len() as u64;
    stripped.keys = keys;
    Some(stripped)
}

/// Drop evidence no row references and remap references, preserving order.
fn prune_evidence(item: &mut SnapshotItem) {
    let mut used = vec![false; item.request_evidence.len()];
    let rows = || {
        item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
    };
    for row in rows() {
        let references = row.evidence_ref.into_iter().chain(
            row.identity_parts
                .iter()
                .flatten()
                .filter_map(|part| part.evidence_ref),
        );
        for reference in references {
            if let Some(slot) = used.get_mut(usize::from(reference)) {
                *slot = true;
            }
        }
    }
    if used.iter().all(|used| *used) {
        return;
    }
    let mut next = 0_u16;
    let positions = used
        .iter()
        .map(|used| {
            let index = next;
            next += u16::from(*used);
            used.then_some(index)
        })
        .collect::<Vec<_>>();
    item.request_evidence = std::mem::take(&mut item.request_evidence)
        .into_iter()
        .zip(&used)
        .filter_map(|(entry, used)| used.then_some(entry))
        .collect();
    let remap = |reference: &mut Option<u16>| {
        *reference = reference.and_then(|old| positions.get(usize::from(old)).copied().flatten());
    };
    for row in item.model_usage.iter_mut().chain(
        item.usage_buckets
            .iter_mut()
            .flat_map(|bucket| bucket.model_usage.iter_mut()),
    ) {
        remap(&mut row.evidence_ref);
        for part in row.identity_parts.iter_mut().flatten() {
            remap(&mut part.evidence_ref);
        }
    }
}

/// Re-run the bucket and top-row reconciliation on the emitted wire alone:
/// money presence on every part, bucket rows reproduced by their shares, and
/// top rows equal to the receiver-arithmetic sum of their bucket rows.
fn wire_reconciles(item: &SnapshotItem) -> bool {
    let rows = || {
        item.model_usage.iter().chain(
            item.usage_buckets
                .iter()
                .flat_map(|bucket| &bucket.model_usage),
        )
    };
    if !rows().all(parts_presence_holds) {
        return false;
    }
    let Some(grouping) = wire_grouping(item).filter(|grouping| grouping.failed.is_none()) else {
        return false;
    };
    let mut top: BTreeMap<RowKey, Amounts> = BTreeMap::new();
    for bucket in &item.usage_buckets {
        for row in &bucket.model_usage {
            let key = row_key_from_model_usage(row);
            let Some(group) = grouping.get(&bucket.bucket_start, &key) else {
                return false;
            };
            if reproduces(row, &group.total).is_err()
                || top
                    .entry(key)
                    .or_default()
                    .merge_wire(&group.total)
                    .is_none()
            {
                return false;
            }
        }
    }
    top.len() == item.model_usage.len()
        && item.model_usage.iter().all(|row| {
            top.get(&row_key_from_model_usage(row))
                .is_some_and(|amounts| reproduces(row, amounts).is_ok())
        })
}

/// Display follows the emitted rows: stripped model rows name no account.
fn untag_groups(grouping: &mut Grouping, keys: &BTreeSet<RowKey>) {
    for (key, group) in grouping.groups.values_mut().flat_map(BTreeMap::iter_mut) {
        if keys.contains(key) {
            group.by_key = BTreeMap::from([(None, group.total.clone())]);
        }
    }
}

/// Complete compact wire bytes, including the largest policy framing and a
/// possible cache predecessor. Hash values have fixed width as tags change.
pub(crate) fn item_bytes(item: &SnapshotItem) -> usize {
    let policy = super::SnapshotUploadPolicy {
        session_titles_enabled: false,
        workspace_labels_enabled: false,
        session_artifacts_enabled: false,
        session_attribution_enabled: false,
        session_attribution_labels_enabled: false,
    };
    // Hash contents do not affect their encoded size. Do not rebuild semantic
    // leaves just to count bytes: that duplicates per-row allocations on the
    // ordinary, under-cap path. Keep the real envelope/wire serializers here;
    // fixtures compare this shape with the upload serializer.
    let source = SnapshotSource::ClaudeCode;
    let hash = "0".repeat(64);
    let mut component_hashes = [
        "usage_accounting",
        "lifecycle_activity",
        "latency",
        "display_identity",
        "attribution",
        "artifacts",
    ]
    .into_iter()
    .map(|name| (name, hash.clone()))
    .collect::<BTreeMap<_, _>>();
    if source.derives_context_posture() {
        component_hashes.insert("context_posture", hash.clone());
    }
    if item.activity_summary.is_some() {
        component_hashes.insert("activity_summary", hash.clone());
    }
    let mut envelope = super::SnapshotSemanticEnvelope {
        component_contract_version: super::SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        revision_contract_version: super::SNAPSHOT_REVISION_CONTRACT_VERSION,
        upload_policy: policy,
        component_hashes,
        revision_hash: hash.clone(),
        revision_v2_contract_version: super::SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
        revision_v2_canonicalization: crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        revision_v2_parser_version: source.parser_version(),
        revision_v2_scan_identity_version: source.scan_identity_version(),
        revision_v2_hash: hash.clone(),
        content_hash: hash,
        hash_epoch: super::SNAPSHOT_CONTENT_HASH_EPOCH,
        base_head_etag: item.cache_base_head_etag.clone(),
    };
    if envelope.base_head_etag.is_none()
        && (item.cache_observations.is_some()
            || item.cache_observations_state.is_some()
            || !item.cache_requests.is_empty())
    {
        envelope.base_head_etag = Some("0".repeat(64));
    }
    if serde_json::to_vec(&envelope).map_or(true, |bytes| {
        bytes.len() > super::MAX_SEMANTIC_ENVELOPE_BYTES
    }) {
        return usize::MAX;
    }
    serde_json::to_vec(&super::SnapshotItemWire {
        snapshot: item,
        semantic_envelope: envelope,
    })
    .map_or(usize::MAX, |bytes| bytes.len())
}

// --- Canonical hash leaf (W0 `session_identity_leaf:v3`) ---------------------

/// The conditional `request_identity` leaf of `usage_accounting`, present only
/// under the new collector. Identities are dereferenced and parts sorted by
/// authority key, so neither evidence order nor part order reaches the hash,
/// while which usage ran on which key (login included) always does.
pub(crate) fn semantic_leaf(item: &SnapshotItem) -> Value {
    let evidence = item.request_evidence.as_slice();
    json!({
        "model_usage": item
            .model_usage
            .iter()
            .map(|row| row_leaf(row, evidence))
            .collect::<Vec<_>>(),
        "refused": item.request_identity_refusals > 0,
        "usage_buckets": item
            .usage_buckets
            .iter()
            .map(|bucket| bucket
                .model_usage
                .iter()
                .map(|row| row_leaf(row, evidence))
                .collect::<Vec<_>>())
            .collect::<Vec<_>>(),
    })
}

/// Authority-key order of a dereferenced leaf identity (untagged sorts first).
type LeafOrder = (u8, u8, String, u8, String, String);

fn deref(
    login: Option<&String>,
    evidence_ref: Option<u16>,
    evidence: &[SnapshotRequestEvidence],
) -> Option<(Value, LeafOrder)> {
    let entry = evidence.get(usize::from(evidence_ref?))?;
    let org = entry.provider_workspace_hash.as_ref();
    Some((
        json!({"basis": entry.identity_basis, "login": login, "org": org}),
        (
            1,
            u8::from(login.is_some()),
            login.cloned().unwrap_or_default(),
            u8::from(org.is_some()),
            org.cloned().unwrap_or_default(),
            entry.identity_basis.clone(),
        ),
    ))
}

fn row_leaf(row: &SnapshotModelUsage, evidence: &[SnapshotRequestEvidence]) -> Value {
    // Option (ii): the receiver's leaf for a row deferring to retained proof.
    if row.identity_retained {
        return json!({"retained": true});
    }
    if let Some(parts) = &row.identity_parts {
        let mut leaves = parts
            .iter()
            .map(|part| {
                let identity = deref(
                    part.account_identifier_hash.as_ref(),
                    part.evidence_ref,
                    evidence,
                );
                let sort = identity.as_ref().map_or(
                    (0, 0, String::new(), 0, String::new(), String::new()),
                    |(_, sort)| sort.clone(),
                );
                let mut leaf = json!({
                    "identity": identity.map_or(Value::Null, |(value, _)| value),
                    "input_tokens": part.input_tokens,
                    "output_tokens": part.output_tokens,
                    "cache_read_tokens": part.cache_read_tokens,
                    "cache_creation_5m_tokens": part.cache_creation_5m_tokens,
                    "cache_creation_1h_tokens": part.cache_creation_1h_tokens,
                    "reasoning_output_tokens": part.reasoning_output_tokens,
                    "unattributed_total_tokens": part.unattributed_total_tokens,
                    "request_count": part.request_count,
                });
                let object = leaf.as_object_mut().expect("part leaf is an object");
                for (name, value) in [
                    ("cost_usd", &part.cost_usd),
                    ("input_cost_usd", &part.input_cost_usd),
                    ("output_cost_usd", &part.output_cost_usd),
                    ("cache_read_cost_usd", &part.cache_read_cost_usd),
                    ("cache_creation_cost_usd", &part.cache_creation_cost_usd),
                ] {
                    if let Some(value) = value {
                        object.insert(name.to_string(), json!(value));
                    }
                }
                (sort, leaf)
            })
            .collect::<Vec<_>>();
        leaves.sort_by(|left, right| left.0.cmp(&right.0));
        return json!({"parts": leaves.into_iter().map(|(_, leaf)| leaf).collect::<Vec<_>>()});
    }
    deref(
        row.account_identifier_hash.as_ref(),
        row.evidence_ref,
        evidence,
    )
    .map_or(Value::Null, |(identity, _)| json!({"identity": identity}))
}

// --- Transcript organization markers (cached accumulator state) -------------

/// Most markers one file may carry before transcript bases switch off for it.
pub(crate) const MAX_ORG_MARKERS_PER_FILE: usize = 64;

/// One `credential_org` marker, positioned by the response sequence at its line:
/// a response with sequence `s` follows it iff `s >= position`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OrgMarker {
    position: u64,
    /// `None` when the marker's organization is blank or malformed.
    org: Option<String>,
    /// Terminal/SDK trust: the first marker, an unchanged org after a trusted
    /// marker, or an org change that came with a new `session_context`.
    terminal_trusted: bool,
}

/// Owned, line-ordered marker state for one file. Only the organization hash
/// and a local change detector for `session_context` are kept; no email or raw
/// text is retained or sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OrgMarkers {
    entries: Vec<OrgMarker>,
    starting_marker: Option<OrgMarker>,
    overflowed: bool,
    context_digest: Option<String>,
    context_changed: bool,
    /// Response positions of the first non-blank `session_context` email and
    /// of the first later `session_context` naming a different one.
    context_position: Option<u64>,
    context_flip_position: Option<u64>,
    /// Status-coverage key of the folder holding this file, bound when the
    /// item is built and only for a file with a recorded email.
    home: Option<crate::claude_status_coverage::HomeKey>,
}

/// Field check on an already-decoded, owned (non-inherited) Claude line.
pub(crate) fn note_marker_line(
    markers: &mut Option<Box<OrgMarkers>>,
    value: &Value,
    response_position: u64,
) {
    if value.get("type").and_then(Value::as_str) != Some("attachment") {
        return;
    }
    let Some(attachment) = value.get("attachment") else {
        return;
    };
    match attachment.get("type").and_then(Value::as_str) {
        Some("session_context") => {
            let text = attachment
                .get("context")
                .and_then(|context| context.get("userEmail"))
                .and_then(Value::as_str)
                .map(|text| text.trim().to_ascii_lowercase())
                .unwrap_or_default();
            // Domain-separated SHA-256 (an H value in the durable store).
            let digest = format!(
                "{:x}",
                sha2::Sha256::new()
                    .chain_update(b"ottto-claude-org-marker-context:v1\0")
                    .chain_update(text.as_bytes())
                    .finalize()
            );
            let state = markers.get_or_insert_with(Box::default);
            if state.context_digest.as_deref() != Some(digest.as_str()) {
                if state.context_digest.is_some() && state.context_flip_position.is_none() {
                    state.context_flip_position = Some(response_position);
                }
                state.context_changed = state.context_digest.is_some() || !state.entries.is_empty();
                state.context_digest = Some(digest);
            }
            if !text.is_empty() && state.context_position.is_none() {
                state.context_position = Some(response_position);
            }
        }
        Some("credential_org") => {
            let org = attachment
                .get("organizationUuid")
                .and_then(Value::as_str)
                .and_then(crate::claude_local_otel::canonical_uuid)
                .and_then(|uuid| {
                    ottto_core::billing_identity_hash("anthropic", "organization", &uuid)
                });
            let state = markers.get_or_insert_with(Box::default);
            if state.overflowed {
                return;
            }
            if state.entries.len() == MAX_ORG_MARKERS_PER_FILE {
                state.overflowed = true;
                state.entries = Vec::new();
                return;
            }
            let terminal_trusted = match state.entries.last() {
                None => true,
                Some(previous) => {
                    state.context_changed || (previous.terminal_trusted && previous.org == org)
                }
            };
            state.context_changed = false;
            let marker = OrgMarker {
                position: response_position,
                org,
                terminal_trusted,
            };
            if state.starting_marker.is_none() {
                state.starting_marker = Some(marker.clone());
            }
            state.entries.push(marker);
        }
        _ => {}
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MarkerVerdict<'m> {
    None,
    Trusted(&'m str),
    Overflow,
    UntrustedFlip,
    BadOrg,
}

impl OrgMarkers {
    /// Binds the registered-folder key once the item's path is known.
    pub(crate) fn bind_home(&mut self, transcript: &std::path::Path) {
        if self.context_position.is_some() {
            self.home = crate::claude_status_coverage::transcript_home_key(transcript);
        }
    }

    /// The folder key when one unchanged email precedes the response with
    /// `sequence` (line order; an email switch at or before it disqualifies).
    pub(crate) fn email_home(
        &self,
        sequence: u64,
    ) -> Option<&crate::claude_status_coverage::HomeKey> {
        let precedes = self.context_position.is_some_and(|at| at <= sequence)
            && self.context_flip_position.map_or(true, |at| at > sequence);
        (precedes && !self.overflowed)
            .then_some(self.home.as_ref())
            .flatten()
    }

    /// The marker governing the response with `sequence`, by line order only.
    pub(crate) fn verdict(&self, sequence: u64, desktop: bool) -> MarkerVerdict<'_> {
        if self.overflowed {
            return MarkerVerdict::Overflow;
        }
        let Some(marker) = self
            .entries
            .iter()
            .rev()
            .find(|marker| marker.position <= sequence)
        else {
            return MarkerVerdict::None;
        };
        match &marker.org {
            None => MarkerVerdict::BadOrg,
            Some(_) if !desktop && !marker.terminal_trusted => MarkerVerdict::UntrustedFlip,
            Some(org) => MarkerVerdict::Trusted(org),
        }
    }
}

// E2 consumes this compact, native-sequence-ordered placement before any
// requests aggregate. Marker state is bounded independently of request count.
pub(crate) type AccountPartition = Option<Arc<AuthorityKey>>;

#[derive(Clone, Debug)]
struct AccountRun {
    position: u64,
    account: AccountPartition,
    /// First nonzero usage following this marker: its response position and
    /// E2 copy status. Zero-usage responses may separate it from the marker.
    copied: Option<(u64, bool)>,
}
crate::heap_layout_bound::fields!(AccountRun; position, account, copied);

#[derive(Clone, Debug, Default)]
pub(crate) struct RequestAccounts {
    pub(crate) starting: AccountPartition,
    pub(crate) fallback: AccountPartition,
    bound: AccountPartition,
    retained_root: AccountPartition,
    runs: Vec<AccountRun>,
    pub(crate) mixed: bool,
    pub(crate) conflict: bool,
    pub(crate) subagent: bool,
    pub(crate) inherited: u64,
    skipped_inherited: u64,
    first_retained: Option<u64>,
    reconciled: bool,
    /// Root start known, but the native Unknown grains are not filled yet.
    root_fallback_pending: bool,
    /// This page could not read the family's strict sidecar evidence; no
    /// account may fill its shares (SOURCE: unhealthy root is all-Unknown).
    unhealthy_no_fallback: bool,
    /// The uniform wire account a non-discard unhealthy read cleared (Lead B
    /// Addendum 4); the bound owner admits the Unknown body only if it was its own.
    unhealthy_cleared_account: Option<String>,
}
crate::heap_layout_bound::fields!(AuthorityKey; login, org, basis);
crate::heap_layout_bound::fields!(RequestAccounts; starting, fallback, bound, retained_root, runs, mixed, conflict, subagent, inherited, skipped_inherited, first_retained, reconciled, root_fallback_pending, unhealthy_no_fallback, unhealthy_cleared_account);

/// One account policy for E2. Never use a later marker for an earlier request.
/// A conflict fills missing shares; trusted own/earlier org runs stay intact.
/// Subagents are assigned their root's starting account at page finalization.
pub(crate) fn request_accounts(
    markers: Option<&OrgMarkers>,
    bound: Option<&str>,
    first_sequence: Option<u64>,
    subagent: bool,
    excluded: &[u64],
) -> RequestAccounts {
    let bound = bound.filter(|hash| wire_login_is_valid(hash)).map(|login| {
        Arc::new(AuthorityKey {
            login: Some(login.to_owned()),
            org: None,
            basis: TELEMETRY_LOGIN,
        })
    });
    let mut accounts = RequestAccounts {
        starting: bound.clone(),
        fallback: bound.clone(),
        bound,
        subagent,
        ..Default::default()
    };
    if subagent {
        return accounts;
    }
    let Some(markers) = markers else {
        // Unknown here is provisional until existing account evidence runs.
        return accounts;
    };
    let Some(first) = first_sequence else {
        return accounts;
    };
    // Only E2 can exclude a request. Marker timestamps never decide identity.
    let own_marker = |marker: &&OrgMarker| excluded.binary_search(&marker.position).is_err();
    if markers.overflowed {
        if let Some(marker) = markers
            .starting_marker
            .as_ref()
            .filter(own_marker)
            .filter(|marker| marker.position <= first)
        {
            if let Some(org) = marker.org.as_deref().filter(|_| marker.terminal_trusted) {
                accounts.starting = Some(Arc::new(AuthorityKey {
                    login: None,
                    org: Some(org.to_owned()),
                    basis: TRANSCRIPT_ORG,
                }));
                accounts.runs.push(AccountRun {
                    position: marker.position,
                    account: accounts.starting.clone(),
                    copied: None,
                });
            }
        }
    }
    accounts.fallback = accounts.starting.clone();
    accounts.conflict = markers.overflowed;
    // Positions where one request carries two different orgs (R3-N2).
    let mut contradicted = Vec::new();
    for marker in markers.entries.iter().filter(own_marker) {
        let Some(org) = marker.org.as_deref().filter(|_| {
            marker.terminal_trusted
                || accounts
                    .runs
                    .iter()
                    .rev()
                    .find_map(|run| run.account.as_ref())
                    .map_or(true, |key| key.org.as_deref() == marker.org.as_deref())
        }) else {
            accounts.conflict = true;
            if accounts
                .runs
                .last()
                .map_or(true, |run| run.position != marker.position)
            {
                accounts.runs.push(AccountRun {
                    position: marker.position,
                    account: None,
                    copied: None,
                });
            }
            continue;
        };
        if let Some(previous) = accounts.runs.last() {
            if previous.position == marker.position {
                if previous.account.as_ref().and_then(|key| key.org.as_deref()) != Some(org) {
                    accounts.conflict = true;
                    contradicted.push(marker.position);
                }
                continue;
            }
        }
        let key = accounts
            .starting
            .as_ref()
            .filter(|key| key.org.as_deref() == Some(org))
            .cloned()
            .or_else(|| {
                accounts.runs.iter().find_map(|run| {
                    run.account
                        .as_ref()
                        .filter(|key| key.org.as_deref() == Some(org))
                        .cloned()
                })
            })
            .unwrap_or_else(|| {
                Arc::new(AuthorityKey {
                    login: None,
                    org: Some(org.to_owned()),
                    basis: TRANSCRIPT_ORG,
                })
            });
        accounts.runs.push(AccountRun {
            position: marker.position,
            account: Some(key),
            copied: None,
        });
    }
    // Derive the first own request's start from the accepted own stream,
    // preserving the first observation of a conflicting same-position pair.
    if !markers.overflowed {
        if let Some(key) = accounts
            .runs
            .iter()
            .rev()
            .filter(|run| run.position <= first)
            .find_map(|run| run.account.as_ref())
        {
            accounts.starting = Some(key.clone());
        }
        accounts.fallback = accounts.starting.clone();
    }
    // R3-N2 (QUOTA): a later request carrying two different orgs is never
    // guessed: it goes to the starting (or bound) account, counted as a
    // conflict above. A pair at the session start is the start itself.
    for run in &mut accounts.runs {
        if run.position > first && contradicted.contains(&run.position) {
            run.account = accounts.starting.clone();
        }
    }
    if accounts
        .runs
        .iter()
        .filter_map(|run| run.account.as_ref())
        .collect::<BTreeSet<_>>()
        .len()
        > MAX_AUTHORITY_KEYS
    {
        accounts.conflict = true;
    }
    accounts.mixed = accounts
        .runs
        .iter()
        .any(|run| run.account.is_some() && run.account != accounts.starting);
    // Keep bounded runs through native copy adjudication so the first
    // retained request can establish the real start even under a conflict.
    accounts
}

impl RequestAccounts {
    pub(crate) fn account(&self, sequence: u64) -> AccountPartition {
        if self.unhealthy_no_fallback {
            return None;
        }
        if self.subagent {
            return self.starting.clone().or_else(|| {
                (!self.root_fallback_pending)
                    .then(|| self.fallback.clone())
                    .flatten()
            });
        }
        let end = self.runs.partition_point(|run| run.position <= sequence);
        self.runs[..end]
            .iter()
            .rev()
            .find_map(|run| run.account.clone())
            .or_else(|| self.starting.clone())
            .or_else(|| {
                (!self.root_fallback_pending)
                    .then(|| self.fallback.clone())
                    .flatten()
            })
    }
    fn is_inherited(&self, sequence: u64) -> bool {
        !self.subagent
            && ((self.starting.is_none() && self.runs.is_empty() && self.fallback.is_some())
                || matches!(self.runs.binary_search_by_key(&sequence, |run| run.position), Err(at) if at > 0))
    }
    pub(crate) fn observe(&mut self, sequence: u64, copied: bool) {
        let next = self.runs.partition_point(|run| run.copied.is_some());
        for run in self.runs[next..]
            .iter_mut()
            .take_while(|run| run.position <= sequence)
        {
            run.copied = Some((sequence, copied));
        }
        if !copied {
            self.first_retained.get_or_insert(sequence);
        }
        if self.is_inherited(sequence) {
            let into = if copied {
                &mut self.skipped_inherited
            } else {
                &mut self.inherited
            };
            *into = into.saturating_add(1);
        }
    }
    /// The governing native marker run; E2 uses its own skipped ranges to
    /// stage inherited usage until its copy decision is final.
    pub(crate) fn copied_marker_position(&self, sequence: u64) -> Option<u64> {
        let end = self.runs.partition_point(|run| run.position <= sequence);
        let runs = &self.runs[..end];
        // Keep every marker boundary, even a provisionally rejected flip:
        // removing its copied predecessor can make that marker authoritative.
        runs.iter()
            .rev()
            .find(|run| run.account.is_some())
            .filter(|run| matches!(run.copied, Some((_, true))))?;
        runs.last().map(|run| run.position)
    }

    /// X_out's E term for a gate-on fold's accounts: the boxed
    /// `request_accounts` for `markers` and a bound login of `login` bytes,
    /// built twice while `finish_native` rebuilds beside the first, with
    /// each build's scratch (the contradicted positions, the distinct-key
    /// set, the excluded positions). Each `AccountPartition` is charged per
    /// reference. Also what one grain key's partition costs, and the marker
    /// runs (at most one inherited body each).
    pub(crate) fn finish_heap_bound(
        markers: Option<&OrgMarkers>,
        login: usize,
    ) -> Option<(usize, usize, usize)> {
        use crate::heap_layout_bound::tree_node_bytes;
        use std::mem::{align_of, size_of};
        let (runs, org) = markers.map_or((0, 0), |markers| {
            let org = markers
                .entries
                .iter()
                .chain(&markers.starting_marker)
                .filter_map(|marker| marker.org.as_ref().map(String::capacity))
                .max()
                .unwrap_or(0);
            (markers.entries.len().max(1), org)
        });
        // Neither a login nor a marker: every partition is None.
        let partition = if login == 0 && runs == 0 {
            0
        } else {
            size_of::<AuthorityKey>()
                .checked_add(align_of::<AuthorityKey>())?
                .checked_add(2 * size_of::<usize>())?
                .checked_add(login.max(org))?
        };
        // `push` growth from four slots.
        let slots = if runs == 0 {
            0
        } else {
            runs.checked_mul(2)?.checked_add(4)?
        };
        let build = slots
            .checked_mul(size_of::<AccountRun>())?
            // starting, fallback, bound, retained_root and every run's account
            .checked_add(runs.checked_add(4)?.checked_mul(partition)?)?;
        let scratch = slots.checked_mul(2 * size_of::<u64>())?.checked_add(
            runs.checked_add(1)?
                .checked_mul(tree_node_bytes::<&Arc<AuthorityKey>, ()>()?)?,
        )?;
        let bytes = size_of::<Self>()
            .checked_add(align_of::<Self>())?
            .checked_add(build.checked_mul(2)?)?
            .checked_add(scratch)?;
        Some((bytes, partition, runs))
    }

    /// Rebuild only after the money owner confirms exclusion. Restored files
    /// keep every marker; excluded requests cannot lend a marker to own usage.
    pub(crate) fn finish_native(&mut self, markers: Option<&OrgMarkers>, prefix_excluded: bool) {
        if prefix_excluded && !self.subagent {
            let excluded = self
                .runs
                .iter()
                .filter(|run| matches!(run.copied, Some((_, true))))
                .map(|run| run.position)
                .collect::<Vec<_>>();
            let mut own = request_accounts(
                markers,
                self.bound.as_ref().and_then(|key| key.login.as_deref()),
                self.first_retained,
                false,
                &excluded,
            );
            own.inherited = self.inherited;
            own.skipped_inherited = self.skipped_inherited;
            own.first_retained = self.first_retained;
            *self = own;
        }
    }
    pub(crate) fn restore_copies(&mut self) {
        self.inherited = self
            .inherited
            .saturating_add(std::mem::take(&mut self.skipped_inherited));
    }

    /// The money owner has decided individual copies. Exclude only markers
    /// on still-removed/held requests; an emitted unproven prefix keeps its
    /// own markers. Build beside the original so its grains can be moved.
    pub(crate) fn after_copy_decision(
        &self,
        markers: Option<&OrgMarkers>,
        skipped: &[(u64, u64)],
        first_retained: Option<u64>,
    ) -> Option<Self> {
        if self.subagent {
            return None;
        }
        let excluded = self
            .runs
            .iter()
            .filter(|run| {
                let Some((response, true)) = run.copied else {
                    return false;
                };
                let at = skipped.partition_point(|(_, end)| *end <= response);
                skipped.get(at).is_some_and(|(start, _)| *start <= response)
            })
            .map(|run| run.position)
            .collect::<Vec<_>>();
        if excluded.is_empty() {
            return None;
        }
        let mut own = request_accounts(
            markers,
            self.bound.as_ref().and_then(|key| key.login.as_deref()),
            first_retained.or(self.first_retained),
            false,
            &excluded,
        );
        own.inherited = self.inherited;
        own.skipped_inherited = self.skipped_inherited;
        own.first_retained = first_retained.or(self.first_retained);
        Some(own)
    }
}

/// Own exact telemetry uses the existing request classifier, with the same
/// standing as an own credential_org. Only missing evidence inherits an
/// earlier own request, then the start/binding; every such fill is counted.
/// A family whose strict sidecar read failed this page inherits nothing: its
/// requests stay Unknown, counted per reason in the returned totals.
pub(crate) fn reconcile_request_accounts(
    items: &mut [SnapshotItem],
    evidence: &ScanEvidence<'_>,
) -> super::ClaudeUnhealthyRootNoFallbackCounts {
    use super::claude_request_money::e2::place_request_identity;
    let mut no_fallback = super::ClaudeUnhealthyRootNoFallbackCounts::default();
    for item in items {
        let Some(mut fold) = item.claude_money.take() else {
            continue;
        };
        let Some(mut accounts) = fold.accounts.take() else {
            item.claude_money = Some(fold);
            continue;
        };
        if accounts.reconciled {
            fold.accounts = Some(accounts);
            item.claude_money = Some(fold);
            continue;
        }
        let root = super::claude_snapshot_family_root_ref(item);
        if evidence.unhealthy_roots.contains(root) {
            // The classifier refuses every request here (IncompleteEvidence).
            // A retained, creator, start or earlier-request account is not
            // evidence for requests whose own proof could not be read: collapse
            // the partitions in place so tokens, costs, side calls and id-less
            // shares survive with no account. Durable bindings are untouched.
            let reason = evidence.unhealthy_reason(root);
            no_fallback.add(
                reason,
                fold.entity
                    .grains
                    .values()
                    .map(|grain| grain.requests)
                    .fold(0_u64, u64::saturating_add),
            );
            fold.entity.repartition(None);
            accounts.unhealthy_no_fallback = true;
            // A discard keeps #932's hold: nothing to admit.
            accounts.unhealthy_cleared_account = (reason != UnhealthyRootReason::Discarded)
                .then(|| super::exact_session_account_hash(item))
                .flatten();
            accounts.starting = None;
            accounts.fallback = None;
            accounts.inherited = 0;
            accounts.skipped_inherited = 0;
            accounts.reconciled = true;
            for occurrence in item.claude_usage_occurrences.values_mut() {
                occurrence.e2_inherited = Some(false);
            }
            fold.accounts = Some(accounts);
            item.claude_money = Some(fold);
            // Emission carries the account owner's uniform row login to rows
            // that bypass final identity grouping (non-subscription or mixed
            // billing). That login came from this unreadable pair too.
            if super::set_claude_account_hash(item, None) {
                item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            }
            continue;
        }
        let native = accounts.clone();
        // Existing account-owner qualification remains a fallback for a
        // markerless file, never an override of a request's own telemetry.
        if !accounts.subagent
            && accounts.starting.is_none()
            && !accounts.mixed
            && item.claude_org_markers.is_none()
            && item.claude_usage_request_ids.iter().all(|request| {
                !evidence.invalid_logins.contains(&(
                    super::claude_snapshot_family_root_ref(item),
                    request.as_str(),
                ))
            })
        {
            if let Some(login) = super::exact_session_account_hash(item) {
                let key = Some(Arc::new(AuthorityKey {
                    login: Some(login),
                    org: None,
                    basis: TELEMETRY_LOGIN,
                }));
                accounts.starting = key.clone();
                accounts.fallback = key.clone();
                if accounts.bound.is_none() {
                    accounts.bound = key;
                }
            }
        }
        // Existing occurrence storage owns these requests. The temporary sort
        // is 16 bytes per resolved request, at most 1 MiB (native 65,536 cap).
        let mut occurrences = std::mem::take(&mut item.claude_usage_occurrences);
        let mut requests = occurrences.iter_mut().collect::<Vec<_>>();
        requests.sort_unstable_by_key(|(_, occurrence)| occurrence.sequence);
        let first_retained = requests
            .iter()
            .find(|(_, occurrence)| {
                !fold.is_skipped(occurrence.sequence) && !occurrence.usage.is_zero()
            })
            .map(|(_, occurrence)| occurrence.sequence);
        let old_identified = requests
            .iter()
            .filter(|(_, occurrence)| {
                !fold.is_skipped(occurrence.sequence)
                    && !occurrence.usage.is_zero()
                    && native.is_inherited(occurrence.sequence)
            })
            .map(|(_, occurrence)| occurrence.usage.request_count)
            .sum::<u64>();
        accounts.inherited = accounts.inherited.saturating_sub(old_identified);
        let mut earlier: Option<(u64, AccountPartition)> = None;
        let mut keys: Vec<Arc<AuthorityKey>> = Vec::new();
        // Recompute local clocks at their final accounts. Id-less records do
        // not prove an exact request identity and cannot decide current login.
        for grain in fold.entity.grains.values_mut() {
            grain.last_own_at = None;
        }
        for (request, occurrence) in requests {
            if fold.is_skipped(occurrence.sequence) || occurrence.usage.is_zero() {
                occurrence.e2_inherited = Some(false);
                continue;
            }
            let sequence = occurrence.sequence;
            let root = super::claude_snapshot_family_root_ref(item);
            let telemetry = evidence
                .requests
                .get(&(root, request.as_str()))
                .and_then(|row| *row);
            let identity = request_occurrence_facts(item, request, occurrence, false)
                .map(|facts| classify_ref(evidence, &facts));
            let own = match identity {
                Some(IdentityRef::Tagged(key)) if telemetry.is_some() && key.login.is_some() => {
                    let found = keys.iter().find(|known| key.matches(known));
                    match found {
                        Some(known) => Some(Arc::clone(known)),
                        None if keys.len() < MAX_AUTHORITY_KEYS => {
                            let own = Arc::new(key.to_key());
                            keys.push(Arc::clone(&own));
                            Some(own)
                        }
                        None => {
                            // Preserve the verdict for the existing grouping
                            // cap allocator; valid overflow is not missing data.
                            fold.entity.identity_over_cap = true;
                            accounts.conflict = true;
                            None
                        }
                    }
                }
                _ => None,
            };
            let marker_end = native.runs.partition_point(|run| run.position <= sequence);
            let marker = native.runs[..marker_end]
                .iter()
                .rev()
                .find(|run| run.account.is_some());
            let own_marker = marker.filter(|run| run.position == sequence);
            // Absence of a paired trace is not a contradiction of an own org.
            // Keep the existing strong-org guards; only genuinely conflicting
            // telemetry is disclosed, never used to relocate an own org run.
            let contradicted =
                matches!(evidence.requests.get(&(root, request.as_str())), Some(None))
                    || telemetry.is_some_and(|row| {
                        row.request_identity.as_ref().is_some_and(|identity| {
                            matches!(
                                identity.disposition,
                                ClaudeIdentityDisposition::Conflict
                                    | ClaudeIdentityDisposition::Invalid
                            ) || matches!(
                                identity.account.disposition,
                                ClaudeIdentityDisposition::Conflict
                                    | ClaudeIdentityDisposition::Invalid
                            ) || (identity.account.disposition
                                != ClaudeIdentityDisposition::Missing
                                && evidence.invalid_logins.contains(&(root, request.as_str())))
                                || match organization_hash(identity) {
                                    Err(()) => true,
                                    Ok(Some(org)) => own_marker
                                        .and_then(|run| run.account.as_ref())
                                        .and_then(|key| key.org.as_deref())
                                        .is_some_and(|own| own != org),
                                    Ok(None) => false,
                                }
                        })
                    });
            accounts.conflict |= contradicted;
            let preserve_org = contradicted && own_marker.is_some();
            let refused = contradicted && own.is_none() && own_marker.is_none();
            let before = accounts.inherited;
            let account = if preserve_org {
                own_marker.and_then(|run| run.account.clone())
            } else if let Some(own) = own {
                let account = Some(own);
                // The first retained request establishes the actual start;
                // a durable binding only fills a request with no own evidence.
                if !accounts.subagent && first_retained == Some(sequence) {
                    accounts.starting = account.clone();
                    accounts.fallback = account.clone();
                }
                earlier = Some((sequence, account.clone()));
                account
            } else if refused {
                accounts.conflict = true;
                accounts.inherited = accounts
                    .inherited
                    .saturating_add(occurrence.usage.request_count);
                accounts.fallback.clone().or_else(|| accounts.bound.clone())
            } else {
                let account = match (marker, earlier.as_ref()) {
                    (Some(marker), Some((position, account))) if marker.position < *position => {
                        account.clone()
                    }
                    (Some(marker), _) => marker.account.clone(),
                    (_, Some((_, account))) => account.clone(),
                    _ => accounts
                        .starting
                        .clone()
                        .or_else(|| accounts.fallback.clone())
                        .or_else(|| accounts.bound.clone()),
                };
                if own_marker.is_none() && account.is_some() {
                    accounts.inherited = accounts
                        .inherited
                        .saturating_add(occurrence.usage.request_count);
                }
                account
            };
            occurrence.e2_inherited = account.as_ref().map(|_| accounts.inherited > before);
            place_request_identity(
                &mut fold,
                occurrence,
                telemetry,
                native.account(sequence),
                account,
            );
        }
        item.claude_usage_occurrences = occurrences;
        accounts.reconciled = true;
        fold.accounts = Some(accounts);
        item.claude_money = Some(fold);
    }
    no_fallback
}

/// Lead B Addendum 4 (option 1): the account this page cleared from `item` for
/// a non-discard unhealthy read. If it was the bound owner's, main would have
/// uploaded the body, so it uploads Unknown now instead of being held.
pub(crate) fn unhealthy_cleared_account(item: &SnapshotItem) -> Option<&str> {
    item.claude_money
        .as_deref()?
        .accounts
        .as_deref()?
        .unhealthy_cleared_account
        .as_deref()
}

/// Read retained creator bindings using the same machine/session key as the
/// account owner. No transcript read, new index field, or current-login guess.
pub(crate) fn retain_root_accounts(items: &mut [SnapshotItem], index: &ScanIndex, machine: &str) {
    for item in items {
        if item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.accounts.as_deref())
            .is_none()
        {
            continue;
        }
        let root = super::claude_snapshot_family_root_ref(item);
        let key = super::sha256_hex(&["session_owner:v1", machine, root]);
        let retained = index
            .session_account_bindings
            .get(&key)
            .filter(|binding| wire_login_is_valid(&binding.account_identifier_hash))
            .map(|binding| {
                Arc::new(AuthorityKey {
                    login: Some(binding.account_identifier_hash.clone()),
                    org: None,
                    basis: TELEMETRY_LOGIN,
                })
            });
        let fold = item.claude_money.as_deref_mut().expect("checked fold");
        let accounts = fold.accounts.as_deref_mut().expect("checked accounts");
        if accounts.subagent {
            accounts.retained_root = retained;
        } else if retained.is_some() {
            // A native markerless file may not yet carry its persisted creator
            // binding. Fill only missing shares, never a later own-org run.
            if accounts.bound.is_none() {
                accounts.bound = retained.clone();
            }
            if accounts.starting.is_none() {
                accounts.starting = retained.clone();
                accounts.fallback = retained.clone();
                fold.entity.inherit_missing(retained);
            }
        }
    }
}

/// Root placement is fixed before summing path twins. A missing/Unknown root
/// stays Unknown; a subagent's own marker can never manufacture a root account.
pub(crate) fn inherit_root_accounts(items: &mut [SnapshotItem], settled: bool) {
    // Select the root's earliest native start, independently of page/map order.
    // Contradictory observations at the same start use the retained binding.
    struct Root {
        first: i128,
        starting: AccountPartition,
        bound: AccountPartition,
        conflict: bool,
        known: bool,
        // Kind of the original start evidence, retained through fallback.
        org_start: bool,
        start_conflict: bool,
        bound_conflict: bool,
    }
    let mut roots = BTreeMap::<String, Root>::new();
    for item in items.iter() {
        let Some(accounts) = item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.accounts.as_deref())
        else {
            continue;
        };
        // An unhealthy family lends no start to its children or twins.
        if accounts.subagent || accounts.unhealthy_no_fallback {
            continue;
        }
        let first = item
            .source_started_at
            .as_deref()
            .and_then(super::rfc3339_unix_nanos)
            .unwrap_or(i128::MAX);
        let candidate = Root {
            first,
            starting: accounts.starting.clone(),
            bound: accounts.bound.clone(),
            conflict: accounts.conflict,
            known: accounts.starting.is_some(),
            org_start: accounts
                .starting
                .as_ref()
                .is_some_and(|key| key.org.is_some()),
            start_conflict: false,
            bound_conflict: false,
        };
        match roots.entry(item.source_session_id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(candidate);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let root = entry.get_mut();
                let any_conflict = root.conflict || candidate.conflict;
                if candidate.known && (!root.known || first < root.first) {
                    *root = candidate;
                } else if first == root.first {
                    if root.bound.is_some()
                        && candidate.bound.is_some()
                        && root.bound != candidate.bound
                    {
                        root.bound_conflict = true;
                    }
                    if root.bound_conflict {
                        root.bound = None;
                    } else if root.bound.is_none() {
                        root.bound = candidate.bound.clone();
                    }
                    if root.known && candidate.known && root.starting != candidate.starting {
                        if root.org_start != candidate.org_start {
                            // Different kinds do not contradict each other.
                            if candidate.org_start {
                                root.starting = candidate.starting.clone();
                                root.org_start = true;
                                root.start_conflict = false;
                            }
                        } else {
                            root.start_conflict = true;
                            root.conflict = true;
                        }
                    }
                    // A fallback is only as strong as the current binding.
                    // A later contradictory binding invalidates it too.
                    if root.start_conflict {
                        root.starting = root.bound.clone();
                    }
                }
                root.conflict |= any_conflict;
            }
        }
    }
    for item in items {
        let root = super::claude_snapshot_family_root_ref(item).to_owned();
        let Some(fold) = item.claude_money.as_deref_mut() else {
            continue;
        };
        let Some(accounts) = fold.accounts.as_deref_mut() else {
            continue;
        };
        if accounts.unhealthy_no_fallback {
            continue;
        }
        if accounts.subagent {
            accounts.starting = match roots.get(&root) {
                Some(root) => root.starting.clone(),
                None => accounts.retained_root.clone(),
            };
            accounts.fallback = accounts.starting.clone();
            if settled || accounts.reconciled {
                // Own request logins survive; only missing shares inherit RD47.
                let inherited = fold
                    .entity
                    .grains
                    .iter()
                    .filter(|((_, _, account), _)| account.is_none())
                    .map(|(_, grain)| grain.requests)
                    .sum::<u64>()
                    .saturating_sub(fold.side_requests);
                fold.entity.inherit_missing(accounts.fallback.clone());
                if accounts.fallback.is_some() {
                    accounts.inherited = accounts.inherited.saturating_add(inherited);
                    for occurrence in item.claude_usage_occurrences.values_mut() {
                        if occurrence.e2_inherited.is_none() && !occurrence.usage.is_zero() {
                            occurrence.e2_inherited = Some(true);
                        }
                    }
                }
            } else {
                fold.entity.repartition(accounts.fallback.clone());
            }
        } else if let Some(root) = roots.get(&root) {
            accounts.fallback = root.starting.clone();
            // The side-call pass lends the root start without remapping
            // this file's native grains. Keep account(sequence) aligned with
            // those grains until the final missing-share fill is applied.
            accounts.root_fallback_pending = !settled && accounts.starting.is_none();
            if root.conflict {
                accounts.conflict = true;
            }
            if settled {
                // Markerless twins inherit the resolved session start, not a
                // provisional Unknown partition from their native file.
                fold.entity.inherit_missing(accounts.fallback.clone());
                if accounts.starting.is_none()
                    && accounts.runs.is_empty()
                    && accounts.fallback.is_some()
                {
                    accounts.inherited = fold
                        .entity
                        .grains
                        .values()
                        .map(|grain| grain.requests)
                        .sum::<u64>()
                        .saturating_sub(fold.side_requests);
                }
            }
        }
    }
}

// Merge borrowed native request-id iterators. Counter dedup needs no set or
// copy proportional to response count; id-less native usage remains counted.
// The next request is the minimum over every member's peeked head; a
// `while let` would hold that mutable walk across the body.
#[allow(clippy::while_let_loop)]
fn inherited_requests(members: &[&SnapshotItem]) -> u64 {
    let mut identified = 0u64;
    let mut total = 0u64;
    for item in members {
        let fold = item.claude_money.as_deref().expect("identity fold");
        let accounts = fold.accounts.as_deref().expect("identity accounts");
        total = total.saturating_add(accounts.inherited);
        for occurrence in item.claude_usage_occurrences.values() {
            if !fold.is_skipped(occurrence.sequence)
                && !occurrence.usage.is_zero()
                && occurrence
                    .e2_inherited
                    .unwrap_or_else(|| accounts.is_inherited(occurrence.sequence))
            {
                identified = identified.saturating_add(occurrence.usage.request_count);
            }
        }
    }
    let mut merged = total.saturating_sub(identified);
    let mut heads = members
        .iter()
        .map(|item| item.claude_usage_occurrences.iter().peekable())
        .collect::<Vec<_>>();
    loop {
        let Some(request) = heads
            .iter_mut()
            .filter_map(|head| head.peek().map(|(request, _)| *request))
            .min()
        else {
            break;
        };
        let mut counted = false;
        let mut inherited = true;
        let mut requests = 0;
        for (head, item) in heads.iter_mut().zip(members) {
            if head
                .peek()
                .is_some_and(|(candidate, _)| *candidate == request)
            {
                let (_, occurrence) = head.next().expect("peeked native request");
                let fold = item.claude_money.as_deref().expect("identity fold");
                let accounts = fold.accounts.as_deref().expect("identity accounts");
                if !fold.is_skipped(occurrence.sequence) && !occurrence.usage.is_zero() {
                    counted = true;
                    inherited &= occurrence
                        .e2_inherited
                        .unwrap_or_else(|| accounts.is_inherited(occurrence.sequence));
                    requests = requests.max(occurrence.usage.request_count);
                }
            }
        }
        if counted && inherited {
            merged = merged.saturating_add(requests);
        }
    }
    merged
}

pub(crate) fn page_identity_counts(items: &[SnapshotItem]) -> IdentityCounts {
    // Once per session, independent of which path twin the page lists first.
    let mut sessions =
        BTreeMap::<&str, (bool, bool, BTreeSet<&AccountPartition>, Vec<&SnapshotItem>)>::new();
    for item in items {
        let Some(fold) = item.claude_money.as_deref() else {
            continue;
        };
        let Some(accounts) = fold.accounts.as_deref() else {
            continue;
        };
        let session = sessions.entry(&item.source_session_id).or_default();
        session.0 |= accounts.mixed;
        session.1 |= accounts.conflict;
        session
            .2
            .extend(fold.entity.grains.keys().map(|(_, _, account)| account));
        session.3.push(item);
    }
    let mut counts = IdentityCounts::default();
    for (mixed, conflict, partitions, members) in sessions.into_values() {
        counts.claude_mixed_login_sessions += u64::from(mixed || partitions.len() > 1);
        counts.claude_inherited_org_requests += inherited_requests(&members);
        counts.claude_identity_conflict_fallbacks += u64::from(conflict);
    }
    counts
}

pub(crate) fn record_page_identity_counts(items: &[SnapshotItem]) {
    let counts = page_identity_counts(items);
    for (counter, value) in IDENTITY_COUNTS.iter().zip([
        counts.claude_mixed_login_sessions,
        counts.claude_inherited_org_requests,
        counts.claude_identity_conflict_fallbacks,
    ]) {
        if value != 0 {
            counter.fetch_add(value, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

static IDENTITY_COUNTS: [std::sync::atomic::AtomicU64; 5] =
    [const { std::sync::atomic::AtomicU64::new(0) }; 5];

pub(crate) fn record_listed_legacy_counts(families: u64, files: u64) {
    // Current loaded-list inventory, not process-total sums across cycles.
    IDENTITY_COUNTS[3].store(families, std::sync::atomic::Ordering::Relaxed);
    IDENTITY_COUNTS[4].store(files, std::sync::atomic::Ordering::Relaxed);
}
#[derive(Default, serde::Serialize)]
pub(crate) struct IdentityCounts {
    #[serde(skip_serializing_if = "budget::Counts::is_empty")]
    identity_cap: budget::Counts,
    #[serde(skip_serializing_if = "is_zero")]
    claude_mixed_login_sessions: u64,
    #[serde(skip_serializing_if = "is_zero")]
    claude_inherited_org_requests: u64,
    #[serde(skip_serializing_if = "is_zero")]
    claude_identity_conflict_fallbacks: u64,
    #[serde(skip_serializing_if = "is_zero")]
    claude_listed_legacy_families: u64,
    #[serde(skip_serializing_if = "is_zero")]
    claude_listed_legacy_files: u64,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
pub(crate) fn take_identity_counts() -> IdentityCounts {
    let [mixed, inherited, conflicts, families, files] = IDENTITY_COUNTS
        .each_ref()
        .map(|counter| counter.swap(0, std::sync::atomic::Ordering::Relaxed));
    IdentityCounts {
        identity_cap: budget::take_counts(),
        claude_mixed_login_sessions: mixed,
        claude_inherited_org_requests: inherited,
        claude_identity_conflict_fallbacks: conflicts,
        claude_listed_legacy_families: families,
        claude_listed_legacy_files: files,
    }
}

/// Exact final E2 rows, including copied exclusions and telemetry side calls.
/// E2 owns placement; this owner supplies contract-5 keys and evidence only.
fn request_owned_grouping(item: &SnapshotItem) -> Option<Grouping> {
    let mut grouping = Grouping::new(bucket_row_count(item));
    super::claude_request_money::e2::visit_identity_rows(
        item,
        |bucket, row, account, cost, last_at| {
            let mut usage = super::usage_totals_from_model_usage(&row);
            if let Some(cost) = cost {
                usage.costs.observed = true;
                usage.costs.reported = true;
                usage.costs.total = Some(u128::from(cost) * 1_000_000);
            }
            let identity = match account.as_ref() {
                Some(key) => IdentityRef::Tagged(KeyRef {
                    login: key.login.as_deref(),
                    org: key.org.as_deref(),
                    basis: key.basis,
                }),
                None => IdentityRef::Missing,
            };
            let at = last_at
                .and_then(|at| OffsetDateTime::from_unix_timestamp_nanos(at).ok())
                .and_then(|at| at.format(&Rfc3339).ok());
            grouping.add_at(
                bucket,
                &row_key_from_model_usage(&row),
                &usage,
                identity,
                at.as_deref(),
            );
        },
    )?;
    grouping.upstream_proof_lost = item
        .claude_money
        .as_deref()
        .is_some_and(|fold| fold.entity.identity_over_cap);
    grouping.keys_over_cap |= grouping.upstream_proof_lost;
    grouping.latest.unordered |= item
        .claude_money
        .as_deref()
        .is_some_and(|fold| fold.entity.clock_incomplete)
        || item.claude_usage_occurrences.values().any(|occurrence| {
            !occurrence.usage.is_zero()
                && item
                    .claude_money
                    .as_deref()
                    .is_some_and(|fold| !fold.is_skipped(occurrence.sequence))
                && (!occurrence.event_clock_complete
                    || occurrence
                        .timestamp
                        .as_deref()
                        .and_then(rfc3339_unix_seconds)
                        .is_none())
        });
    Some(grouping)
}

// --- Per-request classification -------------------------------------------

/// Telemetry younger than this at scan time is still being flushed by a healthy
/// sidecar writer (retained evidence: ~5 minutes of flush lag before a scan).
/// One isolated, provisional constant.
pub(crate) const TELEMETRY_FLUSH_WINDOW_SECONDS: u64 = 300;

/// Scan-local evidence shared by every item of one Claude pass.
#[derive(Default)]
pub(crate) struct ScanEvidence<'a> {
    pub(crate) requests: BTreeMap<(&'a str, &'a str), Option<&'a ClaudeLocalOtelEvidence>>,
    pub(crate) owners: BTreeMap<(&'a str, &'a str), Option<&'a ClaudeTraceOwnershipEvidence>>,
    /// Each request id named by loaded API or trace rows, sorted, with the
    /// one root holding them, or `None` when rows under several roots name
    /// it. Rows are keyed by trace root, so this is how a fork or resume copy
    /// under another root sees that the request already has an owner. Built
    /// on the first request without rows of its own: a pass whose requests
    /// all have their own rows never pays for it.
    request_roots: std::cell::OnceCell<Vec<(&'a str, Option<&'a str>)>>,
    /// Roots whose sidecar reads were incomplete in this pass.
    pub(crate) unhealthy_roots: BTreeSet<String>,
    /// Why each unhealthy root failed, for its no-fallback counter only.
    /// A root missing here counts as `Incomplete`.
    unhealthy_reasons: BTreeMap<String, UnhealthyRootReason>,
    /// Roots with a qualified witness that their telemetry writer is healthy
    /// NOW, the precondition for `Refusal::Pending`. A complete paired-sidecar
    /// load proves only what was already written, not a live writer, and no
    /// existing qualified current-writer witness exists; production therefore
    /// supplies none (pending is unproven; young missing requests stay missing)
    /// until SESSION rules on one. Only tests can populate this.
    pending_writer_witnesses: BTreeSet<String>,
    /// Unique telemetry rows that failed `valid_login`. Every unique row is
    /// checked once here (its fingerprint included); `classify` reuses the
    /// verdict, and a passing row's login is its `account_identifier_hash`.
    invalid_logins: BTreeSet<(&'a str, &'a str)>,
    /// Orgs per login, proven by complete telemetry request identity.
    pub(crate) memberships: BTreeMap<String, BTreeSet<String>>,
    /// Desktop store logins per org, present only under a valid census witness.
    pub(crate) desktop_census: Option<DesktopCensus>,
    /// `TRANSCRIPT_SOLE_LOGIN_ENABLED`; off, a sole census login stays org-only.
    sole_login_enabled: bool,
    /// This scan's copy of the local status-coverage history.
    status_coverage: Option<crate::claude_status_coverage::Ledger>,
    /// Key of the shared default folder, where the email basis never applies.
    default_home: Option<crate::claude_status_coverage::HomeKey>,
    /// Pre-enrichment native evidence already saved by this scan. Request
    /// telemetry may veto its original org for billing without changing the
    /// unambiguous native account used by local Desktop activity.
    native_originals: Option<&'a BTreeMap<String, super::SessionAccountEvidence>>,
    accepted_buckets: Option<&'a AcceptedBuckets>,
    wire_size_reservation: Option<&'a dyn Fn(&SnapshotItem) -> usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct DesktopCensus {
    pub(crate) completed_at_unix_seconds: u64,
    pub(crate) logins_by_org: BTreeMap<String, BTreeSet<String>>,
}

impl<'a> ScanEvidence<'a> {
    pub(crate) fn new(
        api: &'a ClaudeLocalOtelLoadReport,
        trace: &'a ClaudeTraceOwnershipLoadReport,
        unhealthy_roots: BTreeSet<String>,
        desktop_census: Option<DesktopCensus>,
    ) -> Self {
        let mut evidence = Self {
            unhealthy_roots,
            desktop_census,
            sole_login_enabled: TRANSCRIPT_SOLE_LOGIN_ENABLED,
            ..Self::default()
        };
        for (root, rows) in &api.evidence {
            for row in rows {
                evidence
                    .requests
                    .entry((root.as_str(), row.request_id.as_str()))
                    .and_modify(|entry| *entry = None)
                    .or_insert(Some(row));
            }
        }
        // Only unique rows that pass the same integrity checks `classify`
        // applies may establish a (login, org) pair.
        for (&key, row) in &evidence.requests {
            let Some(row) = row else { continue };
            let Some(login) = valid_login(row, key.0) else {
                evidence.invalid_logins.insert(key);
                continue;
            };
            if let Some(org) = row
                .request_identity
                .as_ref()
                .filter(|identity| identity.disposition == ClaudeIdentityDisposition::Complete)
                .and_then(|identity| organization_hash(identity).ok().flatten())
            {
                evidence
                    .memberships
                    .entry(login.to_string())
                    .or_default()
                    .insert(org.to_string());
            }
        }
        for (root, rows) in &trace.evidence {
            for row in rows {
                evidence
                    .owners
                    .entry((root.as_str(), row.request_id.as_str()))
                    .and_modify(|entry| *entry = None)
                    .or_insert(Some(row));
            }
        }
        evidence
    }

    pub(crate) fn with_unhealthy_reasons(
        mut self,
        reasons: BTreeMap<String, UnhealthyRootReason>,
    ) -> Self {
        self.unhealthy_reasons = reasons;
        self
    }

    fn unhealthy_reason(&self, root: &str) -> UnhealthyRootReason {
        self.unhealthy_reasons
            .get(root)
            .copied()
            .unwrap_or(UnhealthyRootReason::Incomplete)
    }

    pub(crate) fn with_accepted_buckets(mut self, accepted: Option<&'a AcceptedBuckets>) -> Self {
        self.accepted_buckets = accepted;
        self
    }

    pub(crate) fn with_wire_size_reservation(
        mut self,
        reservation: Option<&'a dyn Fn(&SnapshotItem) -> usize>,
    ) -> Self {
        self.wire_size_reservation = reservation;
        self
    }

    pub(crate) fn with_native_originals(
        mut self,
        originals: &'a BTreeMap<String, super::SessionAccountEvidence>,
    ) -> Self {
        self.native_originals = Some(originals);
        self
    }

    /// The root whose rows name `request_id` (`Some(None)`: several roots).
    fn request_root(&self, request_id: &str) -> Option<Option<&'a str>> {
        let roots = self.request_roots.get_or_init(|| {
            // Both maps are ordered by (root, request id); merging them
            // yields each pair once.
            let pairs = || {
                let mut api = self.requests.keys().copied().peekable();
                let mut trace = self.owners.keys().copied().peekable();
                std::iter::from_fn(move || match (api.peek(), trace.peek()) {
                    (Some(a), Some(t)) if a < t => api.next(),
                    (Some(a), Some(t)) if a > t => trace.next(),
                    (Some(_), Some(_)) => {
                        trace.next();
                        api.next()
                    }
                    (Some(_), None) => api.next(),
                    (None, _) => trace.next(),
                })
            };
            let mut roots = Vec::with_capacity(pairs().count());
            roots.extend(pairs().map(|(root, request_id)| (request_id, Some(root))));
            roots.sort_unstable();
            roots.dedup_by(|later, kept| {
                if later.0 != kept.0 {
                    return false;
                }
                kept.1 = None;
                true
            });
            roots
        });
        roots
            .binary_search_by(|(known, _)| (*known).cmp(request_id))
            .ok()
            .map(|at| roots[at].1)
    }

    /// Adds this scan's status-coverage copy: the `transcript_email` window
    /// check, and each qualified status-pass (login, org) pairing as org
    /// membership (plan §2a.12(b)). `None` (feed off or failed) adds nothing.
    pub(crate) fn with_status_coverage(
        mut self,
        coverage: Option<crate::claude_status_coverage::Ledger>,
    ) -> Self {
        if let Some(coverage) = &coverage {
            for (login, org) in coverage.pairings() {
                if !self
                    .memberships
                    .get(login)
                    .is_some_and(|orgs| orgs.contains(org))
                {
                    self.memberships
                        .entry(login.to_string())
                        .or_default()
                        .insert(org.to_string());
                }
            }
        }
        self.status_coverage = coverage;
        self.default_home = Some(crate::claude_status_coverage::home_key(
            &crate::agent_status::home_dir().join(".claude"),
        ));
        self
    }

    /// Test-only stand-in for the unruled current-writer witness.
    #[cfg(test)]
    pub(crate) fn with_pending_writer_witnesses(mut self, roots: BTreeSet<String>) -> Self {
        self.pending_writer_witnesses = roots;
        self
    }

    /// Test-only stand-in for a verified sole-login body veto.
    #[cfg(test)]
    pub(crate) fn with_sole_login_enabled(mut self) -> Self {
        self.sole_login_enabled = true;
        self
    }
}

/// `Ok(None)` = no organization observed; `Err` = present but conflicting or invalid.
fn organization_hash(identity: &ClaudeRequestIdentityEvidence) -> Result<Option<&str>, ()> {
    let org = &identity.organization;
    match org.disposition {
        ClaudeIdentityDisposition::Missing => Ok(None),
        ClaudeIdentityDisposition::Invalid | ClaudeIdentityDisposition::Conflict => Err(()),
        ClaudeIdentityDisposition::Complete => org
            .log_record_hash
            .as_deref()
            .or(org.resource_hash.as_deref())
            .filter(|hash| hash_is_valid(hash))
            .map(Some)
            .ok_or(()),
    }
}

/// The row's login when the row itself is intact: D1's capture, count,
/// fingerprint and account-origin checks. Ownership is checked separately.
fn valid_login<'a>(row: &'a ClaudeLocalOtelEvidence, root: &str) -> Option<&'a str> {
    let login = row
        .account_identifier_hash
        .as_deref()
        .filter(|hash| hash_is_valid(hash))?;
    (row.session_id == root
        && row.capture_revision == "claude_api_request:v2"
        && row.request_count == 1
        && row.account_identity_checked
        && super::claude_api_evidence_fingerprint_is_valid(row)
        && row.request_identity.as_ref().map_or(true, |identity| {
            identity.identity_hash_scheme == "provider-sha256:v1"
                && identity.account.disposition == ClaudeIdentityDisposition::Complete
                && account_origin_matches(&identity.account, login)
        }))
    .then_some(login)
}

/// D1's account check: each recorded origin must carry exactly this login.
fn account_origin_matches(account: &ClaudeIdentityAttributeEvidence, login: &str) -> bool {
    let log = account.log_record_hash.as_deref();
    let resource = account.resource_hash.as_deref();
    match account.origin {
        ClaudeIdentityAttributeOrigin::LogRecord => log == Some(login) && resource.is_none(),
        ClaudeIdentityAttributeOrigin::Resource => resource == Some(login) && log.is_none(),
        ClaudeIdentityAttributeOrigin::ResourceAndLogRecord => {
            resource == Some(login) && log == Some(login)
        }
        ClaudeIdentityAttributeOrigin::Missing => false,
    }
}

/// The receiver's stored `account_identifier_hash` spelling.
fn wire_login_is_valid(login: &str) -> bool {
    (8..=128).contains(&login.len())
        && login
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hash_is_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What the classifier knows about one counted request.
pub(crate) struct RequestFacts<'a> {
    pub(crate) root: &'a str,
    pub(crate) source_session_id: &'a str,
    pub(crate) request_id: &'a str,
    /// Original terminal clock from the transcript; `None` for telemetry-only requests.
    pub(crate) terminal_unix_seconds: Option<u64>,
    pub(crate) event_clock_complete: bool,
    pub(crate) marker: MarkerVerdict<'a>,
    pub(crate) desktop: bool,
    pub(crate) scan_unix_seconds: Option<u64>,
    /// Registered-folder key when an unchanged email precedes this request.
    pub(crate) email_home: Option<&'a crate::claude_status_coverage::HomeKey>,
    pub(crate) session_start_unix_seconds: Option<u64>,
    /// Another transcript also carries this request (the pass's duplicate
    /// witness): it is not this transcript's alone.
    pub(crate) duplicated_elsewhere: bool,
}

impl RequestFacts<'_> {
    /// Missing telemetry is pending only for this request's own young clock
    /// and a witnessed healthy writer for its folder; never inferred from
    /// other requests or from complete sidecar loads.
    fn telemetry_pending(&self, evidence: &ScanEvidence<'_>) -> bool {
        if !evidence.pending_writer_witnesses.contains(self.root) {
            return false;
        }
        match (self.terminal_unix_seconds, self.scan_unix_seconds) {
            (Some(at), Some(now)) => {
                at <= now.saturating_add(TELEMETRY_FLUSH_WINDOW_SECONDS)
                    && now < at.saturating_add(TELEMETRY_FLUSH_WINDOW_SECONDS)
            }
            _ => false,
        }
    }
}

/// A borrowed authority key: classification builds no strings; a `Grouping`
/// copies one only when it admits a new key (at most 16 per item).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyRef<'k> {
    login: Option<&'k str>,
    org: Option<&'k str>,
    basis: &'static str,
}

impl KeyRef<'_> {
    fn matches(&self, key: &AuthorityKey) -> bool {
        self.basis == key.basis
            && self.login == key.login.as_deref()
            && self.org == key.org.as_deref()
    }

    fn to_key(self) -> AuthorityKey {
        AuthorityKey {
            login: self.login.map(str::to_string),
            org: self.org.map(str::to_string),
            basis: self.basis,
        }
    }
}

#[cfg(test)]
impl AuthorityKey {
    fn as_ref(&self) -> KeyRef<'_> {
        KeyRef {
            login: self.login.as_deref(),
            org: self.org.as_deref(),
            basis: self.basis,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IdentityRef<'k> {
    Tagged(KeyRef<'k>),
    Missing,
    Refused(Refusal),
}

#[cfg(test)]
impl RequestIdentity {
    pub(crate) fn as_ref(&self) -> IdentityRef<'_> {
        match self {
            RequestIdentity::Tagged(key) => IdentityRef::Tagged(key.as_ref()),
            RequestIdentity::Missing => IdentityRef::Missing,
            RequestIdentity::Refused(refusal) => IdentityRef::Refused(*refusal),
        }
    }
}

#[cfg(test)]
impl From<IdentityRef<'_>> for RequestIdentity {
    fn from(identity: IdentityRef<'_>) -> Self {
        match identity {
            IdentityRef::Tagged(key) => RequestIdentity::Tagged(key.to_key()),
            IdentityRef::Missing => RequestIdentity::Missing,
            IdentityRef::Refused(refusal) => RequestIdentity::Refused(refusal),
        }
    }
}

/// Owned classification, for the ruling tests.
#[cfg(test)]
pub(crate) fn classify(evidence: &ScanEvidence<'_>, facts: &RequestFacts<'_>) -> RequestIdentity {
    classify_ref(evidence, facts).into()
}

pub(crate) fn classify_ref<'k>(
    evidence: &'k ScanEvidence<'_>,
    facts: &RequestFacts<'k>,
) -> IdentityRef<'k> {
    use IdentityRef::{Missing, Refused, Tagged};
    if evidence.unhealthy_roots.contains(facts.root) {
        // Unreadable stronger evidence never falls through (W0 CLS-refused-truncated).
        return Refused(Refusal::IncompleteEvidence);
    }
    let row = match evidence.requests.get(&(facts.root, facts.request_id)) {
        Some(None) => return Refused(Refusal::ConflictingDuplicate),
        Some(Some(row)) => *row,
        None if facts.telemetry_pending(evidence) => return Refused(Refusal::Pending),
        None => {
            // A trace that already owns this request outranks the transcript:
            // a foreign, duplicated or unpaired owner refuses and never borrows
            // this transcript's org or sole login.
            if let Some(owner) = evidence.owners.get(&(facts.root, facts.request_id)) {
                return Refused(match owner {
                    None => Refusal::ConflictingDuplicate,
                    Some(owner) if owner_is_foreign(owner, facts) => Refusal::ForeignOwner,
                    Some(_) => Refusal::IncompleteEvidence,
                });
            }
            // Rows are keyed by trace root: a fork or resume copy holds its
            // original's request with the original's rows under another root.
            // Those rows own it; the copy's markers never claim it.
            match evidence.request_root(facts.request_id) {
                Some(Some(_)) => return Refused(Refusal::ForeignOwner),
                Some(None) => return Refused(Refusal::ConflictingDuplicate),
                None => {}
            }
            if facts.duplicated_elsewhere {
                return Refused(Refusal::ConflictingDuplicate);
            }
            return match transcript_identity(evidence, facts) {
                // A carried or missing clock cannot establish attribution.
                Some(_) if facts.terminal_unix_seconds.is_none() || !facts.event_clock_complete => {
                    Refused(Refusal::BadClock)
                }
                identity => identity.unwrap_or(Missing),
            };
        }
    };
    let login = match row.account_identifier_hash.as_deref() {
        Some(login)
            if !evidence
                .invalid_logins
                .contains(&(facts.root, facts.request_id)) =>
        {
            login
        }
        _ => return Refused(Refusal::InvalidEvidence),
    };
    match evidence.owners.get(&(facts.root, facts.request_id)) {
        Some(None) => return Refused(Refusal::ConflictingDuplicate),
        None if facts.telemetry_pending(evidence) => return Refused(Refusal::Pending),
        None => return Refused(Refusal::IncompleteEvidence),
        Some(Some(owner)) => {
            if owner_is_foreign(owner, facts) || owner.client_request_id != row.client_request_id {
                return Refused(Refusal::ForeignOwner);
            }
        }
    }
    if facts.terminal_unix_seconds.is_none() || !facts.event_clock_complete {
        return Refused(Refusal::BadClock);
    }
    let telemetry_org = match row.request_identity.as_ref() {
        None => None,
        Some(identity) => match organization_hash(identity) {
            Ok(org) => org,
            Err(()) => return Refused(Refusal::ContradictoryOrg),
        },
    };
    if let Some(org) = telemetry_org {
        return Tagged(KeyRef {
            login: Some(login),
            org: Some(org),
            basis: TELEMETRY,
        });
    }
    // Login-only telemetry: a trusted marker org joins only when it is an
    // established org of that login; otherwise today's login rule.
    let org = match facts.marker {
        MarkerVerdict::Trusted(org)
            if evidence
                .memberships
                .get(login)
                .is_some_and(|orgs| orgs.contains(org)) =>
        {
            Some(org)
        }
        _ => None,
    };
    Tagged(KeyRef {
        login: Some(login),
        org,
        basis: TELEMETRY_LOGIN,
    })
}

/// The ownership checks that need no telemetry row.
fn owner_is_foreign(owner: &ClaudeTraceOwnershipEvidence, facts: &RequestFacts<'_>) -> bool {
    owner.session_id != facts.root
        || owner.capture_revision != "claude_llm_request_ownership:v1"
        || !super::claude_trace_evidence_fingerprint_is_valid(owner)
        || super::claude_trace_owner_session_id(facts.root, &owner.agent_id)
            != facts.source_session_id
        || owner.client_request_id.is_empty()
}

/// Transcript bases for a request with no telemetry row or trace owner.
fn transcript_identity<'k>(
    evidence: &'k ScanEvidence<'_>,
    facts: &RequestFacts<'k>,
) -> Option<IdentityRef<'k>> {
    let org = match facts.marker {
        MarkerVerdict::None => return None,
        MarkerVerdict::Overflow => return Some(IdentityRef::Refused(Refusal::MarkerOverflow)),
        MarkerVerdict::UntrustedFlip => return Some(IdentityRef::Refused(Refusal::UntrustedFlip)),
        MarkerVerdict::BadOrg => return Some(IdentityRef::Refused(Refusal::ContradictoryOrg)),
        MarkerVerdict::Trusted(org) => org,
    };
    let sole_login = (facts.desktop && evidence.sole_login_enabled)
        .then_some(())
        .and(evidence.desktop_census.as_ref())
        .filter(|census| {
            facts
                .terminal_unix_seconds
                .is_some_and(|at| census.completed_at_unix_seconds >= at)
        })
        .and_then(|census| census.logins_by_org.get(org))
        .filter(|logins| logins.len() == 1)
        .and_then(|logins| logins.first());
    if let Some(refusal) = email_refusal(evidence, facts, org) {
        return Some(IdentityRef::Refused(refusal));
    }
    Some(IdentityRef::Tagged(match sole_login {
        Some(login) => KeyRef {
            login: Some(login),
            org: Some(org),
            basis: TRANSCRIPT_SOLE_LOGIN,
        },
        None => KeyRef {
            login: None,
            org: Some(org),
            basis: TRANSCRIPT_ORG,
        },
    }))
}

/// `transcript_email` never binds a login. No qualified join from a recorded
/// email to a login exists, and sampled status coverage cannot prove that the
/// slot's login ran continuously over [session start − 300 s, request]. So the
/// basis only decides whether the request keeps its earlier meaning:
/// - not applicable (`None`, the org-only path stands): the basis compiled
///   out, Desktop, no unchanged email before the request, the shared default
///   folder, or a folder proven never registered over the window;
/// - otherwise refused, never weakened to org-only: the feed unavailable or
///   not yet run since restart, a removed slot or forgotten registration, an
///   unknown session start, a conflicting sample, no history spanning the
///   window, or samples that span it but prove nothing.
fn email_refusal(
    evidence: &ScanEvidence<'_>,
    facts: &RequestFacts<'_>,
    org: &str,
) -> Option<Refusal> {
    use crate::claude_status_coverage::{Registration, Verdict};
    if facts.desktop || !transcript_email_enabled() {
        return None;
    }
    let home = facts.email_home?;
    if evidence.default_home.as_ref() == Some(home) {
        return None;
    }
    let Some(coverage) = evidence.status_coverage.as_ref() else {
        return Some(Refusal::CoverageUnavailable);
    };
    let window = facts
        .session_start_unix_seconds
        .and_then(|start| start.checked_sub(crate::claude_status_coverage::SESSION_LEAD_SECONDS))
        .zip(facts.terminal_unix_seconds);
    let Some((from, to)) = window else {
        return Some(Refusal::CoverageUnavailable);
    };
    match coverage.registration(home, from) {
        Registration::Registered => {}
        Registration::NeverRegistered => return None,
        Registration::Unknown => return Some(Refusal::CoverageUnavailable),
    }
    Some(match coverage.verdict(home, from, to, org) {
        Verdict::Unavailable => Refusal::CoverageUnavailable,
        Verdict::Conflicting => Refusal::ContradictoryOrg,
        Verdict::Unqualified => Refusal::CoverageUnqualified,
    })
}

// --- Desktop census freshness witness ---------------------------------------

/// Local completion witness for the Desktop store census: set only when a
/// sweep finishes complete and error-free, bound to this process and to the
/// store inventory it swept. Sole-login inference needs it to postdate the
/// request; anything else (older index, restart, other inventory) is unknown.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DesktopCensusWitness {
    completed_at_unix_seconds: u64,
    process_id: u32,
    inventory: String,
}

impl DesktopCensusWitness {
    pub(super) fn new(now: u64, store_dirs: &BTreeSet<PathBuf>) -> Self {
        Self {
            completed_at_unix_seconds: now,
            process_id: std::process::id(),
            inventory: inventory_digest(store_dirs),
        }
    }

    pub(super) fn retain_for_inventory(witness: &mut Option<Self>, store_dirs: &BTreeSet<PathBuf>) {
        if witness
            .as_ref()
            .is_some_and(|witness| witness.inventory != inventory_digest(store_dirs))
        {
            *witness = None;
        }
    }

    fn valid_at(&self, now: u64) -> bool {
        self.process_id == std::process::id() && self.completed_at_unix_seconds <= now
    }
}

fn inventory_digest(store_dirs: &BTreeSet<PathBuf>) -> String {
    let mut digest = sha2::Sha256::new();
    for dir in store_dirs {
        digest.update(dir.to_string_lossy().as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

/// The census this pass may use: the persisted complete Desktop identity
/// census under a valid witness. Logins per org come from native (unimported)
/// original identities only; bounded by the store's own file cap.
pub(crate) fn desktop_census(index: &ScanIndex) -> Option<DesktopCensus> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    desktop_census_at(index, now)
}

pub(super) fn desktop_census_at(index: &ScanIndex, now: u64) -> Option<DesktopCensus> {
    let witness = index.claude_desktop_census_witness.as_ref()?;
    if !index.claude_desktop_identity_census_complete || !witness.valid_at(now) {
        return None;
    }
    let mut logins_by_org: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entry in index.claude_desktop_title_files.values() {
        let Some(identity) = entry
            .original_identity
            .as_ref()
            .filter(|identity| !identity.imported)
        else {
            continue;
        };
        if let (Some(login), Some(org)) = (
            identity.account_identifier_hash.as_ref(),
            identity.provider_workspace_hash.as_ref(),
        ) {
            logins_by_org
                .entry(org.clone())
                .or_default()
                .insert(login.clone());
        }
    }
    Some(DesktopCensus {
        completed_at_unix_seconds: witness.completed_at_unix_seconds,
        logins_by_org,
    })
}

// --- Scan integration -----------------------------------------------------

/// One counted request as today's row builder placed it.
pub(super) struct Request<'r> {
    pub(super) request_id: &'r str,
    /// (response sequence, original event clock) of the owned transcript
    /// occurrence; `None` for an auxiliary telemetry-only request.
    pub(super) occurrence: Option<(u64, bool)>,
    pub(super) timestamp: &'r str,
    pub(super) bucket_start: &'r str,
    pub(super) row_key: &'r RowKey,
    pub(super) usage: &'r UsageTotals,
}

#[derive(Clone, Copy)]
struct ActivityRequest<'r> {
    request_id: &'r str,
    occurrence: Option<(u64, bool)>,
    timestamp: &'r str,
}

/// Classifies one item's requests as the row builder produces them and folds
/// each straight into a bounded `Grouping`; no request is retained.
pub(crate) struct RequestSink<'s, 'a> {
    evidence: &'s ScanEvidence<'a>,
    /// The duplicate witness, on the transcript path only; reported rows
    /// carry their own telemetry owner.
    duplicates: Option<&'s Duplicates>,
    /// Request-id hashes the reported rebuild excludes as another root's.
    excluded: Option<&'s BTreeSet<String>>,
    root: String,
    desktop: bool,
    scan_unix_seconds: Option<u64>,
    session_start_unix_seconds: Option<u64>,
    grouping: Grouping,
}

impl<'s, 'a> RequestSink<'s, 'a> {
    /// `None` when the item has no request-owner root (never tagged).
    pub(crate) fn for_item(
        evidence: &'s ScanEvidence<'a>,
        item: &SnapshotItem,
        max_groups: usize,
    ) -> Option<Self> {
        Some(Self {
            evidence,
            duplicates: None,
            excluded: None,
            root: owner_root(item)?.to_string(),
            desktop: item
                .origin
                .as_ref()
                .and_then(|origin| origin.entrypoint.as_deref())
                == Some("claude-desktop"),
            scan_unix_seconds: rfc3339_unix_seconds(&item.collected_at),
            session_start_unix_seconds: item
                .source_started_at
                .as_deref()
                .and_then(rfc3339_unix_seconds),
            grouping: Grouping::new(max_groups),
        })
    }

    fn with_duplicates(mut self, duplicates: &'s Duplicates) -> Self {
        self.duplicates = Some(duplicates);
        self
    }

    /// The item's transcript requests (by request-id hash) the reported
    /// rebuild excludes as another root's: a legacy fork's inherited prefix.
    /// Each must be one of the item's distinct transcript requests, and none
    /// may be admitted; they are never classified, so never tag or lend
    /// their owner's evidence.
    pub(crate) fn excluding(mut self, item: &SnapshotItem, excluded: &'s BTreeSet<String>) -> Self {
        if !excluded.is_empty() {
            let members = item
                .claude_usage_request_ids
                .iter()
                .filter(|request_id| {
                    excluded.contains(&format!(
                        "{:x}",
                        sha2::Sha256::digest(request_id.as_bytes())
                    ))
                })
                .count();
            self.grouping.excluded_requests = (members == excluded.len())
                .then(|| u64::try_from(members).ok())
                .flatten();
            self.excluded = Some(excluded);
        }
        self
    }

    pub(super) fn add(&mut self, item: &SnapshotItem, request: Request<'_>) {
        let transcript_member = item.claude_usage_request_ids.contains(request.request_id);
        if transcript_member != request.occurrence.is_some()
            || self.excluded.is_some_and(|excluded| {
                excluded.contains(&format!(
                    "{:x}",
                    sha2::Sha256::digest(request.request_id.as_bytes())
                ))
            })
        {
            self.grouping.unowned_request = true;
        }
        let admitted = match request.occurrence {
            Some(_) => &mut self.grouping.transcript_requests,
            None => &mut self.grouping.telemetry_only_requests,
        };
        *admitted = admitted.saturating_add(1);
        if self.grouping.failed.is_some() {
            return;
        }
        let (sequence, event_clock_complete) = request.occurrence.unzip();
        let duplicated_elsewhere = self.duplicates.is_some_and(|duplicates| {
            !duplicates.is_empty()
                && duplicates.contains_key(&format!(
                    "{:x}",
                    sha2::Sha256::digest(request.request_id.as_bytes())
                ))
        });
        let facts = RequestFacts {
            root: &self.root,
            source_session_id: &item.source_session_id,
            request_id: request.request_id,
            // Auxiliary (telemetry-only) rows carry `observed_at`, which v2
            // OTLP capture may have taken from the observer clock and does not
            // record which; as in D1 they cannot qualify. The trace span start
            // is event-origin but no existing rule qualifies it, and transcript
            // clocks are not theirs to borrow.
            terminal_unix_seconds: request
                .occurrence
                .and_then(|_| rfc3339_unix_seconds(request.timestamp)),
            event_clock_complete: event_clock_complete.unwrap_or(false),
            marker: match (item.claude_org_markers.as_deref(), sequence) {
                (Some(markers), Some(sequence)) => markers.verdict(sequence, self.desktop),
                _ => MarkerVerdict::None,
            },
            desktop: self.desktop,
            scan_unix_seconds: self.scan_unix_seconds,
            email_home: match (item.claude_org_markers.as_deref(), sequence) {
                (Some(markers), Some(sequence)) => markers.email_home(sequence),
                _ => None,
            },
            session_start_unix_seconds: self.session_start_unix_seconds,
            duplicated_elsewhere,
        };
        let identity = classify_ref(self.evidence, &facts);
        // Activity never overrides stronger request identity. A later Desktop
        // line can, however, qualify a marker flip the session-first CLI origin
        // would refuse solely as UntrustedFlip.
        if !self.grouping.unowned_request && !duplicated_elsewhere {
            let original = match self.evidence.native_originals {
                Some(originals) => originals.get(&item.source_session_id),
                None => item.session_account_evidence.as_ref(),
            };
            Self::note_desktop_activity(
                &mut self.grouping.desktop_recent,
                item,
                original,
                ActivityRequest {
                    request_id: request.request_id,
                    occurrence: request.occurrence,
                    timestamp: request.timestamp,
                },
                identity,
            );
        }
        self.grouping.add_at(
            request.bucket_start,
            request.row_key,
            request.usage,
            identity,
            // The owned occurrence's own complete clock, never the observer
            // time a reported rebuild falls back to. A response with an
            // unstamped record keeps an earlier record's time, which proves no
            // order: without a complete clock ("") no request is provably newest.
            request.occurrence.map(|(_, event_clock_complete)| {
                item.claude_usage_occurrences
                    .get(request.request_id)
                    .and_then(|occurrence| occurrence.timestamp.as_deref())
                    .filter(|_| event_clock_complete)
                    .unwrap_or("")
            }),
        );
    }

    fn note_desktop_activity(
        activity: &mut crate::desktop_recent::RecentActivity,
        item: &SnapshotItem,
        original: Option<&super::SessionAccountEvidence>,
        request: ActivityRequest<'_>,
        identity: IdentityRef<'_>,
    ) {
        let Some(occurrence) = item.claude_usage_occurrences.get(request.request_id) else {
            return;
        };
        if !occurrence.desktop_request || !occurrence.event_clock_complete {
            return;
        }
        let Some(owner) = original else {
            return;
        };
        if owner.evidence_source != "claude_desktop_original:v1"
            || owner.identity_disposition != Some("complete")
        {
            return;
        }
        let Some(account) = owner.account_identifier_hash.as_deref() else {
            return;
        };
        let Some((sequence, _)) = request.occurrence else {
            return;
        };
        let org = match item.claude_org_markers.as_deref() {
            Some(markers) => match markers.verdict(sequence, true) {
                MarkerVerdict::Trusted(org) => org,
                _ => return,
            },
            None if keeps_markerless_account(item)
                && super::exact_session_account_hash(item).as_deref() == Some(account) =>
            {
                let Some(org) = owner
                    .provider_workspace_hash
                    .as_deref()
                    .filter(|hash| wire_login_is_valid(hash))
                else {
                    return;
                };
                org
            }
            None => return,
        };
        match identity {
            IdentityRef::Refused(Refusal::UntrustedFlip) | IdentityRef::Missing => {}
            IdentityRef::Refused(_) => return,
            IdentityRef::Tagged(key) => {
                if key.login.is_some_and(|login| login != account)
                    || key.org.is_some_and(|actual| actual != org)
                {
                    return;
                }
            }
        }
        let (Ok(at), Ok(now)) = (
            OffsetDateTime::parse(request.timestamp, &Rfc3339),
            OffsetDateTime::parse(&item.collected_at, &Rfc3339),
        ) else {
            return;
        };
        activity.note(account, org, at, now);
    }

    pub(crate) fn finish(self) -> Grouping {
        self.grouping
    }
}

/// Per-pass counts; local only.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ScanOutcome {
    pub(crate) sent: usize,
    pub(crate) fallback: usize,
    pub(crate) ineligible: usize,
}

const REPORTED: &str = "session_exclusive_reported_usage:v1";

/// Transcript-path requests, from the owned occurrences the parser already
/// retains, placed the way rows were built. `None` when one cannot be, or when
/// they need more distinct buckets or row keys than the item carries (such an
/// item can never reproduce). Each distinct bucket and row key is built once.
fn transcript_requests(item: &SnapshotItem, mut place: impl FnMut(Request<'_>)) -> Option<()> {
    if item.claude_usage_occurrences.len() != item.claude_usage_request_ids.len() {
        return None;
    }
    let mut buckets: BTreeMap<i64, String> = BTreeMap::new();
    let mut rows: Vec<(&str, &SelectorCapture, Option<&str>, RowKey)> = Vec::new();
    for (request_id, occurrence) in &item.claude_usage_occurrences {
        if occurrence.usage.is_zero() {
            continue;
        }
        let timestamp = occurrence.timestamp.as_deref()?;
        let model = occurrence.model.as_deref()?;
        let hour = OffsetDateTime::parse(timestamp, &Rfc3339)
            .ok()?
            .unix_timestamp()
            .div_euclid(3600);
        if !buckets.contains_key(&hour) {
            if buckets.len() == item.usage_buckets.len() {
                return None;
            }
            buckets.insert(hour, activity_bucket_from_timestamp(timestamp)?.0);
        }
        let selector = &*occurrence.selector;
        let effort = occurrence.reasoning_effort.as_deref();
        let row = match rows.iter().position(|(m, s, e, _)| {
            *m == model && (std::ptr::eq(*s, selector) || **s == *selector) && *e == effort
        }) {
            Some(row) => row,
            None => {
                if rows.len() == item.model_usage.len() {
                    return None;
                }
                rows.push((
                    model,
                    selector,
                    effort,
                    build_row_identity(model, selector, effort).0,
                ));
                rows.len() - 1
            }
        };
        place(Request {
            request_id,
            occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
            timestamp,
            bucket_start: &buckets[&hour],
            row_key: &rows[row].3,
            usage: &occurrence.usage,
        });
    }
    Some(())
}

/// Diagnostic-only query; never consumed by a scheduling or attribution gate.
pub(super) fn full_rearm_requests_refused(
    item: &SnapshotItem,
    evidence: &ScanEvidence<'_>,
    reported: Option<&Grouping>,
    duplicates: &Duplicates,
) -> bool {
    let refused = |grouping: &Grouping| {
        grouping.failed.is_some()
            || grouping.unowned_request
            || grouping.keys_over_cap
            || grouping.rows().any(|(_, group)| group.refused)
    };
    if let Some(grouping) = reported {
        return refused(grouping);
    }
    let Some(sink) = RequestSink::for_item(evidence, item, bucket_row_count(item)) else {
        return false;
    };
    let mut sink = sink.with_duplicates(duplicates);
    // An unplaceable own-byte structural shape is already handled by the
    // native census. Preserve any refusals produced before placement stopped.
    let _ = transcript_requests(item, |request| sink.add(item, request));
    refused(&sink.finish())
}

/// The transcript path's request-count guard: the parser counted exactly the
/// owned occurrences that carry usage, each under its own request id. A
/// response whose every usage field is zero (an API-error record with a
/// request id) adds no row, token or money and is never placed, so its id
/// neither counts nor refuses the item; it makes no claim. Any usage counted
/// without an owned occurrence, or an occurrence the count skipped, still
/// refuses. The census and D1 keep the plain request-id count guard.
fn transcript_requests_counted(item: &SnapshotItem) -> bool {
    let counted = item
        .claude_usage_occurrences
        .values()
        .filter(|occurrence| !occurrence.usage.is_zero())
        .count();
    counted > 0
        && item.claude_usage_occurrences.len() == item.claude_usage_request_ids.len()
        && u64::try_from(counted) == Ok(item.request_count)
}

/// The request-owner root for an item, as D1 derives it.
fn owner_root(item: &SnapshotItem) -> Option<&str> {
    match item.source_session_id.split_once("_agent-") {
        Some((root, agent)) => (!root.is_empty() && !agent.is_empty()).then_some(root),
        None => {
            let root = item.source_session_id.as_str();
            (codex_identity_is_uuid_shaped(root) && root == root.to_ascii_lowercase())
                .then_some(root)
        }
    }
}

type Duplicates = BTreeMap<String, BTreeSet<super::ClaudeDuplicateRequestOwner>>;

/// This pass's duplicate witness. Census settlement never authorizes marker
/// tags; duplicates still refuse transcript requests without their own telemetry.
pub(crate) struct TranscriptOwnership<'i> {
    duplicates: &'i Duplicates,
}

impl<'i> TranscriptOwnership<'i> {
    pub(crate) fn after_census(
        index: &'i ScanIndex,
        _disposition: &super::ClaudeUsageAuthorityDisposition,
    ) -> Self {
        Self {
            duplicates: &index.claude_duplicate_request_owners,
        }
    }
}

/// No duplicates: what the classification tests assume.
#[cfg(test)]
pub(crate) fn apply_scan(
    snapshots: &mut [SnapshotItem],
    evidence: &ScanEvidence<'_>,
    reported: BTreeMap<String, Grouping>,
) -> ScanOutcome {
    static NONE: Duplicates = BTreeMap::new();
    let ownership = TranscriptOwnership { duplicates: &NONE };
    let originals = capture_request_owned_originals(snapshots);
    let activity = stage_request_owned_activity(snapshots, evidence, &ownership, &originals);
    let outcome = apply_scan_with_ownership(snapshots, evidence, reported, &ownership);
    publish_request_owned_activity(snapshots, activity);
    outcome
}

/// Tag every eligible Claude item of this pass. Runs before D1, which leaves
/// new-collector items alone; ineligible items stay on today's path untouched.
/// `reported` holds the groupings the reported rebuild produced this pass.
pub(crate) fn apply_scan_with_ownership(
    snapshots: &mut [SnapshotItem],
    evidence: &ScanEvidence<'_>,
    mut reported: BTreeMap<String, Grouping>,
    ownership: &TranscriptOwnership<'_>,
) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();
    for item in snapshots {
        if item.provenance.collector != "claude_code_jsonl" {
            continue;
        }
        match tag_item(item, evidence, &mut reported, ownership) {
            Some(Ok(Tagged::Sent { .. })) => outcome.sent += 1,
            Some(Ok(Tagged::Fallback { .. })) => outcome.fallback += 1,
            Some(Err(_)) | None => outcome.ineligible += 1,
        }
    }
    outcome
}

/// Each physical source's pre-enrichment native original, not a session-keyed
/// projection where path twins can overwrite one another's creator evidence.
#[derive(Default)]
pub(crate) struct RequestOwnedOriginals(
    BTreeMap<(String, Option<String>), Option<super::SessionAccountEvidence>>,
);

pub(crate) fn capture_request_owned_originals(items: &[SnapshotItem]) -> RequestOwnedOriginals {
    let mut originals = RequestOwnedOriginals::default();

    for item in items {
        if item.claude_money.is_none()
            || !item
                .claude_usage_occurrences
                .values()
                .any(|occurrence| occurrence.desktop_request)
        {
            continue;
        }
        originals
            .0
            .entry((
                item.source_session_id.clone(),
                item.source_file_fingerprint.clone(),
            ))
            .and_modify(|original| {
                if original.as_ref() != item.session_account_evidence.as_ref() {
                    *original = None;
                }
            })
            .or_insert_with(|| item.session_account_evidence.clone());
    }
    originals
}

/// Bounded validated activity, kept only across final twin removal/tagging.
#[derive(Default)]
pub(crate) struct RequestOwnedActivity(
    BTreeMap<String, Vec<crate::desktop_recent::RecentActivity>>,
);

pub(crate) fn stage_request_owned_activity(
    items: &[SnapshotItem],
    evidence: &ScanEvidence<'_>,
    ownership: &TranscriptOwnership<'_>,
    originals: &RequestOwnedOriginals,
) -> RequestOwnedActivity {
    let mut page = RequestOwnedActivity::default();

    for item in items {
        if item.claude_money.is_none()
            || !item
                .claude_usage_occurrences
                .values()
                .any(|occurrence| occurrence.desktop_request)
        {
            continue;
        }
        if item
            .model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage),
            )
            .any(|row| !local_subscription(row))
        {
            continue;
        }
        page.0
            .entry(item.source_session_id.clone())
            .or_default()
            .push(collect_request_owned_activity(
                item,
                evidence,
                ownership,
                originals
                    .0
                    .get(&(
                        item.source_session_id.clone(),
                        item.source_file_fingerprint.clone(),
                    ))
                    .and_then(Option::as_ref),
            ));
    }
    page
}

pub(crate) fn publish_request_owned_activity(
    items: &[SnapshotItem],
    mut page: RequestOwnedActivity,
) {
    if page.0.is_empty() {
        return;
    }
    for item in items {
        if !super::claude_history_upgrade::is_request_owned_literal(item) {
            continue;
        }
        #[cfg(not(test))]
        let collector = COLLECTOR;
        #[cfg(test)]
        let collector = cycle_contract(true);
        if item.provenance.collector != collector && !keeps_markerless_account(item) {
            continue;
        }
        for activity in page.0.remove(&item.source_session_id).into_iter().flatten() {
            crate::desktop_recent::publish(activity);
        }
    }
}

fn request_occurrence_facts<'a>(
    item: &'a SnapshotItem,
    request_id: &'a str,
    occurrence: &'a super::ClaudeTranscriptUsageOccurrence,
    duplicated_elsewhere: bool,
) -> Option<RequestFacts<'a>> {
    let root = owner_root(item)?;
    let timestamp = occurrence.timestamp.as_deref()?;
    let desktop = item
        .origin
        .as_ref()
        .and_then(|origin| origin.entrypoint.as_deref())
        == Some("claude-desktop");
    Some(RequestFacts {
        root,
        source_session_id: &item.source_session_id,
        request_id,
        terminal_unix_seconds: rfc3339_unix_seconds(timestamp),
        event_clock_complete: occurrence.event_clock_complete,
        marker: item
            .claude_org_markers
            .as_deref()
            .map_or(MarkerVerdict::None, |markers| {
                markers.verdict(occurrence.sequence, desktop)
            }),
        desktop,
        scan_unix_seconds: rfc3339_unix_seconds(&item.collected_at),
        email_home: item
            .claude_org_markers
            .as_deref()
            .and_then(|markers| markers.email_home(occurrence.sequence)),
        session_start_unix_seconds: item
            .source_started_at
            .as_deref()
            .and_then(rfc3339_unix_seconds),
        duplicated_elsewhere,
    })
}

fn collect_request_owned_activity(
    item: &SnapshotItem,
    evidence: &ScanEvidence<'_>,
    ownership: &TranscriptOwnership<'_>,
    original: Option<&super::SessionAccountEvidence>,
) -> crate::desktop_recent::RecentActivity {
    let Some(fold) = item.claude_money.as_deref() else {
        return Default::default();
    };
    let mut activity = crate::desktop_recent::RecentActivity::default();
    for (request_id, occurrence) in &item.claude_usage_occurrences {
        if !occurrence.desktop_request
            || occurrence.usage.is_zero()
            || fold.is_skipped(occurrence.sequence)
        {
            continue;
        }
        let duplicated = !ownership.duplicates.is_empty()
            && ownership.duplicates.contains_key(&format!(
                "{:x}",
                sha2::Sha256::digest(request_id.as_bytes())
            ));
        if duplicated {
            continue;
        }
        let Some(timestamp) = occurrence.timestamp.as_deref() else {
            continue;
        };
        let Some(facts) = request_occurrence_facts(item, request_id, occurrence, false) else {
            continue;
        };
        let identity = classify_ref(evidence, &facts);
        RequestSink::note_desktop_activity(
            &mut activity,
            item,
            original,
            ActivityRequest {
                request_id,
                occurrence: Some((occurrence.sequence, occurrence.event_clock_complete)),
                timestamp,
            },
            identity,
        );
    }
    activity
}

fn keeps_markerless_account(item: &SnapshotItem) -> bool {
    item.claude_org_markers.is_none()
        && super::exact_session_account_hash(item).is_some()
        && item.claude_money.as_deref().is_some_and(|fold| {
            let mut partitions = fold.entity.grains.keys().map(|(_, _, account)| account);
            let first = partitions.next();
            partitions.all(|account| Some(account) == first)
        })
        && item
            .claude_money
            .as_deref()
            .and_then(|fold| fold.accounts.as_deref())
            .is_some_and(|accounts| {
                !accounts.unhealthy_no_fallback && accounts.starting.is_some() && !accounts.conflict
            })
}

fn tag_item(
    item: &mut SnapshotItem,
    evidence: &ScanEvidence<'_>,
    reported: &mut BTreeMap<String, Grouping>,
    ownership: &TranscriptOwnership<'_>,
) -> Option<Result<Tagged, Ineligible>> {
    let accepted = evidence
        .accepted_buckets
        .and_then(|state| state.get(&item.source_session_id));
    // No ledger is the same as no usable key: share protection is off.
    let miss = evidence
        .accepted_buckets
        .map_or(accepted::UnknownCause::NoKey, AcceptedBuckets::miss_cause);
    let retained = evidence
        .accepted_buckets
        .is_some_and(AcceptedBuckets::retained_enabled);
    if super::claude_history_upgrade::is_request_owned_literal(item) {
        if item
            .model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage),
            )
            .any(|row| !local_subscription(row))
        {
            return None;
        }
        // Single-account markerless bodies keep their established D1 wire
        // shape. The account owner already tagged their final usage uniformly.
        if keeps_markerless_account(item) {
            return None;
        }
        let mut grouping = request_owned_grouping(item)?;
        let lifecycle = (
            item.source_started_at.clone(),
            item.source_ended_at.clone(),
            item.source_last_activity_at.clone(),
        );
        normalize_activity(item);
        grouping.extra_wire_bytes = evidence
            .wire_size_reservation
            .map_or(0, |reserve| reserve(item));
        grouping.accepted_miss = miss;
        let tagged = apply_grouped_with_accepted(item, grouping, accepted, retained);
        if tagged.is_err() {
            (
                item.source_started_at,
                item.source_ended_at,
                item.source_last_activity_at,
            ) = lifecycle;
        }
        // A cap failure cannot authorize a uniform starting-account rewrite.
        // The budget's proved subset or full strip is the final identity body.
        return Some(tagged);
    }
    let root = owner_root(item)?;
    let reported_usage = item.usage_accounting_contract.as_deref() == Some(REPORTED);
    if !item.claude_context_curve_request_index_complete
        // A reported item also counts telemetry-only requests and excludes a
        // legacy fork's inherited prefix; its rebuild's admitted requests are
        // checked against its grouping below instead.
        || (!reported_usage && !transcript_requests_counted(item))
        || item
            .attribution_facts
            .iter()
            .any(|fact| fact.field == "root_session_ref" && fact.value != root)
        || item
            .model_usage
            .iter()
            .chain(
                item.usage_buckets
                    .iter()
                    .flat_map(|bucket| &bucket.model_usage),
            )
            .any(|row| !local_subscription(row))
    {
        return None;
    }
    let mut grouping = if reported_usage {
        let grouping = reported.remove(&item.source_session_id)?;
        if !grouping.reported_requests_admissible(item) {
            return None;
        }
        grouping
    } else {
        let mut sink = RequestSink::for_item(evidence, item, bucket_row_count(item))?
            .with_duplicates(ownership.duplicates);
        transcript_requests(item, |request| sink.add(item, request))?;
        sink.finish()
    };
    // A fork or resume can copy its predecessor's markers. Neither a settled
    // census nor an open fence makes those markers request-owned evidence.
    // Both grouping sources withdraw them before any identity is installed.
    grouping.withdraw_transcript_tags();
    // D1 leaves new-collector items alone, so the backend UTC lifecycle
    // spelling it applies to every item it qualifies happens here, inside the
    // byte cap; an ineligible item returns to D1 exactly as it arrived.
    let lifecycle = (
        item.source_started_at.clone(),
        item.source_ended_at.clone(),
        item.source_last_activity_at.clone(),
    );
    normalize_activity(item);
    grouping.extra_wire_bytes = evidence
        .wire_size_reservation
        .map_or(0, |reserve| reserve(item));
    let desktop_recent = std::mem::take(&mut grouping.desktop_recent);
    let owned = !grouping.unowned_request;
    grouping.accepted_miss = miss;
    let tagged = apply_grouped_with_accepted(item, grouping, accepted, retained);
    if tagged.is_ok() && owned {
        crate::desktop_recent::publish(desktop_recent);
    }
    if tagged.is_err() {
        (
            item.source_started_at,
            item.source_ended_at,
            item.source_last_activity_at,
        ) = lifecycle;
    }
    Some(tagged)
}

crate::heap_layout_bound::fields!(OrgMarkers; entries, starting_marker, overflowed, context_digest, context_changed, context_position, context_flip_position, home);
crate::durable_tail_codec::durable_struct!(OrgMarkers {
    D entries: Vec<OrgMarker>,
    D starting_marker: Option<OrgMarker>,
    N overflowed: bool,
    H context_digest: Option<String>,
    N context_changed: bool,
    N context_position: Option<u64>,
    N context_flip_position: Option<u64>,
    E home: Option<crate::claude_status_coverage::HomeKey>,
});
crate::heap_layout_bound::fields!(OrgMarker; position, org, terminal_trusted);
crate::durable_tail_codec::durable_struct!(OrgMarker {
    N position: u64,
    U org: Option<String>,
    N terminal_trusted: bool,
});
crate::heap_layout_bound::fields!(DesktopCensusWitness; completed_at_unix_seconds, process_id, inventory);
crate::heap_layout_bound::fields!(AccountDisplay; current, history);
crate::heap_layout_bound::fields!(ActiveSessionCurrentAccount; status, account_identifier_hash, organization_identifier_hash, subscription_product, latest_request_at, unknown_reason);
crate::heap_layout_bound::fields!(ActiveSessionAccountUse; account_identifier_hash, organization_identifier_hash, subscription_product, request_count, input_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, output_tokens, last_used_at, current);

#[cfg(test)]
mod request_owned_contract_tests {
    use super::*;
    #[test]
    fn grouping_version_uses_existing_contract_rearm_and_gate_off_stays_identical() {
        assert_eq!(compiled_cycle_contract(true, false), COLLECTOR);
        assert_eq!(compiled_cycle_contract(false, true), "");
        let first = compiled_cycle_contract(true, true);
        assert_ne!(first, COLLECTOR);
        assert_eq!(first, compiled_cycle_contract(true, true));
        assert_eq!(
            serde_json::to_value(IdentityCounts::default()).unwrap(),
            json!({})
        );
    }
}
