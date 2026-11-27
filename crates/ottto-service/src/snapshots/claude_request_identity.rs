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
//! `e2` partitions counted requests using bounded native marker runs before
//! aggregation, then feeds those exact final shares to this same tag installer.
//!
//! Layout: `apply` (apply, cap, display and untag), `accounts` (request
//! account runs and their reconcile) and `scan` (the per-item request scan
//! and `tag_item`). This file keeps the contract, caps, authority keys,
//! grouping, wire rows, org markers, scan evidence and classification.
use super::{
    claude_snapshot_request_id_hashes, rfc3339_unix_seconds, row_key_from_model_usage,
    usd_picos_string, AccountSource, RowKey, SnapshotIdentityPart, SnapshotItem,
    SnapshotModelUsage, SnapshotRequestEvidence, SnapshotSource, UsageTotals, USD_PICO_SCALE,
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
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

mod accounts;
mod apply;
mod scan;

pub(crate) use self::accounts::{
    inherit_root_accounts, reconcile_request_accounts, request_accounts, retain_root_accounts,
    unhealthy_cleared_account,
};
use self::apply::apply_grouped_with_accepted;
pub(crate) use self::apply::AccountDisplay;
#[cfg(test)]
pub(crate) use self::apply::{
    apply, apply_grouped, apply_timed, apply_with_accepted_for_test,
    apply_with_reserved_bytes_for_test, CURRENT_KNOWN, CURRENT_UNKNOWN,
};
#[cfg(test)]
pub(crate) use self::scan::{apply_scan, collect_request_owned_activity, ScanOutcome};
pub(crate) use self::scan::{
    apply_scan_page, capture_request_owned_originals, owner_root, publish_request_owned_activity,
    stage_request_owned_activity, RequestOwnedOriginals, RequestSink,
};
pub(in crate::snapshots) use self::scan::{inventory_digest, Request};

mod accepted;
mod budget;
pub(crate) use accepted::bind_session_context_key;
#[cfg(test)]
pub(crate) use accepted::bind_test_session_context_key;
pub(crate) use accepted::digest_hex;
pub(crate) use accepted::session_context_key_epoch;
pub(crate) use accepted::{AcceptedBuckets, AcceptedSession, IdentityScope};
use budget::Measurement as CapMeasurement;

pub(crate) const COLLECTOR: &str = "claude_code_jsonl:own_request_identity_rows:v1";
pub(crate) const E2_GROUPING: &str =
    "claude_code_jsonl:own_request_identity_rows:v1/e2_grouping:v1";

/// The contract a scan builds Claude bodies under: the full collector token,
/// which names its version, when it captures (every Claude cycle), and `""`
/// otherwise (records written by permit-era builds without a permit).
#[cfg(not(test))]
pub(crate) const fn cycle_contract(captured: bool) -> &'static str {
    compiled_cycle_contract(captured)
}

// Durable grouping version shares the existing identity-contract rearm. The
// wire collector stays v1; gate-off contracts and uploads stay byte-identical.
const fn compiled_cycle_contract(captured: bool) -> &'static str {
    if !captured {
        ""
    } else {
        E2_GROUPING
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
/// (own-request account qualification, mixed bodies, owner holds) that production now
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

pub(crate) const MAX_EVIDENCE_ENTRIES: usize = 32;
pub(crate) const MAX_AUTHORITY_KEYS: usize = 32;
pub(crate) const MAX_PARTS_PER_ROW: usize = MAX_AUTHORITY_KEYS + 1;
/// Declared bound (contract `bounds.total_parts`, `MAX_IDENTITY_PARTS_PER_ITEM`):
/// the receiver's dense parts bound, serialized item bytes / 320, at this
/// pass's item cap (2,048 at the default cap). The byte cap is the real
/// limit; this stops construction early.
pub(crate) const fn max_parts_per_item(max_item_bytes: usize) -> usize {
    max_item_bytes / 320
}
pub(crate) const MAX_ROWS: usize = 100;
/// Receiver `MAX_SNAPSHOT_ITEM_BYTES`, measured on sorted compact JSON.
pub(crate) const MAX_ITEM_BYTES: usize = super::MAX_SNAPSHOT_ITEM_WIRE_BYTES;
pub(crate) const MAX_ADVERTISED_ITEM_BYTES: usize = 8 * 1024 * 1024;

pub(crate) fn effective_item_cap(advertised: Option<u64>) -> usize {
    advertised
        .filter(|bytes| *bytes >= MAX_ITEM_BYTES as u64)
        .map_or(MAX_ITEM_BYTES, |bytes| {
            bytes.min(MAX_ADVERTISED_ITEM_BYTES as u64) as usize
        })
}

/// This pass's receiver limit and the existing cache reconciliation reserve.
#[derive(Clone, Copy)]
pub(crate) struct WireBudget<'a> {
    pub(crate) max_item_bytes: usize,
    pub(crate) reservation: Option<&'a dyn Fn(&SnapshotItem) -> usize>,
}
impl Default for WireBudget<'_> {
    fn default() -> Self {
        Self {
            max_item_bytes: MAX_ITEM_BYTES,
            reservation: None,
        }
    }
}
const MICRO_PICOS: u128 = USD_PICO_SCALE / 1_000_000;
const MAX_MONEY_PICOS: u128 = 1_000_000_000 * USD_PICO_SCALE;

pub(crate) const TELEMETRY: &str = "telemetry";
pub(crate) const TELEMETRY_LOGIN: &str = "telemetry_login";
/// Retired basis: no build ever emitted it. Still parsed, unchanged, so an
/// older body or accepted record that names it never fails to decode.
pub(crate) const LEGACY_TRANSCRIPT_SOLE_LOGIN: &str = "transcript_sole_login";
/// Retired basis: no build emits it any more. Still parsed, as placement and
/// never proof, so an older body or accepted record that names it decodes.
pub(crate) const TRANSCRIPT_RECORDED_LOGIN: &str = "transcript_recorded_login";
pub(crate) const TRANSCRIPT_ORG: &str = "transcript_org";

/// (login, org, full basis). Derived order is the contract order: absent before
/// present for login and org, then the basis token bytewise. A carried key
/// (`account_source`) sorts after its own-evidence twin and is never proof.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AuthorityKey {
    pub(crate) login: Option<String>,
    pub(crate) org: Option<String>,
    pub(crate) basis: &'static str,
    pub(crate) account_source: Option<AccountSource>,
}

impl AuthorityKey {
    fn evidence(&self) -> EvidenceKey {
        EvidenceKey {
            org: self.org.clone(),
            basis: self.basis,
            account_source: self.account_source,
        }
    }

    /// Placement that never proves or freezes a row: a carried account, or the
    /// retired recorded-login basis.
    fn placement_only(&self) -> bool {
        self.account_source.is_some() || self.basis == TRANSCRIPT_RECORDED_LOGIN
    }
}

/// `request_evidence` total order: org absent first, org hash, then basis
/// (then an absent `account_source` first, so unmarked orders are unchanged).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct EvidenceKey {
    org: Option<String>,
    basis: &'static str,
    account_source: Option<AccountSource>,
}

impl EvidenceKey {
    fn wire(&self) -> SnapshotRequestEvidence {
        SnapshotRequestEvidence {
            identity_basis: self.basis.to_string(),
            provider_workspace_hash: self.org.clone(),
            account_source: self.account_source,
        }
    }
}

/// Why a request's usage is left untagged. Only refused-versus-missing reaches
/// the wire (`request_identity_refusals`); the reason stays local.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Refusal {
    ConflictingDuplicate,
    ForeignOwner,
    InvalidEvidence,
    ContradictoryOrg,
    BadClock,
    UntrustedFlip,
    /// Stronger evidence exists but is unreadable or incomplete.
    IncompleteEvidence,
}

/// Closed local diagnostic labels for refusal events in one tagging attempt:
/// classifier reasons and the two other `add_at` arms per request,
/// `cost_missing_collapse` per bucket row, `over_cap_strip` per body that took
/// the full-strip fallback. Partial cap recovery and share protection count in
/// `identity_cap`. Append-only; counts only, never on the wire.
const REFUSAL_CAUSES: [&str; 11] = [
    "conflicting_duplicate",
    "foreign_owner",
    "invalid_evidence",
    "contradictory_org",
    "bad_clock",
    "untrusted_flip",
    "incomplete_evidence",
    "invalid_login",
    "row_authority_cap",
    "cost_missing_collapse",
    "over_cap_strip",
];
const INVALID_LOGIN: usize = 7;
const ROW_AUTHORITY_CAP: usize = 8;
const COST_MISSING_COLLAPSE: usize = 9;
const OVER_CAP_STRIP: usize = 10;
type RefusalCauses = [u32; REFUSAL_CAUSES.len()];

impl Refusal {
    /// This reason's slot in `REFUSAL_CAUSES`.
    const fn cause(self) -> usize {
        match self {
            Refusal::ConflictingDuplicate => 0,
            Refusal::ForeignOwner => 1,
            Refusal::InvalidEvidence => 2,
            Refusal::ContradictoryOrg => 3,
            Refusal::BadClock => 4,
            Refusal::UntrustedFlip => 5,
            Refusal::IncompleteEvidence => 6,
        }
    }
}

fn count_cause(causes: &mut RefusalCauses, cause: usize) {
    causes[cause] = causes[cause].saturating_add(1);
}

crate::local_resource_diagnostics::process_static!(fn with_refusal_causes:
    [std::sync::atomic::AtomicU64; REFUSAL_CAUSES.len()] =
        [const { std::sync::atomic::AtomicU64::new(0) }; REFUSAL_CAUSES.len()]);

/// Adds one tagging attempt's refusal causes to this page's counters.
fn record_refusal_causes(causes: &RefusalCauses) {
    if causes.iter().all(|count| *count == 0) {
        return;
    }
    with_refusal_causes(|counters| {
        for (counter, count) in counters.iter().zip(causes) {
            let _ = counter.try_update(
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
                |n| Some(n.saturating_add(u64::from(*count))),
            );
        }
    });
}

fn take_refusal_causes() -> BTreeMap<&'static str, u64> {
    with_refusal_causes(|counters| {
        REFUSAL_CAUSES
            .into_iter()
            .zip(counters)
            .map(|(label, counter)| (label, counter.swap(0, std::sync::atomic::Ordering::Relaxed)))
            .filter(|(_, count)| *count != 0)
            .collect()
    })
}

/// Owned form of `IdentityRef`, for tests and the builder oracle.
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
    NearCap,
    IdentityHeld,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Tagged {
    /// Increased-cap body remains owed; no revision may be uploaded.
    Held,
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
/// row never qualifies for the sticky budget; other rows are unaffected. The
/// emitted item keeps the global key cap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grouping {
    groups: BTreeMap<String, BTreeMap<RowKey, RowGroup>>,
    group_count: usize,
    max_groups: usize,
    keys: BTreeSet<AuthorityKey>,
    keys_over_cap: bool,
    /// This provenance contract keeps over-cap identity owed, never stripped.
    hold_over_cap: bool,
    upstream_proof_lost: bool,
    /// Additional cache-reconciliation wire bytes, projected once before tags.
    extra_wire_bytes: usize,
    accepted_share_changed: BTreeSet<String>,
    /// Frozen tagged rows absent from their present accepted bucket.
    accepted_rows_vanished: u64,
    /// Why the caller found no accepted state, when it found none.
    accepted_miss: accepted::UnknownCause,
    /// Requests refused here, by `REFUSAL_CAUSES` slot (local diagnostics).
    refusal_causes: RefusalCauses,
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
            hold_over_cap: false,
            upstream_proof_lost: false,
            extra_wire_bytes: 0,
            accepted_share_changed: BTreeSet::new(),
            accepted_rows_vanished: 0,
            accepted_miss: accepted::UnknownCause::NoKey,
            refusal_causes: [0; REFUSAL_CAUSES.len()],
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
                count_cause(&mut self.refusal_causes, INVALID_LOGIN);
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
                    count_cause(&mut self.refusal_causes, ROW_AUTHORITY_CAP);
                    None
                }
            }
            IdentityRef::Missing => None,
            IdentityRef::Refused(reason) => {
                group.refused = true;
                count_cause(&mut self.refusal_causes, reason.cause());
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

    /// Drops every tag that rests on transcript markers: the org-only (and
    /// legacy sole-login) bases. Their usage stays on its row, untagged;
    /// refusals stay. Login-only telemetry never carries an org here.
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

/// Marking a previously accepted carry preserves its placement. A carried
/// slot ACKed without proof remains None; a legacy proved slot compares the
/// unmarked pair. The shared comparison also governs copy invalidation.
fn share_placement(
    accepted: &accepted::AcceptedSession,
    prior: &BTreeSet<Option<[u8; 32]>>,
    key: &AuthorityKey,
) -> Option<[u8; 32]> {
    let hash = accepted.authority_hash(key);
    if key.placement_only() && prior.contains(&None) && !prior.contains(&Some(hash)) {
        None
    } else {
        Some(hash)
    }
}

/// The frozen share set of a row whose current tagged shares differ from it.
fn changed_shares(
    accepted: &accepted::AcceptedSession,
    start: i64,
    row: &RowKey,
    group: &RowGroup,
) -> Option<BTreeSet<Option<[u8; 32]>>> {
    let prior = accepted.row_shares(start, row);
    // Only a row frozen with tagged proof can constrain later proof.
    // New rows and rows previously ACKed untagged remain admissible.
    if prior.is_empty() {
        return None;
    }
    let current = group
        .by_key
        .iter()
        .filter(|(_, amount)| amount.counts != [0; 8])
        .map(|(key, _)| {
            key.as_ref()
                .and_then(|key| share_placement(accepted, &prior, key))
        })
        .collect::<BTreeSet<_>>();
    // Resolving an untagged share to the same surviving tagged set is
    // new proof, not a retag. Missing prior tagged keys still count changed.
    let resolved_missing = prior.contains(&None)
        && current == prior.iter().filter(|key| key.is_some()).copied().collect();
    (current != prior && !resolved_missing).then_some(prior)
}

/// One copy-derived accepted row the identity pass treated as never
/// accepted; the caller tombstones it in the durable ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CopyInvalidation {
    session: String,
    bucket: i64,
    row: RowKey,
}

/// Copy-derived rows: proof a copied marker lent must not keep
/// placing. A frozen row whose shares change and are only accounts copied
/// markers lent to that very row's requests (ones copy-prefix dedupe
/// re-derived without them) is copy-derived: it is treated as never accepted
/// (fresh own tags or untagged, never a refusal or marker). Other changed
/// rows keep the accepted-share refusal, and rows their own evidence still proves are
/// unchanged.
fn copy_derived_rows(
    item: &SnapshotItem,
    grouping: &Grouping,
    accepted: Option<&accepted::AcceptedSession>,
) -> Vec<(i64, RowKey)> {
    let Some(accepted) = accepted else {
        return Vec::new();
    };
    // Per row: the accounts copied markers lent, and whether every lent
    // request's own evidence was positively read this pass.
    let mut lent = BTreeMap::<(i64, RowKey), (BTreeSet<Option<[u8; 32]>>, bool)>::new();
    for (bucket, row, slot) in super::claude_request_money::e2::copied_marker_lent_rows(item) {
        if let Some(start) = accepted::bucket_key(bucket) {
            let (accounts, read) = lent
                .entry((start, row_key_from_model_usage(&row)))
                .or_insert_with(|| (BTreeSet::new(), true));
            accounts.insert(Some(accepted.authority_hash(&slot.lent)));
            *read &= slot.read;
        }
    }
    if lent.is_empty() {
        return Vec::new();
    }
    let groups = grouping
        .groups
        .iter()
        .filter_map(|(bucket, rows)| Some((accepted::bucket_key(bucket)?, rows)))
        .collect::<BTreeMap<_, _>>();
    let mut rows = Vec::new();
    let mut counts = budget::Counts::default();
    for ((start, row), (lent, read)) in lent {
        let group = groups.get(&start).and_then(|rows| rows.get(&row));
        let Some(prior) = group
            .and_then(|group| changed_shares(accepted, start, &row, group))
            .filter(|prior| !prior.is_disjoint(&lent))
        else {
            continue;
        };
        // Without per-ACK provenance, a freeze holding any
        // share copied markers did not lend may be a corrected body's, and
        // evidence this pass could not read may still prove the latest
        // proof. Both keep accepted-share protection, and both are counted.
        if !prior.is_subset(&lent) {
            counts.copy_derived_mixed_not_invalidated += 1;
        } else if !read {
            counts.copy_derived_skipped_evidence_unavailable += 1;
        } else {
            rows.push((start, row));
        }
    }
    if !counts.is_empty() {
        budget::record(&counts);
    }
    rows
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
            let Some(prior) = changed_shares(accepted, start, row, group) else {
                continue;
            };
            grouping.accepted_share_changed.insert(bucket.clone());
            let mut kept = BTreeMap::<Option<AuthorityKey>, Amounts>::new();
            for (key, amount) in std::mem::take(&mut group.by_key) {
                let key = key.filter(|key| prior.contains(&share_placement(accepted, &prior, key)));
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

/// Pure measurement over a request-owned item's currently held native proof.
/// It never reads accounts/transcripts, emits diagnostics or uploads a body.
#[cfg(test)] // Side-run/debug hook; deliberately not a runtime decision input.
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
                MAX_ITEM_BYTES,
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
                            IdentityRef::Tagged(KeyRef {
                                login,
                                org: evidence.provider_workspace_hash.as_deref(),
                                basis: basis_token(&evidence.identity_basis)?,
                                account_source: evidence.account_source,
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

/// The one parser of a stored `identity_basis`, legacy spellings included;
/// an unknown token is `None`.
fn basis_token(basis: &str) -> Option<&'static str> {
    match basis {
        TELEMETRY => Some(TELEMETRY),
        TELEMETRY_LOGIN => Some(TELEMETRY_LOGIN),
        TRANSCRIPT_RECORDED_LOGIN => Some(TRANSCRIPT_RECORDED_LOGIN),
        LEGACY_TRANSCRIPT_SOLE_LOGIN => Some(LEGACY_TRANSCRIPT_SOLE_LOGIN),
        TRANSCRIPT_ORG => Some(TRANSCRIPT_ORG),
        _ => None,
    }
}

fn withdrawn(key: AuthorityKey) -> Option<AuthorityKey> {
    // A retired recorded login is kept as it was named, never re-derived
    // from markers.
    matches!(
        key.basis,
        TELEMETRY | TELEMETRY_LOGIN | TRANSCRIPT_RECORDED_LOGIN
    )
    .then_some(key)
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
    item.request_evidence = evidence.iter().map(EvidenceKey::wire).collect();
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
    }
}

/// Conservative compact wire budget, including the largest policy framing and
/// a possible cache predecessor. Hash values have fixed width as tags change.
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
    let (base_head_etag, conflict_head_challenge, rescan_from_revision_hash, forced_full_rescan) =
        item.cache_handshake();
    let mut envelope = super::SnapshotSemanticEnvelope {
        component_contract_version: super::SNAPSHOT_SEMANTIC_CONTRACT_VERSION,
        upload_policy: policy,
        component_hashes,
        revision_v2_contract_version: super::SNAPSHOT_REVISION_V2_CONTRACT_VERSION,
        revision_v2_canonicalization: crate::canonical_json::CANONICAL_JSON_CONTRACT_VERSION,
        revision_v2_parser_version: source.parser_version(),
        revision_v2_scan_identity_version: source.scan_identity_version(),
        revision_v2_hash: hash.clone(),
        content_hash: hash,
        hash_epoch: super::SNAPSHOT_CONTENT_HASH_EPOCH,
        base_head_etag,
        conflict_head_challenge,
        rescan_from_revision_hash,
        forced_full_rescan,
    };
    if envelope.base_head_etag.is_none()
        && envelope.conflict_head_challenge.is_none()
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
    // Keep the identity admission budget stable across the revision-envelope
    // cutover. Reclaiming these 134 bytes here would retag boundary rows even
    // though this change only removes transport fields.
    .map_or(usize::MAX, |bytes| bytes.len().saturating_add(134))
}

// --- Canonical hash leaf (`session_identity_leaf:v3`) ------------------------

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
            .map(|row| identity_leaf(row, evidence))
            .collect::<Vec<_>>(),
        "refused": item.request_identity_refusals > 0,
        "usage_buckets": item
            .usage_buckets
            .iter()
            .map(|bucket| bucket
                .model_usage
                .iter()
                .map(|row| identity_leaf(row, evidence))
                .collect::<Vec<_>>())
            .collect::<Vec<_>>(),
    })
}

/// Authority-key order of a dereferenced leaf identity (untagged sorts first).
type LeafOrder = (u8, u8, String, u8, String, String, Option<AccountSource>);

fn deref(
    login: Option<&String>,
    evidence_ref: Option<u16>,
    evidence: &[SnapshotRequestEvidence],
) -> Option<(Value, LeafOrder)> {
    let entry = evidence.get(usize::from(evidence_ref?))?;
    let org = entry.provider_workspace_hash.as_ref();
    let mut identity = json!({"basis": entry.identity_basis, "login": login, "org": org});
    // Only a carried share names its source; unmarked leaves keep their bytes.
    if let Some(source) = entry.account_source {
        identity["source"] = json!(source);
    }
    Some((
        identity,
        (
            1,
            u8::from(login.is_some()),
            login.cloned().unwrap_or_default(),
            u8::from(org.is_some()),
            org.cloned().unwrap_or_default(),
            entry.identity_basis.clone(),
            entry.account_source,
        ),
    ))
}

fn identity_leaf(row: &SnapshotModelUsage, evidence: &[SnapshotRequestEvidence]) -> Value {
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
                    (0, 0, String::new(), 0, String::new(), String::new(), None),
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

/// 2026-11-05T00:00:00Z (UTC ms). A request whose own provider time is at or
/// after it follows the latest valid org line; an earlier request keeps the
/// terminal trust it had, so a cold read equals a stored one.
pub(crate) const ACCOUNT_RULE_FROM: i64 = 1_793_836_800_000;

/// A provider time (UTC s) at or after `ACCOUNT_RULE_FROM`.
pub(crate) fn from_account_rule(unix_seconds: Option<u64>) -> bool {
    unix_seconds
        .and_then(|at| i64::try_from(at).ok())
        .is_some_and(|at| at.saturating_mul(1_000) >= ACCOUNT_RULE_FROM)
}

/// 2026-11-09T00:00:00Z (UTC s). A root file's first response with its own
/// telemetry row but no trace owner takes that row's login when its own
/// provider time is at or after it; an earlier request keeps its refusal.
pub(crate) const SPANLESS_FIRST_REQUEST_FROM: u64 = 1_794_182_400;

/// The sequence of `item`'s first response when it may take its own row's
/// login without a trace owner: an original root file (no fork parent or
/// inherited prefix) whose sequence-0 response has a request id (so no id-less
/// or unresolved response precedes it), counts, is not a copy, and shares its
/// id with no other response. Read before the occurrence map drains.
fn spanless_first_sequence(
    item: &SnapshotItem,
    fold: &super::claude_request_money::e2::FileFold,
) -> Option<u64> {
    if fold.fork_parent().is_some()
        || item.claude_context_curve_owned_start_proven
        || owner_root(item) != Some(item.source_session_id.as_str())
    {
        return None;
    }
    let (request, first) = item
        .claude_usage_occurrences
        .iter()
        .find(|(_, occurrence)| occurrence.sequence == 0)?;
    (!first.usage.is_zero()
        && !fold.is_skipped(first.sequence)
        && !fold.unproven_copy(first)
        && !fold.is_ambiguous(request))
    .then_some(first.sequence)
}

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
/// and a keyed local change detector for `session_context` are kept; no email
/// or raw text is retained or sent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct OrgMarkers {
    entries: Vec<OrgMarker>,
    starting_marker: RetiredStartingMarker,
    overflowed: RetiredOverflow,
    context_digest: Option<String>,
    context_changed: bool,
    /// Response position of the first non-blank `session_context` email.
    context_position: Option<u64>,
    context_flip_position: RetiredContextFlipPosition,
}

/// Retired: the starting marker earlier builds stored beside the entries (it
/// copied the first one). Decoded and dropped, written as `None`, so a stored
/// head keeps its layout and still loads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RetiredStartingMarker;

/// Retired: the marker-count flag earlier builds stored. A head that set it had
/// dropped its markers, so it does not decode and the file reads cold. Written
/// as `false`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RetiredOverflow;

/// Retired: the position of the first later `session_context` naming a
/// different email, which earlier builds stored. Nothing reads it, so it is
/// decoded and dropped, written as `None`, and a stored head still loads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RetiredContextFlipPosition;

impl crate::durable_tail_codec::Durable for RetiredStartingMarker {
    fn put(
        &self,
        e: &mut crate::durable_tail_codec::Enc,
    ) -> Result<(), crate::durable_tail_codec::Refuse> {
        crate::durable_tail_codec::Durable::put(&None::<OrgMarker>, e)
    }
    fn take(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<Self, crate::durable_tail_codec::Corrupt> {
        <Option<OrgMarker> as crate::durable_tail_codec::Durable>::take(d).map(|_| Self)
    }
    fn verify(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::durable_tail_codec::Corrupt> {
        <Option<OrgMarker> as crate::durable_tail_codec::Durable>::verify(d)
    }
    fn shape(s: &mut crate::durable_tail_codec::Shape) {
        <Option<OrgMarker> as crate::durable_tail_codec::Durable>::shape(s);
    }
}

impl crate::durable_tail_codec::Durable for RetiredOverflow {
    fn put(
        &self,
        e: &mut crate::durable_tail_codec::Enc,
    ) -> Result<(), crate::durable_tail_codec::Refuse> {
        crate::durable_tail_codec::Durable::put(&false, e)
    }
    fn take(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<Self, crate::durable_tail_codec::Corrupt> {
        if <bool as crate::durable_tail_codec::Durable>::take(d)? {
            return Err(crate::durable_tail_codec::Corrupt);
        }
        Ok(Self)
    }
    fn verify(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::durable_tail_codec::Corrupt> {
        Self::take(d).map(|_| ())
    }
    fn shape(s: &mut crate::durable_tail_codec::Shape) {
        <bool as crate::durable_tail_codec::Durable>::shape(s);
    }
}

impl crate::durable_tail_codec::Durable for RetiredContextFlipPosition {
    fn put(
        &self,
        e: &mut crate::durable_tail_codec::Enc,
    ) -> Result<(), crate::durable_tail_codec::Refuse> {
        crate::durable_tail_codec::Durable::put(&None::<u64>, e)
    }
    fn take(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<Self, crate::durable_tail_codec::Corrupt> {
        <Option<u64> as crate::durable_tail_codec::Durable>::take(d).map(|_| Self)
    }
    fn verify(
        d: &mut crate::durable_tail_codec::Dec<'_>,
    ) -> Result<(), crate::durable_tail_codec::Corrupt> {
        <Option<u64> as crate::durable_tail_codec::Durable>::verify(d)
    }
    fn shape(s: &mut crate::durable_tail_codec::Shape) {
        <Option<u64> as crate::durable_tail_codec::Durable>::shape(s);
    }
}

/// The hashed organization of a `credential_org` attachment; `None` when blank
/// or malformed.
fn marker_org_hash(attachment: &Value) -> Option<String> {
    attachment
        .get("organizationUuid")
        .and_then(Value::as_str)
        .and_then(crate::claude_local_otel::canonical_uuid)
        .and_then(|uuid| ottto_core::billing_identity_hash("anthropic", "organization", &uuid))
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
            let state = markers.get_or_insert_with(Box::default);
            match accepted::session_context_digest(&text) {
                // No key, no field: a sentence that cannot be compared explains
                // no organization change.
                None => state.context_digest = None,
                // An earlier email with no digest (no key then, or scrubbed on a
                // key change) cannot be compared: this sentence is a fresh
                // baseline. It explains no organization change.
                Some(digest) if state.context_digest.as_deref() != Some(digest.as_str()) => {
                    let compared = state.context_digest.is_some();
                    state.context_changed =
                        compared || (state.context_position.is_none() && !state.entries.is_empty());
                    state.context_digest = Some(digest);
                }
                Some(_) => {}
            }
            if !text.is_empty() && state.context_position.is_none() {
                state.context_position = Some(response_position);
            }
        }
        Some("credential_org") => {
            let org = marker_org_hash(attachment);
            let state = markers.get_or_insert_with(Box::default);
            let terminal_trusted = match state.entries.last() {
                None => true,
                Some(previous) => {
                    state.context_changed || (previous.terminal_trusted && previous.org == org)
                }
            };
            state.context_changed = false;
            state.entries.push(OrgMarker {
                position: response_position,
                org,
                terminal_trusted,
            });
        }
        _ => {}
    }
}

crate::local_resource_diagnostics::process_static!(fn with_context_digest_scrubs:
    std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0));

/// This thread's count only, so a test takes no other test's identity counts.
#[cfg(test)]
pub(crate) fn take_context_digest_scrubs_for_test() -> u64 {
    with_context_digest_scrubs(|counter| counter.swap(0, std::sync::atomic::Ordering::Relaxed))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MarkerVerdict<'m> {
    None,
    Trusted(&'m str),
    UntrustedFlip,
    BadOrg,
}

impl OrgMarkers {
    /// Every recorded response position: each is the file's response count
    /// when its line was read.
    pub(crate) fn positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.entries
            .iter()
            .map(|marker| marker.position)
            .chain(self.context_position)
    }
    /// Ends comparison across a key change, keeping the markers and their
    /// earlier verdicts. This state exists only once a sentence or marker was
    /// read, so position 0 stands in when none was recorded: the next sentence
    /// is a fresh baseline, never a first sentence, and any email stays refused.
    pub(crate) fn scrub_context_digest(&mut self) {
        self.context_digest = None;
        self.context_changed = false;
        if self.context_position.is_none() {
            self.context_position = Some(0);
        }
        with_context_digest_scrubs(|counter| {
            counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        });
    }

    /// The marker governing the response with `sequence`, by line order only.
    /// `latest` (Desktop, or a request from `ACCOUNT_RULE_FROM`) trusts any
    /// valid org line; otherwise an unexplained flip is refused.
    pub(crate) fn verdict(&self, sequence: u64, latest: bool) -> MarkerVerdict<'_> {
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
            Some(_) if !latest && !marker.terminal_trusted => MarkerVerdict::UntrustedFlip,
            Some(org) => MarkerVerdict::Trusted(org),
        }
    }
}

// `e2` consumes this compact, native-sequence-ordered placement before any
// requests aggregate.
pub(crate) type AccountPartition = Option<Arc<AuthorityKey>>;
/// A counted request's grain slot (live key, origin), the account a copied
/// marker lent it, and whether this pass positively read its own evidence.
#[derive(Clone, Debug)]
pub(crate) struct LentSlot {
    pub(crate) key: super::claude_request_money::body::ClaudeLiveKey,
    pub(crate) origin: Option<super::claude_request_money::body::ClaudeRequestUsageOrigin>,
    pub(crate) lent: Arc<AuthorityKey>,
    /// Classified tagged or missing, never refused (e.g. unreadable).
    pub(crate) read: bool,
}
crate::heap_layout_bound::fields!(LentSlot; key, origin, lent, read);

#[derive(Clone, Debug)]
struct AccountRun {
    position: u64,
    account: AccountPartition,
    /// First nonzero usage following this marker: its response position and
    /// `e2` copy status. Zero-usage responses may separate it from the marker.
    copied: Option<(u64, bool)>,
    /// Starts at `trust_from` with the org of a refused earlier line: never an
    /// own marker position.
    split: bool,
}
crate::heap_layout_bound::fields!(AccountRun; position, account, copied, split);

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
    first_retained: Option<u64>,
    /// First response sequence whose provider time is from `ACCOUNT_RULE_FROM`;
    /// org lines govern from it as on Desktop. Kept for native-copy rebuilds.
    trust_from: Option<u64>,
    reconciled: bool,
    /// Root start known, but the native Unknown grains are not filled yet.
    root_fallback_pending: bool,
    /// This page could not read the family's strict sidecar evidence; no
    /// account may fill its shares (an unhealthy root is all-Unknown).
    unhealthy_no_fallback: bool,
    /// The uniform wire account a non-discard unhealthy read cleared; the
    /// bound owner admits the Unknown body only if it was its own.
    unhealthy_cleared_account: Option<String>,
    /// Copy-prefix switch on: per counted request whose account a copied
    /// marker had lent (the copy decision re-derived it without the marker),
    /// its grain slot, kept current through telemetry placement, and that
    /// account (see `copy_derived_rows`).
    pub(crate) copied_marker_lent: BTreeMap<u64, LentSlot>,
    /// This transcript's carry verdicts.
    carried: CarryCounts,
}
crate::heap_layout_bound::fields!(AuthorityKey; login, org, basis, account_source);
crate::heap_layout_bound::fields!(RequestAccounts; starting, fallback, bound, retained_root, runs, mixed, conflict, subagent, first_retained, trust_from, reconciled, root_fallback_pending, unhealthy_no_fallback, unhealthy_cleared_account, copied_marker_lent, carried);

/// The carry rule's verdicts for one transcript.
#[derive(Clone, Copy, Debug, Default)]
struct CarryCounts {
    /// A counted gap no own account could reach: no seed, an incomplete
    /// transcript, a seed over the key cap, or a run a no-account row ended.
    no_seed: bool,
    /// Counted own telemetry that names no valid account (API key, cloud,
    /// placeholder), or a request refused because its named owner could not
    /// be read. Either way no session-start fill reaches this file.
    blocked_no_account: bool,
    /// Runtime-only resource verdict, propagated into the existing item HOLD.
    keys_over_cap: bool,
}
crate::heap_layout_bound::fields!(CarryCounts; no_seed, blocked_no_account, keys_over_cap);

#[derive(Default, serde::Serialize)]
pub(crate) struct IdentityCounts {
    #[serde(skip_serializing_if = "budget::Counts::is_empty")]
    identity_cap: budget::Counts,
    /// Retained Claude parses scrubbed on an attribution key change.
    #[serde(skip_serializing_if = "is_zero")]
    claude_context_digest_scrubs: u64,
    /// Why usage was left untagged with a refusal, by closed cause label.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    request_identity_refusal: BTreeMap<&'static str, u64>,
}
fn is_zero(value: &u64) -> bool {
    *value == 0
}
pub(crate) fn take_identity_counts() -> IdentityCounts {
    IdentityCounts {
        identity_cap: budget::take_counts(),
        claude_context_digest_scrubs: with_context_digest_scrubs(|counter| {
            counter.swap(0, std::sync::atomic::Ordering::Relaxed)
        }),
        request_identity_refusal: take_refusal_causes(),
    }
}

fn entity_grouping(
    entity: &super::claude_request_money::e2::ClaudeEntityBody,
    bucket_rows: usize,
) -> Grouping {
    let mut grouping = Grouping::new(bucket_rows);
    super::claude_request_money::e2::visit_entity_identity_rows(
        entity,
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
                    account_source: key.account_source,
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
    );
    grouping
}

pub(crate) fn tag_telemetry_entity(
    item: &mut SnapshotItem,
    entity: &super::claude_request_money::e2::ClaudeEntityBody,
    accepted: Option<&AcceptedBuckets>,
    budget: WireBudget<'_>,
) -> bool {
    let mut grouping = entity_grouping(entity, bucket_row_count(item));
    grouping.hold_over_cap = true;
    grouping.extra_wire_bytes = budget.reservation.map_or(0, |reserve| reserve(item));
    let known = accepted.and_then(|state| state.get(&item.source_session_id));
    matches!(
        apply_grouped_with_accepted(item, grouping, known, budget.max_item_bytes),
        Ok(Tagged::Sent { .. })
    )
}

/// Exact final `e2` rows, including copied exclusions and telemetry side calls.
/// `e2` owns placement; this owner supplies contract-5 keys and evidence only.
fn request_owned_grouping(item: &SnapshotItem) -> Option<Grouping> {
    let mut grouping = entity_grouping(
        &item.claude_money.as_deref()?.entity,
        bucket_row_count(item),
    );
    let carry_keys_over_cap = item
        .claude_money
        .as_deref()
        .and_then(|fold| fold.accounts.as_deref())
        .is_some_and(|accounts| accounts.carried.keys_over_cap);
    grouping.upstream_proof_lost = item
        .claude_money
        .as_deref()
        .is_some_and(|fold| fold.entity.identity_over_cap);
    grouping.upstream_proof_lost |= carry_keys_over_cap;
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

/// Scan-local evidence shared by every item of one Claude pass.
#[derive(Default)]
pub(crate) struct ScanEvidence<'a> {
    pub(crate) requests: BTreeMap<(&'a str, &'a str), Option<&'a ClaudeLocalOtelEvidence>>,
    pub(crate) owners: BTreeMap<(&'a str, &'a str), Option<&'a ClaudeTraceOwnershipEvidence>>,
    /// This pass's scope and the cross-root answers the strict read built
    /// root by root over it.
    cross: Option<&'a super::claude_cross_root_evidence::CrossRootEvidence>,
    /// The request roots come from `cross`, not from the loaded rows.
    streamed: bool,
    /// Test-only reachable fallback for the whole-corpus oracle: request roots
    /// of the loaded rows, built on the first request without rows of its own.
    request_roots: std::cell::OnceCell<RequestRootIndex>,
    /// Roots whose sidecar reads were incomplete in this pass.
    pub(crate) unhealthy_roots: BTreeSet<String>,
    /// Unhealthy roots whose strict trace read this pass discarded (it grew
    /// or was replaced mid-read); the trace-discard account hold withholds their family.
    trace_discarded_roots: BTreeSet<String>,
    /// Unique telemetry rows that failed `valid_login`. Every unique row is
    /// checked once here (its fingerprint included); `classify` reuses the
    /// verdict, and a passing row's login is its `account_identifier_hash`.
    invalid_logins: BTreeSet<(&'a str, &'a str)>,
    /// Pre-enrichment native evidence already saved by this scan. Request
    /// telemetry may veto its original org for billing without changing the
    /// unambiguous native account used by local Desktop activity.
    native_originals: Option<&'a BTreeMap<String, super::SessionAccountEvidence>>,
    accepted_buckets: Option<&'a AcceptedBuckets>,
    wire_budget: WireBudget<'a>,
}

/// Each request id named by healthy API or trace rows, as its SHA-256, with
/// the ordinal of the one root holding it, or `SEVERAL` when rows
/// under several roots name it. Rows are keyed by trace root, so this is how a
/// fork or resume copy under another root sees that the request already has
/// an owner. A root's API and trace rows of one request are one claim: each
/// root's ids are deduplicated as the root is added, before the collapse.
#[derive(Default)]
pub(crate) struct RequestRootIndex(Vec<([u8; 32], u32)>);

impl RequestRootIndex {
    const SEVERAL: u32 = u32::MAX;

    /// Adds one root's API and trace request ids, in any order. Call once per root.
    pub(crate) fn add_root<'r>(&mut self, root: u32, request_ids: impl Iterator<Item = &'r str>) {
        let mut ids = request_ids
            .map(|id| <[u8; 32]>::from(sha2::Sha256::digest(id.as_bytes())))
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        self.0.extend(ids.into_iter().map(|id| (id, root)));
    }

    /// Once every root is in: sort, then collapse ids held by several roots.
    pub(crate) fn finish(&mut self) {
        self.0.sort_unstable();
        self.0.dedup_by(|later, kept| {
            if later.0 != kept.0 {
                return false;
            }
            kept.1 = Self::SEVERAL;
            true
        });
        self.0.shrink_to_fit();
    }

    /// `Some(Some(root))`: one root's rows name `request_id`; `Some(None)`: several.
    pub(crate) fn get(&self, request_id: &str) -> Option<Option<u32>> {
        let id = <[u8; 32]>::from(sha2::Sha256::digest(request_id.as_bytes()));
        let at = self.0.binary_search_by(|(known, _)| known.cmp(&id)).ok()?;
        let root = self.0[at].1;
        Some((root != Self::SEVERAL).then_some(root))
    }
}

/// One root's API rows by request id: the row, or `None` when several name it.
fn unique_by_request(
    rows: &[ClaudeLocalOtelEvidence],
) -> BTreeMap<&str, Option<&ClaudeLocalOtelEvidence>> {
    let mut unique = BTreeMap::new();
    for row in rows {
        unique
            .entry(row.request_id.as_str())
            .and_modify(|entry| *entry = None)
            .or_insert(Some(row));
    }
    unique
}

impl<'a> ScanEvidence<'a> {
    pub(crate) fn new(
        api: &'a ClaudeLocalOtelLoadReport,
        trace: &'a ClaudeTraceOwnershipLoadReport,
        unhealthy_roots: BTreeSet<String>,
    ) -> Self {
        let mut evidence = Self {
            unhealthy_roots,
            ..Self::default()
        };
        for (root, rows) in &api.evidence {
            for (request_id, row) in unique_by_request(rows) {
                evidence.requests.insert((root.as_str(), request_id), row);
            }
        }
        for (&key, row) in &evidence.requests {
            let Some(row) = row else { continue };
            if valid_login(row, key.0).is_none() {
                evidence.invalid_logins.insert(key);
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

    /// The scope's cross-root answers, for a pass whose reports hold only the
    /// page roots: request roots and named owners.
    pub(crate) fn with_cross_root(
        mut self,
        cross: &'a super::claude_cross_root_evidence::CrossRootEvidence,
    ) -> Self {
        self.cross = Some(cross);
        self.streamed = true;
        self
    }

    /// The whole-corpus oracle: its reports hold every scope root's rows; the
    /// scope still names the owners.
    pub(crate) fn with_scope(
        mut self,
        cross: &'a super::claude_cross_root_evidence::CrossRootEvidence,
    ) -> Self {
        self.cross = Some(cross);
        self
    }

    /// The scope names another session as this request's owner (a census
    /// holder or the file's fork parent) whose side files could not be read.
    /// Only for a request with no API row of its own.
    pub(crate) fn owner_unreadable(&self, root: &str, request_id: &str) -> bool {
        self.cross.is_some_and(|cross| {
            cross
                .named_owners(root, request_id)
                .any(|owner| self.unhealthy_roots.contains(owner))
        })
    }

    pub(crate) fn with_trace_discarded_roots(mut self, roots: BTreeSet<String>) -> Self {
        self.trace_discarded_roots = roots;
        self
    }

    pub(crate) fn with_accepted_buckets(mut self, accepted: Option<&'a AcceptedBuckets>) -> Self {
        self.accepted_buckets = accepted;
        self
    }

    pub(crate) fn with_wire_budget(mut self, budget: WireBudget<'a>) -> Self {
        self.wire_budget = budget;
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
    fn request_root(&self, request_id: &str) -> Option<Option<u32>> {
        if let Some(cross) = self.cross.filter(|_| self.streamed) {
            return cross.request_roots.get(request_id);
        }
        self.request_roots
            .get_or_init(|| {
                let mut ids_by_root = BTreeMap::<&str, Vec<&str>>::new();
                for &(root, id) in self.requests.keys().chain(self.owners.keys()) {
                    ids_by_root.entry(root).or_default().push(id);
                }
                let mut roots = RequestRootIndex::default();
                for (ordinal, ids) in (0..).zip(ids_by_root.into_values()) {
                    roots.add_root(ordinal, ids.into_iter());
                }
                roots.finish();
                roots
            })
            .get(request_id)
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

/// The org of a row whose request identity is complete.
fn complete_org(row: &ClaudeLocalOtelEvidence) -> Option<&str> {
    row.request_identity
        .as_ref()
        .filter(|identity| identity.disposition == ClaudeIdentityDisposition::Complete)
        .and_then(|identity| organization_hash(identity).ok().flatten())
}

/// A telemetry-only side call's own account: an intact row login with a
/// complete org (the same checks `classify` applies). `None` when
/// either is missing or incomplete: the caller keeps the session fallback.
pub(crate) fn side_call_account(row: &ClaudeLocalOtelEvidence, root: &str) -> AccountPartition {
    let login = valid_login(row, root)?;
    let org = complete_org(row)?;
    Some(Arc::new(AuthorityKey {
        login: Some(login.to_owned()),
        org: Some(org.to_owned()),
        basis: TELEMETRY,
        account_source: None,
    }))
}

/// The row's login when the row itself is intact: the legacy account path's capture, count,
/// fingerprint and account-origin checks. Ownership is checked separately.
pub(super) fn valid_login<'a>(row: &'a ClaudeLocalOtelEvidence, root: &str) -> Option<&'a str> {
    let login = row
        .account_identifier_hash
        .as_deref()
        .filter(|hash| hash_is_valid(hash))?;
    (&*row.session_id == root
        && &*row.capture_revision == "claude_api_request:v2"
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

/// The legacy account path's check: each recorded origin must carry exactly this login.
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

pub(super) fn hash_is_valid(hash: &str) -> bool {
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
    /// `spanless_first_sequence` named this request.
    pub(crate) spanless_first: bool,
}

/// A borrowed authority key: classification builds no strings; a `Grouping`
/// copies one only when it admits a new key (at most `MAX_AUTHORITY_KEYS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KeyRef<'k> {
    login: Option<&'k str>,
    org: Option<&'k str>,
    basis: &'static str,
    account_source: Option<AccountSource>,
}

impl KeyRef<'_> {
    fn matches(&self, key: &AuthorityKey) -> bool {
        self.basis == key.basis
            && self.login == key.login.as_deref()
            && self.org == key.org.as_deref()
            && self.account_source == key.account_source
    }

    fn to_key(self) -> AuthorityKey {
        AuthorityKey {
            login: self.login.map(str::to_string),
            org: self.org.map(str::to_string),
            basis: self.basis,
            account_source: self.account_source,
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
            account_source: self.account_source,
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

/// Owned classification, for the ownership tests.
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
        // Unreadable stronger evidence never falls through: it is refused as
        // incomplete, never classified from weaker evidence.
        return Refused(Refusal::IncompleteEvidence);
    }
    let row = match evidence.requests.get(&(facts.root, facts.request_id)) {
        Some(None) => return Refused(Refusal::ConflictingDuplicate),
        Some(Some(row)) => *row,
        None => {
            // A trace that already owns this request outranks the transcript:
            // a foreign, duplicated or unpaired owner refuses and never borrows
            // this transcript's org.
            if let Some(owner) = evidence.owners.get(&(facts.root, facts.request_id)) {
                return Refused(match owner {
                    None => Refusal::ConflictingDuplicate,
                    Some(owner) if owner_is_foreign(owner, facts.root, facts.source_session_id) => {
                        Refusal::ForeignOwner
                    }
                    Some(_) => Refusal::IncompleteEvidence,
                });
            }
            // An owner the scope names but could not read leaves the request
            // unproven: the copy's markers never claim it.
            if evidence.owner_unreadable(facts.root, facts.request_id) {
                return Refused(Refusal::IncompleteEvidence);
            }
            // Rows are keyed by trace root: a fork or resume copy holds its
            // original's request with the original's rows under another root.
            // Those rows own it; the copy's markers never claim it.
            match evidence.request_root(facts.request_id) {
                Some(Some(_)) => return Refused(Refusal::ForeignOwner),
                Some(None) => return Refused(Refusal::ConflictingDuplicate),
                None => {}
            }
            return match transcript_identity(facts) {
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
        // No trace owner: only the original root's first response from the
        // cutoff, claimed by no other root or unreadable owner, keeps its row.
        None if facts.spanless_first
            && facts.root == facts.source_session_id
            && !row.client_request_id.is_empty()
            && facts
                .terminal_unix_seconds
                .is_some_and(|at| at >= SPANLESS_FIRST_REQUEST_FROM)
            && !evidence.owner_unreadable(facts.root, facts.request_id)
            && !matches!(evidence.request_root(facts.request_id), Some(None)) => {}
        None => return Refused(Refusal::IncompleteEvidence),
        Some(Some(owner)) => {
            if owner_is_foreign(owner, facts.root, facts.source_session_id)
                || owner.client_request_id != row.client_request_id
            {
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
            account_source: None,
        });
    }
    // Login-only telemetry never borrows a transcript marker's org.
    Tagged(KeyRef {
        login: Some(login),
        org: None,
        basis: TELEMETRY_LOGIN,
        account_source: None,
    })
}

/// The ownership checks that need no telemetry row; the legacy account path
/// shares them.
pub(super) fn owner_is_foreign(
    owner: &ClaudeTraceOwnershipEvidence,
    root: &str,
    source_session_id: &str,
) -> bool {
    &*owner.session_id != root
        || &*owner.capture_revision != "claude_llm_request_ownership:v1"
        || !super::claude_trace_evidence_fingerprint_is_valid(owner)
        || super::claude_trace_owner_session_id(root, &owner.agent_id) != source_session_id
        || owner.client_request_id.is_empty()
}

/// Transcript bases for a request with no telemetry row or trace owner.
fn transcript_identity<'k>(facts: &RequestFacts<'k>) -> Option<IdentityRef<'k>> {
    let org = match facts.marker {
        MarkerVerdict::None => return None,
        MarkerVerdict::UntrustedFlip => return Some(IdentityRef::Refused(Refusal::UntrustedFlip)),
        MarkerVerdict::BadOrg => return Some(IdentityRef::Refused(Refusal::ContradictoryOrg)),
        MarkerVerdict::Trusted(org) => org,
    };
    Some(IdentityRef::Tagged(KeyRef {
        login: None,
        org: Some(org),
        basis: TRANSCRIPT_ORG,
        account_source: None,
    }))
}

fn request_occurrence_facts<'a>(
    item: &'a SnapshotItem,
    request_id: &'a str,
    occurrence: &'a super::ClaudeTranscriptUsageOccurrence,
    spanless_first: Option<u64>,
) -> Option<RequestFacts<'a>> {
    let root = owner_root(item)?;
    let timestamp = occurrence.timestamp.as_deref()?;
    let desktop = item
        .origin
        .as_ref()
        .and_then(|origin| origin.entrypoint.as_deref())
        == Some("claude-desktop");
    let terminal_unix_seconds = rfc3339_unix_seconds(timestamp);
    Some(RequestFacts {
        root,
        source_session_id: &item.source_session_id,
        request_id,
        terminal_unix_seconds,
        event_clock_complete: occurrence.event_clock_complete,
        marker: item
            .claude_org_markers
            .as_deref()
            .map_or(MarkerVerdict::None, |markers| {
                markers.verdict(
                    occurrence.sequence,
                    desktop || from_account_rule(terminal_unix_seconds),
                )
            }),
        spanless_first: spanless_first == Some(occurrence.sequence),
    })
}

crate::heap_layout_bound::fields!(OrgMarkers; entries, starting_marker, overflowed, context_digest, context_changed, context_position, context_flip_position);
crate::durable_tail_codec::durable_struct!(OrgMarkers {
    D entries: Vec<OrgMarker>,
    D starting_marker: RetiredStartingMarker,
    N overflowed: RetiredOverflow,
    H context_digest: Option<String>,
    N context_changed: bool,
    N context_position: Option<u64>,
    N context_flip_position: RetiredContextFlipPosition,
});
crate::heap_layout_bound::fields!(OrgMarker; position, org, terminal_trusted);
crate::heap_layout_bound::no_heap!(true; RetiredStartingMarker, RetiredOverflow, RetiredContextFlipPosition);
crate::durable_tail_codec::durable_struct!(OrgMarker {
    N position: u64,
    U org: Option<String>,
    N terminal_trusted: bool,
});
crate::heap_layout_bound::fields!(AccountDisplay; current, history);
crate::heap_layout_bound::fields!(ActiveSessionCurrentAccount; status, account_identifier_hash, organization_identifier_hash, subscription_product, latest_request_at, unknown_reason);
crate::heap_layout_bound::fields!(ActiveSessionAccountUse; account_identifier_hash, organization_identifier_hash, subscription_product, request_count, input_tokens, cache_read_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, output_tokens, last_used_at, current);

#[cfg(test)]
mod context_digest_tests;

#[cfg(test)]
mod org_line_tests;

#[cfg(test)]
mod request_owned_contract_tests {
    use super::*;
    #[test]
    fn grouping_version_uses_existing_contract_rearm_and_gate_off_stays_identical() {
        assert_eq!(compiled_cycle_contract(false), "");
        let first = compiled_cycle_contract(true);
        assert_ne!(first, COLLECTOR);
        assert_eq!(first, compiled_cycle_contract(true));
        assert_eq!(
            serde_json::to_value(IdentityCounts::default()).unwrap(),
            json!({})
        );
    }
}
