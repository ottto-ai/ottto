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
//! no transcript read, parse or retained state.

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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(crate) const COLLECTOR: &str = "claude_code_jsonl:own_request_identity_rows:v1";

/// Compiled on. Each cycle still emits only under that cycle's exact cohort
/// hint token (`emission_permit`); without it the body is today's.
pub(crate) const EMISSION_ENABLED: bool = true;

/// Marker capture and the census witness run only in a scan whose sync cycle
/// holds an emission permit. Outside a cycle nothing captures in a released
/// build; tests capture by default so parser fixtures see markers.
pub(crate) const fn capture_by_default() -> bool {
    cfg!(test)
}

/// `transcript_email` (and its status-coverage feed) needs its own review and
/// receiver acceptance on top of contract-5 emission. Flipping this is a
/// separate, parent-owned change.
pub(crate) const TRANSCRIPT_EMAIL_ENABLED: bool = false;

pub(crate) const fn transcript_email_enabled() -> bool {
    (EMISSION_ENABLED && TRANSCRIPT_EMAIL_ENABLED) || cfg!(test)
}

/// `transcript_sole_login` needs the receiver's time-scoped sole-login body
/// veto verified as deployed, on top of contract-5 emission. Until then a
/// qualifying Desktop census still yields org-only (`transcript_org`); the
/// email gate does not cover this basis. Flipping this is a separate,
/// parent-owned change.
pub(crate) const TRANSCRIPT_SOLE_LOGIN_ENABLED: bool = false;

/// The activity-hint token (`session_request_identity_contract`) the server
/// sends only to the approved cohort on the accepted-log route. It is not the
/// collector name.
pub(crate) const COHORT_HINT_TOKEN: &str = "own_request_identity_rows:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CohortDenial {
    EmissionDisabled,
    OtherSource,
    NoToken,
    UnknownToken,
}

/// Proof that this sync cycle may capture identity evidence and build
/// contract-5 bodies. Only `emission_permit` makes one (`permit_when` takes
/// the emission constant as an argument, for tests).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EmissionPermit(());

/// The current cycle's permit, from the activity hint fetched for it with
/// this device's credential. A missing, null or unknown token denies; nothing
/// is persisted, so a revoked token denies from the next fetched cycle and a
/// restart or account switch starts from that cycle's hint.
pub(crate) fn emission_permit(
    source: SnapshotSource,
    hint_token: Option<&str>,
) -> Result<EmissionPermit, CohortDenial> {
    permit_when(EMISSION_ENABLED, source, hint_token)
}

pub(super) fn permit_when(
    emission_enabled: bool,
    source: SnapshotSource,
    hint_token: Option<&str>,
) -> Result<EmissionPermit, CohortDenial> {
    if !emission_enabled {
        return Err(CohortDenial::EmissionDisabled);
    }
    if source != SnapshotSource::ClaudeCode {
        return Err(CohortDenial::OtherSource);
    }
    match hint_token {
        None => Err(CohortDenial::NoToken),
        Some(COHORT_HINT_TOKEN) => Ok(EmissionPermit(())),
        Some(_) => Err(CohortDenial::UnknownToken),
    }
}

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
        for index in 0..5 {
            self.poisoned[index] |= other.poisoned[index];
            if let Some(value) = other.costs[index] {
                self.costs[index] = Some(self.costs[index].unwrap_or(0).checked_add(value)?);
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
}

/// Per-item aggregation at today's (bucket, row key) x authority-key grain,
/// fed one request at a time so nothing grows with the request count. Groups
/// are capped by the rows the item can carry (more could never reproduce), and
/// each group by `MAX_AUTHORITY_KEYS` plus the untagged entry: keys past the
/// cap fold into untagged as they arrive, before any encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Grouping {
    groups: BTreeMap<String, BTreeMap<RowKey, RowGroup>>,
    group_count: usize,
    max_groups: usize,
    keys: BTreeSet<AuthorityKey>,
    keys_over_cap: bool,
    failed: Option<Ineligible>,
}

impl Grouping {
    pub(crate) fn new(max_groups: usize) -> Self {
        Self {
            groups: BTreeMap::new(),
            group_count: 0,
            max_groups,
            keys: BTreeSet::new(),
            keys_over_cap: false,
            failed: None,
        }
    }

    pub(super) fn add(
        &mut self,
        bucket_start: &str,
        row_key: &RowKey,
        usage: &UsageTotals,
        identity: IdentityRef<'_>,
    ) {
        if self.failed.is_some() {
            return;
        }
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
        let key = match identity {
            // Only a strictly lowercase-hex login reaches the wire; anything
            // else is refused here, never transformed into another identity.
            IdentityRef::Tagged(key) if !key.login.map_or(true, wire_login_is_valid) => {
                group.refused = true;
                None
            }
            IdentityRef::Tagged(key) if !self.keys_over_cap => {
                // At most `MAX_AUTHORITY_KEYS` keys: scan before copying one.
                if !self.keys.iter().any(|known| key.matches(known)) {
                    if self.keys.len() == MAX_AUTHORITY_KEYS {
                        self.keys_over_cap = true;
                    } else {
                        self.keys.insert(key.to_key());
                    }
                }
                (!self.keys_over_cap).then_some(key)
            }
            IdentityRef::Tagged(_) => None,
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
                let key = key.and_then(|key| match key.basis {
                    TELEMETRY => Some(key),
                    TELEMETRY_LOGIN => Some(AuthorityKey { org: None, ..key }),
                    _ => None,
                });
                if kept.entry(key).or_default().merge(&amounts).is_none() {
                    self.failed = Some(Ineligible::RowsNotReproduced);
                }
            }
            group.by_key = kept;
        }
    }

    fn rows(&self) -> impl Iterator<Item = (&RowKey, &RowGroup)> {
        self.groups.values().flatten()
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

/// Tag `item` from its aggregated requests. Returns `Err` when the item must
/// stay on today's path (it is left unchanged). On success the item carries the
/// new collector, the tagged or fallback shape, and a fresh fingerprint.
pub(crate) fn apply_grouped(
    item: &mut SnapshotItem,
    mut grouping: Grouping,
) -> Result<Tagged, Ineligible> {
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
            .merge(&group.total)
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
                    by_key
                        .entry(authority.clone())
                        .or_default()
                        .merge(amounts)
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

    let lost = bucket_identities
        .iter()
        .flatten()
        .filter(|identity| !matches!(identity, RowIdentity::Untagged))
        .count() as u64;
    if over_cap.is_empty() {
        // In place: an over-size result is stripped below to the same
        // fallback the untouched item would get, so no item copy is needed.
        install(item, &evidence, top_identities, bucket_identities, refusals);
        if item_bytes(item) <= MAX_ITEM_BYTES {
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            return Ok(Tagged::Sent { refusals });
        }
        over_cap.insert(OverCap::Bytes);
    }
    let refusals = lost.max(1).saturating_add(prior_refusals);
    strip(item);
    item.provenance.collector = COLLECTOR.to_string();
    item.request_identity_refusals = refusals;
    item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
    Ok(Tagged::Fallback {
        over_cap: over_cap.into_iter().collect(),
        refusals,
    })
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
                if wire.is_some() && !amounts.wire(index).is_some_and(micro_exact) {
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

/// Sorted compact JSON bytes, the receiver's item-size measure.
pub(crate) fn item_bytes(item: &SnapshotItem) -> usize {
    serde_json::to_value(item)
        .ok()
        .and_then(|value| serde_json::to_vec(&value).ok())
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
            let digest = format!("{:x}", sha2::Sha256::digest(text.as_bytes()));
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
            state.entries.push(OrgMarker {
                position: response_position,
                org,
                terminal_trusted,
            });
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

/// Classifies one item's requests as the row builder produces them and folds
/// each straight into a bounded `Grouping`; no request is retained.
pub(crate) struct RequestSink<'s, 'a> {
    evidence: &'s ScanEvidence<'a>,
    /// The duplicate witness, on the transcript path only; reported rows
    /// carry their own telemetry owner.
    duplicates: Option<&'s Duplicates>,
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

    pub(super) fn add(&mut self, item: &SnapshotItem, request: Request<'_>) {
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
        self.grouping.add(
            request.bucket_start,
            request.row_key,
            request.usage,
            identity,
        );
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

/// What this pass's duplicate census settled about who holds a transcript
/// request. Known only after the reported rebuild has updated the witness.
pub(crate) struct TranscriptOwnership<'i> {
    /// Request-id hashes that more than one transcript carries.
    duplicates: &'i Duplicates,
    /// The pass compared every indexed Claude transcript's current requests
    /// (complete, valid census with the fence open, and every indexed member
    /// observed this window). Fence coverage alone is not enough: it excuses
    /// a family under a bound authority quarantine, whose requests were not
    /// compared. Only then can a request without its own telemetry be shown
    /// to be this transcript's alone, so only then may markers tag it.
    settled: bool,
}

impl<'i> TranscriptOwnership<'i> {
    pub(crate) fn after_census(
        index: &'i ScanIndex,
        disposition: &super::ClaudeUsageAuthorityDisposition,
    ) -> Self {
        let census = &disposition.duplicate_census;
        Self {
            duplicates: &index.claude_duplicate_request_owners,
            settled: census.census_complete
                && census.coverage_complete
                && disposition.transcript_ownership_complete
                && !census.census_invalid
                && !census.fence_after,
        }
    }
}

/// A settled pass with no duplicates: what the classification tests assume.
#[cfg(test)]
pub(crate) fn apply_scan(
    snapshots: &mut [SnapshotItem],
    evidence: &ScanEvidence<'_>,
    reported: BTreeMap<String, Grouping>,
) -> ScanOutcome {
    static NONE: Duplicates = BTreeMap::new();
    apply_scan_with_ownership(
        snapshots,
        evidence,
        reported,
        &TranscriptOwnership {
            duplicates: &NONE,
            settled: true,
        },
    )
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

fn tag_item(
    item: &mut SnapshotItem,
    evidence: &ScanEvidence<'_>,
    reported: &mut BTreeMap<String, Grouping>,
    ownership: &TranscriptOwnership<'_>,
) -> Option<Result<Tagged, Ineligible>> {
    let root = owner_root(item)?;
    if !item.claude_context_curve_request_index_complete
        || claude_snapshot_request_id_hashes(item).is_none()
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
    let mut grouping = if item.usage_accounting_contract.as_deref() == Some(REPORTED) {
        reported.remove(&item.source_session_id)?
    } else {
        let mut sink = RequestSink::for_item(evidence, item, bucket_row_count(item))?
            .with_duplicates(ownership.duplicates);
        transcript_requests(item, |request| sink.add(item, request))?;
        sink.finish()
    };
    if !ownership.settled {
        // An unmarked fork or resume copies its predecessor's lines, markers
        // included, and nothing short of a fully compared pass shows which
        // lines are copies: markers tag nothing this pass.
        grouping.withdraw_transcript_tags();
    }
    // D1 leaves new-collector items alone, so the backend UTC lifecycle
    // spelling it applies to every item it qualifies happens here, inside the
    // byte cap; an ineligible item returns to D1 exactly as it arrived.
    let lifecycle = (
        item.source_started_at.clone(),
        item.source_ended_at.clone(),
        item.source_last_activity_at.clone(),
    );
    normalize_activity(item);
    let tagged = apply_grouped(item, grouping);
    if tagged.is_err() {
        (
            item.source_started_at,
            item.source_ended_at,
            item.source_last_activity_at,
        ) = lifecycle;
    }
    Some(tagged)
}

crate::heap_layout_bound::fields!(OrgMarkers; entries, overflowed, context_digest, context_changed, context_position, context_flip_position, home);
crate::heap_layout_bound::fields!(OrgMarker; position, org, terminal_trusted);
crate::heap_layout_bound::fields!(DesktopCensusWitness; completed_at_unix_seconds, process_id, inventory);
