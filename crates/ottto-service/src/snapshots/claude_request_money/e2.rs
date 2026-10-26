//! E2 request-owned Claude money from the native resolved-response fold.
//! Native resolution owns counts; this module only decides copies, attaches
//! reported telemetry cost and side calls, and emits one literal body per
//! session. The upload gate is OFF: DARK never changes an item, a scan
//! identity, parser scope or body witness.
use super::super::claude_context_file_birth::ClaudeFileBirth;
use super::super::claude_history_upgrade::{
    claude_path_twin_groups, path_twins, probe_opened_birth, ClaudeTwinGroups,
};
use super::super::claude_money_birth_store::{location_key, LocationKey};
use super::super::claude_request_census::claude_request_hash;
use super::super::claude_request_identity::{self, AccountPartition, RequestAccounts};
use super::super::{
    claude_api_cache_creation, claude_api_matches_transcript_occurrence,
    claude_index_path_family_member, claude_index_path_member_ref, claude_row_placement,
    claude_snapshot_family_root_ref, claude_trace_evidence_fingerprint_is_valid,
    claude_trace_owner_session_id, local_index_key, rfc3339_unix_nanos, validate_claude_api_row,
    ClaudeTranscriptUsageOccurrence, PlacedClaudeUsage, RowKey, ScanIndex, ScanTraversalCheckpoint,
    ScanTraversalPath, SelectorCapture, SnapshotItem, UsageTotals,
};
use super::body::{reported_inputs, ClaudeGrainSide, ClaudeLiveKey, ClaudeRequestUsageOrigin};
use super::ClaudeMoneyTokens;
use crate::claude_local_otel::{
    ClaudeApiEvidenceRead, ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport,
    ClaudeTraceOwnershipLoadReport,
};
use crate::telemetry_attach::{join, Attachment, DisclosureReason, Holders};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const GATE: bool = false;
/// A record this much older than its file's effective birth was copied in.
/// Copies written within it are counted (known residual, disclosed nowhere).
pub(in crate::snapshots) const SLACK: i128 = 2_000_000_000;
const HOUR_NANOS: i128 = 3_600_000_000_000;
/// Same bound the P1 holder walk used. A census walk that hits it cannot
/// decide: the affected sessions or families are held, never counted.
const SIDE_CALL_DEADLINE: Duration = Duration::from_millis(250);

pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    {
        if ENABLED.with(std::cell::Cell::get) {
            return true;
        }
    }
    GATE
}
#[cfg(test)]
thread_local! { static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
#[cfg(test)]
pub(crate) fn with_enabled<T>(f: impl FnOnce() -> T) -> T {
    struct Reset(bool);
    impl Drop for Reset {
        fn drop(&mut self) {
            ENABLED.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(ENABLED.with(|v| v.replace(true)));
    f()
}

// Per-stage wall clock for the F3 perf receipt. Test builds only: the
// daemon build has no timer here, `timed` is just the call.
#[cfg(test)]
thread_local! {
    static STAGES: RefCell<BTreeMap<&'static str, Duration>> = const { RefCell::new(BTreeMap::new()) };
}
#[cfg(test)]
pub(crate) fn take_stages() -> BTreeMap<&'static str, Duration> {
    STAGES.with(|stages| std::mem::take(&mut *stages.borrow_mut()))
}
#[inline(always)]
pub(in crate::snapshots) fn timed<T>(stage: &'static str, f: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    let start = Instant::now();
    let value = f();
    #[cfg(test)]
    STAGES.with(|stages| *stages.borrow_mut().entry(stage).or_default() += start.elapsed());
    #[cfg(not(test))]
    let _ = stage;
    value
}

// Why folds disclosed and why sessions were held, per reason, for the bench
// receipt. Test builds only: the daemon build keeps the totals only.
#[cfg(test)]
thread_local! {
    static DIAG: RefCell<BTreeMap<&'static str, u64>> = const { RefCell::new(BTreeMap::new()) };
}
#[cfg(test)]
pub(crate) fn take_diag() -> BTreeMap<&'static str, u64> {
    DIAG.with(|diag| std::mem::take(&mut *diag.borrow_mut()))
}
#[inline(always)]
fn diag(reason: &'static str, n: u64) {
    #[cfg(test)]
    if n > 0 {
        DIAG.with(|diag| *diag.borrow_mut().entry(reason).or_default() += n);
    }
    #[cfg(not(test))]
    let _ = (reason, n);
}
/// The largest `value` seen under `key` since the last take (test builds).
#[inline(always)]
fn diag_max(key: &'static str, value: u64) {
    #[cfg(test)]
    DIAG.with(|diag| {
        let mut diag = diag.borrow_mut();
        let max = diag.entry(key).or_default();
        *max = (*max).max(value);
    });
    #[cfg(not(test))]
    let _ = (key, value);
}

/// Benchmark seam (snapshot_sync money_e2_bench_tests). Test builds only.
#[cfg(test)]
pub(crate) mod bench_seam {
    /// Run `run` with the E2 upload gate forced on (`true`) or at its
    /// shipped default (`false`, dark) for every page `run` drives on this
    /// thread (the benchmark is single-threaded).
    pub(crate) fn with_gate<T>(on: bool, run: impl FnOnce() -> T) -> T {
        if on {
            super::with_enabled(run)
        } else {
            assert!(!super::enabled(), "dark means the shipped gate is off");
            run()
        }
    }
    /// E2 counter deltas not yet written to a native_collection_page line,
    /// then zeroed: the same nonzero-only keys as that line.
    pub(crate) fn drain_counts() -> serde_json::Value {
        serde_json::to_value(super::take_counts()).expect("E2 counts serialize")
    }
    /// Per-stage wall clock (µs) since the last take, then zeroed.
    pub(crate) fn take_stages() -> serde_json::Value {
        super::take_stages()
            .into_iter()
            .map(|(stage, spent)| {
                (
                    stage.to_owned(),
                    serde_json::json!(spent.as_micros() as u64),
                )
            })
            .collect::<serde_json::Map<_, _>>()
            .into()
    }
    /// Disclosures and holds by reason since the last take, then zeroed.
    pub(crate) fn take_diag() -> serde_json::Value {
        serde_json::to_value(super::take_diag()).expect("E2 diag serializes")
    }
    /// Run `run` with synthetic root births (local index key -> unix
    /// nanos) standing in for creation time, which Linux cannot set.
    pub(crate) fn with_staged_births<T>(
        births: std::collections::BTreeMap<String, u64>,
        run: impl FnOnce() -> T,
    ) -> T {
        crate::snapshots::claude_history_upgrade::with_staged_births_for_test(births, run)
    }
}

/// The parse-time view of the durable birth table (T1's `BirthStore`).
pub(in crate::snapshots) struct ReadContext<'a> {
    pub(in crate::snapshots) index: &'a ScanIndex,
    pub(in crate::snapshots) path: &'a Path,
    /// The page's path-twin groups: the one twin rule, built once per page.
    pub(in crate::snapshots) twins: &'a std::cell::OnceCell<ClaudeTwinGroups>,
}
impl ReadContext<'_> {
    /// Current membership plus this page's metadata generation probe.
    /// No filesystem lookup here: T4's twin walk already paid for it.
    fn live(&self, member: &str, location: LocationKey) -> bool {
        self.index.claude_money_birth_store.witnessed(location) && self.indexed(member, location)
    }
    /// An indexed path, or one this traversal observed that is not indexed
    /// yet (a first-seen twin or a new copy still to be read on this page).
    fn indexed(&self, member: &str, location: LocationKey) -> bool {
        self.twin_key(member, location).is_some()
    }
    /// The key of `member`'s path twin at `location`. A member with a single
    /// path has no twin group: no OTHER location of it is indexed.
    fn twin_key(&self, member: &str, location: LocationKey) -> Option<&str> {
        self.twins
            .get_or_init(|| {
                let own = session_member(self.path).map(std::borrow::Cow::into_owned);
                claude_path_twin_groups(self.index, &own.into_iter().collect())
            })
            .get(member)?
            .iter()
            .map(|(key, _)| key.as_str())
            .find(|key| location_key(key) == location)
    }
}

/// Same member spelling as T4's twin index, including subagent stems.
fn session_member(path: &Path) -> Option<std::borrow::Cow<'_, str>> {
    let member = claude_index_path_member_ref(path)?;
    Some(match member.subagent_stem {
        Some(_) => std::borrow::Cow::Owned(member.into_owned().1),
        None => std::borrow::Cow::Borrowed(member.root),
    })
}

/// How this path stands in its session's birth table at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The session's live location (or its first sight): inherits the
    /// session's effective cutoff across earlier proven moves.
    Owner,
    /// Another live path holds the session: own observed birth only.
    Twin,
    /// The recorded owner path is gone: this read proves a move from it.
    Moved(LocationKey),
}
impl crate::heap_layout_bound::HeapLayoutBound for Role {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}
/// This root file's own location key (inline digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Located(LocationKey);
impl crate::heap_layout_bound::HeapLayoutBound for Located {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// The proof a held copy skip needs; `decide_page_copies` checks it per
/// request once per page.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyProof {
    /// The earliest live same-session path twin (its index key).
    Twin(String),
    /// Earlier MAIN files of other sessions (/branch of an all-pre-birth file).
    Holders,
}
impl crate::heap_layout_bound::HeapLayoutBound for CopyProof {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Twin(key) => key.heap_bound(c),
            Self::Holders => c.add(0),
        }
    }
}

/// After parse: record the opened physical birth (never the inherited
/// cutoff) and, on a proven move, transfer the session's live location.
pub(in crate::snapshots) fn remember_birth(index: &mut ScanIndex, path: &Path, fold: &FileFold) {
    let (Some(physical), Some(member)) = (fold.physical, session_member(path)) else {
        return;
    };
    let key = local_index_key(path);
    let store = &mut index.claude_money_birth_store;
    store.record_opened(&member, &key, physical, fold.money_birth.opened());
    if let Role::Moved(from) = fold.role {
        store.record_proven_move(&member, from, &key);
    }
}

/// Pure accumulation consumed by the #699 literal emitter. No census, claims,
/// custody, maturity or alternate response classifier participates here.
#[derive(Debug, Clone)]
pub(crate) struct ClaudeEntityBody {
    pub(crate) grains: BTreeMap<
        (
            ClaudeLiveKey,
            Option<ClaudeRequestUsageOrigin>,
            AccountPartition,
        ),
        ClaudeGrainSide,
    >,
    pub(crate) bucket_activity: BTreeMap<String, (i128, i128)>,
    pub(crate) removed: ClaudeMoneyTokens,
    pub(crate) removed_requests: u64,
    /// False unless finish_page proves every counted request matched or a
    /// side call under a complete telemetry read.
    pub(crate) telemetry_owned_complete: bool,
    pub(crate) resolver_conflicts: u64,
    pub(crate) held: bool,
    pub(crate) certificate_ok: bool,
    pub(crate) activity_unix: u64,
    pub(crate) activity_nanos: i128,
    /// Gate off: what the trial receipt and the counters read, in place of
    /// `grains` (which then stays empty).
    pub(super) dark: DarkTally,
}
impl Default for ClaudeEntityBody {
    fn default() -> Self {
        Self {
            grains: BTreeMap::new(),
            bucket_activity: BTreeMap::new(),
            removed: Default::default(),
            removed_requests: 0,
            telemetry_owned_complete: false,
            resolver_conflicts: 0,
            held: false,
            certificate_ok: true,
            activity_unix: 0,
            activity_nanos: 0,
            dark: DarkTally::default(),
        }
    }
}
impl ClaudeEntityBody {
    #[allow(clippy::too_many_arguments)]
    fn add(
        &mut self,
        key: ClaudeLiveKey,
        tokens: &ClaudeMoneyTokens,
        requests: u64,
        cost: Option<u64>,
        origin: Option<ClaudeRequestUsageOrigin>,
        at: Option<i128>,
        account: AccountPartition,
    ) {
        if !enabled() {
            let hour = origin.is_none().then(|| bucket_hour(&key.0)).flatten();
            self.dark.add(hour, tokens, requests, cost);
            return;
        }
        if let Some(at) = at {
            self.note_activity(&key.0, at, at);
        }
        self.grains
            .entry((key, origin, account))
            .or_default()
            .add(tokens, requests, cost);
    }
    fn note_activity(&mut self, bucket: &str, first: i128, last: i128) {
        match self.bucket_activity.get_mut(bucket) {
            Some(bounds) => {
                bounds.0 = bounds.0.min(first);
                bounds.1 = bounds.1.max(last);
            }
            None => {
                self.bucket_activity
                    .insert(bucket.to_owned(), (first, last));
            }
        }
        self.activity_nanos = self.activity_nanos.max(last);
    }
    /// Identity can collapse an undecidable session without changing money.
    pub(crate) fn repartition(&mut self, account: AccountPartition) {
        self.map_accounts(|_| account.clone());
    }
    /// Resolve provisional Unknown shares without rewriting any own org run.
    pub(crate) fn inherit_missing(&mut self, account: AccountPartition) {
        if account.is_some() && self.grains.keys().any(|(_, _, key)| key.is_none()) {
            self.map_accounts(|key| key.or_else(|| account.clone()));
        }
    }
    fn map_accounts(&mut self, mut place: impl FnMut(AccountPartition) -> AccountPartition) {
        let grains = std::mem::take(&mut self.grains);
        for ((key, origin, account), grain) in grains {
            Self::merge_grain(
                self.grains
                    .entry((key, origin, place(account)))
                    .or_default(),
                &grain,
            );
        }
    }
    fn merge_grain(into: &mut ClaudeGrainSide, grain: &ClaudeGrainSide) {
        into.tokens.add(&grain.tokens);
        into.requests = into.requests.saturating_add(grain.requests);
        into.cost_micros = into.cost_micros.saturating_add(grain.cost_micros);
        into.unpriced = into.unpriced.saturating_add(grain.unpriced);
        into.contributions = into.contributions.saturating_add(grain.contributions);
    }

    /// Grains and their activity only (a held copy moving back to counted).
    fn absorb_grains(&mut self, other: &Self) {
        for (key, grain) in &other.grains {
            let into = self.grains.entry(key.clone()).or_default();
            Self::merge_grain(into, grain);
        }
        for (bucket, (first, last)) in &other.bucket_activity {
            self.note_activity(bucket, *first, *last);
        }
        self.dark.absorb(&other.dark);
    }
    /// Path twins of one session sum into the one emitted entity.
    fn sum(&mut self, other: &Self) {
        self.absorb_grains(other);
        self.removed.add(&other.removed);
        self.removed_requests = self.removed_requests.saturating_add(other.removed_requests);
        self.resolver_conflicts = self
            .resolver_conflicts
            .saturating_add(other.resolver_conflicts);
        self.held |= other.held;
        self.certificate_ok &= other.certificate_ok;
        self.activity_unix = self.activity_unix.max(other.activity_unix);
        self.activity_nanos = self.activity_nanos.max(other.activity_nanos);
    }
    fn totals(&self) -> (ClaudeMoneyTokens, u64) {
        let mut tokens = self.dark.side.tokens;
        let mut requests = self.dark.side.requests;
        for grain in self.grains.values() {
            tokens.add(&grain.tokens);
            requests = requests.saturating_add(grain.requests);
        }
        (tokens, requests)
    }
    /// Transcript requests still on their estimated (token-priced) grain.
    fn estimated_requests(&self) -> u64 {
        self.grains
            .iter()
            .filter(|((_, origin, _), _)| origin.is_none())
            .map(|(_, grain)| grain.requests)
            .sum::<u64>()
            + self.dark.estimated_in(0, u32::MAX)
    }
    /// Responses folded in (grains and the dark tally).
    fn contributions(&self) -> u64 {
        self.grains
            .values()
            .map(|grain| grain.contributions)
            .sum::<u64>()
            + self.dark.side.contributions
    }
    /// Take one estimated request back from `slot` (its usage moves to a
    /// reported grain next). False when the slot cannot give it back.
    fn take_estimated(
        &mut self,
        slot: &(
            ClaudeLiveKey,
            Option<ClaudeRequestUsageOrigin>,
            AccountPartition,
        ),
        tokens: &ClaudeMoneyTokens,
        requests: u64,
    ) -> bool {
        let Some(grain) = self.grains.get_mut(slot) else {
            return bucket_hour(&slot.0 .0)
                .is_some_and(|hour| self.dark.take(hour, tokens, requests));
        };
        let (Some(left), Some(left_requests)) = (
            grain.tokens.checked_sub(tokens),
            grain.requests.checked_sub(requests),
        ) else {
            return false;
        };
        grain.tokens = left;
        grain.requests = left_requests;
        grain.contributions = grain.contributions.saturating_sub(1);
        grain.unpriced = grain.unpriced.saturating_sub(1);
        if grain.contributions == 0 {
            self.grains.remove(slot);
        }
        true
    }
}

/// Gate off (dark): no per-hour grain map. The trial receipt reads the
/// totals; `unmatched_1h` reads the estimated requests per unix hour that
/// telemetry attach has not moved. 8 bytes per hour with estimated usage.
#[derive(Debug, Clone, Default)]
pub(super) struct DarkTally {
    side: ClaudeGrainSide,
    /// (unix hour, estimated requests), sorted by hour.
    estimated: Vec<(u32, u32)>,
}
crate::heap_layout_bound::fields!(DarkTally; side, estimated);
impl DarkTally {
    fn add(
        &mut self,
        hour: Option<u32>,
        tokens: &ClaudeMoneyTokens,
        requests: u64,
        cost: Option<u64>,
    ) {
        self.side.add(tokens, requests, cost);
        if let Some(hour) = hour {
            self.bump(hour, requests);
        }
    }
    fn bump(&mut self, hour: u32, requests: u64) {
        let requests = u32::try_from(requests).unwrap_or(u32::MAX);
        // Responses arrive in transcript order: almost always the last hour.
        match self.estimated.last_mut() {
            Some((last, count)) if *last == hour => *count = count.saturating_add(requests),
            Some((last, _)) if *last > hour => {
                match self.estimated.binary_search_by_key(&hour, |(at, _)| *at) {
                    Ok(at) => {
                        let count = &mut self.estimated[at].1;
                        *count = count.saturating_add(requests);
                    }
                    Err(at) => self.estimated.insert(at, (hour, requests)),
                }
            }
            _ => self.estimated.push((hour, requests)),
        }
    }
    fn take(&mut self, hour: u32, tokens: &ClaudeMoneyTokens, requests: u64) -> bool {
        let Ok(at) = self.estimated.binary_search_by_key(&hour, |(at, _)| *at) else {
            return false;
        };
        let (Some(count), Some(left), Some(left_requests)) = (
            u32::try_from(requests)
                .ok()
                .and_then(|requests| self.estimated[at].1.checked_sub(requests)),
            self.side.tokens.checked_sub(tokens),
            self.side.requests.checked_sub(requests),
        ) else {
            return false;
        };
        if count == 0 {
            self.estimated.remove(at);
        } else {
            self.estimated[at].1 = count;
        }
        self.side.tokens = left;
        self.side.requests = left_requests;
        self.side.contributions = self.side.contributions.saturating_sub(1);
        self.side.unpriced = self.side.unpriced.saturating_sub(1);
        true
    }
    fn absorb(&mut self, other: &Self) {
        ClaudeEntityBody::merge_grain(&mut self.side, &other.side);
        for &(hour, requests) in &other.estimated {
            self.bump(hour, u64::from(requests));
        }
    }
    /// Estimated requests in hours `[from, to)`.
    fn estimated_in(&self, from: u32, to: u32) -> u64 {
        self.estimated
            .iter()
            .filter(|(hour, _)| (from..to).contains(hour))
            .map(|(_, requests)| u64::from(*requests))
            .sum()
    }
    fn shrink(&mut self) {
        self.estimated.shrink_to_fit();
    }
}

/// The unix hour of a normalized bucket start (`activity_bucket_from_timestamp`).
fn bucket_hour(bucket: &str) -> Option<u32> {
    u32::try_from(rfc3339_unix_nanos(bucket)?.div_euclid(HOUR_NANOS)).ok()
}

/// The gate-off grain key: the hour bucket only. Dark keeps no grain map, so
/// it never builds a placement for a key it would not keep.
fn hour_key(timestamp: &str) -> Option<ClaudeLiveKey> {
    let (bucket, _) = super::super::activity_bucket_from_timestamp(timestamp)?;
    Some((bucket, String::new(), BTreeMap::new()))
}
crate::heap_layout_bound::fields!(ClaudeEntityBody; grains, bucket_activity, removed, removed_requests, telemetry_owned_complete, resolver_conflicts, held, certificate_ok, activity_unix, activity_nanos, dark);
// Existing grain types were inline P1 values; E retains only the aggregate.
crate::heap_layout_bound::fields!(ClaudeGrainSide; tokens, requests, cost_micros, unpriced, contributions);
impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestUsageOrigin {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

/// What this page's telemetry read did for one fold.
#[derive(Debug, Clone, Default)]
struct FoldTelemetry {
    /// attach ran with a reader witness for this fold's family.
    read: bool,
    /// Reader health complete and no row disclosed by the join.
    complete: bool,
    /// Hour bucket of the family's first API row: older usage is outside
    /// what telemetry could report, so it is not "unmatched".
    start_bucket: Option<String>,
    /// Rows the join left unheld on this page (side-call candidates).
    side_candidates: u64,
    /// The side-call pass finished for this family (or had nothing to do).
    side_calls_done: bool,
    /// One family view on its first fold only. Hashes accelerate exact request
    /// lookups; collisions are checked against the existing request sets.
    membership: FamilyMembership,
}
crate::heap_layout_bound::fields!(FoldTelemetry; read, complete, start_bucket, side_candidates, side_calls_done, membership);

/// Elapsed work is diagnostic, never part of native scan identity or parity.
/// Keep Debug deterministic while retaining the measured value for receipts.
#[derive(Clone, Default)]
struct FoldNanos(u64);
impl std::fmt::Debug for FoldNanos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FoldNanos")
    }
}
impl crate::heap_layout_bound::HeapLayoutBound for FoldNanos {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileFold {
    pub(crate) entity: ClaudeEntityBody,
    /// Copy rule with the EFFECTIVE cutoff (inherited across proven moves).
    money_birth: ClaudeFileBirth,
    /// The opened file's own physical birth; the only birth ever recorded.
    physical: Option<i128>,
    role: Role,
    location: Option<Located>,
    base_selector: SelectorCapture,
    bucket_fallback: Option<String>,
    /// Model-less responses: the running native model fallback at their turn,
    /// so attach rebuilds exactly the key observe used. Rare, so sparse.
    model_fallbacks: BTreeMap<u64, String>,
    /// Held pre-birth responses, as half-open sequence ranges.
    skipped: Vec<(u64, u64)>,
    /// Pre-birth grains held until finish_native confirms the skip.
    copy: ClaudeEntityBody,
    /// Held copies without a request id: no census can prove them, so a
    /// proof-checked skip counts them after all. Rare, so boxed.
    idless_copy: Option<Box<ClaudeEntityBody>>,
    /// The proof `decide_page_copies` checks per request before the page
    /// treats the held copies as removed.
    proof: Option<CopyProof>,
    /// Counted requests inheriting a possibly excluded marker. Sparse and
    /// bounded by the existing 64 marker runs, never by response count.
    /// Boxed: one pointer on every fold, the map only when present.
    #[allow(clippy::box_collection)]
    prefix_inherited: Option<Box<BTreeMap<u64, ClaudeEntityBody>>>,
    copied: u64,
    first_own: Option<u64>,
    /// Request hashes two responses of this file claim; filled on demand.
    ambiguous: BTreeSet<u64>,
    disclosed: u64,
    /// Wall time in this fold's E2-added work only (`fold_us`, see `spend`).
    e2_nanos: FoldNanos,
    responses: u64,
    root_fallbacks: u64,
    side: ClaudeMoneyTokens,
    pub(crate) side_requests: u64,
    telemetry: FoldTelemetry,
    pub(crate) accounts: Option<Box<RequestAccounts>>,
}
crate::heap_layout_bound::fields!(FileFold; entity, money_birth, physical, role, location, base_selector, bucket_fallback, model_fallbacks, skipped, copy, idless_copy, proof, prefix_inherited, copied, first_own, ambiguous, disclosed, e2_nanos, responses, root_fallbacks, side, side_requests, telemetry, accounts);
impl FileFold {
    pub(in crate::snapshots) fn new(
        birth: ClaudeFileBirth,
        context: Option<&ReadContext<'_>>,
        base_selector: SelectorCapture,
        bucket_fallback: Option<String>,
    ) -> Self {
        let started = Instant::now();
        let physical = birth.physical_birth_nanos();
        let mut role = Role::Owner;
        let mut cutoff = None;
        let mut location = None;
        if let (Some(context), Some(_)) = (context, physical) {
            if let Some(member) = session_member(context.path) {
                let key = local_index_key(context.path);
                let here = location_key(&key);
                location = Some(Located(here));
                let store = &context.index.claude_money_birth_store;
                let observed = store.observed_birth(&member, &key);
                cutoff = match store.live_location(&member) {
                    None => observed,
                    Some(live) if live == here => store.effective_cutoff(&member, &key),
                    Some(live) if context.indexed(&member, live) => {
                        role = Role::Twin;
                        observed
                    }
                    Some(live) => {
                        role = Role::Moved(live);
                        let session = store.session_effective_cutoff(&member);
                        match (session, observed) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (a, b) => a.or(b),
                        }
                    }
                };
            }
        }
        // A lone subagent keeps the context birth exemption. A later same-member
        // path twin uses the normal money cutoff; finish_native still requires
        // the earlier object's current identity/extent to validate the skip.
        let subagent_twin = context.is_some_and(|context| {
            claude_index_path_member_ref(context.path).is_some_and(|m| m.subagent_stem.is_some())
                && physical.is_some_and(|physical| {
                    let member = session_member(context.path).unwrap();
                    let here = location_key(&local_index_key(context.path));
                    context
                        .index
                        .claude_money_birth_store
                        .observations(&member)
                        .any(|(location, observed)| {
                            // The roots' total order: of two equal-birth
                            // twins exactly one is the earlier.
                            location != here
                                && (observed, location) < (physical, here)
                                && context.indexed(&member, location)
                        })
                })
        });
        let money_birth = if subagent_twin {
            birth.with_money_birth(physical)
        } else {
            birth
        };
        let mut fold = Self {
            entity: Default::default(),
            money_birth: money_birth.with_minimum(cutoff),
            physical,
            role,
            location,
            base_selector,
            bucket_fallback,
            model_fallbacks: BTreeMap::new(),
            skipped: Vec::new(),
            copy: Default::default(),
            idless_copy: None,
            proof: None,
            prefix_inherited: None,
            copied: 0,
            first_own: None,
            ambiguous: BTreeSet::new(),
            disclosed: 0,
            e2_nanos: FoldNanos::default(),
            responses: 0,
            root_fallbacks: 0,
            side: Default::default(),
            side_requests: 0,
            telemetry: Default::default(),
            accounts: None,
        };
        fold.spend(started);
        fold
    }

    /// `fold_us` (owner definition, P2) counts ONLY the work E2 adds: this
    /// fold's new/set_identity, observe per response and finish_native, plus
    /// the page passes (`PageSpent`). The native parse, resolve, placement
    /// and row add it shares are never in it; total page CPU against the
    /// pre-E2 reference is the cost gate for those.
    fn spend(&mut self, started: Instant) {
        self.e2_nanos.0 = self
            .e2_nanos
            .0
            .saturating_add(u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX));
    }

    /// Native-finalizer input seam: identity policy stays with its owner.
    pub(in crate::snapshots) fn set_identity(
        &mut self,
        markers: Option<&claude_request_identity::OrgMarkers>,
        bound: Option<&str>,
        session: Option<&str>,
        context: Option<&ReadContext<'_>>,
        first_sequence: Option<u64>,
    ) {
        if !enabled() {
            return;
        }
        let started = Instant::now();
        let subagent = context
            .and_then(|c| claude_index_path_member_ref(c.path))
            .is_some_and(|member| member.subagent_stem.is_some())
            || session.is_some_and(|session| session.contains("_agent-"));
        self.accounts = Some(Box::new(claude_request_identity::request_accounts(
            markers,
            bound,
            first_sequence,
            subagent,
            &[],
        )));
        self.spend(started);
    }

    /// The effective cutoff (copy rule), for tests.
    #[cfg(test)]
    pub(crate) fn birth(&self) -> Option<i128> {
        self.money_birth.birth_nanos()
    }

    /// Counted and disclosed, once per decision. `reason` names it in test
    /// receipts only.
    fn disclose(&mut self, reason: &'static str, responses: u64) {
        self.disclosed += responses;
        diag(reason, responses);
    }

    /// The native resolver dropped one of two incompatible records.
    pub(in crate::snapshots) fn note_resolver_conflict(&mut self) {
        self.entity.resolver_conflicts = self.entity.resolver_conflicts.saturating_add(1);
    }

    /// Two responses claim `request_id`: its telemetry can never attach.
    pub(in crate::snapshots) fn note_ambiguous(&mut self, request_id: &str) {
        self.ambiguous
            .insert(super::super::claude_request_census::claude_request_hash(
                request_id,
            ));
    }

    fn is_ambiguous(&self, request_id: &str) -> bool {
        !self.ambiguous.is_empty()
            && self
                .ambiguous
                .contains(&super::super::claude_request_census::claude_request_hash(
                    request_id,
                ))
    }

    pub(crate) fn is_skipped(&self, sequence: u64) -> bool {
        let at = self.skipped.partition_point(|(_, end)| *end <= sequence);
        self.skipped
            .get(at)
            .is_some_and(|(start, _)| *start <= sequence)
    }

    /// `placed` is the native finalizer's own placement of this response
    /// (None: zero usage, no native row), so the grain key equals the native
    /// row's without placing twice.
    pub(in crate::snapshots) fn observe(
        &mut self,
        sequence: u64,
        has_request_id: bool,
        usage: &UsageTotals,
        at: Option<i128>,
        placed: Option<&PlacedClaudeUsage>,
        effort: Option<&str>,
    ) {
        let started = Instant::now();
        self.observe_response(sequence, has_request_id, usage, at, placed, effort);
        self.spend(started);
    }

    fn observe_response(
        &mut self,
        sequence: u64,
        has_request_id: bool,
        usage: &UsageTotals,
        at: Option<i128>,
        placed: Option<&PlacedClaudeUsage>,
        effort: Option<&str>,
    ) {
        self.responses += 1;
        let copied = self.money_birth.copied_with_slack(at, SLACK);
        if copied == Some(false) {
            self.first_own.get_or_insert(sequence);
        }
        let Some(placed) = placed else {
            return;
        };
        let live = enabled();
        if placed.fell_back && live {
            self.model_fallbacks.insert(sequence, placed.model.clone());
        }
        let Some(key) = placed.placement.as_ref().map(|placement| {
            if !live {
                return (placement.bucket.clone(), String::new(), BTreeMap::new());
            }
            live_key(
                &placed.model,
                placement.bucket.clone(),
                placement.reduced_context.clone(),
                &placement.row_key,
                effort,
            )
        }) else {
            // Native drops it as unplaceable usage; never publish over it.
            self.entity.certificate_ok = false;
            self.disclose("unplaceable", 1);
            return;
        };
        let account = self.accounts.as_mut().and_then(|accounts| {
            accounts.observe(sequence, copied == Some(true));
            accounts.account(sequence)
        });
        let tokens = ClaudeMoneyTokens::from_usage(usage);
        let requests = usage.request_count;
        if copied == Some(true) {
            self.copied += 1;
            self.entity.removed.add(&tokens);
            self.entity.removed_requests += requests;
            if !has_request_id {
                self.idless_copy
                    .get_or_insert_with(Box::default)
                    .add(key, &tokens, requests, None, None, at, account);
                return;
            }
            match self.skipped.last_mut() {
                Some((_, end)) if *end == sequence => *end += 1,
                _ => self.skipped.push((sequence, sequence + 1)),
            }
            self.copy
                .add(key, &tokens, requests, None, None, at, account);
            return;
        }
        if copied.is_none() && self.money_birth.birth_nanos().is_some() {
            self.disclose("untimed_record", 1); // counted, birth unproven
        }
        // Keep the original placement while copy ownership is undecided.
        // Only requests inheriting a held marker need a temporary aggregate.
        let prefix = self
            .accounts
            .as_deref()
            .and_then(|accounts| accounts.copied_marker_position(sequence));
        let into = match prefix {
            Some(position) => self
                .prefix_inherited
                .get_or_insert_with(Box::default)
                .entry(position)
                .or_default(),
            None => &mut self.entity,
        };
        into.add(key, &tokens, requests, None, None, at, account);
    }

    /// Confirm, or undo, the held pre-birth skip. A partial copy (own lines
    /// after birth) is skipped on timestamps with a writer certificate from
    /// those own lines. Every other skip needs a PROOF that
    /// `decide_page_copies` checks per request on the page: a same-session
    /// earlier path twin (stored birth, total (birth, location) order, a
    /// certified writer) or, for an all-pre-birth MAIN file, earlier main
    /// files of other sessions (/branch; the request ids are the proof, no
    /// writer certificate). Without one the copies count and are disclosed.
    pub(in crate::snapshots) fn finish_native(
        &mut self,
        context: Option<&ReadContext<'_>>,
        markers: Option<&claude_request_identity::OrgMarkers>,
    ) {
        let started = Instant::now();
        self.decide_native(context, markers);
        // The fold lives until the page finishes: keep no parse-time slack.
        self.entity.dark.shrink();
        self.skipped.shrink_to_fit();
        self.spend(started);
    }

    fn decide_native(
        &mut self,
        context: Option<&ReadContext<'_>>,
        markers: Option<&claude_request_identity::OrgMarkers>,
    ) {
        if self.money_birth.uncertain_root() {
            self.disclose("uncertain_birth", self.responses); // counted, disclosed
        }
        if self.copied == 0 {
            self.finish_identity_start(false, markers);
            return;
        }
        // The witness order is total over (effective birth, location), so of
        // two live all-pre-birth paths exactly one is skipped, whatever role
        // (an equal-birth owner can lose to its twin).
        let needs_original = self.first_own.is_none()
            || matches!(self.role, Role::Twin)
            || context.is_some_and(|context| {
                self.location.is_some_and(|Located(location)| {
                    context
                        .index
                        .claude_money_birth_store
                        .staged_location(location)
                })
            });
        let certified = self.money_birth.writer_certified(self.first_own);
        if certified && !needs_original {
            // Timestamp skip: id-less copies stay skipped with the rest.
            self.idless_copy = None;
            self.keep_copies(true, markers);
            return;
        }
        if certified {
            if let Some(witness) = self.original_witness(context) {
                self.proof = Some(CopyProof::Twin(witness));
                self.keep_copies(true, markers);
                return;
            }
        }
        if self.cross_session_candidate(context) {
            self.proof = Some(CopyProof::Holders);
            // Should the page find no holder, the restored copies keep the
            // accounts their own markers give them (QUOTA: never moved).
            self.keep_copies(false, markers);
            return;
        }
        let copy = std::mem::take(&mut self.copy);
        self.entity.absorb_grains(&copy);
        if let Some(idless) = self.idless_copy.take() {
            self.entity.absorb_grains(&idless);
        }
        if let Some(accounts) = self.accounts.as_deref_mut() {
            accounts.restore_copies();
        }
        self.entity.removed = Default::default();
        self.entity.removed_requests = 0;
        self.skipped.clear();
        self.disclose("copy_unproven", self.copied);
        self.copied = 0;
        self.finish_identity_start(false, markers);
    }

    /// Hold the copies as removed (finally, or until the page checks them).
    fn keep_copies(
        &mut self,
        prefix_excluded: bool,
        markers: Option<&claude_request_identity::OrgMarkers>,
    ) {
        self.finish_identity_start(prefix_excluded, markers);
        self.copy = Default::default();
    }

    fn finish_identity_start(
        &mut self,
        prefix_excluded: bool,
        markers: Option<&claude_request_identity::OrgMarkers>,
    ) {
        if let Some(accounts) = self.accounts.as_deref_mut() {
            accounts.finish_native(markers, prefix_excluded);
            if let Some(inherited) = self.prefix_inherited.take() {
                for (position, mut inherited) in *inherited {
                    if prefix_excluded {
                        inherited.repartition(accounts.account(position));
                    }
                    self.entity.absorb_grains(&inherited);
                }
            }
        }
    }

    /// The key of the earliest live same-session path twin, if any.
    fn original_witness(&self, context: Option<&ReadContext<'_>>) -> Option<String> {
        let (Some(context), Some(physical)) = (context, self.physical) else {
            return None;
        };
        let member = session_member(context.path)?;
        let key = local_index_key(context.path);
        let location = context.index.claude_money_birth_store.original_witness_at(
            &member,
            &key,
            physical,
            |location| context.live(&member, location),
        )?;
        context.twin_key(&member, location).map(str::to_owned)
    }

    /// Owner ruling (/branch, --fork-session): an all-pre-birth MAIN file
    /// whose copies `decide_page_copies` checks against other sessions'
    /// earlier main files, in one census walk per page.
    fn cross_session_candidate(&self, context: Option<&ReadContext<'_>>) -> bool {
        self.first_own.is_none()
            && self.physical.is_some()
            && self.location.is_some()
            && context.is_some_and(|context| {
                claude_index_path_member_ref(context.path)
                    .is_some_and(|member| member.subagent_stem.is_none())
            })
    }

    /// This fold's (effective birth, location): the total copy order.
    fn copy_order(&self) -> Option<(i128, LocationKey)> {
        let physical = self.physical?;
        let Located(here) = self.location?;
        Some((
            self.money_birth
                .birth_nanos()
                .map_or(physical, |birth| birth.min(physical)),
            here,
        ))
    }

    /// The estimated grain key `observe` gave this transcript occurrence.
    fn occurrence_key(
        &self,
        occurrence: &ClaudeTranscriptUsageOccurrence,
    ) -> Option<ClaudeLiveKey> {
        if !enabled() {
            return hour_key(
                occurrence
                    .timestamp
                    .as_deref()
                    .or(self.bucket_fallback.as_deref())?,
            );
        }
        let model = occurrence
            .model
            .as_deref()
            .or_else(|| {
                self.model_fallbacks
                    .get(&occurrence.sequence)
                    .map(String::as_str)
            })
            .unwrap_or("unknown");
        grain_key(
            model,
            &self.base_selector,
            SelectorCapture::clone(&occurrence.selector),
            occurrence.reasoning_effort.as_deref(),
            occurrence.timestamp.as_deref(),
            self.bucket_fallback.as_deref(),
        )
    }

    /// One held copy whose proof failed counts after all: from the removal
    /// back to its estimated grain, disclosed.
    fn restore_one(&mut self, occurrence: &ClaudeTranscriptUsageOccurrence) {
        let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
        let requests = occurrence.usage.request_count;
        let (Some(key), Some(removed), Some(removed_requests)) = (
            self.occurrence_key(occurrence),
            self.entity.removed.checked_sub(&tokens),
            self.entity.removed_requests.checked_sub(requests),
        ) else {
            // Cannot give it back exactly: never publish over it.
            self.entity.certificate_ok = false;
            return;
        };
        self.entity.removed = removed;
        self.entity.removed_requests = removed_requests;
        let account = self
            .accounts
            .as_ref()
            .and_then(|accounts| accounts.account(occurrence.sequence));
        let at = occurrence.timestamp.as_deref().and_then(rfc3339_unix_nanos);
        self.entity
            .add(key, &tokens, requests, None, None, at, account);
        self.unskip(occurrence.sequence);
        self.copied = self.copied.saturating_sub(1);
        self.disclose("copy_uncovered", 1);
    }

    /// Held id-less copies count: no census can prove them.
    fn restore_idless(&mut self) {
        let Some(idless) = self.idless_copy.take() else {
            return;
        };
        let (tokens, requests) = idless.totals();
        let responses = idless.contributions();
        match (
            self.entity.removed.checked_sub(&tokens),
            self.entity.removed_requests.checked_sub(requests),
        ) {
            (Some(removed), Some(removed_requests)) => {
                self.entity.removed = removed;
                self.entity.removed_requests = removed_requests;
                self.entity.absorb_grains(&idless);
                self.copied = self.copied.saturating_sub(responses);
                self.disclose("copy_idless", responses);
            }
            _ => self.entity.certificate_ok = false,
        }
    }

    fn unskip(&mut self, sequence: u64) {
        let at = self.skipped.partition_point(|(_, end)| *end <= sequence);
        let Some(&(start, end)) = self.skipped.get(at) else {
            return;
        };
        if start > sequence {
            return;
        }
        match (start < sequence, sequence + 1 < end) {
            (false, false) => {
                self.skipped.remove(at);
            }
            (true, false) => self.skipped[at].1 = sequence,
            (false, true) => self.skipped[at].0 = sequence + 1,
            (true, true) => {
                self.skipped[at].1 = sequence;
                self.skipped.insert(at + 1, (sequence + 1, end));
            }
        }
    }

    /// Unmatched counted requests in hours telemetry should have reported:
    /// older than one hour and not before the family's first API row.
    fn unmatched_1h(&self, hour_ago_bucket: &str) -> u64 {
        let Some(start) = self.telemetry.start_bucket.as_deref() else {
            return 0;
        };
        let dark = bucket_hour(start)
            .zip(bucket_hour(hour_ago_bucket))
            .map_or(0, |(from, to)| self.entity.dark.estimated_in(from, to));
        self.entity
            .grains
            .iter()
            .filter(|((key, origin, _), _)| {
                origin.is_none() && key.0.as_str() >= start && key.0.as_str() < hour_ago_bucket
            })
            .map(|(_, grain)| grain.requests)
            .sum::<u64>()
            + dark
    }

    fn telemetry_complete(&self) -> bool {
        self.telemetry.read
            && self.telemetry.complete
            && self.telemetry.side_calls_done
            && self.entity.estimated_requests() == 0
    }
}

/// The one E2 grain key: T1's native row placement plus the billing fields
/// and effort the literal emitter hoists. Estimated, matched and side-call
/// grains all go through here, so an estimated key equals the native row's.
fn grain_key(
    model: &str,
    base: &SelectorCapture,
    selector: SelectorCapture,
    effort: Option<&str>,
    timestamp: Option<&str>,
    fallback: Option<&str>,
) -> Option<ClaudeLiveKey> {
    if !enabled() {
        return hour_key(timestamp.or(fallback)?);
    }
    let placed = claude_row_placement(model, base, selector, effort, timestamp, fallback)?;
    Some(live_key(
        model,
        placed.bucket,
        placed.reduced_context,
        &placed.row_key,
        effort,
    ))
}

/// A native placement as the E2 grain key: its bucket and reduced context
/// plus the billing fields and effort the literal emitter hoists.
fn live_key(
    model: &str,
    bucket: String,
    mut context: BTreeMap<String, String>,
    row_key: &RowKey,
    effort: Option<&str>,
) -> ClaudeLiveKey {
    for (field, value) in row_key.billing_fields() {
        if let Some(value) = value {
            context.insert(field.to_owned(), value.to_owned());
        }
    }
    if let Some(effort) = effort {
        context.insert("reasoning_effort".into(), effort.into());
    }
    (bucket, model.to_owned(), context)
}

/// Matched and side-call grains keep today's reported-rebuild enrichment
/// (`reported_live_key`): OTEL speed joins the selector, an OTEL effort tier
/// fills a missing transcript effort (now kept in the context, #699 parity),
/// the transcript's model and clock win, and the API row's clock and model
/// are the fallbacks. Placed through [`grain_key`].
fn reported_key(
    row: &ClaudeLocalOtelEvidence,
    occurrence: Option<&ClaudeTranscriptUsageOccurrence>,
    base: &SelectorCapture,
) -> Option<ClaudeLiveKey> {
    let inputs = reported_inputs(&row.model, &row.speed, &row.effort, occurrence);
    grain_key(
        inputs.model,
        base,
        inputs.selector,
        inputs.effort,
        inputs.timestamp,
        Some(&row.observed_at),
    )
}

/// Family members of the page by root, as item indices.
fn page_families(items: &[SnapshotItem]) -> BTreeMap<String, Vec<usize>> {
    let mut families = BTreeMap::<String, Vec<usize>>::new();
    for (index, item) in items.iter().enumerate() {
        let root = claude_snapshot_family_root_ref(item);
        match families.get_mut(root) {
            Some(members) => members.push(index),
            None => {
                families.insert(root.to_owned(), vec![index]);
            }
        }
    }
    families
}

/// Transient acceleration only, never an ownership identity. Every hit is
/// checked against the exact request id in the existing member map/set. A
/// word-at-a-time multiply mix: entropy lands in the high bits the view keeps.
fn membership_hash(request_id: &str) -> u64 {
    const MIX: u64 = 0x517c_c1b7_2722_0a95;
    let bytes = request_id.as_bytes();
    let mut hash = bytes.len() as u64;
    let mut words = bytes.chunks_exact(8);
    for word in &mut words {
        let word = u64::from_le_bytes(word.try_into().unwrap());
        hash = (hash.rotate_left(5) ^ word).wrapping_mul(MIX);
    }
    let mut tail = [0u8; 8];
    tail[..words.remainder().len()].copy_from_slice(words.remainder());
    (hash.rotate_left(5) ^ u64::from_le_bytes(tail)).wrapping_mul(MIX)
}

/// One item's request ids: its request set, then the occurrence keys outside
/// it. Both are sorted, so one merge walk replaces a set lookup per key.
fn item_request_ids(item: &SnapshotItem) -> impl Iterator<Item = &String> {
    let mut ids = item.claude_usage_request_ids.iter().peekable();
    item.claude_usage_request_ids
        .iter()
        .chain(item.claude_usage_occurrences.keys().filter(move |key| {
            while ids.next_if(|id| id < key).is_some() {}
            ids.peek() != Some(key)
        }))
}

/// A transient member index in the low bits, a hash accelerator in the rest.
/// At 736 members this leaves 54 hash bits. Collisions only add exact lookups;
/// they never certify membership. Eight bytes per existing request, no strings.
#[derive(Debug, Clone, Default)]
struct FamilyMembership {
    entries: Vec<u64>,
    member_mask: u64,
}
crate::heap_layout_bound::fields!(FamilyMembership; entries, member_mask);

/// Attach and subtraction share this one view, consumed before candidate
/// hashes and trace owners are allocated. Indices are into the unchanged page.
fn family_membership(items: &[SnapshotItem], members: &[usize]) -> FamilyMembership {
    let count = members
        .iter()
        .map(|&index| item_request_ids(&items[index]).count())
        .sum();
    let bits = usize::BITS - items.len().saturating_sub(1).leading_zeros();
    let member_mask = u64::MAX.checked_shr(64 - bits).unwrap_or(0);
    let mut entries = Vec::with_capacity(count);
    for &index in members {
        for id in item_request_ids(&items[index]) {
            entries.push((membership_hash(id) & !member_mask) | index as u64);
        }
    }
    entries.sort_unstable();
    FamilyMembership {
        entries,
        member_mask,
    }
}

fn matching_members<'a>(
    view: &'a FamilyMembership,
    request_id: &str,
) -> impl Iterator<Item = usize> + 'a {
    let hash_mask = !view.member_mask;
    let hash = membership_hash(request_id) & hash_mask;
    let start = view.entries.partition_point(|key| key & hash_mask < hash);
    view.entries[start..]
        .iter()
        .take_while(move |&&key| key & hash_mask == hash)
        .map(|&key| (key & view.member_mask) as usize)
}

/// Same-session twins share the first holder; distinct sessions are ambiguous.
fn holders(items: &[SnapshotItem], view: &FamilyMembership, request_id: &str) -> Holders<usize> {
    let mut found = None::<usize>;
    let mut held = false;
    for index in matching_members(view, request_id) {
        let item = &items[index];
        let Some(occurrence) = item.claude_usage_occurrences.get(request_id) else {
            continue;
        };
        let Some(fold) = item.claude_money.as_deref() else {
            held = true;
            continue;
        };
        if fold.is_skipped(occurrence.sequence) {
            held = true;
            continue;
        }
        if fold.is_ambiguous(request_id) {
            return Holders::Many;
        }
        match found {
            None => found = Some(index),
            Some(first) if items[first].source_session_id == item.source_session_id => {}
            Some(_) => return Holders::Many,
        }
    }
    match found {
        Some(index) => Holders::One(index),
        None if held => Holders::HeldNotAttachable,
        None => Holders::None,
    }
}

/// The request ids of `item` whose response is held as a copy.
fn skipped_ids(item: &SnapshotItem) -> impl Iterator<Item = &String> + '_ {
    let fold = item.claude_money.as_deref();
    item.claude_usage_occurrences
        .iter()
        .filter(move |(_, occurrence)| {
            fold.is_some_and(|fold| fold.is_skipped(occurrence.sequence))
        })
        .map(|(id, _)| id)
}

/// Owner rulings (COST: never twice, never dropped). Decide every held copy
/// skip of the page once, before telemetry attach, so a copy that counts
/// after all is matched like any counted request. A request stays removed
/// only if its proof file's CURRENT revision holds that request id: that
/// file's parse on this page, else its census record bound to its index
/// entry's fingerprint. Requests no current revision holds count and are
/// disclosed. What cannot be decided yet (the proof file not read at its
/// current revision, a holder not indexed yet, the census walk deadline)
/// holds the session: delayed to a later page, never counted. All the
/// page's cross-session checks share ONE census walk. Runs in both gate
/// modes; dark only counts.
pub(crate) fn decide_page_copies(items: &mut [SnapshotItem], index: &ScanIndex) {
    let _spent = PageSpent::start("page.copies");
    let mut holders = Vec::new();
    for at in 0..items.len() {
        let Some(fold) = items[at].claude_money.as_deref_mut() else {
            continue;
        };
        // A page decides afresh (a test re-deciding a larger page included).
        fold.entity.held = false;
        let proof = fold.proof.clone();
        match proof {
            Some(CopyProof::Twin(witness)) => decide_twin(items, at, &witness, index),
            Some(CopyProof::Holders) => holders.push(at),
            None => {}
        }
    }
    if !holders.is_empty() {
        decide_holders(items, &holders, index);
    }
}

fn decide_twin(items: &mut [SnapshotItem], at: usize, witness: &str, index: &ScanIndex) {
    let location = Some(Located(location_key(witness)));
    let session = &items[at].source_session_id;
    // The witness's parse on this page is its current revision by construction.
    let on_page = items.iter().find(|item| {
        &item.source_session_id == session
            && item
                .claude_money
                .as_deref()
                .is_some_and(|fold| fold.location == location)
    });
    let uncovered = match on_page {
        Some(original) => Some(
            skipped_ids(&items[at])
                .filter(|id| !original.claude_usage_request_ids.contains(*id))
                .cloned()
                .collect::<Vec<_>>(),
        ),
        None => index
            .claude_request_census
            .get(witness)
            .filter(|record| scan_evidence(index, witness, record))
            .map(|record| {
                skipped_ids(&items[at])
                    .filter(|id| !record.holds_hash(claude_request_hash(id)))
                    .cloned()
                    .collect()
            }),
    };
    match uncovered {
        Some(uncovered) => restore_uncovered(&mut items[at], &uncovered),
        None => hold_copies(&mut items[at], "held_twin_unproven"),
    }
}

/// What `key`'s census record proves about the file now (owner rule P2:
/// holding a session withholds its UPLOAD only; its scan state stays
/// evidence). The record of the settled revision (its index entry, same
/// fingerprint) proves it; so does the record of a scan whose upload is held
/// (entry absent or not advanced), while the file is still there. Retired,
/// over-budget, twin and older-derivation records prove nothing.
fn scan_evidence(
    index: &ScanIndex,
    key: &str,
    record: &super::super::claude_request_census::ClaudeRequestCensusRecord,
) -> bool {
    record.proves_scan()
        && (index
            .files
            .get(key)
            .is_some_and(|entry| record.proves_current(&entry.source_file_fingerprint))
            || Path::new(key).is_file())
}

/// Another session's main file this traversal has not put on any page yet:
/// queued, not indexed, and without scan state. Only these can make a copy
/// wait. A scanned file, held or not, is evidence (`scan_evidence`), never a
/// reason to wait, so held sessions never wait on each other; with the queue
/// drained (traversal complete) nothing is pending and what exists decides.
fn unscanned_main_roots(index: &ScanIndex) -> BTreeSet<String> {
    index
        .traversal
        .iter()
        .flat_map(|traversal| traversal.pending_candidates.iter())
        .map(|candidate| local_index_key(&candidate.path))
        .filter(|key| {
            !index.files.contains_key(key) && index.claude_request_census.get(key).is_none()
        })
        .filter_map(|key| {
            let member = claude_index_path_member_ref(Path::new(&key))?;
            member
                .subagent_stem
                .is_none()
                .then(|| member.root.to_owned())
        })
        .collect()
}

/// One census walk for every all-pre-birth main file of the page. A holder
/// proves a request when it is another session's main file whose scan state
/// holds it (`scan_evidence`) and earlier in (effective birth, location); a
/// holder without a stored birth is probed once. Only the walk deadline and
/// an unscanned other-session main file delay a decision.
fn decide_holders(items: &mut [SnapshotItem], folds: &[usize], index: &ScanIndex) {
    struct Wanted {
        at: usize,
        session: String,
        order: (i128, LocationKey),
        hashes: Vec<u64>,
        covered: BTreeSet<u64>,
    }
    let mut wanted = folds
        .iter()
        .filter_map(|&at| {
            let item = &items[at];
            let order = item.claude_money.as_deref()?.copy_order()?;
            let mut hashes = skipped_ids(item)
                .map(|id| claude_request_hash(id))
                .collect::<Vec<_>>();
            hashes.sort_unstable();
            hashes.dedup();
            Some(Wanted {
                at,
                session: item.source_session_id.clone(),
                order,
                hashes,
                covered: BTreeSet::new(),
            })
        })
        .collect::<Vec<_>>();
    // (hash, wanted file), sorted: each holder hit finds the files that want
    // it directly, never a pass over every wanted file per holder record.
    let mut wanting = wanted
        .iter()
        .enumerate()
        .flat_map(|(at, wanted)| wanted.hashes.iter().map(move |&hash| (hash, at)))
        .collect::<Vec<_>>();
    wanting.sort_unstable();
    let mut union = wanting.iter().map(|&(hash, _)| hash).collect::<Vec<_>>();
    union.dedup();
    let store = &index.claude_money_birth_store;
    let walked = index.claude_request_census.main_transcript_holders(
        &union,
        Instant::now() + SIDE_CALL_DEADLINE,
        |key, root, record, hits| {
            // Per holder record, each at most once and only when another
            // session wants one of its ids: evidence, then (birth, location).
            let mut holder = None::<Option<(i128, LocationKey)>>;
            for &hash in hits {
                let from = wanting.partition_point(|&(wanted, _)| wanted < hash);
                for &(_, at) in wanting[from..].iter().take_while(|&&(h, _)| h == hash) {
                    let file = &mut wanted[at];
                    if file.session == root {
                        continue;
                    }
                    let holder = *holder.get_or_insert_with(|| {
                        if !scan_evidence(index, key, record) {
                            return None;
                        }
                        let birth = store.effective_cutoff(root, key).or_else(|| {
                            probe_opened_birth(key)
                                .filter(|opened| opened.birth != 0)
                                .map(|opened| i128::from(opened.birth))
                        })?;
                        Some((birth, location_key(key)))
                    });
                    if holder.is_some_and(|holder| holder < file.order) {
                        file.covered.insert(hash);
                    }
                }
            }
        },
    );
    let pending = std::cell::OnceCell::<BTreeSet<String>>::new();
    for wanted in wanted {
        let uncovered = wanted
            .hashes
            .iter()
            .copied()
            .filter(|hash| !wanted.covered.contains(hash))
            .collect::<Vec<_>>();
        if walked.is_none() {
            hold_copies(&mut items[wanted.at], "held_copy_deadline");
            continue;
        }
        if !uncovered.is_empty()
            && pending
                .get_or_init(|| unscanned_main_roots(index))
                .iter()
                .any(|root| *root != wanted.session)
        {
            hold_copies(&mut items[wanted.at], "held_copy_unscanned");
            continue;
        }
        let ids = skipped_ids(&items[wanted.at])
            .filter(|id| uncovered.binary_search(&claude_request_hash(id)).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        restore_uncovered(&mut items[wanted.at], &ids);
    }
}

/// The proof cannot be decided on this page: the session is withheld.
fn hold_copies(item: &mut SnapshotItem, reason: &'static str) {
    if let Some(fold) = item.claude_money.as_deref_mut() {
        fold.entity.held = true;
        diag(reason, 1);
    }
}

/// Decided: `uncovered` (and every id-less copy) counts, disclosed.
fn restore_uncovered(item: &mut SnapshotItem, uncovered: &[String]) {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = item
    else {
        return;
    };
    for id in uncovered {
        if fold.is_ambiguous(id) {
            // Two responses claim it: no single grain to give back.
            fold.entity.certificate_ok = false;
        } else if let Some(occurrence) = claude_usage_occurrences.get(id) {
            fold.restore_one(occurrence);
        }
    }
    fold.restore_idless();
    fold.proof = None;
    if fold.copied == 0 {
        // Every copy counts after all: their inherited-marker tally too.
        if let Some(accounts) = fold.accounts.as_deref_mut() {
            accounts.restore_copies();
        }
    }
}

/// Move one matched transcript request from its estimated grain to its
/// reported grain: priced => telemetry_matched, no cost => telemetry_unpriced
/// (server rule). Counts never change. False when the estimated grain cannot
/// give it back (then it stays estimated and is disclosed).
fn attach_one(item: &mut SnapshotItem, row: &ClaudeLocalOtelEvidence) -> bool {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = item
    else {
        return false;
    };
    let Some(occurrence) = claude_usage_occurrences.get(row.request_id.as_str()) else {
        return false;
    };
    let Some(estimated) = fold.occurrence_key(occurrence) else {
        return false;
    };
    let Some(reported) = reported_key(row, Some(occurrence), &fold.base_selector) else {
        return false;
    };
    let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
    let requests = occurrence.usage.request_count;
    let account = fold
        .accounts
        .as_ref()
        .and_then(|a| a.account(occurrence.sequence));
    let slot = (estimated, None, account.clone());
    if !fold.entity.take_estimated(&slot, &tokens, requests) {
        return false;
    }
    // Parse a clock only when the reported key landed in another hour.
    let at = (reported.0 != slot.0 .0)
        .then(|| rfc3339_unix_nanos(&row.observed_at))
        .flatten();
    let origin = if row.cost_usd_micros.is_some() {
        ClaudeRequestUsageOrigin::TelemetryMatched
    } else {
        ClaudeRequestUsageOrigin::TelemetryUnpriced
    };
    fold.entity.add(
        reported,
        &tokens,
        requests,
        row.cost_usd_micros,
        Some(origin),
        at,
        account,
    );
    true
}

/// Attach the page's already-decoded API rows (`ClaudeApiEvidenceRead`, the
/// live sidecar read incl. its paid preload) to transcript-counted requests
/// through the source-neutral join, once per family root. Compatibility is
/// the existing owner `claude_api_matches_transcript_occurrence` (a sidecar
/// thinking count of 0 matches). Row-driven: no per-row map is built.
pub(crate) fn attach_page(items: &mut [SnapshotItem], read: &ClaudeApiEvidenceRead) {
    let _spent = PageSpent::start("page.attach");
    let families = timed("attach.families", || page_families(items));
    let items = RefCell::new(items);
    for (root, members) in &families {
        let folds = members
            .iter()
            .copied()
            .filter(|index| items.borrow()[*index].claude_money.is_some())
            .collect::<Vec<_>>();
        let Some(&first) = folds.first() else {
            continue;
        };
        // Once per fold: a second call must never move a grain twice.
        if folds.iter().any(|index| {
            items.borrow()[*index]
                .claude_money
                .as_deref()
                .is_some_and(|fold| fold.telemetry.read)
        }) {
            continue;
        }
        // No witness for this root: telemetry stays unread (incomplete).
        let Some(report) = read.session_report(root) else {
            continue;
        };
        let start_bucket = report
            .rows
            .first()
            .and_then(|row| super::super::activity_bucket_from_timestamp(&row.observed_at))
            .map(|(bucket, _)| bucket);
        let membership = timed("attach.membership", || {
            family_membership(&items.borrow(), members)
        });
        let mut disclosed = 0u64;
        let counts = timed("attach.join", || {
            join(
                report,
                |request_id| {
                    timed("attach.holders", || {
                        holders(&items.borrow(), &membership, request_id)
                    })
                },
                |row, holder| {
                    timed("attach.compatible", || {
                        validate_claude_api_row(row, root)
                            && items.borrow()[*holder]
                                .claude_usage_occurrences
                                .get(row.request_id.as_str())
                                .is_some_and(|occurrence| {
                                    claude_api_matches_transcript_occurrence(row, occurrence)
                                })
                    })
                },
                |event| match event {
                    Attachment::Matched { row, holder } => timed("attach.attach_one", || {
                        let mut items = items.borrow_mut();
                        if !attach_one(&mut items[holder], row) {
                            disclosed += 1;
                            diag("attach_lost", 1);
                        }
                    }),
                    Attachment::Unheld(_) => {}
                    Attachment::Disclosed { reason, .. } => {
                        disclosed += 1;
                        diag(
                            match reason {
                                DisclosureReason::DuplicateReport => "attach_duplicate",
                                DisclosureReason::ManyHolders => "attach_many_holders",
                                DisclosureReason::Incompatible => "attach_incompatible",
                            },
                            1,
                        );
                    }
                },
            )
        });
        let mut items = items.borrow_mut();
        for index in folds {
            if let Some(fold) = items[index].claude_money.as_deref_mut() {
                fold.telemetry = FoldTelemetry {
                    read: true,
                    complete: counts.complete && disclosed == 0,
                    start_bucket: start_bucket.clone(),
                    side_candidates: counts.unheld as u64,
                    side_calls_done: counts.unheld == 0,
                    membership: FamilyMembership::default(),
                };
                if index == first {
                    fold.disclosed += disclosed; // per reason above
                }
            }
        }
        if counts.unheld > 0 {
            items[first]
                .claude_money
                .as_deref_mut()
                .unwrap()
                .telemetry
                .membership = membership;
        }
    }
}

/// Side calls (telemetry-only requests no family transcript holds) keep
/// today's attribution (COST): the trace-named member's body; the root only
/// when no trace row names a member (counted). One membership pass over the
/// family's rows; off-page holders come from the family-scoped census
/// lookup, skipped when there are no candidates. Runs after the per-root
/// trace read: `api`/`trace` hold only roots whose sidecars are complete.
///
/// Returns the family roots whose side calls could not be decided (the
/// census walk hit its deadline, or a trace-named member's directory is still
/// queued by the walk): the caller holds their owed history files through the
/// unhealthy-telemetry seam, so a later page publishes the exact side-call
/// money; their bodies stay telemetry-incomplete meanwhile.
pub(crate) fn side_calls_page(
    items: &mut [SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    index: &ScanIndex,
) -> BTreeSet<String> {
    let _spent = PageSpent::start("page.side_calls");
    let mut unresolved = BTreeSet::new();
    if enabled() {
        timed("side.inherit", || {
            claude_request_identity::inherit_root_accounts(items, false)
        });
    }
    let owing = |item: &SnapshotItem| {
        item.claude_money
            .as_deref()
            .is_some_and(|fold| fold.telemetry.read && !fold.telemetry.side_calls_done)
    };
    if !items.iter().any(owing) {
        return unresolved;
    }
    let families = timed("side.families", || {
        page_families(items)
            .into_iter()
            .filter(|(_, members)| members.iter().any(|index| owing(&items[*index])))
            .collect::<Vec<_>>()
    });
    let mut candidates = BTreeMap::<&str, Vec<&ClaudeLocalOtelEvidence>>::new();
    let mut wanted = BTreeMap::<&str, Vec<u64>>::new();
    let mut invalid = BTreeMap::<&str, u64>::new();
    for (root, members) in &families {
        let first = members
            .iter()
            .copied()
            .find(|&i| items[i].claude_money.is_some())
            .unwrap();
        let membership = std::mem::take(
            &mut items[first]
                .claude_money
                .as_deref_mut()
                .unwrap()
                .telemetry
                .membership,
        );
        let Some(rows) = api.evidence.get(root.as_str()) else {
            continue; // unhealthy pair: discard the view, stay undone/disclosed
        };
        let mut family = Vec::with_capacity(rows.len());
        for row in rows {
            if timed("side.subtract", || {
                matching_members(&membership, &row.request_id).any(|index| {
                    items[index]
                        .claude_usage_request_ids
                        .contains(&row.request_id)
                })
            }) {
                continue;
            }
            if !timed("side.validate", || validate_claude_api_row(row, root)) {
                *invalid.entry(root.as_str()).or_default() += 1;
                continue;
            }
            family.push(row);
        }
        drop(membership);
        let mut hashes = timed("side.hash", || {
            family
                .iter()
                .map(|row| {
                    super::super::claude_request_census::claude_request_hash(&row.request_id)
                })
                .collect::<Vec<_>>()
        });
        timed("side.sort", || {
            hashes.sort_unstable();
            hashes.dedup();
            family.sort_unstable_by(|a, b| a.request_id.cmp(&b.request_id));
        });
        wanted.insert(root.as_str(), hashes);
        candidates.insert(root.as_str(), family);
    }
    // Families with no candidate row need no census answer: no walk.
    let mut census = if wanted.values().all(Vec::is_empty) {
        Some(BTreeMap::new())
    } else {
        timed("side.census", || {
            index
                .claude_request_census
                .family_transcript_holders(&wanted, Instant::now() + SIDE_CALL_DEADLINE)
        })
    };
    drop(wanted);
    // Session ids naming a directory the walk queued but has not listed.
    let queued = std::cell::OnceCell::<BTreeSet<String>>::new();
    for (root, members) in &families {
        let first = members
            .iter()
            .copied()
            .find(|index| items[*index].claude_money.is_some());
        let rows = candidates.remove(root.as_str());
        // The census deadline: no candidate is counted (an off-page
        // transcript may hold it); the family's owed history is held so a
        // later page decides. An unhealthy pair is already held by its caller.
        if census.is_none() && rows.as_ref().is_some_and(|rows| !rows.is_empty()) {
            unresolved.insert(root.clone());
        }
        // A family without candidates is decided whatever the walk did.
        let family_census = match (first, rows.as_ref(), census.as_mut()) {
            (Some(_), Some(_), Some(census)) => {
                Some(census.remove(root.as_str()).unwrap_or_default())
            }
            (Some(_), Some(rows), None) if rows.is_empty() => Some(Default::default()),
            _ => None,
        };
        let (Some(first), Some(rows), Some(mut family_census)) = (first, rows, family_census)
        else {
            // The family stays telemetry-incomplete.
            if let Some(index) = first {
                if let Some(fold) = items[index].claude_money.as_deref_mut() {
                    let candidates = fold.telemetry.side_candidates;
                    fold.disclose("side_undecided", candidates);
                }
            }
            continue;
        };
        let mut rows = rows;
        if !family_census.held.is_empty() {
            timed("side.retain", || {
                rows.retain(|row| {
                    !family_census
                        .held
                        .contains(&claude_request_hash(&row.request_id))
                })
            });
        }
        // Held candidates never allocate a trace-owner slot. Release the census
        // intersection before the borrowed owner vector is allocated.
        family_census.held.clear();
        let owners = timed("side.trace_owners", || {
            trace_owners(root, &rows, trace.evidence.get(root.as_str()))
        });
        let targets = timed("side.targets", || {
            members
                .iter()
                .filter_map(|&index| {
                    items[index]
                        .claude_money
                        .as_ref()
                        .map(|_| (items[index].source_session_id.clone(), index))
                })
                .fold(BTreeMap::new(), |mut targets, (id, index)| {
                    targets.entry(id).or_insert(index); // first path twin, as attach
                    targets
                })
        });
        let mut disclosed = invalid.get(root.as_str()).copied().unwrap_or(0);
        diag("side_invalid", disclosed);
        // Members this traversal saw but has not indexed yet: read later.
        let unread = std::cell::OnceCell::<BTreeSet<String>>::new();
        let mut waiting = false;
        // Built once per distinct value: member ids per trace agent, and keys
        // per (model, speed, effort, hour), since a side call's placement
        // reads its clock only for the hour bucket (`claude_row_placement`).
        let mut owner_ids = BTreeMap::<&str, String>::new();
        let mut keys = BTreeMap::<(&str, &str, &str, i128), Option<ClaudeLiveKey>>::new();
        for (row, owner) in rows.iter().zip(owners) {
            let mut fallback = owner.is_none();
            let mut owner = match owner {
                Some(trace) => owner_ids
                    .entry(trace.agent_id.as_str())
                    .or_insert_with(|| claude_trace_owner_session_id(root, &trace.agent_id))
                    .as_str(),
                None => root.as_str(),
            };
            // A named member with no transcript anywhere can never count it:
            // the root does, counted as a fallback (COST Q3). A member with
            // a transcript (indexed, or seen and still to be read) counts it
            // itself when read.
            if !targets.contains_key(owner)
                && owner != root.as_str()
                && !family_census.members.contains(owner)
                && !unread
                    .get_or_init(|| unread_members(index, root))
                    .contains(owner)
            {
                // The walk has not listed the family's directory yet: the
                // member's transcript may still turn up and count it, so the
                // root counting it now would count it twice. Gate on, the root
                // was deferred at selection, so this is a backstop: wait
                // (held); once listed, a member still without a transcript
                // falls back. Dark (the reference selection) leaves the row
                // to the member, as the gate would.
                if queued
                    .get_or_init(|| queued_directory_names(index))
                    .contains(root.as_str())
                {
                    waiting = true;
                    diag("side_call_undiscovered", 1);
                    continue;
                }
                owner = root.as_str();
                fallback = true;
            }
            let Some(target) = targets.get(owner).copied() else {
                continue;
            };
            let Some((cache_5m, cache_1h, unattributed)) =
                timed("side.cache_split", || claude_api_cache_creation(row))
            else {
                disclosed += 1; // contradictory cache split
                diag("side_cache_split", 1);
                continue;
            };
            let tokens = ClaudeMoneyTokens {
                input: row.input_tokens,
                output: row.output_tokens,
                cache_read: row.cache_read_tokens,
                cache_5m,
                cache_1h,
                unattributed,
                reasoning: row.reasoning_output_tokens,
            };
            let Some(fold) = items[target].claude_money.as_deref_mut() else {
                continue;
            };
            let at = rfc3339_unix_nanos(&row.observed_at);
            let Some(key) = timed("side.reported_key", || {
                let build = || reported_key(row, None, &SelectorCapture::default());
                match at {
                    Some(at) => keys
                        .entry((
                            row.model.as_str(),
                            row.speed.as_str(),
                            row.effort.as_str(),
                            at.div_euclid(HOUR_NANOS),
                        ))
                        .or_insert_with(build)
                        .clone(),
                    None => build(),
                }
            }) else {
                disclosed += 1;
                diag("side_unplaceable", 1);
                continue;
            };
            let origin = if row.cost_usd_micros.is_some() {
                ClaudeRequestUsageOrigin::TelemetryReported
            } else {
                ClaudeRequestUsageOrigin::TelemetryUnpriced
            };
            timed("side.add", || {
                fold.entity.add(
                    key,
                    &tokens,
                    1,
                    row.cost_usd_micros,
                    Some(origin),
                    at,
                    fold.accounts.as_ref().and_then(|a| a.fallback.clone()),
                )
            });
            fold.side.add(&tokens);
            fold.side_requests += 1;
            if fallback {
                fold.root_fallbacks += 1;
            }
        }
        if waiting && enabled() {
            // The root's session is withheld (re-read on a later page, once
            // the walk lists the directory) and its owed history waits too.
            if let Some(&at) = targets.get(root.as_str()) {
                hold_copies(&mut items[at], "held_side_call_undiscovered");
            }
            unresolved.insert(root.clone());
        } else {
            for index in members {
                if let Some(fold) = items[*index].claude_money.as_deref_mut() {
                    fold.telemetry.side_calls_done = true;
                }
            }
        }
        if let Some(fold) = items[first].claude_money.as_deref_mut() {
            fold.disclosed += disclosed; // per reason above
        }
    }
    unresolved
}

/// Every path component of the directories the traversal queued but has not
/// listed. A family's member transcripts live under `<root>/subagents/`; the
/// root file being on a page means its own directory was listed, so the
/// family's directory is still to be listed exactly when `<root>` is here.
fn queued_directory_names(index: &ScanIndex) -> BTreeSet<String> {
    index
        .traversal
        .as_ref()
        .map(|traversal| directory_names(&traversal.pending_directories))
        .unwrap_or_default()
}

fn directory_names(queued: &VecDeque<ScanTraversalPath>) -> BTreeSet<String> {
    queued
        .iter()
        .flat_map(|directory| directory.path.components())
        .filter_map(|component| match component {
            std::path::Component::Normal(name) => name.to_str().map(str::to_owned),
            _ => None,
        })
        .collect()
}

/// Gate on: a root file whose family directory the walk still queues goes
/// back to the front of the queue for a later page. Its members are not
/// discovered yet, so a side call their telemetry names could only wait
/// (`side_calls_page` holds the root, and a held upload costs the sweep a
/// full re-read) or count at the root, then again at the member. Deferring
/// costs nothing: the walk lists the directory within its budgeted pages.
/// Dark keeps the reference selection.
pub(in crate::snapshots) fn defer_roots_of_queued_families(
    selected: &mut Vec<ScanTraversalPath>,
    traversal: &mut ScanTraversalCheckpoint,
) {
    if traversal.pending_directories.is_empty() {
        return;
    }
    let queued = directory_names(&traversal.pending_directories);
    let (deferred, kept): (Vec<_>, Vec<_>) =
        std::mem::take(selected).into_iter().partition(|candidate| {
            claude_index_path_member_ref(&candidate.path).is_some_and(|member| {
                member.subagent_stem.is_none() && queued.contains(member.root)
            })
        });
    *selected = kept;
    diag("deferred_root_queued_family", deferred.len() as u64);
    for candidate in deferred.into_iter().rev() {
        traversal.pending_candidates.push_front(candidate);
    }
}

/// The family members of `root` this traversal observed but has not indexed.
fn unread_members(index: &ScanIndex, root: &str) -> BTreeSet<String> {
    index
        .traversal
        .iter()
        .flat_map(|traversal| traversal.observed_index_keys.iter())
        .filter(|key| !index.files.contains_key(*key))
        .filter_map(|key| claude_index_path_member_ref(Path::new(key)))
        .filter(|member| member.root == root)
        .map(|member| member.into_owned().1)
        .collect()
}

/// The trace-named owner of each sorted candidate row (None: no trace row,
/// or an invalid one, names it). One pass over the trace rows, binary search
/// into the candidates: no map sized by rows.
fn trace_owners<'a>(
    root: &str,
    rows: &[&ClaudeLocalOtelEvidence],
    trace: Option<&'a Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
) -> Vec<Option<&'a crate::claude_local_otel::ClaudeTraceOwnershipEvidence>> {
    let mut owners = vec![None; rows.len()];
    for row in trace.into_iter().flatten() {
        let Ok(at) = rows.binary_search_by(|candidate| {
            candidate.request_id.as_str().cmp(row.request_id.as_str())
        }) else {
            continue;
        };
        if row.capture_revision == "claude_llm_request_ownership:v1"
            && row.session_id == root
            && timed("side.trace_fingerprint", || {
                claude_trace_evidence_fingerprint_is_valid(row)
            })
        {
            owners[at] = Some(row);
        }
    }
    owners
}

/// Whether this page's API sidecar read succeeded (T4 passes it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TelemetryRead {
    Loaded,
    Failed,
}

/// DARK comparison happens after today's authoritative body fold. Only the
/// explicit gate permits mutation; one summed entity is emitted per session
/// (path twins sum). A failed telemetry read never yields a "complete"
/// body; T4 keeps that page's owed history files owed.
///
/// Returns the sessions whose entity was withheld (held twin, uncertified,
/// identity already tagged, overflow). Their items stay on the page
/// unchanged so the caller holds them (`hold_request_owned`): a removed item
/// would let the page settle its file without a body. Gate off: empty.
pub(crate) fn finish_page(
    items: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    telemetry: TelemetryRead,
) -> BTreeSet<String> {
    let _spent = PageSpent::start("page.finish");
    struct Session {
        entity: ClaudeEntityBody,
        complete: bool,
        /// Native transcript totals (None: a reported rebuild replaced them).
        native: Option<(ClaudeMoneyTokens, u64)>,
        side: (ClaudeMoneyTokens, u64),
        locations: Vec<LocationKey>,
        /// Decision counters, recorded once the session is decided.
        decided: Counts,
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as i128);
    let hour_ago = time::OffsetDateTime::from_unix_timestamp_nanos(now - HOUR_NANOS)
        .ok()
        .and_then(|clock| {
            clock
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .and_then(|clock| super::super::activity_bucket_from_timestamp(&clock))
        .map(|(bucket, _)| bucket)
        .unwrap_or_default();
    if enabled() {
        claude_request_identity::inherit_root_accounts(items, true);
        claude_request_identity::record_page_identity_counts(items);
    }
    let mut sessions = BTreeMap::<&str, Session>::new();
    for item in items.iter() {
        let Some(fold) = item.claude_money.as_deref() else {
            continue;
        };
        // Work counts on every read; decisions only when decided (below).
        diag_max("max_file_fold_us", fold.e2_nanos.0 / 1_000);
        record_counts(Counts([
            fold.e2_nanos.0 / 1_000,
            fold.responses,
            0,
            0,
            0,
            0,
            0,
            0,
        ]));
        let session = sessions
            .entry(item.source_session_id.as_str())
            .or_insert_with(|| Session {
                entity: Default::default(),
                complete: telemetry == TelemetryRead::Loaded,
                native: Some(Default::default()),
                side: Default::default(),
                locations: Vec::new(),
                decided: Counts::default(),
            });
        diag("resolver_conflict", fold.entity.resolver_conflicts);
        session.decided.add(&Counts([
            0,
            0,
            fold.entity.removed_requests,
            // disclosed: everything counted without proof, resolver
            // conflicts included, once per decision.
            fold.disclosed + fold.entity.resolver_conflicts,
            fold.unmatched_1h(&hour_ago),
            fold.root_fallbacks,
            fold.entity.resolver_conflicts,
            0,
        ]));
        session.entity.sum(&fold.entity);
        session.complete &= fold.telemetry_complete();
        session.side.0.add(&fold.side);
        session.side.1 += fold.side_requests;
        session
            .locations
            .extend(fold.location.map(|located| located.0));
        match (
            &mut session.native,
            item.usage_accounting_contract.is_none(),
        ) {
            (Some((tokens, requests)), true) => {
                tokens.add(&ClaudeMoneyTokens {
                    input: item.input_tokens,
                    output: item.output_tokens,
                    cache_read: item.cache_read_tokens,
                    cache_5m: item.cache_creation_5m_tokens,
                    cache_1h: item.cache_creation_1h_tokens,
                    unattributed: item.unattributed_total_tokens,
                    reasoning: item.reasoning_output_tokens,
                });
                *requests = requests.saturating_add(item.request_count);
            }
            (native, _) => *native = None,
        }
    }
    // Trial receipt: transcript grains + removed copies == native totals.
    for session in sessions.values() {
        let Some((native, native_requests)) = &session.native else {
            continue;
        };
        let (mut explained, requests) = session.entity.totals();
        let Some(transcript) = explained.checked_sub(&session.side.0) else {
            record_counts(Counts([0, 0, 0, 0, 0, 0, 0, 1]));
            continue;
        };
        explained = transcript;
        explained.add(&session.entity.removed);
        let explained_requests = requests
            .saturating_sub(session.side.1)
            .saturating_add(session.entity.removed_requests);
        if &explained != native || explained_requests != *native_requests {
            record_counts(Counts([0, 0, 0, 0, 0, 0, 0, 1]));
        }
    }
    if !enabled() {
        // Dark: a session the gate would hold is undecided, not disclosed.
        for session in sessions.into_values() {
            record_decided(session.entity.held, session.decided);
        }
        // Nothing reads a fold after counting. Release them so the page
        // neither keeps them nor clones them with every upload attempt.
        for item in items.iter_mut() {
            item.claude_money = None;
        }
        return BTreeSet::new();
    }
    let locations = sessions
        .iter()
        .map(|(session, state)| (*session, state.locations.as_slice()))
        .collect::<Vec<_>>();
    let held = absent_twins(&locations, index);
    diag("held_absent_twin", held.len() as u64);
    drop(locations);
    let mut decided = Vec::with_capacity(sessions.len());
    let mut entities = sessions
        .into_iter()
        .map(|(session, mut state)| {
            state.entity.telemetry_owned_complete = state.complete;
            state.entity.held |= held.contains(session);
            decided.push((session.to_owned(), state.decided));
            (session.to_owned(), state.entity)
        })
        .collect::<BTreeMap<_, _>>();
    let mut withheld = BTreeSet::new();
    items.retain_mut(|item| {
        if item.claude_money.is_none() {
            return true;
        }
        // One body per session: the first item carries the summed entity.
        // A withheld session keeps every item (twins too) for the hold.
        let Some(entity) = entities.remove(&item.source_session_id) else {
            return withheld.contains(&item.source_session_id);
        };
        // apply refuses before mutating, so a withheld item is unchanged.
        if !super::emit::apply(item, &entity) {
            withheld.insert(item.source_session_id.clone());
        } else if let Some(fold) = item.claude_money.as_deref_mut() {
            // Keep the final summed placement for contract 5, not the first twin.
            fold.entity = entity;
        }
        true
    });
    diag("withheld_sessions", withheld.len() as u64);
    // A withheld session is read again: its decisions count on that page.
    for (session, counts) in decided {
        record_decided(withheld.contains(&session), counts);
    }
    withheld
}

/// Each decision counts once: a held (undecided) session records nothing
/// here; the page that decides it does.
fn record_decided(held: bool, counts: Counts) {
    if held {
        diag("undecided_sessions", 1);
    } else {
        record_counts(counts);
    }
}

/// Visit the exact final placement; account classification belongs to identity.
pub(crate) fn visit_identity_rows(
    item: &SnapshotItem,
    mut visit: impl FnMut(&str, super::super::SnapshotModelUsage, AccountPartition, Option<u64>),
) -> Option<()> {
    let fold = item.claude_money.as_deref()?;
    for ((key, origin, account), grain) in &fold.entity.grains {
        visit(
            &key.0,
            super::emit::grain_row(key, *origin, grain, None),
            account.clone(),
            grain.cost(),
        );
    }
    Some(())
}

/// Sessions (roots and subagent members) with a live indexed path that is
/// not on this page: never publish one path over complete twin history. Only
/// sessions whose birth table knows more paths than the page holds build the
/// shared twin groups (after the scan, so not the page's own copy).
fn absent_twins(sessions: &[(&str, &[LocationKey])], index: &ScanIndex) -> BTreeSet<String> {
    let store = &index.claude_money_birth_store;
    let suspects = sessions
        .iter()
        .filter(|(session, here)| {
            store
                .observations(session)
                .any(|(location, _)| !here.contains(&location))
        })
        .collect::<Vec<_>>();
    let mut held = BTreeSet::new();
    if suspects.is_empty() {
        return held;
    }
    let groups = claude_path_twin_groups(index, &BTreeSet::new());
    for (session, here) in suspects {
        let absent = path_twins(&groups, session).is_some_and(|keys| {
            keys.iter().any(|(key, size)| {
                size.is_some() && !here.contains(&location_key(key)) && Path::new(key).is_file()
            })
        });
        if absent {
            held.insert((*session).to_owned());
        }
    }
    held
}

// Existing native_collection_page carrier, nonzero only. These are shared
// process fold deltas since its previous Claude page line.
use std::sync::atomic::{AtomicU64, Ordering};
const COUNT_NAMES: [&str; 8] = [
    "fold_us",
    "responses",
    "copy_skipped",
    "disclosed",
    "unmatched_1h",
    "side_call_root_fallback",
    "resolver_conflicts",
    // Trial-only: transcript grains + removals differ from native totals.
    "dark_unexplained",
];
static COUNTS: [AtomicU64; 8] = [const { AtomicU64::new(0) }; 8];
/// A page pass's share of `fold_us` (see `FileFold::spend`), on drop.
struct PageSpent(
    Instant,
    #[cfg_attr(not(test), allow(dead_code))] &'static str,
);
impl PageSpent {
    fn start(stage: &'static str) -> Self {
        Self(Instant::now(), stage)
    }
}
impl Drop for PageSpent {
    fn drop(&mut self) {
        let elapsed = self.0.elapsed();
        let spent = u64::try_from(elapsed.as_micros()).unwrap_or(u64::MAX);
        record_counts(Counts([spent, 0, 0, 0, 0, 0, 0, 0]));
        // The bench's fold_us breakdown: per page pass, the rest is per file.
        #[cfg(test)]
        STAGES.with(|stages| *stages.borrow_mut().entry(self.1).or_default() += elapsed);
    }
}
fn record_counts(counts: Counts) {
    for (counter, value) in COUNTS.iter().zip(counts.0) {
        if value != 0 {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }
}
pub(crate) fn take_counts() -> Counts {
    Counts(COUNTS.each_ref().map(|c| c.swap(0, Ordering::Relaxed)))
}
#[derive(Debug, Default)]
pub(crate) struct Counts([u64; 8]);
impl Counts {
    fn add(&mut self, other: &Self) {
        for (sum, value) in self.0.iter_mut().zip(other.0) {
            *sum = sum.saturating_add(value);
        }
    }
}
impl Serialize for Counts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in COUNT_NAMES.into_iter().zip(self.0) {
            if value != 0 {
                map.serialize_entry(key, &value)?;
            }
        }
        map.end()
    }
}

crate::heap_layout_bound::fields!(ClaudeMoneyTokens; input, output, cache_read, cache_5m, cache_1h, unattributed, reasoning);

#[cfg(test)]
#[path = "e2_tests.rs"]
mod tests;

/// A selected path twin pulls its complete family into this existing native
/// page's forced-family path. No parser/scope/identity bump is involved.
pub(in crate::snapshots) fn selected_twin_roots<'a>(
    paths: impl Iterator<Item = &'a Path>,
    twins: &ClaudeTwinGroups,
) -> BTreeSet<String> {
    paths
        .filter_map(claude_index_path_family_member)
        .filter(|(_, member)| path_twins(twins, member).is_some())
        .map(|(root, _)| root)
        .collect()
}

#[cfg(test)]
#[path = "e2_pipeline_observer_tests.rs"]
pub(crate) mod pipeline_test_observer;
