//! E2 request-owned Claude money from the native resolved-response fold.
//! Native resolution owns counts; this module only decides copies, attaches
//! reported telemetry cost and side calls, and emits one literal body per
//! session. The upload gate is ON; DARK test arms never change an item, a
//! scan identity, parser scope or body witness.
use super::super::claude_context_file_birth::ClaudeFileBirth;
use super::super::claude_history_upgrade::{
    claude_path_twin_groups, path_twins, probe_opened_birth, ClaudeTwinGroups,
    REQUEST_OWNED_USAGE_CONTRACT,
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
use super::body::{
    reported_inputs, reported_model_effort, ClaudeGrainSide, ClaudeLiveKey,
    ClaudeRequestUsageOrigin,
};
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
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Inline fields are paid by their containing slot and own no allocation.
// Visit only owned heaps: scalar-by-scalar walks otherwise exhaust the
// native frame's 4096-visit guard even when the frame uses under 1 MiB.
// Destructuring is exhaustive; a field moved into the inline group must
// prove INLINE_ONLY before the walk can succeed. Byte/visit caps stay native.
macro_rules! money_heap_fields {
    ($t:ty; inline: [$($inline:ident),*]; heap: [$($heap:ident),*]) => {
        impl crate::heap_layout_bound::HeapLayoutBound for $t {
            fn stable_heap(&self) -> bool {
                let Self { $($inline,)* $($heap,)* } = self;
                true $(&& crate::heap_layout_bound::HeapLayoutBound::stable_heap($inline))*
                    $(&& crate::heap_layout_bound::HeapLayoutBound::stable_heap($heap))*
            }
            fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                let Self { $($inline,)* $($heap,)* } = self;
                $(require_inline($inline)?;)*
                $(crate::heap_layout_bound::HeapLayoutBound::heap_bound($heap, c)?;)*
                Some(())
            }
            fn completed_heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
                let Self { $($inline,)* $($heap,)* } = self;
                $(require_inline($inline)?;)*
                $(crate::heap_layout_bound::HeapLayoutBound::completed_heap_bound($heap, c)?;)*
                Some(())
            }
        }
    };
}
#[inline(always)]
fn require_inline<T: crate::heap_layout_bound::HeapLayoutBound>(_: &T) -> Option<()> {
    T::INLINE_ONLY.then_some(())
}

pub(crate) const GATE: bool = true;
/// A record this much older than its file's effective birth was copied in.
/// Copies written within it are counted (known residual, disclosed nowhere).
pub(in crate::snapshots) const SLACK: i128 = 2_000_000_000;
const HOUR_NANOS: i128 = 3_600_000_000_000;
/// Same bound the P1 holder walk used. A census walk that hits it cannot
/// decide: the affected sessions or families are held, never counted.
const SIDE_CALL_DEADLINE: Duration = Duration::from_millis(250);

/// Local release switch. Only the exact value `1` opts in; unset, `0`,
/// unknown and non-Unicode values preserve released money behavior. This is
/// process configuration, independent of the server's wire capability.
pub(crate) fn resumed_prefix_enabled() -> bool {
    #[cfg(test)]
    {
        if PRE_CHANGE_BUILDER.with(std::cell::Cell::get) {
            return false;
        }
        if let Some(on) = RESUMED_PREFIX.with(std::cell::Cell::get) {
            return on;
        }
    }
    std::env::var("OTTTO_CLAUDE_RESUMED_PREFIX_DEDUPE").as_deref() == Ok("1")
}
#[cfg(test)]
thread_local! {
    static RESUMED_PREFIX: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    static PRE_CHANGE_BUILDER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
pub(crate) struct ResumedPrefixForTest(Option<bool>);
#[cfg(test)]
impl ResumedPrefixForTest {
    pub(crate) fn set(on: bool) -> Self {
        Self(RESUMED_PREFIX.with(|v| v.replace(Some(on))))
    }
}
#[cfg(test)]
impl Drop for ResumedPrefixForTest {
    fn drop(&mut self) {
        RESUMED_PREFIX.with(|v| v.set(self.0));
    }
}
#[cfg(test)]
pub(crate) fn with_pre_change_builder<T>(f: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            PRE_CHANGE_BUILDER.with(|v| v.set(self.0));
        }
    }
    let _restore = Restore(PRE_CHANGE_BUILDER.with(|v| v.replace(true)));
    f()
}
#[path = "e2_legacy.rs"]
mod legacy;
#[cfg(test)]
#[path = "e2_pre_change_builder.rs"]
mod pre_change_builder;

pub(crate) fn enabled() -> bool {
    #[cfg(test)]
    if let Some(on) = ENABLED.with(std::cell::Cell::get) {
        return on;
    }
    GATE
}
#[cfg(test)]
thread_local! { static ENABLED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) }; }
/// Forces the gate on this thread until dropped, then restores the previous
/// setting. `GateForTest::off()` pins a test of the gate-off (pre-flip) path.
#[cfg(test)]
pub(crate) struct GateForTest(Option<bool>);
#[cfg(test)]
impl GateForTest {
    pub(crate) fn set(on: bool) -> Self {
        Self(ENABLED.with(|v| v.replace(Some(on))))
    }
    pub(crate) fn off() -> Self {
        Self::set(false)
    }
}
#[cfg(test)]
impl Drop for GateForTest {
    fn drop(&mut self) {
        ENABLED.with(|v| v.set(self.0));
    }
}
#[cfg(test)]
fn with_gate_for_test<T>(on: bool, f: impl FnOnce() -> T) -> T {
    let _gate = GateForTest::set(on);
    f()
}
#[cfg(test)]
pub(crate) fn with_enabled<T>(f: impl FnOnce() -> T) -> T {
    let _prefix = ResumedPrefixForTest::set(true);
    with_gate_for_test(true, f)
}
/// Owner B (SOURCE Amendment 14): revision 3 keeps a listed family, and
/// every family while the list pauses adoption, on ordinary (pre-E2)
/// money. With the gate on, E2 applies to every other family; a family it
/// does not apply to behaves exactly as gate off (no fold, so no literal).
pub(crate) fn family_applies(index: &ScanIndex, root: &str, subagent_stem: Option<&str>) -> bool {
    applies_unless_listed(
        index,
        index
            .claude_reemission_exclusions
            .excludes(root, subagent_stem),
    )
}

/// `family_applies` for the family of the file a parse opened.
pub(in crate::snapshots) fn file_applies(context: &ReadContext<'_>) -> bool {
    applies_unless_listed(
        context.index,
        claude_index_path_member_ref(context.path).is_some_and(|member| {
            context
                .index
                .claude_reemission_exclusions
                .excludes(member.root, member.subagent_stem)
        }),
    )
}

fn applies_unless_listed(index: &ScanIndex, listed: bool) -> bool {
    enabled() && !listed && !index.claude_reemission_exclusions.pauses_adoption()
}
/// A build from before the switch-on (gate off), e.g. a fixture cycle that
/// stands in for an older daemon at body-witness revision 1 or 2.
#[cfg(test)]
pub(crate) fn with_disabled<T>(f: impl FnOnce() -> T) -> T {
    with_gate_for_test(false, f)
}
// Synthetic transcripts are created when a test runs, after their records'
// fixed timestamps, so E2 would read every record as copied in. A fixture
// that models ordinary transcripts (written after their file's birth) sets
// the physical birth E2 sees for every file read on this thread. Staged
// per-file births still win.
#[cfg(test)]
thread_local! {
    static FIXTURE_BIRTH: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn with_fixture_birth<T>(unix_nanos: u64, f: impl FnOnce() -> T) -> T {
    struct Reset(Option<u64>);
    impl Drop for Reset {
        fn drop(&mut self) {
            FIXTURE_BIRTH.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(FIXTURE_BIRTH.with(|v| v.replace(Some(unix_nanos))));
    f()
}
#[cfg(test)]
pub(in crate::snapshots) fn fixture_birth() -> Option<u64> {
    FIXTURE_BIRTH.with(std::cell::Cell::get)
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
    /// Run `run` with the E2 upload gate forced on (`true`) or off
    /// (`false`, dark) for every page `run` drives on this thread (the
    /// benchmark is single-threaded).
    pub(crate) fn with_gate<T>(on: bool, run: impl FnOnce() -> T) -> T {
        if on {
            super::with_enabled(run)
        } else {
            super::with_disabled(run)
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
    /// With the index key of the original its `fork-context-ref` line names.
    Holders(Option<String>),
}
impl crate::heap_layout_bound::HeapLayoutBound for CopyProof {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Twin(key) | Self::Holders(Some(key)) => key.heap_bound(c),
            Self::Holders(None) => c.add(0),
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

/// Money-rule marks of a settled request-owned body (design item 8).
pub(crate) mod money_mark {
    /// Copies were removed from the body.
    pub(crate) const COPY: u8 = 1;
    /// Copies counted without proof (disclosed).
    pub(crate) const DISCLOSED: u8 = 2;
    /// Usage on transcript estimates (telemetry not complete).
    pub(crate) const ESTIMATED: u8 = 4;
    /// A telemetry-matched request without a reported price.
    pub(crate) const UNPRICED: u8 = 8;
    /// The native resolver dropped one of two incompatible records.
    pub(crate) const CONFLICT: u8 = 16;
    /// This file was kept on ordinary money by the local list.
    pub(crate) const LEGACY: u8 = 32;
    /// #825's `STAMPED_WITHOUT_PERMIT`, retired with the identity permit
    /// (contract 5 always on). Stores may still carry it: it is decoded and
    /// carried through every restamp as stored (durable entry digests bind
    /// the raw byte), but never set, cleared, acted on or replayed.
    pub(crate) const RETIRED_PERMIT: u8 = 64;
}
/// Money-rule versions and the marks each one re-reads. Version 1 is the
/// switch-on, whose revision 3 already re-reads every file. A later money
/// fix appends a row naming the marks it changes, so only those files are
/// re-owed (once, under the history budget); never a revision bump, which
/// re-reads the whole history. Version 2 re-owes nothing (#825 seeded its
/// retired permit mark there); it stays so stored versions keep their meaning.
const MONEY_RULES: &[(u16, u8)] = &[(1, 0), (2, 0)];
#[cfg(test)]
thread_local! {
    static TEST_MONEY_RULES: std::cell::Cell<Option<&'static [(u16, u8)]>> =
        const { std::cell::Cell::new(None) };
}
#[cfg(test)]
pub(crate) fn with_money_rules<T>(rules: &'static [(u16, u8)], f: impl FnOnce() -> T) -> T {
    struct Reset(Option<&'static [(u16, u8)]>);
    impl Drop for Reset {
        fn drop(&mut self) {
            TEST_MONEY_RULES.with(|v| v.set(self.0));
        }
    }
    let _reset = Reset(TEST_MONEY_RULES.with(|v| v.replace(Some(rules))));
    f()
}
fn money_rules() -> &'static [(u16, u8)] {
    #[cfg(test)]
    if let Some(rules) = TEST_MONEY_RULES.with(std::cell::Cell::get) {
        return rules;
    }
    MONEY_RULES
}

/// The marks of one finalized item; zero for a body without the literal.
pub(crate) fn money_marks(item: &SnapshotItem) -> u8 {
    if item.usage_accounting_contract.as_deref() != Some(REQUEST_OWNED_USAGE_CONTRACT) {
        return 0;
    }
    let unpriced = item
        .usage_buckets
        .iter()
        .flat_map(|bucket| &bucket.model_usage)
        .any(|row| {
            row.selector_context
                .get("request_usage_origin")
                .is_some_and(|origin| origin == "telemetry_unpriced")
        });
    [
        (
            item.removed_request_count.unwrap_or(0) > 0,
            money_mark::COPY,
        ),
        (
            item.claude_money
                .as_deref()
                .is_some_and(|f| f.disclosed > 0),
            money_mark::DISCLOSED,
        ),
        (
            item.telemetry_owned_complete != Some(true),
            money_mark::ESTIMATED,
        ),
        (unpriced, money_mark::UNPRICED),
        (item.resolver_conflict_count.is_some(), money_mark::CONFLICT),
    ]
    .into_iter()
    .filter(|(set, _)| *set)
    .fold(0, |marks, (_, mark)| marks | mark)
}

/// A request-owned emitted body after its last local consumer (comparison,
/// finalizer, contract 5, account qualification and optional shadow): the
/// final rows own its money now; native inputs can go too. `money_marks`
/// still reads `disclosed` when the settled body is acknowledged, so a
/// disclosing fold keeps its inline counters and frees every heap field;
/// any other fold is dropped.
pub(crate) fn release_emitted_fold(item: &mut SnapshotItem) {
    if super::request_owned_family_root(item).is_none() {
        return;
    }
    // These serde-skipped inputs have served every local consumer. Emptying
    // them here also keeps the generic upload clone from copying native maps.
    item.claude_usage_occurrences = BTreeMap::new();
    item.claude_usage_request_ids = BTreeSet::new();
    let Some(fold) = item.claude_money.as_deref_mut() else {
        return;
    };
    if fold.disclosed == 0 {
        #[cfg(test)]
        pipeline_test_observer::releasing(fold);
        item.claude_money = None;
        return;
    }
    let FileFold {
        entity,
        own_requests: _,
        resumed_prefix: _,
        copy_unproven_wire: _,
        money_birth: _,
        physical,
        role: _,
        location,
        base_selector,
        bucket_fallback,
        model_fallbacks,
        skipped,
        copy,
        idless_copy,
        idless_inherited,
        first_idless,
        proof,
        prefix_inherited,
        copied: _,
        first_own,
        ambiguous,
        disclosed: _,
        e2_nanos: _,
        responses: _,
        root_fallbacks: _,
        side: _,
        side_requests: _,
        telemetry,
        accounts,
        prefix: _,
    } = fold;
    *entity = Default::default();
    *physical = None;
    *location = None;
    *base_selector = Default::default();
    *bucket_fallback = None;
    *model_fallbacks = BTreeMap::new();
    *skipped = Vec::new();
    *copy = None;
    *idless_copy = None;
    *idless_inherited = None;
    *first_idless = None;
    *proof = None;
    *prefix_inherited = None;
    *first_own = None;
    *ambiguous = BTreeSet::new();
    *telemetry = Default::default();
    *accounts = None;
}

/// Once per money-rule version, after the revision activates: re-owe every
/// indexed Claude file whose marks a newer rule names; the history gate
/// paces them like any owed file. The version is recorded in the same index
/// save, and marks of paths no longer indexed are dropped.
pub(crate) fn apply_money_rules(index: &mut ScanIndex) {
    let rules = money_rules();
    let stored = index.claude_money_birth_store.money_rule_version();
    let Some(&(current, _)) = rules.last() else {
        return;
    };
    if !enabled() || stored >= current {
        return;
    }
    let mask = rules
        .iter()
        .filter(|(version, _)| *version > stored)
        .fold(0, |mask, (_, marks)| mask | marks);
    let to = index
        .active_effective_upload_body_witness_revision
        .saturating_sub(1);
    let mut live = Vec::new();
    let mut owed = Vec::new();
    for key in index.files.keys() {
        if claude_index_path_member_ref(Path::new(key)).is_none() {
            continue;
        }
        let location = location_key(key);
        if index.claude_money_birth_store.money_marks(location) & mask != 0 {
            owed.push(key.clone());
        }
        live.push(location);
    }
    for key in owed {
        index.re_owe_effective_upload_body_witness_revision(&key, to);
    }
    live.sort_unstable();
    let store = &mut index.claude_money_birth_store;
    store.retain_money_marks(&live);
    store.set_money_rule_version(current);
}

/// Pure accumulation consumed by the request-owned literal emitter. No census, claims,
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
    /// Local-only uncertainty from every counted path twin.
    pub(crate) clock_incomplete: bool,
    /// Exact telemetry exceeded the identity owner's bounded key pool.
    pub(crate) identity_over_cap: bool,
    // False proves both live maps have never allocated. Empty live maps
    // retain their conservative root charge after a removal.
    pub(super) live_maps_initialized: bool,
    pub(crate) activity_unix: u64,
    pub(crate) activity_nanos: i128,
    /// Gate off: what the counters read, in place of `grains` (which then
    /// stays empty).
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
            clock_incomplete: false,
            identity_over_cap: false,
            live_maps_initialized: false,
            activity_unix: 0,
            activity_nanos: 0,
            dark: DarkTally::default(),
        }
    }
}
pub(super) const COPY_UNPROVEN_KEY: &str = "__ottto_copy_unproven";
fn mark_copy_key(key: &mut ClaudeLiveKey) {
    key.2.insert(COPY_UNPROVEN_KEY.into(), "true".into());
}
impl ClaudeEntityBody {
    fn mark_copy_unproven(&mut self) {
        self.grains = std::mem::take(&mut self.grains)
            .into_iter()
            .map(|((mut key, origin, account), grain)| {
                mark_copy_key(&mut key);
                ((key, origin, account), grain)
            })
            .collect();
    }

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
        self.live_maps_initialized = true;
        if let Some(at) = at {
            self.note_activity(&key.0, at, at);
        }
        let grain = self.grains.entry((key, origin, account)).or_default();
        grain.add(tokens, requests, cost);
        grain.last_own_at = grain.last_own_at.max(at);
    }
    /// Gate on, `add` into an existing slot: the key is cloned only when
    /// the slot is new.
    fn add_slot(
        &mut self,
        slot: &(
            ClaudeLiveKey,
            Option<ClaudeRequestUsageOrigin>,
            AccountPartition,
        ),
        tokens: &ClaudeMoneyTokens,
        requests: u64,
        cost: Option<u64>,
        at: Option<i128>,
    ) {
        self.live_maps_initialized = true;
        if let Some(at) = at {
            self.note_activity(&slot.0 .0, at, at);
        }
        let grain = match self.grains.get_mut(slot) {
            Some(grain) => grain,
            None => self.grains.entry(slot.clone()).or_default(),
        };
        grain.add(tokens, requests, cost);
        grain.last_own_at = grain.last_own_at.max(at);
    }
    fn note_activity(&mut self, bucket: &str, first: i128, last: i128) {
        self.live_maps_initialized = true;
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
        self.live_maps_initialized |= !self.grains.is_empty();
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
        into.last_own_at = into.last_own_at.max(grain.last_own_at);
    }

    /// Grains and their activity only (a held copy moving back to counted).
    fn absorb_grains(&mut self, other: &Self) {
        self.live_maps_initialized |= !other.grains.is_empty() || !other.bucket_activity.is_empty();
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
        self.clock_incomplete |= other.clock_incomplete;
        self.identity_over_cap |= other.identity_over_cap;
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
        self.live_maps_initialized = true;
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

/// Gate off (dark): no per-hour grain map. `unmatched_1h` reads the
/// estimated requests per unix hour that telemetry attach has not moved.
/// 8 bytes per hour with estimated usage.
#[derive(Debug, Clone, Default)]
pub(super) struct DarkTally {
    side: ClaudeGrainSide,
    /// (unix hour, estimated requests), sorted by hour.
    estimated: Vec<(u32, u32)>,
}
money_heap_fields!(DarkTally; inline: [side]; heap: [estimated]);
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
// A never-initialized live map cannot have a retained empty root. Charging
// fictitious roots here makes a dark file exceed the native finish budget.
// Initialized maps keep the ordinary conservative bound even after emptying.
macro_rules! entity_heap_method {
    ($method:ident) => {
        fn $method(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
            let Self {
                grains,
                bucket_activity,
                dark,
                live_maps_initialized,
                removed: _,
                removed_requests: _,
                telemetry_owned_complete: _,
                resolver_conflicts: _,
                held: _,
                certificate_ok: _,
                clock_incomplete: _,
                identity_over_cap: _,
                activity_unix: _,
                activity_nanos: _,
            } = self;
            // Nonempty maps remain charged even for synthetic test entities
            // whose fields were populated directly.
            if *live_maps_initialized || !grains.is_empty() || !bucket_activity.is_empty() {
                crate::heap_layout_bound::HeapLayoutBound::$method(grains, c)?;
                crate::heap_layout_bound::HeapLayoutBound::$method(bucket_activity, c)?;
            }
            crate::heap_layout_bound::HeapLayoutBound::$method(dark, c)
        }
    };
}
impl crate::heap_layout_bound::HeapLayoutBound for ClaudeEntityBody {
    const STABLE_HEAP: bool = true;
    entity_heap_method!(heap_bound);
    entity_heap_method!(completed_heap_bound);
}
// Existing grain types were inline P1 values; E retains only the aggregate.
impl crate::heap_layout_bound::HeapLayoutBound for ClaudeGrainSide {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        // Exhaustive: every field is an inline token/counter, already paid
        // by its containing slot. No per-token graph walk is needed.
        let Self {
            tokens: _,
            requests: _,
            cost_micros: _,
            unpriced: _,
            contributions: _,
            last_own_at: _,
        } = self;
        c.add(0)
    }
}
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
money_heap_fields!(FoldTelemetry; inline: [read, complete, side_candidates, side_calls_done]; heap: [start_bucket, membership]);

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

/// The copied prefix's page outcome (copy-family fix, Lead B Addendum 2),
/// local diagnostics only until SOURCE/COST consume the flag: requests of
/// the copied prefix (before the file's resume boundary) that count because
/// their copy proof failed (flagged and disclosed, never dropped), the
/// reported cost of those matched to priced telemetry, and stored removals
/// reused without a current holder.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PrefixTally {
    unproven_requests: u64,
    /// Id-less copies counted after all: no request id can ever prove them.
    unproven_idless: u64,
    priced_requests: u64,
    cost_micros: u64,
    reused: u64,
    held_requests: u64,
    hold_expired: u64,
    metadata_lost: u64,
    removed_priced_requests: u64,
    removed_cost_micros: u64,
}
impl crate::heap_layout_bound::HeapLayoutBound for PrefixTally {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileFold {
    pub(crate) entity: ClaudeEntityBody,
    own_requests: u64,
    resumed_prefix: bool,
    copy_unproven_wire: bool,
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
    /// Pre-birth grains held until finish_native confirms the skip. Sparse:
    /// most files have none, and finish_native drops them before page attach.
    copy: Option<Box<ClaudeEntityBody>>,
    /// Held copies without a request id: no census can prove them, so a
    /// proof-checked skip counts them after all. Rare, so boxed.
    idless_copy: Option<Box<ClaudeEntityBody>>,
    /// Id-less copied usage staged by its native marker until that marker's
    /// request is decided. At most one body per bounded marker run.
    #[allow(clippy::box_collection)]
    idless_inherited: Option<Box<BTreeMap<u64, ClaudeEntityBody>>>,
    first_idless: Option<u64>,
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
    /// The copied prefix's page outcome (local diagnostics only).
    prefix: PrefixTally,
}
money_heap_fields!(FileFold; inline: [own_requests, resumed_prefix, copy_unproven_wire, money_birth, role, copied, disclosed, e2_nanos, responses, root_fallbacks, side, side_requests, prefix]; heap: [entity, physical, location, first_own, base_selector, bucket_fallback, model_fallbacks, skipped, copy, idless_copy, idless_inherited, first_idless, proof, prefix_inherited, ambiguous, telemetry, accounts]);

/// What the finish hands a gate-on fold, sized for
/// [`FileFold::finish_heap_bound`] (X_out's E term).
#[derive(Debug, Default, Clone, Copy)]
pub(in crate::snapshots) struct FoldShape {
    /// Responses the fold observes, each its own grain in the worst case.
    pub(in crate::snapshots) responses: usize,
    /// Responses naming no model: each a `model_fallbacks` entry.
    pub(in crate::snapshots) modelless: usize,
    /// The largest model a key or fallback copies.
    pub(in crate::snapshots) model: usize,
    /// Summed over responses: the text and entries (roots apart) a key's
    /// context can copy, the base selector's share included.
    pub(in crate::snapshots) context_strings: usize,
    pub(in crate::snapshots) context_entries: usize,
    /// `base_selector`'s completed heap (a clone of the current selector),
    /// and `bucket_fallback`'s text.
    pub(in crate::snapshots) base_selector: usize,
    pub(in crate::snapshots) bucket_fallback: usize,
    /// One key's `AccountPartition`, and the accounts with their rebuild
    /// (`RequestAccounts::finish_heap_bound`).
    pub(in crate::snapshots) partition: usize,
    pub(in crate::snapshots) accounts: usize,
    /// Org marker runs: at most one inherited body each.
    pub(in crate::snapshots) marker_runs: usize,
    /// The copy proof's text with its scratch.
    pub(in crate::snapshots) proof: usize,
}

impl FileFold {
    /// X_out's E term (gate on): the fold `finalize_claude_responses_e2`
    /// builds, at its peak, in the `completed_heap` convention. Every
    /// response is its own grain: the key (bucket, model, context map,
    /// partition), its slot and its bucket's activity entry. One moment
    /// holds grains twice: `absorb_grains` clones a held body (pre-birth
    /// copies, id-less copies, a marker's inherited usage) into the entity
    /// while the body is alive, and every response can sit in one. The
    /// accounts' rebuild is in their own term.
    pub(in crate::snapshots) fn finish_heap_bound(shape: &FoldShape) -> Option<usize> {
        use super::super::claude_response_records::RFC3339_TEXT_BYTES;
        use crate::heap_layout_bound::tree_node_bytes;
        use std::mem::{align_of, size_of};
        let FoldShape {
            responses,
            modelless,
            model,
            context_strings,
            context_entries,
            base_selector,
            bucket_fallback,
            partition,
            accounts,
            marker_runs,
            proof,
        } = *shape;
        let grain = tree_node_bytes::<
            (
                ClaudeLiveKey,
                Option<ClaudeRequestUsageOrigin>,
                AccountPartition,
            ),
            ClaudeGrainSide,
        >()?;
        let activity = tree_node_bytes::<String, (i128, i128)>()?;
        let context = tree_node_bytes::<String, String>()?;
        // A body's two maps keep a root each, even empty.
        let body = grain.checked_add(activity)?;
        let per_response = grain
            .checked_add(activity)?
            .checked_add(RFC3339_TEXT_BYTES.checked_mul(2)?)? // the key's and activity's bucket
            .checked_add(model)?
            .checked_add(partition)?
            .checked_add(context)?; // the key's context root
        let grains = responses
            .checked_mul(per_response)?
            .checked_add(context_entries.checked_mul(context)?)?
            .checked_add(context_strings)?;
        let absorb = grains;
        // The held copy and id-less copy boxes.
        let held = size_of::<ClaudeEntityBody>()
            .checked_add(align_of::<ClaudeEntityBody>())?
            .checked_add(body)?
            .checked_mul(2)?;
        let inherited = if marker_runs == 0 {
            0
        } else {
            size_of::<BTreeMap<u64, ClaudeEntityBody>>()
                .checked_add(align_of::<BTreeMap<u64, ClaudeEntityBody>>())?
                .checked_add(marker_runs.checked_add(1)?.checked_mul(
                    tree_node_bytes::<u64, ClaudeEntityBody>()?.checked_add(body)?,
                )?)?
        };
        let fallbacks = modelless
            .checked_add(1)?
            .checked_mul(tree_node_bytes::<u64, String>()?)?
            .checked_add(modelless.checked_mul(model)?)?;
        // `push` growth from four slots, and `shrink_to_fit`'s copy.
        let skipped = responses
            .checked_mul(3)?
            .checked_add(4)?
            .checked_mul(size_of::<(u64, u64)>())?;
        // A request id is noted on its second claim: at most half the
        // responses.
        let ambiguous = (responses / 2 + 1).checked_mul(tree_node_bytes::<u64, ()>()?)?;
        let mut out = 0usize;
        for bytes in [
            size_of::<Self>().checked_add(align_of::<Self>())?, // `claude_money`'s box
            body,                                               // the entity's roots
            grains,
            absorb,
            held,
            if resumed_prefix_enabled() {
                inherited.checked_mul(2)?
            } else {
                inherited
            },
            base_selector,
            bucket_fallback,
            fallbacks,
            skipped,
            ambiguous,
            accounts,
            proof,
        ] {
            out = out.checked_add(bytes)?;
        }
        Some(out)
    }
}
impl FileFold {
    pub(in crate::snapshots) fn new(
        birth: ClaudeFileBirth,
        context: Option<&ReadContext<'_>>,
        base_selector: SelectorCapture,
        bucket_fallback: Option<String>,
    ) -> Self {
        let started = Instant::now();
        #[cfg(test)]
        let birth = {
            let mut birth = birth;
            if let Some(at) = fixture_birth() {
                birth.set_birth_for_test(i128::from(at));
            }
            birth
        };
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
            own_requests: 0,
            resumed_prefix: resumed_prefix_enabled(),
            copy_unproven_wire: resumed_prefix_enabled()
                && context.is_some_and(|c| c.index.copy_unproven_enabled),
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
            idless_inherited: None,
            first_idless: None,
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
            prefix: PrefixTally::default(),
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

    /// A response of the copied prefix (before the resume boundary, by the
    /// clock `observe` read) that still counts after the page's decision:
    /// its copy proof failed. Exactly the flagged range; own turns never.
    fn unproven_copy(&self, occurrence: &ClaudeTranscriptUsageOccurrence) -> bool {
        let at = occurrence.timestamp.as_deref().and_then(rfc3339_unix_nanos);
        !occurrence.usage.is_zero()
            && self.money_birth.copied_with_slack(at, SLACK) == Some(true)
            && !self.is_skipped(occurrence.sequence)
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
        let Some(placement) = placed.placement.as_ref() else {
            // Native drops it as unplaceable usage; never publish over it.
            self.entity.certificate_ok = false;
            self.disclose("unplaceable", 1);
            return;
        };
        // Gate off keeps only the hour tally: read the hour, build no key.
        let key = if live {
            Grain::Live(live_key(
                &placed.model,
                placement.bucket.clone(),
                placement.reduced_context.clone(),
                &placement.row_key,
                effort,
            ))
        } else {
            Grain::Hour(bucket_hour(&placement.bucket))
        };
        let account = self.accounts.as_mut().and_then(|accounts| {
            accounts.observe(sequence, copied == Some(true));
            accounts.account(sequence)
        });
        if !has_request_id {
            self.first_idless.get_or_insert(sequence);
        }
        let tokens = ClaudeMoneyTokens::from_usage(usage);
        let requests = usage.request_count;
        if self.resumed_prefix && copied == Some(false) {
            self.own_requests += requests;
        }
        if copied == Some(true) {
            self.copied += 1;
            self.entity.removed.add(&tokens);
            self.entity.removed_requests += requests;
            if !has_request_id {
                let marker = self
                    .resumed_prefix
                    .then(|| {
                        self.accounts
                            .as_deref()
                            .and_then(|accounts| accounts.copied_marker_position(sequence))
                    })
                    .flatten();
                let into = match marker {
                    Some(position) => self
                        .idless_inherited
                        .get_or_insert_with(Box::default)
                        .entry(position)
                        .or_default(),
                    None => self.idless_copy.get_or_insert_with(Box::default),
                };
                key.put(into, &tokens, requests, at, account);
                return;
            }
            match self.skipped.last_mut() {
                Some((_, end)) if *end == sequence => *end += 1,
                _ => self.skipped.push((sequence, sequence + 1)),
            }
            key.put(
                self.copy.get_or_insert_with(Box::default),
                &tokens,
                requests,
                at,
                account,
            );
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
        key.put(into, &tokens, requests, at, account);
    }

    /// Confirm, or undo, the held pre-birth skip. A partial copy (own lines
    /// after birth) is skipped on timestamps with a writer certificate from
    /// those own lines. Every other skip needs a PROOF that
    /// `decide_page_copies` checks per request on the page: a same-session
    /// earlier path twin (stored birth, total (birth, location) order, a
    /// certified writer) or, for an all-pre-birth MAIN file or the copied
    /// prefix of a resumed MAIN file with an uncertified writer, earlier
    /// main files of other sessions (/branch, resume; the request ids are the
    /// proof, no writer certificate). Without one the copies count and are
    /// disclosed.
    /// `fork_parent`: the session a `fork-context-ref` line names (empty:
    /// none single).
    pub(in crate::snapshots) fn finish_native(
        &mut self,
        context: Option<&ReadContext<'_>>,
        markers: Option<&claude_request_identity::OrgMarkers>,
        fork_parent: Option<&str>,
    ) {
        let started = Instant::now();
        #[cfg(test)]
        if PRE_CHANGE_BUILDER.with(std::cell::Cell::get) {
            self.decide_native_pre_change(context, markers, fork_parent);
            self.entity.dark.shrink();
            self.skipped.shrink_to_fit();
            self.spend(started);
            return;
        }
        self.decide_native(context, markers, fork_parent);
        // The fold lives until the page finishes: keep no parse-time slack.
        self.entity.dark.shrink();
        self.skipped.shrink_to_fit();
        self.spend(started);
    }

    fn decide_native(
        &mut self,
        context: Option<&ReadContext<'_>>,
        markers: Option<&claude_request_identity::OrgMarkers>,
        fork_parent: Option<&str>,
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
            self.idless_inherited = None;
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
        if self.cross_session_candidate(context, certified) {
            // The named original is a sibling file of the same project.
            let parent = fork_parent
                .filter(|parent| !parent.is_empty())
                .zip(context)
                .map(|(parent, context)| {
                    local_index_key(&context.path.with_file_name(format!("{parent}.jsonl")))
                });
            self.proof = Some(CopyProof::Holders(parent));
            // Should the page find no holder, the restored copies keep the
            // accounts their own markers give them (QUOTA: never moved).
            // Keep marker-dependent grains staged until the page decides
            // individual requests; provisional markers must not become own
            // account evidence before proof removes their copied request.
            if self.resumed_prefix {
                self.copy = None;
            } else {
                self.keep_copies(false, markers);
            }
            return;
        }
        if let Some(mut copy) = self.copy.take() {
            if self.copy_unproven_wire {
                copy.mark_copy_unproven();
            }
            self.entity.absorb_grains(&copy);
        }
        self.restore_idless();
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
        self.copy = None;
    }

    fn finish_identity_start(
        &mut self,
        prefix_excluded: bool,
        markers: Option<&claude_request_identity::OrgMarkers>,
    ) {
        if let Some(accounts) = self.accounts.as_deref_mut() {
            accounts.finish_native(markers, prefix_excluded);
        }
        self.absorb_prefix_inherited(prefix_excluded);
    }

    fn absorb_prefix_inherited(&mut self, repartition: bool) {
        if let Some(inherited) = self.prefix_inherited.take() {
            for (position, mut inherited) in *inherited {
                if repartition {
                    inherited
                        .repartition(self.accounts.as_deref().and_then(|a| a.account(position)));
                }
                self.entity.absorb_grains(&inherited);
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
    /// earlier main files, in one census walk per page. Copy-family fix
    /// (Lead B 2026-10-30): a resumed MAIN file (own turns after its copied
    /// prefix) whose writer is not certified gets the same per-request check
    /// for its prefix, whatever the writer version. A certified resumed file
    /// keeps its timestamp or twin rule (never two removals of one request).
    fn cross_session_candidate(&self, context: Option<&ReadContext<'_>>, certified: bool) -> bool {
        (self.first_own.is_none() || (self.resumed_prefix && !certified))
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
        let mut key = self.occurrence_key_unmarked(occurrence)?;
        if self.copy_unproven_wire && self.unproven_copy(occurrence) {
            mark_copy_key(&mut key);
        }
        Some(key)
    }

    fn occurrence_key_unmarked(
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
            self.occurrence_key_unmarked(occurrence).map(|mut key| {
                if self.copy_unproven_wire {
                    mark_copy_key(&mut key);
                }
                key
            }),
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
        if let Some(idless) = self.idless_copy.take() {
            self.restore_idless_body(*idless, None);
        }
        if let Some(inherited) = self.idless_inherited.take() {
            for (position, idless) in *inherited {
                self.restore_idless_body(idless, Some(position));
            }
        }
    }

    fn restore_idless_body(&mut self, mut idless: ClaudeEntityBody, position: Option<u64>) {
        if self.copy_unproven_wire {
            idless.mark_copy_unproven();
        }
        let (tokens, requests) = idless.totals();
        let responses = idless.contributions();
        match (
            self.entity.removed.checked_sub(&tokens),
            self.entity.removed_requests.checked_sub(requests),
        ) {
            (Some(removed), Some(removed_requests)) => {
                self.entity.removed = removed;
                self.entity.removed_requests = removed_requests;
                match position {
                    Some(position) => self
                        .prefix_inherited
                        .get_or_insert_with(Box::default)
                        .entry(position)
                        .or_default()
                        .absorb_grains(&idless),
                    None => self.entity.absorb_grains(&idless),
                }
                self.copied = self.copied.saturating_sub(responses);
                if self.resumed_prefix {
                    self.prefix.unproven_idless += requests;
                }
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

/// One observed response's slot: its grain key (gate on) or its estimated
/// hour (gate off, what `ClaudeEntityBody::add` keeps of an origin-less key).
enum Grain {
    Live(ClaudeLiveKey),
    Hour(Option<u32>),
}

impl Grain {
    fn put(
        self,
        into: &mut ClaudeEntityBody,
        tokens: &ClaudeMoneyTokens,
        requests: u64,
        at: Option<i128>,
        account: AccountPartition,
    ) {
        match self {
            Grain::Live(key) => into.add(key, tokens, requests, None, None, at, account),
            Grain::Hour(hour) => into.dark.add(hour, tokens, requests, None),
        }
    }
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

/// Matched and side-call grains keep reported enrichment:
/// OTEL speed joins the selector, an OTEL effort tier
/// fills a missing transcript effort (kept in the context),
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
money_heap_fields!(FamilyMembership; inline: [member_mask]; heap: [entries]);

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
/// defers the unresolved prefix; own turns emit. The third decision pass
/// emits any still-unproven prefix flagged. All the
/// page's cross-session checks share ONE census walk. Runs in both gate
/// modes; dark only counts. Returns the removals to store (gate on only):
/// the caller applies them to the index (`CopyRemovalUpdates::apply`).
pub(crate) fn decide_page_copies(
    items: &mut [SnapshotItem],
    index: &ScanIndex,
) -> CopyRemovalUpdates {
    let _spent = PageSpent::start("page.copies");
    if !resumed_prefix_enabled() {
        let mut holders = Vec::new();
        for at in 0..items.len() {
            let Some(fold) = items[at].claude_money.as_deref_mut() else {
                continue;
            };
            fold.entity.held = false;
            match fold.proof.clone() {
                Some(CopyProof::Twin(witness)) => decide_twin(items, at, &witness, index),
                Some(CopyProof::Holders(_)) => holders.push(at),
                None => {}
            }
        }
        if !holders.is_empty() {
            legacy::decide_holders(items, &holders, index);
        }
        return CopyRemovalUpdates::default();
    }
    let mut holders = Vec::new();
    let mut resolved_holds = Vec::new();
    for at in 0..items.len() {
        let Some(fold) = items[at].claude_money.as_deref_mut() else {
            continue;
        };
        // A page decides afresh (a test re-deciding a larger page included).
        fold.entity.held = false;
        fold.prefix = PrefixTally {
            unproven_idless: fold.prefix.unproven_idless,
            ..PrefixTally::default()
        };
        let proof = fold.proof.clone();
        if enabled() && !matches!(proof, Some(CopyProof::Holders(_))) {
            if let Some(Located(file)) = fold.location {
                if index.claude_copy_removals.pending(file) {
                    resolved_holds.push(file);
                }
            }
        }
        match proof {
            Some(CopyProof::Twin(witness)) => decide_twin(items, at, &witness, index),
            Some(CopyProof::Holders(_)) => holders.push(at),
            None => {}
        }
    }
    let mut updates = if holders.is_empty() {
        CopyRemovalUpdates::default()
    } else {
        decide_holders(items, &holders, index)
    };
    if !resolved_holds.is_empty() {
        let state = updates
            .state
            .get_or_insert_with(|| index.claude_copy_removals.clone());
        for file in resolved_holds {
            state.clear_hold(file);
        }
    }
    if enabled() {
        for at in holders {
            finish_holder_identity(&mut items[at]);
        }
        for item in items.iter_mut() {
            tally_unproven_prefix(item, index.claude_copy_removals.metadata_lost());
        }
    }
    updates
}

/// Apply the money decision to the existing native account policy before
/// telemetry attachment. Only the decided skipped marker positions disappear.
fn finish_holder_identity(item: &mut SnapshotItem) {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_org_markers,
        claude_usage_occurrences,
        ..
    } = item
    else {
        return;
    };
    let Some(mut accounts) = fold.accounts.take() else {
        return;
    };
    let first_retained = claude_usage_occurrences
        .values()
        .filter(|o| !fold.is_skipped(o.sequence) && !o.usage.is_zero())
        .map(|o| o.sequence)
        .chain(fold.first_idless)
        .min();
    let rebuilt =
        accounts.after_copy_decision(claude_org_markers.as_deref(), &fold.skipped, first_retained);
    if let Some(own) = rebuilt.as_ref() {
        // Restored identified prefix grains were placed with the original
        // native policy. Own/id-less marker-dependent grains are still staged.
        for occurrence in claude_usage_occurrences.values() {
            if !fold.unproven_copy(occurrence) {
                continue;
            }
            place_request_identity(
                fold,
                occurrence,
                None,
                accounts.account(occurrence.sequence),
                own.account(occurrence.sequence),
            );
        }
    }
    let changed = rebuilt.is_some();
    if let Some(own) = rebuilt {
        *accounts = own;
    }
    fold.accounts = Some(accounts);
    fold.absorb_prefix_inherited(changed);
}

/// The flagged range of a decided fold: its copied-prefix requests that
/// count because their proof failed (Lead B Addendum 2). A held fold emits
/// nothing on this page, so it flags nothing.
fn tally_unproven_prefix(item: &mut SnapshotItem, metadata_lost: bool) {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = item
    else {
        return;
    };
    // Every counted copy was disclosed when its proof failed.
    if fold.entity.held || fold.disclosed == 0 {
        return;
    }
    fold.prefix.unproven_requests = claude_usage_occurrences
        .values()
        .filter(|occurrence| fold.unproven_copy(occurrence))
        .map(|occurrence| occurrence.usage.request_count)
        .sum();
    if metadata_lost {
        fold.prefix.metadata_lost = fold.prefix.unproven_requests + fold.prefix.unproven_idless;
    }
}

/// Removal decisions of one page for the index's stored copy removals.
#[derive(Debug, Default)]
pub(crate) struct CopyRemovalUpdates {
    state: Option<super::copy_removals::CopyRemovals>,
    added: u64,
    unrecorded: u64,
}
impl CopyRemovalUpdates {
    /// The bounded replacement carries stored decisions and retry debt in the
    /// same index save. A refused decision still removes proven copies.
    pub(crate) fn apply(self, index: &mut ScanIndex) {
        if let Some(state) = self.state {
            index.claude_copy_removals = state;
        }
        diag("copy_removal_stored", self.added);
        diag("copy_removal_store_overflow", self.unrecorded);
        diag("copy_removed_unrecorded", self.unrecorded);
        if self.unrecorded > 0 {
            eprintln!(
                "local Claude money: alarm=copy_removal_store_full copy_removed_unrecorded={}",
                self.unrecorded
            );
        }
        record_counts(Counts::removal_store(self.added, self.unrecorded));
    }
}

/// Location keys of every indexed MAIN Claude file: a stored removal's
/// holder proves only while it is still indexed.
fn indexed_main_files(index: &ScanIndex) -> BTreeMap<LocationKey, &str> {
    index
        .files
        .keys()
        .filter(|key| {
            claude_index_path_member_ref(Path::new(key.as_str()))
                .is_some_and(|member| member.subagent_stem.is_none())
        })
        .map(|key| (location_key(key), key.as_str()))
        .collect()
}

/// A stored removal of `hash` under `holder` (index key): `None` when the
/// holder's census can no longer answer (retired, over budget or no
/// record), so the stored decision stands; else whether its record holds
/// the hash (a record that lacks it disproves the stored ownership).
fn stored_holder_answer(index: &ScanIndex, holder: &str, hash: u64) -> Option<bool> {
    index
        .claude_request_census
        .get(holder)
        .filter(|record| record.proves_scan())
        .and_then(|record| {
            if record.holds_hash(hash) {
                Some(true)
            } else if record.is_lossy() {
                None
            }
            // E7 Addendum 6: absence is unknown.
            else {
                Some(false)
            }
        })
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
            .filter(|record| scan_evidence(index, witness, record) == Evidence::Current)
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

/// What a census record proves about its file now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Evidence {
    /// It lists the requests the file holds.
    Current,
    /// The file changed since that scan and this traversal still queues it:
    /// the decision waits for the re-read (a stale holder never decides).
    Queued,
    /// The live mtime changed since the census read, whether queued or not.
    Stale,
    /// Nothing: retired, over budget, twin, older derivation, or a held
    /// scan whose file is gone.
    None,
}

/// What `key`'s census record proves about the file now (owner rule P2:
/// holding a session withholds its UPLOAD only; its scan state stays
/// evidence). The record of the settled revision (its index entry, same
/// fingerprint) proves it; so does the record of a scan whose upload is held
/// (entry absent or not advanced), while the file is still there. A file
/// modified since its recorded read is Stale until read again (PR A M2).
/// A queued size change also waits, including changes within one mtime
/// second (PR C). Unchanged held scans remain evidence, never upload proof.
fn scan_evidence(
    index: &ScanIndex,
    key: &str,
    record: &super::super::claude_request_census::ClaudeRequestCensusRecord,
) -> Evidence {
    if !record.proves_scan() {
        return Evidence::None;
    }
    let settled = index
        .files
        .get(key)
        .filter(|entry| record.proves_current(&entry.source_file_fingerprint));
    let metadata = std::fs::metadata(key).ok().filter(|m| m.is_file());
    if let Some(metadata) = &metadata {
        let now = metadata
            .modified()
            .ok()
            .and_then(super::super::unix_seconds);
        if matches!((record.modified(), now), (Some(read), Some(now)) if read != now) {
            return Evidence::Stale;
        }
    }
    let changed = match (settled, &metadata) {
        (Some(entry), Some(metadata)) => metadata.len() != entry.size_bytes,
        (Some(_), None) => false,
        (None, Some(metadata)) => record.modified().is_some_and(|at| {
            metadata
                .modified()
                .ok()
                .and_then(super::super::unix_seconds)
                != Some(at)
        }),
        (None, None) => return Evidence::None,
    };
    if changed && queued(index, key) {
        Evidence::Queued
    } else {
        Evidence::Current
    }
}

/// This traversal still queues `key` for a page.
fn queued(index: &ScanIndex, key: &str) -> bool {
    index.traversal.as_ref().is_some_and(|traversal| {
        traversal
            .pending_candidates
            .iter()
            .any(|candidate| candidate.path == Path::new(key))
    })
}

/// Another session's main file this traversal has not put on any page yet
/// and that has no scan state: queued, without a census record (unscanned,
/// or indexed without one). Only these, and a queued stale holder
/// (`Evidence::Queued`), can make a copy wait. A scanned file, held or not,
/// is evidence (`scan_evidence`), never a reason to wait, so held sessions
/// never wait on each other; with the queue drained (traversal complete)
/// nothing is pending and what exists decides.
fn unscanned_main_roots(index: &ScanIndex) -> BTreeSet<String> {
    unscanned_main_files(index)
        .into_iter()
        .map(|(root, _)| root)
        .collect()
}

/// `unscanned_main_roots` with each file's index key.
fn unscanned_main_files(index: &ScanIndex) -> Vec<(String, String)> {
    index
        .traversal
        .iter()
        .flat_map(|traversal| traversal.pending_candidates.iter())
        .map(|candidate| local_index_key(&candidate.path))
        .filter(|key| index.claude_request_census.get(key).is_none())
        .filter_map(|key| {
            let member = claude_index_path_member_ref(Path::new(&key))?;
            let root = member
                .subagent_stem
                .is_none()
                .then(|| member.root.to_owned())?;
            Some((root, key))
        })
        .collect()
}

/// Unscanned other main files: (session root, copy order when known).
type UnscannedOrders = Vec<(String, Option<(i128, LocationKey)>)>;

/// Copy-family fix: a resumed file waits only for an unscanned main file
/// of another session that may be its earlier holder (born before it, or
/// birth unknown); a later file cannot hold its copied prefix.
fn unscanned_earlier_main(
    index: &ScanIndex,
    pending: &std::cell::OnceCell<UnscannedOrders>,
    session: &str,
    order: (i128, LocationKey),
) -> bool {
    pending
        .get_or_init(|| {
            unscanned_main_files(index)
                .into_iter()
                .map(|(root, key)| {
                    let order = holder_order(&index.claude_money_birth_store, &root, &key);
                    (root, order)
                })
                .collect()
        })
        .iter()
        .any(|(root, holder)| {
            root != session && !matches!(holder, Some(holder) if *holder >= order)
        })
}

/// A holder's place in the total copy order: (effective birth, location).
/// A holder without a stored birth is probed once.
fn holder_order(
    store: &super::super::claude_money_birth_store::BirthStore,
    root: &str,
    key: &str,
) -> Option<(i128, LocationKey)> {
    let birth = store.effective_cutoff(root, key).or_else(|| {
        probe_opened_birth(key)
            .filter(|opened| opened.birth != 0)
            .map(|opened| i128::from(opened.birth))
    })?;
    Some((birth, location_key(key)))
}

/// Owner direction (PR C (a)): a /branch names its original in a
/// `fork-context-ref` line. When that original is still indexed but its
/// census cannot answer (retired after 35 idle days, over budget, older
/// derivation, none), the named earlier original is the copy proof for the
/// requests no current record covers. A current record that lacks a request
/// proves the original does not hold it: no proof then.
fn parent_proves(
    index: &ScanIndex,
    parent: &str,
    session: &str,
    order: (i128, LocationKey),
) -> bool {
    let Some(member) = claude_index_path_member_ref(Path::new(parent)) else {
        return false;
    };
    member.subagent_stem.is_none()
        && member.root != session
        && index.files.contains_key(parent)
        && !index
            .claude_request_census
            .get(parent)
            .is_some_and(|record| record.proves_scan())
        && holder_order(&index.claude_money_birth_store, member.root, parent)
            .is_some_and(|holder| holder < order)
}

/// One census walk for every all-pre-birth main file of the page. A holder
/// proves a request when it is another session's main file whose scan state
/// holds it (`scan_evidence`) and earlier in (effective birth, location).
/// The walk deadline, a queued size change, a holder modified since its
/// census read, and an unscanned other-session main file delay a decision.
fn decide_holders(
    items: &mut [SnapshotItem],
    folds: &[usize],
    index: &ScanIndex,
) -> CopyRemovalUpdates {
    if !index.persistence_available() {
        for at in folds {
            hold_copies(&mut items[*at], "index_unavailable");
        }
        return CopyRemovalUpdates::default();
    }

    struct Wanted {
        at: usize,
        session: String,
        order: (i128, LocationKey),
        hashes: Vec<u64>,
        /// Hash -> the earliest holder whose current scan state proves it.
        covered: BTreeMap<u64, (i128, LocationKey)>,
        /// Hashes a stored removal keeps removed (its holder still indexed).
        stored: BTreeSet<u64>,
        /// Own turns follow the copied prefix: waits only for a possibly
        /// earlier unscanned holder (`unscanned_earlier_main`).
        resumed: bool,
        /// A holder that would cover it changed and is still queued.
        waiting: bool,
        /// Hashes held only by an earlier file modified since its census read.
        stale: BTreeSet<u64>,
        /// The original its `fork-context-ref` line names.
        parent: Option<String>,
    }
    let live = std::cell::OnceCell::<BTreeMap<LocationKey, &str>>::new();
    let mut wanted = folds
        .iter()
        .filter_map(|&at| {
            let item = &items[at];
            let fold = item.claude_money.as_deref()?;
            let order = fold.copy_order()?;
            let resumed = fold.first_own.is_some();
            let parent = match &fold.proof {
                Some(CopyProof::Holders(parent)) => parent.clone(),
                _ => None,
            };
            let mut hashes = skipped_ids(item)
                .map(|id| claude_request_hash(id))
                .collect::<Vec<_>>();
            hashes.sort_unstable();
            hashes.dedup();
            // Addendum 1: a stored removal stays removed after its holder's
            // id list retires, while that holder is still indexed. A holder
            // whose census disproves it invalidates that saved decision.
            // Positive proof also remains valid if the walk hits its deadline.
            let mut stored = BTreeSet::new();
            if enabled() {
                for (holder, held) in index.claude_copy_removals.get(order.1) {
                    let Some(key) = live.get_or_init(|| indexed_main_files(index)).get(holder)
                    else {
                        continue;
                    };
                    stored.extend(held.iter().filter(|&&hash| {
                        hashes.binary_search(&hash).is_ok()
                            && stored_holder_answer(index, key, hash) != Some(false)
                    }));
                }
            }
            Some(Wanted {
                at,
                session: item.source_session_id.clone(),
                order,
                hashes,
                covered: BTreeMap::new(),
                stored,
                resumed,
                waiting: false,
                stale: BTreeSet::new(),
                parent,
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
            let mut holder = None::<Option<(Evidence, (i128, LocationKey))>>;
            for &hash in hits {
                let from = wanting.partition_point(|&(wanted, _)| wanted < hash);
                for &(_, at) in wanting[from..].iter().take_while(|&&(h, _)| h == hash) {
                    let file = &mut wanted[at];
                    if file.session == root {
                        continue;
                    }
                    let holder = *holder.get_or_insert_with(|| {
                        let evidence = scan_evidence(index, key, record);
                        if evidence == Evidence::None {
                            return None;
                        }
                        Some((evidence, holder_order(store, root, key)?))
                    });
                    match holder {
                        Some((evidence, holder)) if holder < file.order => match evidence {
                            Evidence::Queued => file.waiting = true,
                            Evidence::Stale => {
                                file.stale.insert(hash);
                            }
                            Evidence::Current => {
                                let earliest = file.covered.entry(hash).or_insert(holder);
                                *earliest = (*earliest).min(holder);
                            }
                            Evidence::None => {}
                        },
                        _ => {}
                    }
                }
            }
        },
    );
    let pending = std::cell::OnceCell::<BTreeSet<String>>::new();
    let pending_files = std::cell::OnceCell::new();
    let mut updates = CopyRemovalUpdates::default();
    if enabled() {
        let mut state = index.claude_copy_removals.clone();
        let live = live.get_or_init(|| indexed_main_files(index));
        state.retain_files(|file| live.contains_key(&file));
        updates.state = Some(state);
    }
    for wanted in wanted {
        let uncovered = wanted
            .hashes
            .iter()
            .copied()
            .filter(|hash| !wanted.covered.contains_key(hash) && !wanted.stored.contains(hash))
            .collect::<Vec<_>>();
        let reused = wanted
            .stored
            .iter()
            .filter(|hash| !wanted.covered.contains_key(hash))
            .count() as u64;
        if let Some(state) = updates.state.as_mut() {
            let groups = stored_groups(index, &live, wanted.covered, wanted.order.1);
            let stored = state.store(wanted.order.1, groups);
            updates.added += stored.added;
            updates.unrecorded += stored.overflow;
        }
        note_reused(&mut items[wanted.at], reused);
        // Only the unresolved prefix waits. Persisted retry debt reselects
        // the file after its own-turn ACK, even when it is unchanged; its
        // third decision emits any remaining unproven requests flagged.
        if walked.is_none() {
            defer_prefix(
                &mut items[wanted.at],
                &uncovered,
                &mut updates.state,
                wanted.order.1,
                "held_copy_deadline",
            );
            continue;
        }
        if wanted.waiting || uncovered.iter().any(|hash| wanted.stale.contains(hash)) {
            defer_prefix(
                &mut items[wanted.at],
                &uncovered,
                &mut updates.state,
                wanted.order.1,
                "held_copy_stale_holder",
            );
            continue;
        }
        // The pre-existing all-copy /branch lineage rule is not request-id
        // proof for a resumed prefix. Missing/retired ids there must emit
        // flagged, even when the transcript names an earlier parent.
        if !wanted.resumed
            && !uncovered.is_empty()
            && wanted
                .parent
                .as_deref()
                .is_some_and(|parent| parent_proves(index, parent, &wanted.session, wanted.order))
        {
            if let Some(state) = updates.state.as_mut() {
                state.clear_hold(wanted.order.1);
            }
            diag("copy_parent_ref", uncovered.len() as u64);
            restore_uncovered(&mut items[wanted.at], &[]);
            continue;
        }
        // A resumed file waits only for a possible earlier holder; an
        // all-copy file for any unscanned main file (unchanged).
        let blocked = !uncovered.is_empty()
            && if wanted.resumed {
                unscanned_earlier_main(index, &pending_files, &wanted.session, wanted.order)
            } else {
                pending
                    .get_or_init(|| unscanned_main_roots(index))
                    .iter()
                    .any(|root| *root != wanted.session)
            };
        if blocked {
            defer_prefix(
                &mut items[wanted.at],
                &uncovered,
                &mut updates.state,
                wanted.order.1,
                "held_copy_unscanned",
            );
            continue;
        }
        if let Some(state) = updates.state.as_mut() {
            state.clear_hold(wanted.order.1);
        }
        // Lead B Addendum 2: what no holder proves now (its id list retired,
        // over budget or missing, no stored removal) counts, flagged.
        let ids = skipped_ids(&items[wanted.at])
            .filter(|id| uncovered.binary_search(&claude_request_hash(id)).is_ok())
            .cloned()
            .collect::<Vec<_>>();
        restore_uncovered(&mut items[wanted.at], &ids);
    }
    updates
}

/// The file's removals to store: its stored hashes whose holder is still
/// indexed and not disproven by a record that lacks them, plus each newly
/// proven hash under its earliest current holder.
fn stored_groups<'a>(
    index: &'a ScanIndex,
    live: &std::cell::OnceCell<BTreeMap<LocationKey, &'a str>>,
    mut covered: BTreeMap<u64, (i128, LocationKey)>,
    file: LocationKey,
) -> BTreeMap<LocationKey, BTreeSet<u64>> {
    let mut groups = BTreeMap::<LocationKey, BTreeSet<u64>>::new();
    let old = index.claude_copy_removals.get(file);
    for (holder, hashes) in old {
        let Some(key) = live.get_or_init(|| indexed_main_files(index)).get(holder) else {
            continue;
        };
        let kept = hashes
            .iter()
            .filter(|&&hash| stored_holder_answer(index, key, hash) != Some(false));
        let into = groups.entry(*holder).or_default();
        for &hash in kept {
            // Consume covered entries once; never search every holder group
            // again for every currently proven request.
            covered.remove(&hash);
            into.insert(hash);
        }
    }
    groups.retain(|_, hashes| !hashes.is_empty());
    for (hash, (_, holder)) in covered {
        groups.entry(holder).or_default().insert(hash);
    }
    groups
}

/// Stored removals this decision kept without a current holder's proof.
fn note_reused(item: &mut SnapshotItem, reused: u64) {
    if let Some(fold) = item.claude_money.as_deref_mut() {
        fold.prefix.reused = reused;
        diag("copy_removal_reused", reused);
    }
}

/// A transient proof wait keeps only the unresolved prefix off this body's
/// totals. Its own turns emit, and persisted retry debt makes the prefix
/// discoverable after ACK/semantic no-op/restart. Third decision pass expires.
fn defer_prefix(
    item: &mut SnapshotItem,
    uncovered: &[u64],
    state: &mut Option<super::copy_removals::CopyRemovals>,
    file: LocationKey,
    reason: &'static str,
) {
    let ids = skipped_ids(item)
        .filter(|id| uncovered.binary_search(&claude_request_hash(id)).is_ok())
        .cloned()
        .collect::<Vec<_>>();
    let Some(state) = state.as_mut() else {
        hold_copies(item, reason);
        return;
    };
    if ids.is_empty() {
        state.clear_hold(file);
        restore_uncovered(item, &[]);
        return;
    }
    if !state.advance_hold(file) {
        restore_uncovered(item, &ids);
        if let Some(fold) = item.claude_money.as_deref_mut() {
            fold.prefix.hold_expired = ids
                .iter()
                .filter_map(|id| item.claude_usage_occurrences.get(id))
                .map(|o| o.usage.request_count)
                .sum();
        }
        return;
    }
    diag(reason, 1);
    let Some(fold) = item.claude_money.as_deref_mut() else {
        return;
    };
    // Id-less prefixes have no request-id proof to wait for: emit flagged.
    fold.restore_idless();
    for id in &ids {
        let Some(o) = item.claude_usage_occurrences.get(id) else {
            continue;
        };
        let tokens = ClaudeMoneyTokens::from_usage(&o.usage);
        if let (Some(tokens), Some(requests)) = (
            fold.entity.removed.checked_sub(&tokens),
            fold.entity
                .removed_requests
                .checked_sub(o.usage.request_count),
        ) {
            fold.entity.removed = tokens;
            fold.entity.removed_requests = requests;
            fold.copied = fold.copied.saturating_sub(1);
            fold.prefix.held_requests += o.usage.request_count;
        } else {
            fold.entity.certificate_ok = false;
        }
    }
    if fold.first_own.is_none() {
        // An all-copy file has no own turns to publish; retain its existing
        // whole-body hold, now bounded by the same retry debt.
        fold.entity.held = true;
        // Whole-body undecided counters are otherwise suppressed at finish;
        // the held prefix must still be visible in production diagnostics.
        let mut held = Counts::default();
        held.0[16] = fold.prefix.held_requests;
        held.0[17] = u64::from(fold.prefix.held_requests > 0);
        record_counts(held);
    }
    fold.proof = None;
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
    let holder_proof = matches!(fold.proof, Some(CopyProof::Holders(_)));
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
    if !holder_proof {
        fold.absorb_prefix_inherited(false);
    }
}

/// Move one matched transcript request from its estimated grain to its
/// reported grain: priced => telemetry_matched, no cost => telemetry_unpriced
/// (server rule). Counts never change. False when the estimated grain cannot
/// give it back (then it stays estimated and is disclosed).
fn attach_one(
    item: &mut SnapshotItem,
    holder: usize,
    row: &ClaudeLocalOtelEvidence,
    memo: &mut AttachMemo,
) -> bool {
    let SnapshotItem {
        claude_money: Some(fold),
        claude_usage_occurrences,
        ..
    } = item
    else {
        return false;
    };
    let Some(occurrence) = claude_usage_occurrences.get_mut(row.request_id.as_str()) else {
        return false;
    };
    if !enabled() {
        let attached = attach_dark(fold, occurrence, row);
        occurrence.telemetry_attached |= attached;
        return attached;
    }
    // The hour the estimated key is placed in (`occurrence_key`): its clock,
    // else the file's fallback; none or unreadable places no key.
    let clock = occurrence.timestamp.as_deref();
    let Some(hour) = clock
        .or(fold.bucket_fallback.as_deref())
        .and_then(rfc3339_unix_nanos)
        .map(|nanos| nanos.div_euclid(HOUR_NANOS))
    else {
        return false;
    };
    let account = fold
        .accounts
        .as_ref()
        .and_then(|a| a.account(occurrence.sequence));
    let shared = SlotInputs {
        holder,
        model: occurrence.model.as_deref().unwrap_or_else(|| {
            fold.model_fallbacks
                .get(&occurrence.sequence)
                .map_or("unknown", String::as_str)
        }),
        selector: Arc::as_ptr(&occurrence.selector) as usize,
        speed: "",
        effort: occurrence.reasoning_effort.as_deref(),
        hour,
        account: account.as_ref().map_or(0, |key| Arc::as_ptr(key) as usize),
        origin: None,
        copy_unproven: fold.copy_unproven_wire && fold.unproven_copy(occurrence),
    };
    let Some(estimated) = memo.estimated.get(shared, || {
        let key = fold.occurrence_key(occurrence)?;
        Some((key, None, account.clone()))
    }) else {
        return false;
    };
    // `reported_key`'s inputs (`reported_inputs`): the transcript's clock
    // wins, else the row's; the row's speed joins the selector.
    let Some(reported_hour) = (match clock {
        Some(_) => Some(hour),
        None => rfc3339_unix_nanos(&row.observed_at).map(|nanos| nanos.div_euclid(HOUR_NANOS)),
    }) else {
        return false;
    };
    let origin = if row.cost_usd_micros.is_some() {
        ClaudeRequestUsageOrigin::TelemetryMatched
    } else {
        ClaudeRequestUsageOrigin::TelemetryUnpriced
    };
    let (model, effort) = reported_model_effort(&row.model, &row.effort, Some(occurrence));
    let inputs = SlotInputs {
        model,
        speed: &row.speed,
        effort,
        hour: reported_hour,
        origin: Some(origin),
        ..shared
    };
    let Some(reported) = memo.reported.get(inputs, || {
        let mut key = reported_key(row, Some(occurrence), &fold.base_selector)?;
        if inputs.copy_unproven {
            mark_copy_key(&mut key);
        }
        Some((key, Some(origin), account.clone()))
    }) else {
        return false;
    };
    let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
    let requests = occurrence.usage.request_count;
    if !fold.entity.take_estimated(estimated, &tokens, requests) {
        return false;
    }
    // Keep the existing wire bucket activity clock. Identity independently
    // folds own-request clocks after attachment; observer time never decides
    // the local current account.
    let at = (reported.0 .0 != estimated.0 .0)
        .then(|| rfc3339_unix_nanos(&row.observed_at))
        .flatten();
    fold.entity
        .add_slot(reported, &tokens, requests, row.cost_usd_micros, at);
    if let Some(cost) = row.cost_usd_micros {
        if fold.resumed_prefix && fold.unproven_copy(occurrence) {
            fold.prefix.priced_requests += requests;
            fold.prefix.cost_micros = fold.prefix.cost_micros.saturating_add(cost);
        }
    }
    occurrence.telemetry_attached = true;
    true
}

/// A grain slot: its key, origin and account partition.
type Slot = (
    ClaudeLiveKey,
    Option<ClaudeRequestUsageOrigin>,
    AccountPartition,
);

/// What places a matched row's slot. Equal inputs place equal keys: the
/// holder fixes the fold (base selector, fallback clock, model fallbacks),
/// the selector is the occurrence's shared one (one per distinct value in a
/// file) and the account its shared partition, so pointers identify them
/// while the page holds them.
#[derive(Clone, Copy)]
struct SlotInputs<'a> {
    holder: usize,
    model: &'a str,
    selector: usize,
    speed: &'a str,
    effort: Option<&'a str>,
    hour: i128,
    account: usize,
    origin: Option<ClaudeRequestUsageOrigin>,
    copy_unproven: bool,
}
struct PlacedSlot {
    holder: usize,
    model: String,
    selector: usize,
    speed: String,
    effort: Option<String>,
    hour: i128,
    account: usize,
    origin: Option<ClaudeRequestUsageOrigin>,
    copy_unproven: bool,
    slot: Option<Slot>,
}
impl PlacedSlot {
    fn placed_by(&self, inputs: &SlotInputs<'_>) -> bool {
        self.holder == inputs.holder
            && self.hour == inputs.hour
            && self.selector == inputs.selector
            && self.account == inputs.account
            && self.origin == inputs.origin
            && self.copy_unproven == inputs.copy_unproven
            && self.model == inputs.model
            && self.speed == inputs.speed
            && self.effort.as_deref() == inputs.effort
    }
}

/// A family's matched rows repeat a few slots (one holder, hour, model):
/// each is placed once for its run of rows. Transient per family and bounded
/// (`MEMO_SLOTS`, recycled in turn), so it never grows with the page.
#[derive(Default)]
struct SlotMemo {
    placed: Vec<PlacedSlot>,
    next: usize,
}
const MEMO_SLOTS: usize = 8;
impl SlotMemo {
    fn get(
        &mut self,
        inputs: SlotInputs<'_>,
        place: impl FnOnce() -> Option<Slot>,
    ) -> Option<&Slot> {
        let at = match self
            .placed
            .iter()
            .position(|placed| placed.placed_by(&inputs))
        {
            Some(at) => at,
            None => {
                let placed = PlacedSlot {
                    holder: inputs.holder,
                    model: inputs.model.to_owned(),
                    selector: inputs.selector,
                    speed: inputs.speed.to_owned(),
                    effort: inputs.effort.map(str::to_owned),
                    hour: inputs.hour,
                    account: inputs.account,
                    origin: inputs.origin,
                    copy_unproven: inputs.copy_unproven,
                    slot: place(),
                };
                if self.placed.len() < MEMO_SLOTS {
                    self.placed.push(placed);
                    self.placed.len() - 1
                } else {
                    let at = self.next;
                    self.placed[at] = placed;
                    self.next = (at + 1) % MEMO_SLOTS;
                    at
                }
            }
        };
        self.placed[at].slot.as_ref()
    }
}
#[derive(Default)]
struct AttachMemo {
    estimated: SlotMemo,
    reported: SlotMemo,
}

/// Gate off, `attach_one` without a grain map: the same checks and the same
/// tally moves. The estimated slot is its hour (`occurrence_key`, then
/// `take_estimated`'s fallback); the reported key only has to exist, and
/// with a transcript clock it is that clock's hour, already checked. The
/// tally ignores the reported key and clock, so neither is built.
fn attach_dark(
    fold: &mut FileFold,
    occurrence: &ClaudeTranscriptUsageOccurrence,
    row: &ClaudeLocalOtelEvidence,
) -> bool {
    let Some(estimated) = fold.occurrence_key(occurrence) else {
        return false;
    };
    if occurrence.timestamp.is_none() && hour_key(&row.observed_at).is_none() {
        return false;
    }
    let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
    let requests = occurrence.usage.request_count;
    let tally = &mut fold.entity.dark;
    if !bucket_hour(&estimated.0).is_some_and(|hour| tally.take(hour, &tokens, requests)) {
        return false;
    }
    tally.add(None, &tokens, requests, row.cost_usd_micros);
    true
}

/// Re-place an already-counted native request after the identity owner has
/// classified its exact telemetry. Reuse attachment's keys and exact money;
/// no second resolver, token counter or row allocator participates.
pub(crate) fn place_request_identity(
    fold: &mut FileFold,
    occurrence: &ClaudeTranscriptUsageOccurrence,
    telemetry: Option<&ClaudeLocalOtelEvidence>,
    from: AccountPartition,
    to: AccountPartition,
) {
    let Some(estimated) = fold.occurrence_key(occurrence) else {
        return;
    };
    let reported = telemetry
        .filter(|_| occurrence.telemetry_attached)
        .and_then(|row| {
            let mut key = reported_key(row, Some(occurrence), &fold.base_selector)?;
            if fold.copy_unproven_wire && fold.unproven_copy(occurrence) {
                mark_copy_key(&mut key);
            }
            let origin = if row.cost_usd_micros.is_some() {
                ClaudeRequestUsageOrigin::TelemetryMatched
            } else {
                ClaudeRequestUsageOrigin::TelemetryUnpriced
            };
            fold.entity
                .grains
                .contains_key(&(key.clone(), Some(origin), from.clone()))
                .then_some((key, Some(origin), row.cost_usd_micros))
        });
    let (key, origin, cost) = reported.unwrap_or((estimated, None, None));
    let slot = (key.clone(), origin, from);
    let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
    let requests = occurrence.usage.request_count;
    let at = occurrence.timestamp.as_deref().and_then(rfc3339_unix_nanos);
    if slot.2 == to {
        if let Some(grain) = fold.entity.grains.get_mut(&slot) {
            grain.last_own_at = grain.last_own_at.max(at);
        }
        return;
    }
    // take_estimated owns exact token/request removal; reported contributions
    // differ only in the cost and unpriced counters removed alongside them.
    let Some(grain) = fold.entity.grains.get(&slot) else {
        fold.entity.certificate_ok = false;
        return;
    };
    let Some(left_cost) = grain.cost_micros.checked_sub(cost.unwrap_or(0)) else {
        fold.entity.certificate_ok = false;
        return;
    };
    let unpriced = grain.unpriced;
    if !fold.entity.take_estimated(&slot, &tokens, requests) {
        fold.entity.certificate_ok = false;
        return;
    }
    if let Some(grain) = fold.entity.grains.get_mut(&slot) {
        grain.cost_micros = left_cost;
        grain.unpriced = unpriced.saturating_sub(u64::from(cost.is_none()));
    }
    fold.entity
        .add(key, &tokens, requests, cost, origin, at, to);
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
        if resumed_prefix_enabled() {
            for row in report.rows {
                let Some(cost) = row.cost_usd_micros else {
                    continue;
                };
                if report.duplicate_keys.contains(&row.request_id)
                    || !validate_claude_api_row(row, root)
                {
                    continue;
                }
                for at in matching_members(&membership, &row.request_id) {
                    let mut items = items.borrow_mut();
                    let item = &mut items[at];
                    let Some(occurrence) = item.claude_usage_occurrences.get(&row.request_id)
                    else {
                        continue;
                    };
                    let Some(fold) = item.claude_money.as_deref_mut() else {
                        continue;
                    };
                    // A partially held prefix has no per-id final removal view.
                    // Leave its dollars uncovered rather than pricing a hold.
                    if fold.resumed_prefix
                        && !fold.entity.held
                        && fold.prefix.held_requests == 0
                        && fold.is_skipped(occurrence.sequence)
                        && !fold.is_ambiguous(&row.request_id)
                        && !occurrence.usage.is_zero()
                        && claude_api_matches_transcript_occurrence(row, occurrence)
                    {
                        fold.prefix.removed_priced_requests += occurrence.usage.request_count;
                        fold.prefix.removed_cost_micros =
                            fold.prefix.removed_cost_micros.saturating_add(cost);
                    }
                }
            }
        }
        let mut disclosed = 0u64;
        let mut memo = AttachMemo::default();
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
                        if !attach_one(&mut items[holder], holder, row, &mut memo) {
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
    if !index.persistence_available() {
        return items.iter().map(|i| i.source_session_id.clone()).collect();
    }

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
            if enabled() {
                if let Some(at) = at {
                    fold.entity.note_activity(&key.0, at, at);
                }
            }
            timed("side.add", || {
                fold.entity.add(
                    key,
                    &tokens,
                    1,
                    row.cost_usd_micros,
                    Some(origin),
                    None,
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
    if !index.persistence_available() {
        let held = items.iter().map(|i| i.source_session_id.clone()).collect();
        items.clear();
        return held;
    }

    let _spent = PageSpent::start("page.finish");
    struct Session {
        entity: ClaudeEntityBody,
        /// A single-path session's entity is moved out of its fold, not
        /// cloned. A path twin's arrival keeps the first fold's own entity
        /// here, so a withheld session's items stay unchanged.
        first_original: Option<ClaudeEntityBody>,
        /// The first fold's own (telemetry_owned_complete, held,
        /// activity_nanos, clock_incomplete), restored on a withheld session.
        first_undo: (bool, bool, i128, bool),
        folds: usize,
        complete: bool,
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
    let mut corrected_sessions = BTreeSet::new();
    let mut sessions = BTreeMap::<&str, Session>::new();
    for item in items.iter_mut() {
        let SnapshotItem {
            claude_money: Some(fold),
            source_session_id,
            claude_usage_occurrences,
            ..
        } = item
        else {
            continue;
        };
        let source_session_id: &String = source_session_id;
        // OFF would restore an uncertified resumed prefix. Count only a
        // proven removal, never a held/unproven request or certified skip.
        if fold.resumed_prefix
            && fold.first_own.is_some()
            && !fold.money_birth.writer_certified(fold.first_own)
            && fold.entity.removed_requests > 0
        {
            corrected_sessions.insert(source_session_id.clone());
        }
        // Work counts on every read; decisions only when decided (below).
        diag_max("max_file_fold_us", fold.e2_nanos.0 / 1_000);
        record_counts(Counts::work([
            fold.e2_nanos.0 / 1_000,
            fold.responses,
            0,
            0,
            0,
            0,
            0,
        ]));
        let session = sessions
            .entry(source_session_id.as_str())
            .or_insert_with(|| Session {
                entity: Default::default(),
                first_original: None,
                first_undo: Default::default(),
                folds: 0,
                complete: telemetry == TelemetryRead::Loaded,
                locations: Vec::new(),
                decided: Counts::default(),
            });
        diag("resolver_conflict", fold.entity.resolver_conflicts);
        let unproven = fold.prefix.unproven_requests + fold.prefix.unproven_idless;
        diag("copy_prefix_unproven", unproven);
        diag("copy_prefix_unproven_files", u64::from(unproven > 0));
        diag("copy_prefix_unproven_cost_micros", fold.prefix.cost_micros);
        diag("copy_removal_metadata_lost", fold.prefix.metadata_lost);
        diag("copy_prefix_held_requests", fold.prefix.held_requests);
        diag(
            "copy_prefix_held_files",
            u64::from(fold.prefix.held_requests > 0),
        );
        diag("copy_prefix_hold_expired", fold.prefix.hold_expired);
        session.decided.add(&Counts::prefix(&fold.prefix));
        if fold.resumed_prefix {
            session.decided.0[22] += fold.own_requests;
            diag(
                "copy_prefix_removed_priced_requests",
                fold.prefix.removed_priced_requests,
            );
            diag(
                "copy_prefix_removed_cost_micros",
                fold.prefix.removed_cost_micros,
            );
            diag("copy_prefix_own_requests", fold.own_requests);
        }
        session.decided.add(&Counts::work([
            0,
            0,
            fold.entity.removed_requests,
            // disclosed: everything counted without proof, resolver
            // conflicts included, once per decision.
            fold.disclosed + fold.entity.resolver_conflicts,
            fold.unmatched_1h(&hour_ago),
            fold.root_fallbacks,
            fold.entity.resolver_conflicts,
        ]));
        session.complete &= fold.telemetry_complete();
        session.folds += 1;
        if session.folds == 1 {
            // Exactly the sum of one fold into an empty body (activity never
            // below the empty body's zero), without cloning its grains.
            session.entity = std::mem::take(&mut fold.entity);
            let entity = &mut session.entity;
            session.first_undo = (
                entity.telemetry_owned_complete,
                entity.held,
                entity.activity_nanos,
                entity.clock_incomplete,
            );
            entity.activity_nanos = entity.activity_nanos.max(0);
        } else {
            if session.folds == 2 && enabled() {
                session.first_original = Some(session.entity.clone());
            }
            session.entity.sum(&fold.entity);
        }
        session.entity.clock_incomplete |= claude_usage_occurrences.values().any(|occurrence| {
            !occurrence.usage.is_zero()
                && !fold.is_skipped(occurrence.sequence)
                && (!occurrence.event_clock_complete
                    || occurrence
                        .timestamp
                        .as_deref()
                        .and_then(rfc3339_unix_nanos)
                        .is_none())
        });
        session
            .locations
            .extend(fold.location.map(|located| located.0));
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
            let first = (state.first_original, state.first_undo);
            (session.to_owned(), (state.entity, first))
        })
        .collect::<BTreeMap<_, _>>();
    let mut withheld = BTreeSet::new();
    let mut corrected_families = BTreeSet::new();
    items.retain_mut(|item| {
        if item.claude_money.is_none() {
            return true;
        }
        // One body per session: the first item carries the summed entity.
        // A withheld session keeps every item (twins too) for the hold.
        let Some((entity, (first_original, undo))) = entities.remove(&item.source_session_id)
        else {
            return withheld.contains(&item.source_session_id);
        };
        // apply refuses before mutating, so a withheld item is unchanged:
        // its fold gets its own entity back (moved out above).
        let emitted = super::emit::apply(item, &entity);
        if emitted {
            if corrected_sessions.contains(&item.source_session_id) {
                corrected_families.insert(claude_snapshot_family_root_ref(item).to_owned());
            }
            if let Some(marked) = item.copy_unproven_counts {
                let mut counts = Counts::default();
                counts.0[19] = marked.rows;
                record_counts(counts);
                diag("copy_prefix_unproven_rows", marked.rows);
            }
        }
        if !emitted {
            withheld.insert(item.source_session_id.clone());
        }
        if let Some(fold) = item.claude_money.as_deref_mut() {
            fold.entity = match (emitted, first_original) {
                // Keep the final summed placement for contract 5, not the first twin.
                (true, _) => entity,
                (false, original) => {
                    let mut original = original.unwrap_or(entity);
                    (
                        original.telemetry_owned_complete,
                        original.held,
                        original.activity_nanos,
                        original.clock_incomplete,
                    ) = undo;
                    original
                }
            };
        }
        true
    });
    if !corrected_families.is_empty() {
        let mut counts = Counts::default();
        counts.0[23] = corrected_families.len() as u64;
        diag("copy_prefix_families_corrected", counts.0[23]);
        record_counts(counts);
    }
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
    mut visit: impl FnMut(
        &str,
        super::super::SnapshotModelUsage,
        AccountPartition,
        Option<u64>,
        Option<i128>,
    ),
) -> Option<()> {
    let fold = item.claude_money.as_deref()?;
    for ((key, origin, account), grain) in &fold.entity.grains {
        visit(
            &key.0,
            super::emit::grain_row(key, *origin, grain, None),
            account.clone(),
            grain.cost(),
            grain.last_own_at,
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
const COUNT_NAMES: [&str; 24] = [
    "fold_us",
    "responses",
    "copy_skipped",
    "disclosed",
    "unmatched_1h",
    "side_call_root_fallback",
    "resolver_conflicts",
    // Copy-family fix (Lead B Addendum 2), class N, diagnostics only: the
    // flagged copied-prefix requests and files, the matched priced share
    // with its reported cost, stored removals reused without a current
    // holder, and stored-removal writes and cap refusals.
    "copy_prefix_unproven_requests",
    "copy_prefix_unproven_files",
    "copy_prefix_unproven_priced_requests",
    "copy_prefix_unproven_cost_micros",
    "copy_removal_reused",
    "copy_removal_stored",
    "copy_removal_store_overflow",
    "copy_removed_unrecorded",
    "copy_removal_metadata_lost",
    "copy_prefix_held_requests",
    "copy_prefix_held_files",
    "copy_prefix_hold_expired",
    "copy_prefix_unproven_rows",
    "copy_prefix_removed_priced_requests",
    "copy_prefix_removed_cost_micros",
    "copy_prefix_own_requests",
    "copy_prefix_families_corrected",
];
static COUNTS: [AtomicU64; 24] = [const { AtomicU64::new(0) }; 24];
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
        record_counts(Counts::work([spent, 0, 0, 0, 0, 0, 0]));
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
pub(crate) struct Counts([u64; 24]);
impl Counts {
    /// The first seven (work and decision) counters.
    fn work(values: [u64; 7]) -> Self {
        let mut all = [0; 24];
        all[..7].copy_from_slice(&values);
        Self(all)
    }
    /// A decided fold's copied-prefix outcome.
    fn prefix(tally: &PrefixTally) -> Self {
        let unproven = tally.unproven_requests + tally.unproven_idless;
        let mut all = [0; 24];
        all[7..12].copy_from_slice(&[
            unproven,
            u64::from(unproven > 0),
            tally.priced_requests,
            tally.cost_micros,
            tally.reused,
        ]);
        all[15] = tally.metadata_lost;
        all[16] = tally.held_requests;
        all[17] = u64::from(tally.held_requests > 0);
        all[18] = tally.hold_expired;
        all[20] = tally.removed_priced_requests;
        all[21] = tally.removed_cost_micros;
        Self(all)
    }
    fn removal_store(added: u64, overflow: u64) -> Self {
        let mut all = [0; 24];
        all[12] = added;
        all[13] = overflow;
        all[14] = overflow;
        Self(all)
    }
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

impl crate::heap_layout_bound::HeapLayoutBound for ClaudeMoneyTokens {
    const INLINE_ONLY: bool = true;
    const STABLE_HEAP: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        let Self {
            input: _,
            output: _,
            cache_read: _,
            cache_5m: _,
            cache_1h: _,
            unattributed: _,
            reasoning: _,
        } = self;
        c.add(0)
    }
}

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
