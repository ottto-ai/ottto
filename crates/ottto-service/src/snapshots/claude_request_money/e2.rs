//! `e2` request-owned Claude money from the native resolved-response fold.
//! Native resolution owns counts; this module only decides copies, attaches
//! reported telemetry cost and side calls, and emits one literal body per
//! session.
//!
//! Layout: `copies` (copy decisions and stored copy ownership) and
//! `telemetry` (attach and side calls). This file keeps the fold state,
//! the entity, the money rules, grain and family keys, and finish.
use super::super::claude_history_upgrade::{
    claude_path_twin_groups, path_twins, ClaudeTwinGroups, REQUEST_OWNED_USAGE_CONTRACT,
};
use super::super::claude_money_birth_store::{location_key, LocationKey};
use super::super::claude_request_census::claude_request_hash;
use super::super::claude_request_identity::{self, AccountPartition, LentSlot, RequestAccounts};
use super::super::sources::claude::context_file_birth::ClaudeFileBirth;
use super::super::{
    claude_family_root_path, claude_index_path_member_ref, claude_row_placement,
    claude_snapshot_family_root_ref, claude_trace_evidence_fingerprint_is_valid, local_index_key,
    rfc3339_unix_nanos, ClaudeTranscriptUsageOccurrence, PlacedClaudeUsage, RowKey, ScanIndex,
    ScanTraversalPath, SelectorCapture, SnapshotItem, UsageTotals,
};
use super::body::{reported_inputs, ClaudeGrainSide, ClaudeLiveKey, ClaudeRequestUsageOrigin};
use super::ClaudeMoneyTokens;
use crate::claude_local_otel::{
    ClaudeApiEvidenceRead, ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport,
    ClaudeTraceOwnershipLoadReport,
};
use crate::telemetry_attach::Holders;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

mod copies;
mod telemetry;

use self::copies::{absent_twins, mark_settled_counted_copies};
#[cfg(test)]
pub(crate) use self::copies::{
    carrier_group_owned_for_test, copied_file_holders_for_test, decide_page_copies,
    reconcile_carrier_images_for_test,
};
pub(in crate::snapshots) use self::copies::{
    copied_file_holders, earlier_holders, first_own_turn_at, selected_twin_roots, Carriers,
    CopyOwnership,
};
pub(crate) use self::copies::{decide_page_copies_planned, page_content_holds};
#[cfg(test)]
use self::copies::{
    from_copy_proof_cutoff, indexed_main_files, origin_owned, parent_proves,
    reconcile_copy_ownership, restore_uncovered, saved_removal_applies, scan_evidence, skipped_ids,
    Evidence, COPY_PROOF_FROM, SUBAGENT_TWIN_FROM,
};
pub(in crate::snapshots) use self::telemetry::defer_roots_of_queued_families;
#[cfg(test)]
use self::telemetry::holders;
pub(crate) use self::telemetry::{
    add_reported_row, attach_page, place_request_identity, side_calls_page, telemetry_scope,
    SideCallDiscovery,
};

/// A record this much older than its file's effective birth was copied in.
/// Copies written within it are counted (known residual, disclosed nowhere).
pub(in crate::snapshots) const SLACK: i128 = 2_000_000_000;
const HOUR_NANOS: i128 = 3_600_000_000_000;

/// Revision 3 keeps a listed family on ordinary (pre-`e2`) money. With the
/// gate on, `e2` applies to every other family, also while the list pauses
/// adoption: a pause holds adoption only, never emission. A family it does
/// not apply to behaves exactly as gate off (no fold, so no literal).
pub(crate) fn family_applies(index: &ScanIndex, root: &str, subagent_stem: Option<&str>) -> bool {
    !index
        .claude_reemission_exclusions
        .excludes(root, subagent_stem)
}

/// `family_applies` for the family of the file a parse opened.
pub(in crate::snapshots) fn file_applies(context: &ReadContext<'_>) -> bool {
    !context.index.claude_family_listed(context.path)
}
// Synthetic transcripts are created when a test runs, after their records'
// fixed timestamps, so `e2` would read every record as copied in. A fixture
// that models ordinary transcripts (written after their file's birth) sets
// the physical birth `e2` sees for every file read on this thread. Staged
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

// Per-stage wall clock for the perf receipt. Test builds only: the
// daemon build has no timer here, `timed` is just the call.
#[cfg(test)]
thread_local! {
    static STAGES: RefCell<BTreeMap<&'static str, Duration>> = const { RefCell::new(BTreeMap::new()) };
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
/// Runs `f`, then puts this thread's diag and stage timers back as they were
/// before it: a comparison run that observes and leaves no count behind.
#[cfg(test)]
pub(crate) fn without_diag<T>(f: impl FnOnce() -> T) -> T {
    let diag = take_diag();
    let stages = STAGES.with(|slot| std::mem::take(&mut *slot.borrow_mut()));
    let value = f();
    DIAG.with(|slot| *slot.borrow_mut() = diag);
    STAGES.with(|slot| *slot.borrow_mut() = stages);
    value
}
#[inline(always)]
pub(in crate::snapshots) fn diag(reason: &'static str, n: u64) {
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

/// The parse-time view of the durable birth table (`BirthStore`).
pub(in crate::snapshots) struct ReadContext<'a> {
    pub(in crate::snapshots) index: &'a ScanIndex,
    pub(in crate::snapshots) path: &'a Path,
    /// The page's path-twin groups: the one twin rule, built once per page.
    pub(in crate::snapshots) twins: &'a std::cell::OnceCell<ClaudeTwinGroups>,
}
impl ReadContext<'_> {
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

/// Same member spelling as the twin index, including subagent stems.
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
crate::heap_layout_bound::no_heap!(false; Role);
/// This root file's own location key (inline digest).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Located(LocationKey);
crate::heap_layout_bound::no_heap!(false; Located);

/// The proof a held copy skip needs; `decide_page_copies` checks it per
/// request once per page.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CopyProof {
    /// Earlier MAIN files of other sessions in the copy's own folder
    /// (`folder`: its parent directory's index key), for /branch and
    /// resume. `parent`: the index key of the original its
    /// `fork-context-ref` line names.
    Holders {
        parent: Option<String>,
        folder: String,
    },
    /// A subagent's family root (its index key): a forked subagent repeats
    /// the parent's last response as its first line, so that first response
    /// counts once, at the root, when the root holds its request id.
    Family(String),
}
impl crate::heap_layout_bound::HeapLayoutBound for CopyProof {
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        match self {
            Self::Holders { parent, folder } => {
                if let Some(parent) = parent {
                    parent.heap_bound(c)?;
                }
                folder.heap_bound(c)
            }
            Self::Family(key) => key.heap_bound(c),
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
    /// `STAMPED_WITHOUT_PERMIT`, retired with the identity permit
    /// (contract 5 always on). Stores may still carry it: it is decoded and
    /// carried through every restamp as stored (durable entry digests bind
    /// the raw byte), but never set, cleared, acted on or replayed.
    pub(crate) const RETIRED_PERMIT: u8 = 64;
}
/// The money-rule epoch stamped on each stored Claude request at its first
/// admission (`ClaudeResponseObservation.rule_epoch`). A field only: no
/// reader, no gate and no stored contribution. Its meaning belongs to E2.
/// A rule acting at parse time is forward under Tail by construction; one
/// acting in the fold gates on the request's own provider timestamp
/// (`observed_at >= T`, as `provider_context_bucket` does), so a cold read
/// equals a stored one; anything else goes through the operator command.
/// 2: org lines govern requests from `ACCOUNT_RULE_FROM`.
pub(crate) const RULE_EPOCH: u8 = 2;

/// Money-rule versions and the marks each one re-reads. Version 1 is the
/// switch-on, whose revision 3 already re-reads every file. A later money
/// fix appends a row naming the marks it changes, so only those files are
/// re-owed (once, under the history budget); never a revision bump, which
/// re-reads the whole history. Version 2 re-owes nothing (the identity-permit
/// change seeded the retired permit mark there); it stays so stored versions
/// keep their meaning.
/// Version 4 re-owes subagent path twins once: a shared response within the
/// copy slack before the later home's birth counts at the earlier home.
/// Version 5 marks settled counted copies once when current holder proof
/// disagrees, without re-owing a body revision or selecting the holder.
const MONEY_RULES: &[(u16, u8)] = &[(1, 0), (2, 0), (3, 0), (4, 0), (5, 0)];
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
    // These serde-skipped inputs have served every local consumer. Release
    // them on the emitted body before upload and settlement.
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
        native_copied: _,
        first_own,
        twin_pending: _,
        ambiguous,
        disclosed: _,
        e2_nanos: _,
        responses: _,
        root_fallbacks: _,
        side: _,
        telemetry,
        accounts,
        prefix: _,
        fork_parent,
        own_tools,
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
    *fork_parent = None;
    *own_tools = None;
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
    if stored >= current {
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
    let rule = |version: u16| stored < version && rules.iter().any(|&(v, _)| v == version);
    let (three, four) = (rule(3), rule(4));
    let twins = (three || four).then(|| claude_path_twin_groups(index, &BTreeSet::new()));
    // Subagent path twins: rule 3 re-owes them with its main copies; from
    // version 3, rule 4 re-owes them alone. Selected once either way.
    let mut subagent = twins
        .as_ref()
        .map(|twins| subagent_twin_files(index, twins))
        .unwrap_or_default();
    if let Some(twins) = twins.as_ref().filter(|_| three) {
        let start = Instant::now();
        let candidates = index.files.keys().filter(|key| {
            claude_index_path_member_ref(Path::new(key)).is_some_and(|member| {
                member.subagent_stem.is_none()
                    && (index
                        .claude_request_census
                        .get(key)
                        .is_some_and(|r| r.is_twin())
                        || path_twins(twins, member.root).is_some()
                        // A cross-session resume can have its own path and
                        // content identity; its counted unproven prefix is
                        // the evidence that selects the correction once.
                        || index.claude_money_birth_store.money_marks(location_key(key))
                            & money_mark::DISCLOSED != 0)
            })
        });
        let selected = copied_file_holders(index, candidates.map(String::as_str));
        let mut reowed = std::mem::take(&mut subagent);
        diag(
            "money_rule_v3_selector_ms",
            start.elapsed().as_millis() as u64,
        );
        for (copy, holder) in selected {
            reowed.insert(copy);
            reowed.insert(holder);
        }
        diag("money_rule_v3_reowed", reowed.len() as u64);
        owed.extend(reowed);
    }
    if four {
        owed.extend(subagent);
    }
    for key in owed {
        index.re_owe_effective_upload_body_witness_revision(&key, to);
    }
    if rule(5) {
        mark_settled_counted_copies(index);
    }
    live.sort_unstable();
    let store = &mut index.claude_money_birth_store;
    store.retain_money_marks(&live);
    store.set_money_rule_version(current);
}

/// Subagent path twins need no main-holder walk: their indexed census
/// overlap selects both homes for one co-read, including copied prefixes.
fn subagent_twin_files(index: &ScanIndex, twins: &ClaudeTwinGroups) -> BTreeSet<String> {
    let mut owed = BTreeSet::new();
    for homes in twins.values() {
        if !homes.first().is_some_and(|(key, _)| {
            claude_index_path_member_ref(Path::new(key))
                .is_some_and(|member| member.subagent_stem.is_some())
        }) {
            continue;
        }
        for (at, (key, _)) in homes.iter().enumerate() {
            let Some(record) = index
                .claude_request_census
                .get(key)
                .filter(|r| r.proves_scan())
            else {
                continue;
            };
            for (other, _) in &homes[..at] {
                let Some(holder) = index
                    .claude_request_census
                    .get(other)
                    .filter(|r| r.proves_scan())
                else {
                    continue;
                };
                for &hash in record.request_hashes() {
                    if holder.holds_hash(hash) {
                        owed.insert(key.clone());
                        owed.insert(other.clone());
                        break;
                    }
                }
            }
        }
    }
    owed
}

/// Fixed count-only causes of the existing certificate veto.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CertificateFailure {
    UnplaceableUsage,
    CopyRestoration,
    IdlessRestoration,
    AmbiguousDuplicate,
    IdentityGrain(IdentityCaller, GrainNearMiss),
    IdentityCost,
    IdentityUsage,
}
/// Which re-placement asked for the missing identity grain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityCaller {
    Request,
    Carry,
    UnprovenCopy,
}
/// Where the request's key or account was found instead of the exact slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum GrainNearMiss {
    OtherAccount,
    OtherKey,
    Absent,
}
impl CertificateFailure {
    fn hold_reason(self) -> &'static str {
        match self {
            Self::UnplaceableUsage => "uncertified_by=unplaceable_usage",
            Self::CopyRestoration => "uncertified_by=copy_restoration",
            Self::IdlessRestoration => "uncertified_by=idless_restoration",
            Self::AmbiguousDuplicate => "uncertified_by=ambiguous_duplicate",
            Self::IdentityGrain(caller, near) => {
                use GrainNearMiss::{Absent, OtherAccount, OtherKey};
                use IdentityCaller::{Carry, Request, UnprovenCopy};
                match (caller, near) {
                    (Request, OtherAccount) => {
                        "uncertified_by=identity_grain.request.other_account"
                    }
                    (Request, OtherKey) => "uncertified_by=identity_grain.request.other_key",
                    (Request, Absent) => "uncertified_by=identity_grain.request.absent",
                    (Carry, OtherAccount) => "uncertified_by=identity_grain.carry.other_account",
                    (Carry, OtherKey) => "uncertified_by=identity_grain.carry.other_key",
                    (Carry, Absent) => "uncertified_by=identity_grain.carry.absent",
                    (UnprovenCopy, OtherAccount) => {
                        "uncertified_by=identity_grain.copy.other_account"
                    }
                    (UnprovenCopy, OtherKey) => "uncertified_by=identity_grain.copy.other_key",
                    (UnprovenCopy, Absent) => "uncertified_by=identity_grain.copy.absent",
                }
            }
            Self::IdentityCost => "uncertified_by=identity_cost",
            Self::IdentityUsage => "uncertified_by=identity_usage",
        }
    }
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
    pub(super) certificate_failure: Option<CertificateFailure>,
    /// Local-only uncertainty from every counted path twin.
    pub(crate) clock_incomplete: bool,
    /// Exact telemetry exceeded the identity owner's bounded key pool.
    pub(crate) identity_over_cap: bool,
    // False proves both live maps have never allocated. Empty live maps
    // retain their conservative root charge after a removal.
    pub(super) live_maps_initialized: bool,
    pub(crate) activity_unix: u64,
    pub(crate) activity_nanos: i128,
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
            certificate_failure: None,
            clock_incomplete: false,
            identity_over_cap: false,
            live_maps_initialized: false,
            activity_unix: 0,
            activity_nanos: 0,
        }
    }
}
pub(super) const COPY_UNPROVEN_KEY: &str = "__ottto_copy_unproven";
fn mark_copy_key(key: &mut ClaudeLiveKey) {
    key.2.insert(COPY_UNPROVEN_KEY.into(), "true".into());
}
impl ClaudeEntityBody {
    fn fail_certificate(&mut self, reason: CertificateFailure) {
        self.certificate_ok = false;
        self.certificate_failure.get_or_insert(reason);
    }

    fn mark_copy_unproven(&mut self) {
        self.grains = std::mem::take(&mut self.grains)
            .into_iter()
            .map(|((mut key, origin, account), grain)| {
                mark_copy_key(&mut key);
                ((key, origin, account), grain)
            })
            .collect();
    }

    #[expect(clippy::too_many_arguments, reason = "8 args; no options struct yet")]
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
        self.certificate_failure = self.certificate_failure.or(other.certificate_failure);
        self.clock_incomplete |= other.clock_incomplete;
        self.identity_over_cap |= other.identity_over_cap;
        self.activity_unix = self.activity_unix.max(other.activity_unix);
        self.activity_nanos = self.activity_nanos.max(other.activity_nanos);
    }
    fn totals(&self) -> (ClaudeMoneyTokens, u64) {
        let mut tokens = ClaudeMoneyTokens::default();
        let mut requests = 0u64;
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
    }
    /// Responses folded in (grains and the dark tally).
    fn contributions(&self) -> u64 {
        self.grains
            .values()
            .map(|grain| grain.contributions)
            .sum::<u64>()
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
            return false;
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

// A never-initialized live map cannot have a retained empty root. Charging
// fictitious roots here makes a dark file exceed the native finish budget.
// Initialized maps keep the ordinary conservative bound even after emptying.
macro_rules! entity_heap_method {
    ($method:ident) => {
        fn $method(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
            let Self {
                grains,
                bucket_activity,
                live_maps_initialized,
                removed: _,
                removed_requests: _,
                telemetry_owned_complete: _,
                resolver_conflicts: _,
                held: _,
                certificate_ok: _,
                certificate_failure: _,
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
            Some(())
        }
    };
}
impl crate::heap_layout_bound::HeapLayoutBound for ClaudeEntityBody {
    const STABLE_HEAP: bool = true;
    entity_heap_method!(heap_bound);
    entity_heap_method!(completed_heap_bound);
}
// Existing grain types were inline values; E retains only the aggregate.
// Exhaustive: every field is an inline token/counter, already paid
// by its containing slot. No per-token graph walk is needed.
crate::heap_layout_bound::no_heap!(true; ClaudeGrainSide {
    tokens, requests, cost_micros, unpriced, contributions, last_own_at,
});
crate::heap_layout_bound::no_heap!(false; ClaudeRequestUsageOrigin);

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
crate::heap_layout_bound::split_fields!(FoldTelemetry; inline: [read, complete, side_candidates, side_calls_done]; heap: [start_bucket, membership]);

/// Elapsed work is diagnostic, never part of native scan identity or parity.
/// Keep Debug deterministic while retaining the measured value for receipts.
#[derive(Clone, Default)]
struct FoldNanos(u64);
impl std::fmt::Debug for FoldNanos {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("FoldNanos")
    }
}
crate::heap_layout_bound::no_heap!(true; FoldNanos);

/// The copied prefix's page outcome (copy-family fix),
/// local diagnostics only until the flag is consumed: requests of
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
    metadata_lost: u64,
    removed_priced_requests: u64,
    removed_cost_micros: u64,
}
crate::heap_layout_bound::no_heap!(true; PrefixTally);

#[derive(Debug, Clone)]
pub(crate) struct FileFold {
    pub(crate) entity: ClaudeEntityBody,
    own_requests: u64,
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
    #[expect(clippy::box_collection, reason = "one pointer when the map is absent")]
    idless_inherited: Option<Box<BTreeMap<u64, ClaudeEntityBody>>>,
    first_idless: Option<u64>,
    /// The proof `decide_page_copies` checks per request before the page
    /// treats the held copies as removed.
    proof: Option<CopyProof>,
    /// Counted requests inheriting a possibly excluded marker. Sparse and
    /// bounded by the existing 64 marker runs, never by response count.
    /// Boxed: one pointer on every fold, the map only when present.
    #[expect(clippy::box_collection, reason = "one pointer when the map is absent")]
    prefix_inherited: Option<Box<BTreeMap<u64, ClaudeEntityBody>>>,
    copied: u64,
    /// Parse-time copy presence, before any restoration; transient, never stored.
    native_copied: bool,
    first_own: Option<u64>,
    /// Only the native subagent branch leaves these skips for page proof.
    twin_pending: bool,
    /// Request hashes two responses of this file claim; filled on demand.
    ambiguous: BTreeSet<u64>,
    disclosed: u64,
    /// Wall time in this fold's `e2`-added work only (`fold_us`, see `spend`).
    e2_nanos: FoldNanos,
    responses: u64,
    root_fallbacks: u64,
    side: ClaudeMoneyTokens,
    telemetry: FoldTelemetry,
    pub(crate) accounts: Option<Box<RequestAccounts>>,
    /// The copied prefix's page outcome (local diagnostics only).
    prefix: PrefixTally,
    /// The one session this file's `fork-context-ref` line names, whatever
    /// copy route the page takes: the page's evidence scope reads its pair.
    fork_parent: Option<String>,
    /// An emitted twin carrier's own tool rows before the twin merge; set
    /// only when the merge changed them, until the identity byte cap or the
    /// fold release takes them.
    own_tools: Option<Box<(Option<Vec<super::super::SnapshotToolUsage>>, bool)>>,
}
crate::heap_layout_bound::split_fields!(FileFold; inline: [own_requests, copy_unproven_wire, money_birth, role, copied, native_copied, twin_pending, disclosed, e2_nanos, responses, root_fallbacks, side, prefix]; heap: [entity, physical, location, first_own, base_selector, bucket_fallback, model_fallbacks, skipped, copy, idless_copy, idless_inherited, first_idless, proof, prefix_inherited, ambiguous, telemetry, accounts, fork_parent, own_tools]);

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
        // path twin holds the native skip until the page proves each request
        // against an earlier same-member fold, or restores it.
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
            copy_unproven_wire: context.is_some_and(|c| c.index.copy_unproven_enabled),
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
            native_copied: false,
            first_own: None,
            twin_pending: false,
            ambiguous: BTreeSet::new(),
            disclosed: 0,
            e2_nanos: FoldNanos::default(),
            responses: 0,
            root_fallbacks: 0,
            side: Default::default(),
            telemetry: Default::default(),
            accounts: None,
            prefix: PrefixTally::default(),
            fork_parent: None,
            own_tools: None,
        };
        fold.spend(started);
        fold
    }

    /// `fold_us` counts ONLY the work `e2` adds: this
    /// fold's new/set_identity, observe per response and finish_native, plus
    /// the page passes (`PageSpent`). The native parse, resolve, placement
    /// and row add it shares are never in it; total page CPU against the
    /// pre-`e2` reference is the cost gate for those.
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
        trust_from: Option<u64>,
    ) {
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
            trust_from,
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

    pub(crate) fn is_ambiguous(&self, request_id: &str) -> bool {
        !self.ambiguous.is_empty()
            && self
                .ambiguous
                .contains(&super::super::claude_request_census::claude_request_hash(
                    request_id,
                ))
    }

    pub(crate) fn fork_parent(&self) -> Option<&str> {
        self.fork_parent.as_deref()
    }
    /// The carrier's own pre-merge tool rows and truncation flag, once.
    pub(crate) fn take_own_tools(
        &mut self,
    ) -> Option<(Option<Vec<super::super::SnapshotToolUsage>>, bool)> {
        self.own_tools.take().map(|own| *own)
    }
    /// This file's own location key, when it has one.
    pub(crate) fn location_key(&self) -> Option<LocationKey> {
        self.location.map(|located| located.0)
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
    pub(crate) fn unproven_copy(&self, occurrence: &ClaudeTranscriptUsageOccurrence) -> bool {
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
        if copied == Some(false) && self.first_own.is_none() {
            self.first_own = Some(sequence);
        }
        let Some(placed) = placed else {
            return;
        };
        if placed.fell_back {
            self.model_fallbacks.insert(sequence, placed.model.clone());
        }
        let Some(placement) = placed.placement.as_ref() else {
            // Native drops it as unplaceable usage; never publish over it.
            self.entity
                .fail_certificate(CertificateFailure::UnplaceableUsage);
            self.disclose("unplaceable", 1);
            return;
        };
        // Gate off keeps only the hour tally: read the hour, build no key.
        let key = {
            Grain::Live(live_key(
                &placed.model,
                placement.bucket.clone(),
                placement.reduced_context.clone(),
                &placement.row_key,
                effort,
            ))
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
        if copied == Some(false) {
            self.own_requests += requests;
        }
        if copied == Some(true) {
            self.copied += 1;
            self.entity.removed.add(&tokens);
            self.entity.removed_requests += requests;
            if !has_request_id {
                let marker = self
                    .accounts
                    .as_deref()
                    .and_then(|accounts| accounts.copied_marker_position(sequence));
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

    /// Confirm, or undo, the held pre-birth skip. A copied MAIN file
    /// (all-pre-birth /branch, or the prefix of a resume) needs a PROOF that
    /// `decide_page_copies` checks per request on the page: earlier main
    /// files of other sessions in its folder hold the request ids.
    /// Without a proof the copies count and are disclosed.
    /// `fork_parent`: the session a `fork-context-ref` line names (empty:
    /// none single).
    pub(in crate::snapshots) fn finish_native(
        &mut self,
        context: Option<&ReadContext<'_>>,
        fork_parent: Option<&str>,
    ) {
        let started = Instant::now();
        self.fork_parent = fork_parent
            .filter(|parent| !parent.is_empty())
            .map(str::to_owned);
        self.native_copied = self.copied > 0;
        self.decide_native(context);
        if self.proof.is_none() {
            self.proof = context
                .and_then(|context| {
                    let member = claude_index_path_member_ref(context.path)?;
                    claude_family_root_path(context.path, member.root)
                })
                .map(|root| CopyProof::Family(local_index_key(&root)));
        }
        // The fold lives until the page finishes: keep no parse-time slack.

        self.skipped.shrink_to_fit();
        self.spend(started);
    }

    fn decide_native(&mut self, context: Option<&ReadContext<'_>>) {
        if self.money_birth.uncertain_root() {
            self.disclose("uncertain_birth", self.responses); // counted, disclosed
        }
        if self.copied == 0 {
            self.finish_identity_start();
            return;
        }
        if let Some(context) = context.filter(|context| self.cross_session_candidate(context)) {
            // The named original is a sibling file of the same project.
            let parent = self.fork_parent.as_deref().map(|parent| {
                local_index_key(&context.path.with_file_name(format!("{parent}.jsonl")))
            });
            let folder = context
                .path
                .parent()
                .map(local_index_key)
                .unwrap_or_default();
            self.proof = Some(CopyProof::Holders { parent, folder });
            // Should the page find no holder, the restored copies keep the
            // accounts their own markers give them (QUOTA: never moved).
            // Keep marker-dependent grains staged until the page decides
            // individual requests; provisional markers must not become own
            // account evidence before proof removes their copied request.
            self.copy = None;
            return;
        }
        if self.ambiguous.is_empty()
            && context.is_some_and(|context| {
                claude_index_path_member_ref(context.path)
                    .is_some_and(|m| m.subagent_stem.is_some())
            })
        {
            self.twin_pending = true;
            self.copy = None;
            self.finish_identity_start();
            return;
        }
        if let Some(mut copy) = self.copy.take() {
            if self.copy_unproven_wire {
                copy.mark_copy_unproven();
            }
            self.entity.absorb_grains(&copy);
        }
        self.restore_idless();
        self.entity.removed = Default::default();
        self.entity.removed_requests = 0;
        self.skipped.clear();
        self.disclose("copy_unproven", self.copied);
        self.copied = 0;
        self.finish_identity_start();
    }

    fn finish_identity_start(&mut self) {
        self.absorb_prefix_inherited(false);
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

    /// /branch and --fork-session (an all-pre-birth MAIN file) and resume
    /// (the copied prefix of a MAIN file with own turns): its copies
    /// `decide_page_copies` checks against other sessions' earlier main
    /// files in its folder, in one census walk per folder per page.
    fn cross_session_candidate(&self, context: &ReadContext<'_>) -> bool {
        self.physical.is_some()
            && self.location.is_some()
            && claude_index_path_member_ref(context.path)
                .is_some_and(|member| member.subagent_stem.is_none())
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

    /// The family root counts this request: move it from its estimated grain
    /// to the removal and skip it, so attach finds the root alone. A grain
    /// that cannot give it back leaves it counted (false).
    fn drop_family_duplicate(&mut self, occurrence: &ClaudeTranscriptUsageOccurrence) -> bool {
        let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
        let requests = occurrence.usage.request_count;
        let account = self
            .accounts
            .as_ref()
            .and_then(|accounts| accounts.account(occurrence.sequence));
        let Some(key) = self.occurrence_key(occurrence) else {
            return false;
        };
        if !self
            .entity
            .take_estimated(&(key, None, account), &tokens, requests)
        {
            return false;
        }
        self.entity.removed.add(&tokens);
        self.entity.removed_requests += requests;
        self.skip(occurrence.sequence);
        true
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
            self.entity
                .fail_certificate(CertificateFailure::CopyRestoration);
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
                self.prefix.unproven_idless += requests;
                self.disclose("copy_idless", responses);
            }
            _ => self
                .entity
                .fail_certificate(CertificateFailure::IdlessRestoration),
        }
    }

    /// Skip one response that is not skipped yet.
    fn skip(&mut self, sequence: u64) {
        let at = self.skipped.partition_point(|(_, end)| *end <= sequence);
        self.skipped.insert(at, (sequence, sequence + 1));
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
        self.entity
            .grains
            .iter()
            .filter(|((key, origin, _), _)| {
                origin.is_none() && key.0.as_str() >= start && key.0.as_str() < hour_ago_bucket
            })
            .map(|(_, grain)| grain.requests)
            .sum::<u64>()
    }

    fn telemetry_complete(&self) -> bool {
        self.telemetry.read
            && self.telemetry.complete
            && self.telemetry.side_calls_done
            && self.entity.estimated_requests() == 0
    }
}

/// The one `e2` grain key: the native row placement plus the billing fields
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
        }
    }
}

/// A native placement as the `e2` grain key: its bucket and reduced context
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
pub(crate) fn page_families(items: &[SnapshotItem]) -> BTreeMap<String, Vec<usize>> {
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
pub(crate) fn item_request_ids(item: &SnapshotItem) -> impl Iterator<Item = &String> {
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
crate::heap_layout_bound::split_fields!(FamilyMembership; inline: [member_mask]; heap: [entries]);

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
) -> impl Iterator<Item = usize> + 'a + use<'a> {
    let hash_mask = !view.member_mask;
    let hash = membership_hash(request_id) & hash_mask;
    let start = view.entries.partition_point(|key| key & hash_mask < hash);
    view.entries[start..]
        .iter()
        .take_while(move |&&key| key & hash_mask == hash)
        .map(|&key| (key & view.member_mask) as usize)
}

/// The proof cannot be decided on this page: the session is withheld.
fn hold_copies(item: &mut SnapshotItem, reason: &'static str) {
    if let Some(fold) = item.claude_money.as_deref_mut() {
        fold.entity.held = true;
        diag(reason, 1);
    }
}

/// This page discarded the family's strict trace read (cap or generation
/// race), so no account can be decided for it: every member is withheld like
/// an undecided copy. No new revision replaces the accepted one; the next
/// clean page decides it. Members without a fold (a family kept on ordinary
/// money by the re-emission list) are returned for the same page withhold.
/// Returns the items withheld and those unfolded sessions.
pub(crate) fn hold_trace_discarded(
    items: &mut [SnapshotItem],
    roots: &BTreeSet<String>,
) -> (u64, BTreeSet<String>) {
    let mut held = 0;
    let mut unfolded = BTreeSet::new();
    for item in items {
        if !roots.contains(claude_snapshot_family_root_ref(item)) {
            continue;
        }
        match item.claude_money.as_deref_mut() {
            Some(fold) => fold.entity.held = true,
            None => {
                unfolded.insert(item.source_session_id.clone());
            }
        }
        held += 1;
    }
    (held, unfolded)
}

/// Whether this page's API sidecar read succeeded (the caller passes it).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TelemetryRead {
    Loaded,
    Failed,
}

/// `finish_page_planned` for a single-chunk page (tests): plans the
/// content-twin holds over `items`.
#[cfg(test)]
pub(crate) fn finish_page(
    items: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    telemetry: TelemetryRead,
    hold_reasons: &mut BTreeMap<&'static str, u64>,
    queued_family_deferred_paths: &BTreeSet<LocationKey>,
) -> BTreeSet<String> {
    let content_held = page_content_holds(items, index);
    let records = index
        .files
        .keys()
        .map(|key| (location_key(key), key))
        .collect();
    finish_page_planned(
        items,
        index,
        telemetry,
        hold_reasons,
        queued_family_deferred_paths,
        PageCopyHolds {
            content: &content_held,
            newer_build: &BTreeSet::new(),
        },
        &records,
    )
}

pub(crate) type ContributionLocations<'a> = BTreeMap<LocationKey, &'a String>;

pub(crate) struct PageCopyHolds<'a> {
    pub(crate) content: &'a BTreeSet<String>,
    pub(crate) newer_build: &'a BTreeSet<String>,
}

/// Finishes one evidence chunk of a page whose content-twin holds were
/// decided once over the whole page. Runs after today's authoritative body
/// fold; one summed entity is emitted per session (path twins sum). A failed
/// telemetry read never yields a "complete" body;
/// `hold_claude_history_for_unread_telemetry` keeps that page's owed history
/// files owed.
///
/// Returns the sessions whose entity was withheld (held twin, uncertified,
/// identity already tagged, overflow). Their items stay on the page
/// unchanged so the caller holds them (`hold_request_owned`): a removed item
/// would let the page settle its file without a body.
pub(crate) fn finish_page_planned(
    items: &mut Vec<SnapshotItem>,
    index: &ScanIndex,
    telemetry: TelemetryRead,
    hold_reasons: &mut BTreeMap<&'static str, u64>,
    queued_family_deferred_paths: &BTreeSet<LocationKey>,
    page_holds: PageCopyHolds<'_>,
    records: &ContributionLocations<'_>,
) -> BTreeSet<String> {
    if !index.persistence_available() {
        let held: BTreeSet<_> = items.iter().map(|i| i.source_session_id.clone()).collect();
        if !held.is_empty() {
            *hold_reasons.entry("index_unavailable").or_default() += held.len() as u64;
        }
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
        /// Later path twins' copied-marker loans: the emitted first item
        /// carries them so `copy_derived_rows` sees every summed request.
        twin_loans: Vec<LentSlot>,
        contributions: Vec<(LocationKey, Arc<[u64]>)>,
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

    claude_request_identity::inherit_root_accounts(items, true);

    // Per session: whether every fold is a covered copy, and the latest last
    // clock and earliest start over its folds, which the emitted body keeps
    // whichever file carries it.
    let mut drop_copies = BTreeMap::<String, (bool, Option<String>, Option<String>)>::new();
    for item in items.iter() {
        if let Some(fold) = item.claude_money.as_deref() {
            let covered = fold.first_own.is_none()
                && fold.entity.removed_requests > 0
                && fold.entity.totals().1 == 0
                && !fold.entity.held
                && fold.location_key().is_some_and(|here| {
                    index
                        .claude_money_birth_store
                        .observations(&item.source_session_id)
                        .any(|(location, _)| location != here)
                });
            let (covered_only, last, start) = drop_copies
                .entry(item.source_session_id.clone())
                .or_insert((true, None, None));
            *covered_only &= covered;
            if let Some(clock) = item.source_last_activity_at.as_deref() {
                if last.as_deref().map_or(true, |current| {
                    super::super::timestamp_is_after(clock, current)
                }) {
                    *last = Some(clock.to_owned());
                }
            }
            if let Some(clock) = item.source_started_at.as_deref() {
                if start.as_deref().map_or(true, |current| {
                    super::super::timestamp_is_after(current, clock)
                }) {
                    *start = Some(clock.to_owned());
                }
            }
        }
    }
    let mut corrected_sessions = BTreeSet::new();
    let mut sessions = BTreeMap::<String, Session>::new();
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
        // Released money restored a resumed prefix. Count only a proven
        // removal, never a held/unproven request.
        if fold.first_own.is_some() && fold.entity.removed_requests > 0 {
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
            .entry(source_session_id.clone())
            .or_insert_with(|| Session {
                entity: Default::default(),
                first_original: None,
                first_undo: Default::default(),
                folds: 0,
                complete: telemetry == TelemetryRead::Loaded,
                locations: Vec::new(),
                decided: Counts::default(),
                twin_loans: Vec::new(),
                contributions: Vec::new(),
            });
        diag("resolver_conflict", fold.entity.resolver_conflicts);
        let unproven = fold.prefix.unproven_requests + fold.prefix.unproven_idless;
        diag("copy_prefix_unproven", unproven);
        diag("copy_prefix_unproven_files", u64::from(unproven > 0));
        diag("copy_prefix_unproven_cost_micros", fold.prefix.cost_micros);
        diag("copy_removal_metadata_lost", fold.prefix.metadata_lost);
        session.decided.add(&Counts::prefix(&fold.prefix));
        session.decided.0[17] += fold.own_requests;
        diag(
            "copy_prefix_removed_priced_requests",
            fold.prefix.removed_priced_requests,
        );
        diag(
            "copy_prefix_removed_cost_micros",
            fold.prefix.removed_cost_micros,
        );
        diag("copy_prefix_own_requests", fold.own_requests);
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
        if let Some(location) = fold.location_key() {
            let mut hashes = claude_usage_occurrences
                .iter()
                .filter(|(_, o)| !fold.is_skipped(o.sequence) && !o.usage.is_zero())
                .map(|(id, _)| claude_request_hash(id))
                .collect::<Vec<_>>();
            hashes.sort_unstable();
            hashes.dedup();
            if !hashes.is_empty() {
                let hashes = records
                    .get(&location)
                    .and_then(|key| index.claude_request_census.get(key))
                    .and_then(|r| r.matching_hashes(&hashes))
                    .unwrap_or_else(|| Arc::from(hashes));
                session.contributions.push((location, hashes));
            }
        }
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
            if session.folds == 2 {
                session.first_original = Some(session.entity.clone());
            }
            session.entity.sum(&fold.entity);
            if let Some(accounts) = fold.accounts.as_deref() {
                session
                    .twin_loans
                    .extend(accounts.copied_marker_lent.values().cloned());
            }
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

    let locations = sessions
        .iter()
        .map(|(session, state)| (session.as_str(), state.locations.as_slice()))
        .collect::<Vec<_>>();
    let content_held = locations
        .iter()
        .filter(|(session, _)| page_holds.content.contains(*session))
        .map(|(session, _)| (*session).to_owned())
        .collect::<BTreeSet<_>>();
    if !content_held.is_empty() {
        *hold_reasons.entry("absent_content_twin").or_default() += content_held.len() as u64;
    }
    // Presence here is this chunk's only: complete because evidence chunk
    // packing never splits a family, and a session's path twins share it.
    let mut held = absent_twins(
        &locations,
        items,
        index,
        queued_family_deferred_paths,
        page_holds.newer_build,
        hold_reasons,
    );
    held.extend(content_held.iter().cloned());
    diag("held_absent_twin", held.len() as u64);
    drop(locations);
    let mut decided = Vec::with_capacity(sessions.len());
    let mut entities = sessions
        .into_iter()
        .map(|(session, mut state)| {
            state.entity.telemetry_owned_complete = state.complete;
            state.entity.held |= held.contains(&session);
            decided.push((session.clone(), state.decided));
            let first = (state.first_original, state.first_undo);
            (
                session,
                (state.entity, first, state.twin_loans, state.contributions),
            )
        })
        .collect::<BTreeMap<_, _>>();
    // Tool usage is display data: the one body carries every twin's names,
    // each at its highest per-file count, so scan order cannot change it. A
    // copied turn counts once; distinct same-tool turns split across twins
    // undercount, never overcount. Single-file sessions keep their own rows.
    let mut twin_tools = BTreeMap::<String, (BTreeMap<String, u64>, bool)>::new();
    for item in items.iter().filter(|item| {
        item.claude_money.is_some()
            && entities
                .get(&item.source_session_id)
                .is_some_and(|(_, (original, _), _, _)| original.is_some())
    }) {
        let Some(rows) = item.tool_usage.as_deref() else {
            continue;
        };
        let (counts, truncated) = twin_tools
            .entry(item.source_session_id.clone())
            .or_default();
        *truncated |= item.tool_usage_truncated;
        for row in rows {
            let count = counts.entry(row.name.clone()).or_default();
            *count = (*count).max(row.count);
        }
    }
    let mut withheld = BTreeSet::new();
    items.retain_mut(|item| {
        if item.claude_money.is_none() {
            return true;
        }
        let (covered_only, span_last, span_start) = drop_copies
            .get(&item.source_session_id)
            .map_or((false, None, None), |(covered, last, start)| {
                (*covered, last.as_deref(), start.as_deref())
            });
        if !content_held.contains(&item.source_session_id) && covered_only {
            return false;
        }
        // One body per session: the first item carries the summed entity.
        // A withheld session keeps every item (twins too) for the hold.
        let Some((entity, (first_original, undo), twin_loans, contributions)) =
            entities.remove(&item.source_session_id)
        else {
            return withheld.contains(&item.source_session_id);
        };
        // apply refuses before mutating, so a withheld item is unchanged:
        // its fold gets its own entity back (moved out above).
        let emitted = super::emit::apply(item, &entity, span_last, span_start);
        if emitted {
            if let Some((counts, truncated)) = twin_tools.remove(&item.source_session_id) {
                let mut rows = super::super::bounded_tool_usage_counts(&counts);
                let truncated = truncated || rows.len() > super::super::MAX_TOOL_USAGE_NAMES;
                rows.truncate(super::super::MAX_TOOL_USAGE_NAMES);
                if item.tool_usage.as_ref() != Some(&rows) || item.tool_usage_truncated != truncated
                {
                    // Outside the fingerprint. The carrier's own rows stay on
                    // the fold: the identity byte cap sheds the added rows first.
                    let own = (
                        item.tool_usage.replace(rows),
                        std::mem::replace(&mut item.tool_usage_truncated, truncated),
                    );
                    if let Some(fold) = item.claude_money.as_deref_mut() {
                        fold.own_tools = Some(Box::new(own));
                    }
                }
            }
            item.request_contributions = contributions.into_boxed_slice();
            if let Some(marked) = item.copy_unproven_counts {
                let mut counts = Counts::default();
                counts.0[14] = marked.rows;
                record_counts(counts);
                diag("copy_prefix_unproven_rows", marked.rows);
            }
        }
        if !emitted {
            let reason = if held.contains(item.source_session_id.as_str()) {
                "absent_twin"
            } else if entity.held {
                "request_owned_held"
            } else if !entity.certificate_ok {
                "uncertified"
            } else {
                "emission_rejected"
            };
            *hold_reasons.entry(reason).or_default() += 1;
            if reason == "uncertified" {
                if let Some(failure) = entity.certificate_failure {
                    *hold_reasons.entry(failure.hold_reason()).or_default() += 1;
                }
            }
            withheld.insert(item.source_session_id.clone());
        }
        if let Some(accounts) = item
            .claude_money
            .as_deref_mut()
            .and_then(|fold| fold.accounts.as_deref_mut())
            .filter(|_| emitted)
        {
            // Reconcile and telemetry placement are done: past here loans are
            // read only as values, so later twins take keys after the first's.
            let lent = &mut accounts.copied_marker_lent;
            let mut next = lent
                .last_key_value()
                .map_or(0, |(key, _)| key.saturating_add(1));
            for slot in twin_loans {
                lent.insert(next, slot);
                next = next.saturating_add(1);
            }
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
    // The guard walks every indexed file; build it only for a corrected session.
    if !corrected_sessions.is_empty() {
        // Literal guards inspect the final request-owned bodies, after apply.
        // A locally rebuilt body vetoed by history is not a corrected family.
        let guard = index.claude_literal_guard(items);
        let corrected_families = items
            .iter()
            .filter(|item| {
                telemetry == TelemetryRead::Loaded
                    && !super::super::claude_reemission_stop_latched()
                    && !withheld.contains(&item.source_session_id)
                    && corrected_sessions.contains(&item.source_session_id)
                    && index.claude_history_emission.permits(item, &guard)
            })
            .map(|item| claude_snapshot_family_root_ref(item).to_owned())
            .collect::<BTreeSet<_>>();
        if !corrected_families.is_empty() {
            let mut counts = Counts::default();
            counts.0[18] = corrected_families.len() as u64;
            diag("copy_prefix_families_corrected", counts.0[18]);
            record_counts(counts);
        }
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

pub(crate) fn emit_entity(item: &mut SnapshotItem, entity: &ClaudeEntityBody) -> bool {
    super::emit::apply(item, entity, None, None)
}

/// The identity row of each request a copied marker
/// had lent an account to, as `visit_identity_rows` builds rows:
/// (bucket start, row, lent account).
pub(crate) fn copied_marker_lent_rows(
    item: &SnapshotItem,
) -> Vec<(&str, super::super::SnapshotModelUsage, &LentSlot)> {
    let Some(accounts) = item
        .claude_money
        .as_deref()
        .and_then(|fold| fold.accounts.as_deref())
    else {
        return Vec::new();
    };
    // Row identity fields come from the slot alone, never from its money.
    accounts
        .copied_marker_lent
        .values()
        .map(|slot| {
            let row = super::emit::grain_row(&slot.key, slot.origin, &Default::default(), None);
            (slot.key.0.as_str(), row, slot)
        })
        .collect()
}

/// Visit exact entity placement; account classification belongs to identity.
pub(crate) fn visit_entity_identity_rows(
    entity: &ClaudeEntityBody,
    mut visit: impl FnMut(
        &str,
        super::super::SnapshotModelUsage,
        AccountPartition,
        Option<u64>,
        Option<i128>,
    ),
) {
    for ((key, origin, account), grain) in &entity.grains {
        visit(
            &key.0,
            super::emit::grain_row(key, *origin, grain, None),
            account.clone(),
            grain.cost(),
            grain.last_own_at,
        );
    }
}

// Existing native_collection_page carrier, nonzero only. These are shared
// process fold deltas since its previous Claude page line.
use std::sync::atomic::{AtomicU64, Ordering};
const COUNT_NAMES: [&str; 25] = [
    "fold_us",
    "responses",
    "copy_skipped",
    "disclosed",
    "unmatched_1h",
    "side_call_root_fallback",
    "resolver_conflicts",
    "copy_prefix_unproven_requests",
    "copy_prefix_unproven_files",
    "copy_prefix_unproven_priced_requests",
    "copy_prefix_unproven_cost_micros",
    "copy_removal_reused",
    "copy_removal_stored",
    "copy_removal_metadata_lost",
    "copy_prefix_unproven_rows",
    "copy_prefix_removed_priced_requests",
    "copy_prefix_removed_cost_micros",
    "copy_prefix_own_requests",
    "copy_prefix_families_corrected",
    "copy_removal_holder_absent_kept",
    "family_copy_deferred",
    "copy_prefix_twin_page_removed",
    "side_call_member_hints",
    "claude_carrier_unknown",
    "claude_carrier_repair",
];
const COUNT_LEN: usize = COUNT_NAMES.len();
static COUNTS: [AtomicU64; COUNT_LEN] = [const { AtomicU64::new(0) }; COUNT_LEN];
/// A page pass's share of `fold_us` (see `FileFold::spend`), on drop.
struct PageSpent(
    Instant,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "the stage name feeds only the test-build timing breakdown"
        )
    )]
    &'static str,
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
    #[cfg(test)]
    PAGE_COUNTS.with(|page| page.borrow_mut().add(&counts));
    for (counter, value) in COUNTS.iter().zip(counts.0) {
        if value != 0 {
            counter.fetch_add(value, Ordering::Relaxed);
        }
    }
}
pub(in crate::snapshots) fn record_carrier_repairs(count: usize) {
    record_counts(Counts::one(24, count as u64));
}
pub(crate) fn take_counts() -> Counts {
    Counts(COUNTS.each_ref().map(|c| c.swap(0, Ordering::Relaxed)))
}
// This thread's share of the shared counters (test builds).
#[cfg(test)]
thread_local! {
    static PAGE_COUNTS: RefCell<Counts> = const { RefCell::new(Counts([0; COUNT_LEN])) };
}
#[derive(Debug)]
pub(crate) struct Counts([u64; COUNT_LEN]);
impl Default for Counts {
    fn default() -> Self {
        Self([0; COUNT_LEN])
    }
}
impl Counts {
    /// The first seven (work and decision) counters.
    fn work(values: [u64; 7]) -> Self {
        let mut all = [0; COUNT_LEN];
        all[..7].copy_from_slice(&values);
        Self(all)
    }
    /// A decided fold's copied-prefix outcome.
    fn prefix(tally: &PrefixTally) -> Self {
        let unproven = tally.unproven_requests + tally.unproven_idless;
        let mut all = [0; COUNT_LEN];
        all[7..12].copy_from_slice(&[
            unproven,
            u64::from(unproven > 0),
            tally.priced_requests,
            tally.cost_micros,
            tally.reused,
        ]);
        all[13] = tally.metadata_lost;
        all[15] = tally.removed_priced_requests;
        all[16] = tally.removed_cost_micros;
        Self(all)
    }
    fn removal_store(added: u64) -> Self {
        let mut all = [0; COUNT_LEN];
        all[12] = added;
        Self(all)
    }
    /// One counter by `n`.
    fn one(at: usize, n: u64) -> Self {
        let mut all = [0; COUNT_LEN];
        all[at] = n;
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

crate::heap_layout_bound::no_heap!(true; ClaudeMoneyTokens {
    input, output, cache_read, cache_5m, cache_1h, unattributed, reasoning,
});

#[cfg(test)]
#[path = "e2_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "e2_holder_redrift_tests.rs"]
mod holder_redrift_tests;

#[cfg(test)]
#[path = "e2_family_duplicate_tests.rs"]
mod family_duplicate_tests;

#[cfg(test)]
#[path = "e2_activity_clock_tests.rs"]
mod activity_clock_tests;

#[cfg(test)]
#[path = "e2_pipeline_observer_tests.rs"]
pub(crate) mod pipeline_test_observer;
