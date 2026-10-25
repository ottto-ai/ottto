//! E2 request-owned Claude money from the native resolved-response fold.
//! Native resolution owns counts; this module only decides copies, attaches
//! reported telemetry cost and side calls, and emits one literal body per
//! session. The upload gate is OFF: DARK never changes an item, a scan
//! identity, parser scope or body witness.
use super::super::claude_context_file_birth::ClaudeFileBirth;
use super::super::claude_money_birth_store::{location_key, LocationKey};
use super::super::{
    claude_api_cache_creation, claude_api_matches_transcript_occurrence,
    claude_index_path_family_member, claude_index_path_member_ref, claude_row_placement,
    claude_snapshot_family_root_ref, claude_trace_evidence_fingerprint_is_valid,
    claude_trace_owner_session_id, insert_selector_raw, local_index_key, rfc3339_unix_nanos,
    validate_claude_api_row, ClaudeTranscriptUsageOccurrence, ResolvedClaudeResponse, ScanIndex,
    SelectorCapture, SnapshotItem, CLAUDE_EFFORT_TIERS,
};
use super::body::{ClaudeGrainSide, ClaudeLiveKey, ClaudeRequestUsageOrigin};
use super::ClaudeMoneyTokens;
use crate::claude_local_otel::{
    ClaudeApiEvidenceRead, ClaudeLocalOtelEvidence, ClaudeLocalOtelLoadReport,
    ClaudeTraceOwnershipLoadReport,
};
use crate::telemetry_attach::{join, Attachment, Holders};
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) const GATE: bool = false;
pub(crate) const MONEY_RULE_VERSION: u16 = 1;
/// A record this much older than its file's effective birth was copied in.
/// Copies written within it are counted (known residual, disclosed nowhere).
const SLACK: i128 = 2_000_000_000;
const HOUR_NANOS: i128 = 3_600_000_000_000;
/// Same bound the P1 holder walk used; a hit is counted and disclosed.
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

/// The parse-time view of the durable birth table (T1's `BirthStore`).
pub(in crate::snapshots) struct ReadContext<'a> {
    pub(in crate::snapshots) index: &'a ScanIndex,
    pub(in crate::snapshots) path: &'a Path,
}
impl ReadContext<'_> {
    /// An indexed root path of `member` with this location still exists.
    /// Store keys are digests, so this walks the index once; only the rare
    /// twin, move and all-pre-birth decisions call it.
    fn live(&self, member: &str, location: LocationKey) -> bool {
        self.index.files.keys().any(|key| {
            claude_index_path_member_ref(Path::new(key))
                .is_some_and(|m| m.subagent_stem.is_none() && m.root == member)
                && location_key(key) == location
                && Path::new(key).is_file()
        })
    }
}

/// A root transcript's session id; subagents are exempt from the birth rule.
fn root_member(path: &Path) -> Option<&str> {
    claude_index_path_member_ref(path)
        .filter(|member| member.subagent_stem.is_none())
        .map(|member| member.root)
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

/// After parse: record the opened physical birth (never the inherited
/// cutoff) and, on a proven move, transfer the session's live location.
pub(in crate::snapshots) fn remember_birth(index: &mut ScanIndex, path: &Path, fold: &FileFold) {
    let (Some(physical), Some(member)) = (fold.physical, root_member(path)) else {
        return;
    };
    let key = local_index_key(path);
    let store = &mut index.claude_money_birth_store;
    store.record_observation(member, &key, physical);
    if let Role::Moved(from) = fold.role {
        store.record_proven_move(member, from, &key);
    }
}

/// Pure accumulation consumed by the #699 literal emitter. No census, claims,
/// custody, maturity or alternate response classifier participates here.
#[derive(Debug, Clone)]
pub(crate) struct ClaudeEntityBody {
    pub(crate) grains: BTreeMap<(ClaudeLiveKey, Option<ClaudeRequestUsageOrigin>), ClaudeGrainSide>,
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
        }
    }
}
impl ClaudeEntityBody {
    fn add(
        &mut self,
        key: ClaudeLiveKey,
        tokens: &ClaudeMoneyTokens,
        requests: u64,
        cost: Option<u64>,
        origin: Option<ClaudeRequestUsageOrigin>,
        at: Option<i128>,
    ) {
        if let Some(at) = at {
            self.note_activity(&key.0, at, at);
        }
        self.grains
            .entry((key, origin))
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
                self.bucket_activity.insert(bucket.to_owned(), (first, last));
            }
        }
        self.activity_nanos = self.activity_nanos.max(last);
    }
    /// Grains and their activity only (a held copy moving back to counted).
    fn absorb_grains(&mut self, other: &Self) {
        for (key, grain) in &other.grains {
            let into = self.grains.entry(key.clone()).or_default();
            into.tokens.add(&grain.tokens);
            into.requests = into.requests.saturating_add(grain.requests);
            into.cost_micros = into.cost_micros.saturating_add(grain.cost_micros);
            into.unpriced = into.unpriced.saturating_add(grain.unpriced);
            into.contributions = into.contributions.saturating_add(grain.contributions);
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
            .filter(|((_, origin), _)| origin.is_none())
            .map(|(_, grain)| grain.requests)
            .sum()
    }
}
crate::heap_layout_bound::fields!(ClaudeEntityBody; grains, bucket_activity, removed, removed_requests, telemetry_owned_complete, resolver_conflicts, held, certificate_ok, activity_unix, activity_nanos);
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
}
crate::heap_layout_bound::fields!(FoldTelemetry; read, complete, start_bucket, side_candidates, side_calls_done);

#[derive(Debug, Clone)]
pub(crate) struct FileFold {
    pub(crate) entity: ClaudeEntityBody,
    /// Copy rule with the EFFECTIVE cutoff (inherited across proven moves).
    money_birth: ClaudeFileBirth,
    /// The opened file's own physical birth; the only birth ever recorded.
    physical: Option<i128>,
    role: Role,
    location: Option<LocationKey>,
    base_selector: SelectorCapture,
    bucket_fallback: Option<String>,
    /// Model-less responses: the running native model fallback at their turn,
    /// so attach rebuilds exactly the key observe used. Rare, so sparse.
    model_fallbacks: BTreeMap<u64, String>,
    /// Held pre-birth responses, as half-open sequence ranges.
    skipped: Vec<(u64, u64)>,
    /// Pre-birth grains held until finish_native confirms the skip.
    copy: ClaudeEntityBody,
    copied: u64,
    first_own: Option<u64>,
    /// Request hashes two responses of this file claim; filled on demand.
    ambiguous: BTreeSet<u64>,
    disclosed: u64,
    pub(in crate::snapshots) fold_us: u64,
    responses: u64,
    root_fallbacks: u64,
    side: ClaudeMoneyTokens,
    side_requests: u64,
    telemetry: FoldTelemetry,
}
crate::heap_layout_bound::fields!(FileFold; entity, money_birth, physical, role, location, base_selector, bucket_fallback, model_fallbacks, skipped, copy, copied, first_own, ambiguous, disclosed, fold_us, responses, root_fallbacks, side, side_requests, telemetry);
impl FileFold {
    pub(in crate::snapshots) fn new(
        birth: ClaudeFileBirth,
        context: Option<&ReadContext<'_>>,
        base_selector: SelectorCapture,
        bucket_fallback: Option<String>,
    ) -> Self {
        let physical = birth.birth_nanos();
        let mut role = Role::Owner;
        let mut cutoff = None;
        let mut location = None;
        if let (Some(context), Some(_)) = (context, physical) {
            if let Some(member) = root_member(context.path) {
                let key = local_index_key(context.path);
                let here = location_key(&key);
                location = Some(here);
                let store = &context.index.claude_money_birth_store;
                let observed = store.observed_birth(member, &key);
                cutoff = match store.live_location(member) {
                    None => observed,
                    Some(live) if live == here => store.effective_cutoff(member, &key),
                    Some(live) if context.live(member, live) => {
                        role = Role::Twin;
                        observed
                    }
                    Some(live) => {
                        role = Role::Moved(live);
                        let session = store.session_effective_cutoff(member);
                        match (session, observed) {
                            (Some(a), Some(b)) => Some(a.min(b)),
                            (a, b) => a.or(b),
                        }
                    }
                };
            }
        }
        Self {
            entity: Default::default(),
            money_birth: birth.with_minimum(cutoff),
            physical,
            role,
            location,
            base_selector,
            bucket_fallback,
            model_fallbacks: BTreeMap::new(),
            skipped: Vec::new(),
            copy: Default::default(),
            copied: 0,
            first_own: None,
            ambiguous: BTreeSet::new(),
            disclosed: 0,
            fold_us: 0,
            responses: 0,
            root_fallbacks: 0,
            side: Default::default(),
            side_requests: 0,
            telemetry: Default::default(),
        }
    }

    /// The effective cutoff (copy rule), for diagnostics and tests.
    pub(crate) fn birth(&self) -> Option<i128> {
        self.money_birth.birth_nanos()
    }

    /// The native resolver dropped one of two incompatible records.
    pub(in crate::snapshots) fn note_resolver_conflict(&mut self) {
        self.entity.resolver_conflicts = self.entity.resolver_conflicts.saturating_add(1);
    }

    /// Two responses claim `request_id`: its telemetry can never attach.
    pub(in crate::snapshots) fn note_ambiguous(&mut self, request_id: &str) {
        self.ambiguous
            .insert(super::super::claude_request_census::claude_request_hash(request_id));
    }

    fn is_ambiguous(&self, request_id: &str) -> bool {
        !self.ambiguous.is_empty()
            && self
                .ambiguous
                .contains(&super::super::claude_request_census::claude_request_hash(request_id))
    }

    fn is_skipped(&self, sequence: u64) -> bool {
        let at = self.skipped.partition_point(|(_, end)| *end <= sequence);
        self.skipped
            .get(at)
            .is_some_and(|(start, _)| *start <= sequence)
    }

    pub(in crate::snapshots) fn observe(
        &mut self,
        response: &ResolvedClaudeResponse,
        at: Option<i128>,
        latest_model: Option<&str>,
    ) {
        self.responses += 1;
        let copied = self.money_birth.copied_with_slack(at, SLACK);
        if copied == Some(false) {
            self.first_own.get_or_insert(response.sequence);
        }
        // Native placement adds no row for zero usage.
        if response.usage.is_zero() {
            return;
        }
        let model = match response.model.as_deref() {
            Some(model) => model,
            None => {
                let fallback = latest_model.unwrap_or("unknown");
                self.model_fallbacks
                    .insert(response.sequence, fallback.to_owned());
                fallback
            }
        };
        let Some(key) = grain_key(
            model,
            &self.base_selector,
            response.selector.clone(),
            response.reasoning_effort.as_deref(),
            response.terminal_timestamp.as_deref(),
            self.bucket_fallback.as_deref(),
        ) else {
            // Native drops it as unplaceable usage; never publish over it.
            self.entity.certificate_ok = false;
            self.disclosed += 1;
            return;
        };
        let tokens = ClaudeMoneyTokens::from_usage(&response.usage);
        let requests = response.usage.request_count;
        if copied == Some(true) {
            self.copied += 1;
            self.entity.removed.add(&tokens);
            self.entity.removed_requests += requests;
            match self.skipped.last_mut() {
                Some((_, end)) if *end == response.sequence => *end += 1,
                _ => self
                    .skipped
                    .push((response.sequence, response.sequence + 1)),
            }
            self.copy.add(key, &tokens, requests, None, None, at);
            return;
        }
        if copied.is_none() && self.money_birth.birth_nanos().is_some() {
            self.disclosed += 1; // untimed root record: counted, birth unproven
        }
        self.entity.add(key, &tokens, requests, None, None, at);
    }

    /// Confirm or undo the held pre-birth skip. A partial copy is skipped only
    /// with a writer certificate from the file's OWN post-birth lines; an
    /// all-pre-birth file only with a PROVEN earlier original (stored birth,
    /// deterministic equal-birth order), so two restored twins can never
    /// delete each other. Everything else counts and discloses.
    pub(in crate::snapshots) fn finish_native(&mut self, context: Option<&ReadContext<'_>>) {
        if self.money_birth.uncertain_root() {
            self.disclosed += self.responses; // unknown birth: counted, disclosed
        }
        if self.copied == 0 {
            return;
        }
        let keep = if self.first_own.is_none() {
            self.role == Role::Twin && self.original_witness(context)
        } else {
            self.money_birth.writer_certified(self.first_own)
        };
        if keep {
            self.copy = Default::default();
            return;
        }
        let copy = std::mem::take(&mut self.copy);
        self.entity.absorb_grains(&copy);
        self.entity.removed = Default::default();
        self.entity.removed_requests = 0;
        self.skipped.clear();
        self.disclosed += self.copied;
        self.copied = 0;
    }

    fn original_witness(&self, context: Option<&ReadContext<'_>>) -> bool {
        let (Some(context), Some(physical)) = (context, self.physical) else {
            return false;
        };
        let Some(member) = root_member(context.path) else {
            return false;
        };
        let key = local_index_key(context.path);
        context
            .index
            .claude_money_birth_store
            .original_witness_at(member, &key, physical, |location| {
                context.live(member, location)
            })
            .is_some()
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
            .filter(|((key, origin), _)| {
                origin.is_none() && key.0.as_str() >= start && key.0.as_str() < hour_ago_bucket
            })
            .map(|(_, grain)| grain.requests)
            .sum()
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
    let placed = claude_row_placement(model, base, selector, effort, timestamp, fallback)?;
    let mut context = placed.reduced_context;
    for (field, value) in placed.row_key.billing_fields() {
        if let Some(value) = value {
            context.insert(field.to_owned(), value.to_owned());
        }
    }
    if let Some(effort) = effort {
        context.insert("reasoning_effort".into(), effort.into());
    }
    Some((placed.bucket, model.to_owned(), context))
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
    let mut selector = occurrence
        .map(|occurrence| SelectorCapture::clone(&occurrence.selector))
        .unwrap_or_default();
    if !row.speed.trim().is_empty() {
        insert_selector_raw(
            &mut selector,
            "speed_mode",
            "claude_code.api_request.speed",
            &serde_json::Value::String(row.speed.clone()),
        );
    }
    let reported_effort = CLAUDE_EFFORT_TIERS
        .contains(&row.effort.as_str())
        .then_some(row.effort.as_str());
    let effort = occurrence
        .and_then(|occurrence| occurrence.reasoning_effort.as_deref())
        .or(reported_effort);
    let model = occurrence
        .and_then(|occurrence| occurrence.model.as_deref())
        .unwrap_or(&row.model);
    grain_key(
        model,
        base,
        selector,
        effort,
        occurrence.and_then(|occurrence| occurrence.timestamp.as_deref()),
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

/// Who on this page counts `request_id`: one counted holder (path twins of
/// one session share it: the first), several sessions (ambiguous), only a
/// skipped copy (held elsewhere, never attached), or nobody.
fn holders(items: &[SnapshotItem], members: &[usize], request_id: &str) -> Holders<usize> {
    let mut found = None::<usize>;
    let mut held = false;
    for &index in members {
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
    let model = occurrence
        .model
        .as_deref()
        .or_else(|| fold.model_fallbacks.get(&occurrence.sequence).map(String::as_str))
        .unwrap_or("unknown");
    let Some(estimated) = grain_key(
        model,
        &fold.base_selector,
        SelectorCapture::clone(&occurrence.selector),
        occurrence.reasoning_effort.as_deref(),
        occurrence.timestamp.as_deref(),
        fold.bucket_fallback.as_deref(),
    ) else {
        return false;
    };
    let Some(reported) = reported_key(row, Some(occurrence), &fold.base_selector) else {
        return false;
    };
    let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
    let requests = occurrence.usage.request_count;
    let slot = (estimated, None);
    let Some(grain) = fold.entity.grains.get_mut(&slot) else {
        return false;
    };
    let (Some(left), Some(left_requests)) = (
        grain.tokens.checked_sub(&tokens),
        grain.requests.checked_sub(requests),
    ) else {
        return false;
    };
    grain.tokens = left;
    grain.requests = left_requests;
    grain.contributions = grain.contributions.saturating_sub(1);
    grain.unpriced = grain.unpriced.saturating_sub(1);
    if grain.contributions == 0 {
        fold.entity.grains.remove(&slot);
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
    fold.entity
        .add(reported, &tokens, requests, row.cost_usd_micros, Some(origin), at);
    true
}

/// Attach the page's already-decoded API rows (`ClaudeApiEvidenceRead`, the
/// live sidecar read incl. its paid preload) to transcript-counted requests
/// through the source-neutral join, once per family root. Compatibility is
/// the existing owner `claude_api_matches_transcript_occurrence` (a sidecar
/// thinking count of 0 matches). Row-driven: no per-row map is built.
pub(crate) fn attach_page(items: &mut [SnapshotItem], read: &ClaudeApiEvidenceRead) {
    let families = page_families(items);
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
        let mut disclosed = 0u64;
        let counts = join(
            report,
            |request_id| holders(&**items.borrow(), members, request_id),
            |row, holder| {
                validate_claude_api_row(row, root)
                    && items.borrow()[*holder]
                        .claude_usage_occurrences
                        .get(row.request_id.as_str())
                        .is_some_and(|occurrence| {
                            claude_api_matches_transcript_occurrence(row, occurrence)
                        })
            },
            |event| match event {
                Attachment::Matched { row, holder } => {
                    let mut items = items.borrow_mut();
                    if !attach_one(&mut items[holder], row) {
                        disclosed += 1;
                    }
                }
                Attachment::Unheld(_) => {}
                Attachment::Disclosed { .. } => disclosed += 1,
            },
        );
        let mut items = items.borrow_mut();
        for index in folds {
            if let Some(fold) = items[index].claude_money.as_deref_mut() {
                fold.telemetry = FoldTelemetry {
                    read: true,
                    complete: counts.complete && disclosed == 0,
                    start_bucket: start_bucket.clone(),
                    side_candidates: counts.unheld as u64,
                    side_calls_done: counts.unheld == 0,
                };
                if index == first {
                    fold.disclosed += disclosed;
                }
            }
        }
    }
}

/// Side calls (telemetry-only requests no family transcript holds) keep
/// today's attribution (COST): the trace-named member's body; the root only
/// when no trace row names a member (counted). One membership pass over the
/// family's rows; off-page holders come from the family-scoped census
/// lookup, skipped when there are no candidates. Runs after the per-root
/// trace read: `api`/`trace` hold only roots whose sidecars are complete.
pub(crate) fn side_calls_page(
    items: &mut [SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    index: &ScanIndex,
) {
    let owing = |item: &SnapshotItem| {
        item.claude_money
            .as_deref()
            .is_some_and(|fold| fold.telemetry.read && !fold.telemetry.side_calls_done)
    };
    if !items.iter().any(owing) {
        return;
    }
    let families = page_families(items)
        .into_iter()
        .filter(|(_, members)| members.iter().any(|index| owing(&items[*index])))
        .collect::<Vec<_>>();
    let mut candidates = BTreeMap::<&str, Vec<&ClaudeLocalOtelEvidence>>::new();
    let mut wanted = BTreeMap::<&str, Vec<u64>>::new();
    let mut invalid = BTreeMap::<&str, u64>::new();
    for (root, members) in &families {
        let Some(rows) = api.evidence.get(root.as_str()) else {
            continue; // unhealthy sidecar pair: stays undone and disclosed
        };
        let mut family = Vec::new();
        for row in rows {
            if members
                .iter()
                .any(|index| items[*index].claude_usage_request_ids.contains(&row.request_id))
            {
                continue;
            }
            if !validate_claude_api_row(row, root) {
                *invalid.entry(root.as_str()).or_default() += 1;
                continue;
            }
            family.push(row);
        }
        let mut hashes = family
            .iter()
            .map(|row| super::super::claude_request_census::claude_request_hash(&row.request_id))
            .collect::<Vec<_>>();
        hashes.sort_unstable();
        hashes.dedup();
        family.sort_unstable_by(|a, b| a.request_id.cmp(&b.request_id));
        wanted.insert(root.as_str(), hashes);
        candidates.insert(root.as_str(), family);
    }
    let census = index
        .claude_request_census
        .family_transcript_holders(&wanted, Instant::now() + SIDE_CALL_DEADLINE);
    for (root, members) in &families {
        let first = members
            .iter()
            .copied()
            .find(|index| items[*index].claude_money.is_some());
        let (Some(first), Some(rows), Some(census)) =
            (first, candidates.get(root.as_str()), census.as_ref())
        else {
            // Unhealthy pair or deadline: counted and disclosed, never dropped
            // silently; the family stays telemetry-incomplete.
            if let Some(fold) = first.and_then(|index| items[index].claude_money.as_deref_mut()) {
                fold.disclosed += fold.telemetry.side_candidates;
            }
            continue;
        };
        let empty = Default::default();
        let family_census = census.get(root.as_str()).unwrap_or(&empty);
        let owners = trace_owners(root, rows, trace.evidence.get(root.as_str()));
        let mut disclosed = invalid.get(root.as_str()).copied().unwrap_or(0);
        for (row, owner) in rows.iter().zip(owners) {
            let hash = super::super::claude_request_census::claude_request_hash(&row.request_id);
            if family_census.held.contains(&hash) {
                continue; // an off-page transcript of the family counts it
            }
            let fallback = owner.is_none();
            let owner = owner.unwrap_or_else(|| root.clone());
            let target = members.iter().copied().find(|index| {
                items[*index].source_session_id == owner && items[*index].claude_money.is_some()
            });
            let Some(target) = target else {
                // Its member counts it when read; a named member with no
                // transcript anywhere cannot, so that is disclosed.
                if !fallback && owner != *root && !family_census.members.contains(&owner) {
                    disclosed += 1;
                }
                continue;
            };
            let Some((cache_5m, cache_1h, unattributed)) = claude_api_cache_creation(row) else {
                disclosed += 1; // contradictory cache split
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
            let Some(key) = reported_key(row, None, &SelectorCapture::default()) else {
                disclosed += 1;
                continue;
            };
            let origin = if row.cost_usd_micros.is_some() {
                ClaudeRequestUsageOrigin::TelemetryReported
            } else {
                ClaudeRequestUsageOrigin::TelemetryUnpriced
            };
            fold.entity.add(
                key,
                &tokens,
                1,
                row.cost_usd_micros,
                Some(origin),
                rfc3339_unix_nanos(&row.observed_at),
            );
            fold.side.add(&tokens);
            fold.side_requests += 1;
            if fallback {
                fold.root_fallbacks += 1;
            }
        }
        for index in members {
            if let Some(fold) = items[*index].claude_money.as_deref_mut() {
                fold.telemetry.side_calls_done = true;
            }
        }
        if let Some(fold) = items[first].claude_money.as_deref_mut() {
            fold.disclosed += disclosed;
        }
    }
}

/// The trace-named owner of each sorted candidate row (None: no trace row,
/// or an invalid one, names it). One pass over the trace rows, binary search
/// into the candidates: no map sized by rows.
fn trace_owners(
    root: &str,
    rows: &[&ClaudeLocalOtelEvidence],
    trace: Option<&Vec<crate::claude_local_otel::ClaudeTraceOwnershipEvidence>>,
) -> Vec<Option<String>> {
    let mut owners = vec![None; rows.len()];
    for row in trace.into_iter().flatten() {
        let Ok(at) = rows.binary_search_by(|candidate| candidate.request_id.as_str().cmp(&row.request_id))
        else {
            continue;
        };
        if row.capture_revision == "claude_llm_request_ownership:v1"
            && row.session_id == root
            && claude_trace_evidence_fingerprint_is_valid(row)
        {
            owners[at] = Some(claude_trace_owner_session_id(root, &row.agent_id));
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
pub(crate) fn finish_page(items: &mut Vec<SnapshotItem>, index: &ScanIndex, telemetry: TelemetryRead) {
    struct Session {
        entity: ClaudeEntityBody,
        complete: bool,
        /// Native transcript totals (None: a reported rebuild replaced them).
        native: Option<(ClaudeMoneyTokens, u64)>,
        side: (ClaudeMoneyTokens, u64),
        locations: Vec<LocationKey>,
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
    let mut sessions = BTreeMap::<&str, Session>::new();
    for item in items.iter() {
        let Some(fold) = item.claude_money.as_deref() else {
            continue;
        };
        record_counts(Counts([
            fold.fold_us,
            fold.responses,
            fold.entity.removed_requests,
            fold.disclosed,
            fold.unmatched_1h(&hour_ago),
            fold.root_fallbacks,
            fold.entity.resolver_conflicts,
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
            });
        session.entity.sum(&fold.entity);
        session.complete &= fold.telemetry_complete();
        session.side.0.add(&fold.side);
        session.side.1 += fold.side_requests;
        session.locations.extend(fold.location);
        match (&mut session.native, item.usage_accounting_contract.is_none()) {
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
        return;
    }
    let locations = sessions
        .iter()
        .map(|(session, state)| (*session, state.locations.as_slice()))
        .collect::<Vec<_>>();
    let held = absent_twins(&locations, index);
    drop(locations);
    let mut entities = sessions
        .into_iter()
        .map(|(session, mut state)| {
            state.entity.telemetry_owned_complete = state.complete;
            state.entity.held |= held.contains(session);
            (session.to_owned(), state.entity)
        })
        .collect::<BTreeMap<_, _>>();
    items.retain_mut(|item| {
        if item.claude_money.is_none() {
            return true;
        }
        // One body per session: the first item carries the summed entity.
        let Some(entity) = entities.remove(&item.source_session_id) else {
            return false;
        };
        super::emit::apply(item, &entity)
    });
}

/// Sessions with a live indexed root path that is not on this page: never
/// publish one path over complete twin history. Only sessions whose birth
/// table knows more paths than the page holds trigger one index walk.
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
    for key in index.files.keys() {
        let Some(member) = claude_index_path_member_ref(Path::new(key)) else {
            continue;
        };
        if member.subagent_stem.is_some() {
            continue;
        }
        let Some((session, here)) = suspects.iter().find(|(session, _)| *session == member.root)
        else {
            continue;
        };
        if !here.contains(&location_key(key)) && Path::new(key).is_file() {
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
    index: &ScanIndex,
) -> BTreeSet<String> {
    let selected = paths
        .filter_map(claude_index_path_family_member)
        .map(|(root, member)| (member, root))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeMap::<String, BTreeSet<&str>>::new();
    for key in index.files.keys().chain(
        index
            .traversal
            .as_ref()
            .into_iter()
            .flat_map(|t| t.observed_index_keys.iter()),
    ) {
        if let Some((_, member)) = claude_index_path_family_member(Path::new(key)) {
            if selected.contains_key(&member) {
                seen.entry(member).or_default().insert(key);
            }
        }
    }
    seen.into_iter()
        .filter(|(_, keys)| keys.len() > 1)
        .filter_map(|(member, _)| selected.get(&member).cloned())
        .collect()
}
