//! Native resolved-response money fold. The upload gate is deliberately OFF.
//! DARK never changes an item, a scan identity, parser scope or body witness.
use super::super::{
    activity_bucket_from_timestamp, build_row_identity, claude_context_file_birth::ClaudeFileBirth,
    claude_index_path_family_member, local_index_key, rfc3339_unix_nanos, ResolvedClaudeResponse,
    ScanIndex, SelectorCapture, SnapshotItem,
};
use super::body::{ClaudeGrainSide, ClaudeLiveKey, ClaudeRequestUsageOrigin};
use super::ClaudeMoneyTokens;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const GATE: bool = false;
pub(crate) const MONEY_RULE_VERSION: u16 = 1;
const SLACK: i128 = 2_000_000_000;
const KNOWN_COPY_WRITERS: &[&str] = &["2.1.309", "2.1.310"];

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SessionBirth {
    minimum: i128,
    path: String,
}
crate::heap_layout_bound::fields!(SessionBirth; minimum, path);

pub(in crate::snapshots) struct ReadContext<'a> {
    pub(in crate::snapshots) index: &'a ScanIndex,
    pub(in crate::snapshots) path: &'a Path,
}
impl ReadContext<'_> {
    fn minimum(&self) -> Option<i128> {
        let key = local_index_key(self.path);
        let path_min = self
            .index
            .files
            .get(&key)
            .and_then(|e| e.claude_money_min_birth_nanos);
        let (_, member) = claude_index_path_family_member(self.path)?;
        // An existing twin retains its own cutoff. Only a move/retirement
        // inherits the session minimum, otherwise summing twins duplicates it.
        let moved = self
            .index
            .claude_money_births
            .get(&member)
            .filter(|b| b.path == key || !Path::new(&b.path).is_file())
            .map(|b| b.minimum);
        match (path_min, moved) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
    fn live_twin(&self) -> bool {
        let Some((_, member)) = claude_index_path_family_member(self.path) else {
            return false;
        };
        let key = local_index_key(self.path);
        // Only the rare all-pre-birth guard walks this inventory; the normal
        // fold uses logarithmic per-path/session lookups, never an index walk.
        self.index.files.keys().any(|other| {
            other != &key
                && claude_index_path_family_member(Path::new(other))
                    .is_some_and(|(_, id)| id == member)
                && Path::new(other).is_file()
        })
    }
}
pub(in crate::snapshots) fn remember_birth(
    index: &mut ScanIndex,
    path: &Path,
    birth: Option<i128>,
) {
    let Some(birth) = birth else { return };
    let Some((_, member)) = claude_index_path_family_member(path) else {
        return;
    };
    let key = local_index_key(path);
    if let Some(entry) = index.files.get_mut(&key) {
        entry.claude_money_min_birth_nanos = Some(
            entry
                .claude_money_min_birth_nanos
                .map_or(birth, |old| old.min(birth)),
        );
    }
    let old = index
        .claude_money_births
        .entry(member)
        .or_insert_with(|| SessionBirth {
            minimum: birth,
            path: key.clone(),
        });
    if birth < old.minimum {
        *old = SessionBirth {
            minimum: birth,
            path: key,
        };
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
    pub(crate) telemetry_owned_complete: bool,
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
            telemetry_owned_complete: true,
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
            let bounds = self
                .bucket_activity
                .entry(key.0.clone())
                .or_insert((at, at));
            bounds.0 = bounds.0.min(at);
            bounds.1 = bounds.1.max(at);
            self.activity_nanos = self.activity_nanos.max(at);
        }
        self.grains
            .entry((key, origin))
            .or_default()
            .add(tokens, requests, cost);
    }
    fn sum(&mut self, other: Self) {
        for (key, grain) in other.grains {
            self.grains
                .entry(key)
                .or_default()
                .add(&grain.tokens, grain.requests, grain.cost());
        }
        for (key, (first, last)) in other.bucket_activity {
            let bounds = self.bucket_activity.entry(key).or_insert((first, last));
            bounds.0 = bounds.0.min(first);
            bounds.1 = bounds.1.max(last);
        }
        self.removed.add(&other.removed);
        self.removed_requests = self.removed_requests.saturating_add(other.removed_requests);
        self.telemetry_owned_complete &= other.telemetry_owned_complete;
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
}
crate::heap_layout_bound::fields!(ClaudeEntityBody; grains, bucket_activity, removed, removed_requests, telemetry_owned_complete, held, certificate_ok, activity_unix, activity_nanos);
// Existing grain types were inline P1 values; E retains only the aggregate.
crate::heap_layout_bound::fields!(ClaudeGrainSide; tokens, requests, cost_micros, unpriced, contributions);
impl crate::heap_layout_bound::HeapLayoutBound for ClaudeRequestUsageOrigin {
    const INLINE_ONLY: bool = true;
    fn heap_bound(&self, c: &mut crate::heap_layout_bound::Counter) -> Option<()> {
        c.add(0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FileFold {
    pub(crate) entity: ClaudeEntityBody,
    pub(crate) birth: Option<i128>,
    rule_version: u16,
    money_birth: ClaudeFileBirth,
    base_selector: SelectorCapture,
    skipped: BTreeSet<u64>,
    pub(in crate::snapshots) ambiguous: BTreeSet<u64>,
    skip_allowed: bool,
    uncertain: bool,
    pub(in crate::snapshots) disclosed: u64,
    pub(in crate::snapshots) fold_us: u64,
    responses: u64,
    unmatched_1h: u64,
    now_nanos: i128,
    joined: bool,
}
crate::heap_layout_bound::fields!(FileFold; entity, birth, rule_version, money_birth, base_selector, skipped, ambiguous, skip_allowed, uncertain, disclosed, fold_us, responses, unmatched_1h, now_nanos, joined);
impl FileFold {
    pub(in crate::snapshots) fn new(
        birth: ClaudeFileBirth,
        context: Option<&ReadContext<'_>>,
        base_selector: SelectorCapture,
    ) -> Self {
        let money_birth = birth.with_minimum(context.and_then(ReadContext::minimum));
        Self {
            entity: Default::default(),
            birth: money_birth.birth_nanos(),
            rule_version: MONEY_RULE_VERSION,
            money_birth,
            base_selector,
            skipped: Default::default(),
            ambiguous: Default::default(),
            skip_allowed: false,
            uncertain: false,
            disclosed: 0,
            fold_us: 0,
            responses: 0,
            unmatched_1h: 0,
            now_nanos: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as i128),
            joined: false,
        }
    }
    pub(in crate::snapshots) fn prepare(
        &mut self,
        responses: &[(ResolvedClaudeResponse, Option<i128>)],
        version: Option<&str>,
        context: Option<&ReadContext<'_>>,
    ) {
        let root = self.money_birth.birth_nanos().is_some() || self.money_birth.uncertain_root();
        let known = version.is_some_and(|v| KNOWN_COPY_WRITERS.contains(&v));
        let all_pre_birth = !responses.is_empty()
            && responses
                .iter()
                .all(|(_, at)| self.money_birth.copied_with_slack(*at, SLACK) == Some(true));
        let orphan_copy = all_pre_birth && !context.is_some_and(ReadContext::live_twin);
        self.skip_allowed = known && !orphan_copy;
        self.uncertain = root && (!known || self.money_birth.uncertain_root() || orphan_copy);
    }
    pub(in crate::snapshots) fn observe(
        &mut self,
        response: &ResolvedClaudeResponse,
        at: Option<i128>,
        latest_model: Option<&str>,
        fallback: Option<&str>,
    ) {
        self.responses += 1;
        let tokens = ClaudeMoneyTokens::from_usage(&response.usage);
        let copied = self.money_birth.copied_with_slack(at, SLACK);
        if self.skip_allowed && copied == Some(true) {
            self.entity.removed.add(&tokens);
            self.entity.removed_requests += response.usage.request_count;
            self.skipped.insert(response.sequence);
            return;
        }
        if self.uncertain || (self.birth.is_some() && at.is_none()) {
            self.disclosed += 1;
        }
        let model = response
            .model
            .as_deref()
            .or(latest_model)
            .unwrap_or("unknown");
        let Some(key) = transcript_key(
            model,
            &self.base_selector,
            &response.selector,
            response.reasoning_effort.as_deref(),
            response.terminal_timestamp.as_deref().or(fallback),
        ) else {
            self.entity.certificate_ok = false;
            self.disclosed += 1;
            return;
        };
        self.entity
            .add(key, &tokens, response.usage.request_count, None, None, at);
        // OTEL is joined below through the live reader; idless responses stay estimated.
        self.unmatched_1h +=
            u64::from(at.is_some_and(|at| self.now_nanos.saturating_sub(at) > 3_600_000_000_000));
    }
}

fn transcript_key(
    model: &str,
    base: &SelectorCapture,
    selector: &SelectorCapture,
    effort: Option<&str>,
    timestamp: Option<&str>,
) -> Option<ClaudeLiveKey> {
    let (bucket, _) = activity_bucket_from_timestamp(timestamp?)?;
    let mut merged = base.clone();
    merged.merge(selector.clone());
    let (row, mut context, _) = build_row_identity(model, &merged, effort);
    for (field, value) in row.billing_fields() {
        if let Some(value) = value {
            context.insert(field.to_owned(), value.to_owned());
        }
    }
    if let Some(effort) = effort {
        context.insert("reasoning_effort".into(), effort.into());
    }
    Some((bucket, model.into(), context))
}

/// Attach API facts already decoded by ClaudeApiEvidenceRead's live sidecar
/// path (including load_paid_for_roots). No shadow-tail dependency or pricing.
/// Native resolution owns counts: this loop only moves a matched grain to its
/// reported origin, never refolds the request-id map as a counting source.
pub(crate) fn attach_page(
    items: &mut [SnapshotItem],
    api: &BTreeMap<String, Vec<crate::claude_local_otel::ClaudeLocalOtelEvidence>>,
    index: &ScanIndex,
) {
    let mut attached = BTreeSet::<(String, u64)>::new();
    for item in items.iter_mut() {
        let root = super::super::claude_snapshot_family_root(item);
        let Some(fold) = item.claude_money.as_mut() else {
            continue;
        };
        if fold.joined {
            continue;
        }
        fold.joined = true;
        let rows = api.get(&root);
        let mut lookup = BTreeMap::new();
        let mut conflicts = BTreeSet::new();
        for row in rows
            .into_iter()
            .flatten()
            .filter(|r| super::super::validate_claude_api_row(r, &root))
        {
            if let Some(previous) = lookup.insert(row.request_id.as_str(), row) {
                if previous != row {
                    conflicts.insert(row.request_id.as_str());
                }
            }
        }
        let mut matched = 0u64;
        for (id, occurrence) in &item.claude_usage_occurrences {
            if fold.skipped.contains(&occurrence.sequence) {
                continue;
            }
            let hash = super::super::claude_request_census::claude_request_hash(id);
            if fold.ambiguous.contains(&hash) || conflicts.contains(id.as_str()) {
                fold.disclosed += 1;
                continue;
            }
            let Some(row) = lookup.get(id.as_str()) else {
                continue;
            };
            let model = occurrence.model.as_deref().unwrap_or("unknown");
            let tokens = ClaudeMoneyTokens::from_usage(&occurrence.usage);
            let compatible = row.model == model
                && row.input_tokens == tokens.input
                && row.output_tokens == tokens.output
                && row.cache_read_tokens == tokens.cache_read
                && row.reasoning_output_tokens == tokens.reasoning
                && row.cache_creation_tokens
                    == tokens
                        .cache_5m
                        .saturating_add(tokens.cache_1h)
                        .saturating_add(tokens.unattributed);
            if !compatible || attached.contains(&(root.clone(), hash)) {
                fold.disclosed += 1;
                continue;
            }
            let Some(key) = transcript_key(
                model,
                &fold.base_selector,
                &occurrence.selector,
                occurrence.reasoning_effort.as_deref(),
                occurrence.timestamp.as_deref(),
            ) else {
                continue;
            };
            let Some(grain) = fold.entity.grains.get_mut(&(key.clone(), None)) else {
                fold.disclosed += 1;
                continue;
            };
            let Some(left) = grain.tokens.checked_sub(&tokens) else {
                fold.disclosed += 1;
                continue;
            };
            let Some(requests) = grain.requests.checked_sub(occurrence.usage.request_count) else {
                fold.disclosed += 1;
                continue;
            };
            grain.tokens = left;
            grain.requests = requests;
            grain.contributions = grain.contributions.saturating_sub(1);
            grain.unpriced = grain.unpriced.saturating_sub(1);
            let at = occurrence.timestamp.as_deref().and_then(rfc3339_unix_nanos);
            fold.entity.add(
                key,
                &tokens,
                occurrence.usage.request_count,
                row.cost_usd_micros,
                Some(ClaudeRequestUsageOrigin::TelemetryMatched),
                at,
            );
            attached.insert((root.clone(), hash));
            matched += occurrence.usage.request_count;
            fold.unmatched_1h = fold.unmatched_1h.saturating_sub(u64::from(
                at.is_some_and(|at| fold.now_nanos.saturating_sub(at) > 3_600_000_000_000),
            ));
        }
        fold.entity
            .grains
            .retain(|_, g| g.requests > 0 || g.tokens.conserved() > 0);
        fold.entity.telemetry_owned_complete = fold.entity.totals().1 == matched;
    }
    super::body::e2_side_calls(items, api, index);
}

/// DARK comparison happens after today's authoritative body fold. Only the
/// explicit gate permits mutation; one summed entity is emitted for path twins.
pub(crate) fn finish_page(items: &mut Vec<SnapshotItem>) {
    let mut by_session = BTreeMap::<String, (ClaudeEntityBody, ClaudeMoneyTokens, u64)>::new();
    for item in items.iter() {
        let Some(fold) = item.claude_money.as_deref() else {
            continue;
        };
        let entry = by_session
            .entry(item.source_session_id.clone())
            .or_default();
        entry.0.sum(fold.entity.clone());
        entry.1.add(&ClaudeMoneyTokens {
            input: item.input_tokens,
            output: item.output_tokens,
            cache_read: item.cache_read_tokens,
            cache_5m: item.cache_creation_5m_tokens,
            cache_1h: item.cache_creation_1h_tokens,
            unattributed: item.unattributed_total_tokens,
            reasoning: item.reasoning_output_tokens,
        });
        entry.2 = entry.2.saturating_add(item.request_count);
        record_counts(
            fold.fold_us,
            fold.responses,
            fold.entity.removed_requests,
            fold.disclosed,
            fold.unmatched_1h,
            0,
        );
    }
    for (entity, old, requests) in by_session.values() {
        let (new, new_requests) = entity.totals();
        let mut explained = new;
        explained.add(&entity.removed);
        if &explained != old || new_requests.saturating_add(entity.removed_requests) != *requests {
            record_counts(0, 0, 0, 0, 0, 1);
        }
    }
    if !enabled() {
        return;
    }
    let mut emitted = BTreeSet::new();
    items.retain_mut(|item| {
        if item.claude_money.is_none() {
            return true;
        }
        let Some((entity, _, _)) = by_session.get(&item.source_session_id) else {
            return true;
        };
        if emitted.contains(&item.source_session_id) {
            return false;
        }
        if !super::emit::apply(item, entity) {
            return false;
        }
        emitted.insert(item.source_session_id.clone());
        true
    });
}

// Existing native_collection_page carrier, nonzero only. These are shared
// process fold deltas since its previous Claude page line. Evidence completion
// follows native collection, so its attach/DARK receipts reach the next line.
use std::sync::atomic::{AtomicU64, Ordering};
static COUNTS: [AtomicU64; 6] = [const { AtomicU64::new(0) }; 6];
fn record_counts(
    fold_us: u64,
    responses: u64,
    copy_skipped: u64,
    disclosed: u64,
    unmatched_1h: u64,
    dark_unexplained: u64,
) {
    for (counter, value) in COUNTS.iter().zip([
        fold_us,
        responses,
        copy_skipped,
        disclosed,
        unmatched_1h,
        dark_unexplained,
    ]) {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}
pub(crate) fn take_counts() -> Counts {
    Counts(COUNTS.each_ref().map(|c| c.swap(0, Ordering::Relaxed)))
}
#[derive(Debug, Default)]
pub(crate) struct Counts([u64; 6]);
impl Serialize for Counts {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;
        for (key, value) in [
            "fold_us",
            "responses",
            "copy_skipped",
            "disclosed",
            "unmatched_1h",
            "dark_unexplained",
        ]
        .into_iter()
        .zip(self.0)
        {
            if value != 0 {
                map.serialize_entry(key, &value)?;
            }
        }
        map.end()
    }
}

crate::heap_layout_bound::fields!(ClaudeMoneyTokens; input, output, cache_read, cache_5m, cache_1h, unattributed, reasoning);
