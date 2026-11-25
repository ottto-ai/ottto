//! Reported telemetry for e2: the holder join, attaching reported rows to
//! request slots and identities, side-call discovery for a page, and the
//! reported-row helpers the telemetry-only path shares.

use super::{
    claude_trace_evidence_fingerprint_is_valid, diag, family_membership, hold_copies,
    mark_copy_key, matching_members, page_families, record_counts, reported_key, timed,
    CertificateFailure, ClaudeApiEvidenceRead, ClaudeEntityBody, ClaudeLocalOtelLoadReport,
    ClaudeTraceOwnershipLoadReport, Counts, Duration, FamilyMembership, FileFold, FoldTelemetry,
    GrainNearMiss, IdentityCaller, PageSpent, PathBuf, RefCell, ScanTraversalPath, HOUR_NANOS,
};
use crate::claude_local_otel::ClaudeLocalOtelEvidence;
use crate::snapshots::claude_money_birth_store::{location_key, LocationKey};
use crate::snapshots::claude_request_census::claude_request_hash;
use crate::snapshots::claude_request_identity::{self, AccountPartition};
use crate::snapshots::claude_request_money::body::{
    reported_model_effort, ClaudeLiveKey, ClaudeRequestUsageOrigin,
};
use crate::snapshots::claude_request_money::ClaudeMoneyTokens;
use crate::snapshots::{
    claude_api_cache_creation, claude_api_matches_transcript_occurrence,
    claude_index_path_family_member, claude_index_path_member_ref, claude_trace_owner_session_id,
    local_index_key, rfc3339_unix_nanos, validate_claude_api_row, ClaudeTranscriptUsageOccurrence,
    ScanIndex, ScanTraversalCheckpoint, SelectorCapture, SnapshotItem,
};
use crate::telemetry_attach::{join, Attachment, DisclosureReason, Holders};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

/// Same bound the earlier holder walk used. A census walk that hits it cannot
/// decide: the affected sessions or families are held, never counted.
const SIDE_CALL_DEADLINE: Duration = Duration::from_millis(250);

/// Same-session twins share the first holder; distinct sessions are ambiguous.
pub(super) fn holders(
    items: &[SnapshotItem],
    view: &FamilyMembership,
    request_id: &str,
) -> Holders<usize> {
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
    let observed = rfc3339_unix_nanos(&row.observed_at);
    let at = (reported.0 .0 != estimated.0 .0)
        .then_some(observed)
        .flatten();
    fold.entity
        .add_slot(reported, &tokens, requests, row.cost_usd_micros, at);
    // The request's activity time is the later of its transcript and row
    // clocks, so it never moves back when its evidence moves from the side
    // row to the transcript. Only the entity clock: hours, buckets and owner
    // clocks keep the transcript's.
    if let Some(observed) = observed {
        fold.entity.activity_nanos = fold.entity.activity_nanos.max(observed);
    }
    // A copied marker's lent account follows its request to the reported slot.
    if let Some(lent) = fold
        .accounts
        .as_mut()
        .and_then(|accounts| accounts.copied_marker_lent.get_mut(&occurrence.sequence))
    {
        (lent.key, lent.origin) = (reported.0.clone(), reported.1);
    }
    if let Some(cost) = row.cost_usd_micros {
        if fold.unproven_copy(occurrence) {
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

/// Re-place an already-counted native request after the identity owner has
/// classified its exact telemetry. Reuse attachment's keys and exact money;
/// no second resolver, token counter or row allocator participates.
pub(crate) fn place_request_identity(
    fold: &mut FileFold,
    occurrence: &ClaudeTranscriptUsageOccurrence,
    telemetry: Option<&ClaudeLocalOtelEvidence>,
    from: AccountPartition,
    to: AccountPartition,
    caller: IdentityCaller,
) {
    let Some(estimated) = fold.occurrence_key(occurrence) else {
        return;
    };
    let candidate = telemetry
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
            Some((key, Some(origin), row.cost_usd_micros))
        });
    // A reported key without a grain under `from` is kept only for the
    // count-only near-miss diagnostic below.
    let (reported, unplaced) = match candidate {
        Some(found)
            if fold
                .entity
                .grains
                .contains_key(&(found.0.clone(), found.1, from.clone())) =>
        {
            (Some(found), None)
        }
        other => (None, other.map(|(key, ..)| key)),
    };
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
        let near = grain_near_miss(&fold.entity, &slot, unplaced.as_ref());
        fold.entity
            .fail_certificate(CertificateFailure::IdentityGrain(caller, near));
        return;
    };
    let Some(left_cost) = grain.cost_micros.checked_sub(cost.unwrap_or(0)) else {
        fold.entity
            .fail_certificate(CertificateFailure::IdentityCost);
        return;
    };
    let unpriced = grain.unpriced;
    if !fold.entity.take_estimated(&slot, &tokens, requests) {
        fold.entity
            .fail_certificate(CertificateFailure::IdentityUsage);
        return;
    }
    if let Some(grain) = fold.entity.grains.get_mut(&slot) {
        grain.cost_micros = left_cost;
        grain.unpriced = unpriced.saturating_sub(u64::from(cost.is_none()));
    }
    fold.entity
        .add(key, &tokens, requests, cost, origin, at, to);
}

/// Count-only diagnostic: the request's key under another account, else under
/// `from` with another origin or the unplaced reported key, else absent.
fn grain_near_miss(
    entity: &ClaudeEntityBody,
    slot: &Slot,
    unplaced: Option<&ClaudeLiveKey>,
) -> GrainNearMiss {
    let mut near = GrainNearMiss::Absent;
    for (key, _, account) in entity.grains.keys() {
        if *key == slot.0 || Some(key) == unplaced {
            if *account != slot.2 {
                return GrainNearMiss::OtherAccount;
            }
            near = GrainNearMiss::OtherKey;
        }
    }
    near
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
            .and_then(|row| crate::snapshots::activity_bucket_from_timestamp(&row.observed_at))
            .map(|(bucket, _)| bucket);
        let membership = timed("attach.membership", || {
            family_membership(&items.borrow(), members)
        });
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
                let Some(occurrence) = item.claude_usage_occurrences.get(&row.request_id) else {
                    continue;
                };
                let Some(fold) = item.claude_money.as_deref_mut() else {
                    continue;
                };
                // A partially held prefix has no per-id final removal view.
                // Leave its dollars uncovered rather than pricing a hold.
                if !fold.entity.held
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

/// Page-local exact Task-member discovery. Concrete anchors preserve path twins;
/// neither the index nor telemetry supplies a guessed project directory.
#[derive(Default)]
pub(crate) struct SideCallDiscovery {
    anchors: BTreeMap<String, BTreeSet<PathBuf>>,
    pub(crate) hints: BTreeSet<PathBuf>,
}
impl SideCallDiscovery {
    pub(crate) fn new<'a>(paths: impl Iterator<Item = &'a Path>) -> Self {
        let mut page = Self::default();
        for path in paths {
            let Some(member) =
                claude_index_path_member_ref(path).filter(|member| member.subagent_stem.is_none())
            else {
                continue;
            };
            if let Some(parent) = path.parent() {
                page.anchors
                    .entry(member.root.to_owned())
                    .or_default()
                    .insert(parent.join(member.root).join("subagents"));
            }
        }
        page
    }

    pub(super) fn reserve_member(&mut self, root: &str, owner: &str) -> bool {
        let Some(stem) = owner.strip_prefix(root).and_then(|s| s.strip_prefix('_')) else {
            return false;
        };
        let mut reserved = false;
        for directory in self.anchors.get(root).into_iter().flatten() {
            let path = directory.join(format!("{stem}.jsonl"));
            if !claude_index_path_family_member(&path)
                .is_some_and(|member| member.0 == root && member.1 == owner)
            {
                continue;
            }
            let found = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata.is_file(),
                Err(error) => error.kind() != std::io::ErrorKind::NotFound,
            };
            if found {
                reserved = true;
                if self.hints.insert(path) {
                    diag("side_call_member_hints", 1);
                    record_counts(Counts::one(22, 1));
                }
            }
        }
        reserved
    }
}

/// Side calls (telemetry-only requests no family transcript holds) keep
/// today's attribution: the trace-named member's body; the root only
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
    discovery: &mut SideCallDiscovery,
) -> BTreeSet<String> {
    if !index.persistence_available() {
        return items.iter().map(|i| i.source_session_id.clone()).collect();
    }

    let _spent = PageSpent::start("page.side_calls");
    let mut unresolved = BTreeSet::new();

    timed("side.inherit", || {
        claude_request_identity::inherit_root_accounts(items, false)
    });

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
                    crate::snapshots::claude_request_census::claude_request_hash(&row.request_id)
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
            // the root does, counted as a fallback. A member with
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
                if discovery.reserve_member(root, owner) {
                    continue; // same off-page skip as census/unread members
                }
                owner = root.as_str();
                fallback = true;
            }
            let Some(target) = targets.get(owner).copied() else {
                continue;
            };
            let at = rfc3339_unix_nanos(&row.observed_at);
            let Some(key) = timed("side.reported_key", || {
                let build = || reported_key(row, None, &SelectorCapture::default());
                match at {
                    Some(at) => keys
                        .entry((
                            row.model.as_ref(),
                            row.speed.as_ref(),
                            row.effort.as_ref(),
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
            let Some(fold) = items[target].claude_money.as_deref_mut() else {
                continue;
            };
            let account = fold.accounts.as_ref().and_then(|a| {
                claude_request_identity::side_call_account(row, root).or_else(|| a.fallback.clone())
            });
            let Some(tokens) = add_reported_row(&mut fold.entity, row, account, Some(key)) else {
                disclosed += 1;
                diag("side_cache_split", 1);
                continue;
            };
            fold.side.add(&tokens);
            if fallback {
                fold.root_fallbacks += 1;
            }
        }
        if waiting {
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

/// Every path component of the directories the census walk queued but has not
/// listed. A family's member transcripts live under `<root>/subagents/`; the
/// root file being on a page means its own directory was listed, so the
/// family's directory is still to be listed exactly when `<root>` is here.
/// A re-listing pass's directories (not census members) are left out, so
/// their roots do not wait. That pass starts only once the walk's directory
/// queue is empty, so the two never share it. Its members are NOT guaranteed
/// observed: a directory or member created after the walk is unknown until
/// listed. Once a member is listed, the observed-index (`unread_members`)
/// and family-census guards still apply.
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
        .filter(|directory| directory.census_member)
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
) -> BTreeSet<LocationKey> {
    if traversal.pending_directories.is_empty() {
        return BTreeSet::new();
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
    crate::local_resource_diagnostics::page_selection(
        "claude_code",
        crate::local_resource_diagnostics::PageSelection::DeferredRoots,
        deferred.len() as u64,
    );
    let locations = deferred
        .iter()
        .map(|candidate| location_key(&local_index_key(&candidate.path)))
        .collect();
    for candidate in deferred.into_iter().rev() {
        traversal.pending_candidates.push_front(candidate);
    }
    locations
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
        if &*row.capture_revision == "claude_llm_request_ownership:v1"
            && &*row.session_id == root
            && timed("side.trace_fingerprint", || {
                claude_trace_evidence_fingerprint_is_valid(row)
            })
        {
            owners[at] = Some(row);
        }
    }
    owners
}

/// Shared API row addition. Account fallback is supplied by the caller,
/// never inferred for a telemetry-only entity.
pub(crate) fn add_reported_row(
    entity: &mut ClaudeEntityBody,
    row: &ClaudeLocalOtelEvidence,
    account: AccountPartition,
    key: Option<ClaudeLiveKey>,
) -> Option<ClaudeMoneyTokens> {
    let (cache_5m, cache_1h, unattributed) = claude_api_cache_creation(row)?;
    let tokens = ClaudeMoneyTokens {
        input: row.input_tokens,
        output: row.output_tokens,
        cache_read: row.cache_read_tokens,
        cache_5m,
        cache_1h,
        unattributed,
        reasoning: row.reasoning_output_tokens,
    };
    let key = key.or_else(|| reported_key(row, None, &SelectorCapture::default()))?;
    let origin = if row.cost_usd_micros.is_some() {
        ClaudeRequestUsageOrigin::TelemetryReported
    } else {
        ClaudeRequestUsageOrigin::TelemetryUnpriced
    };
    let at = rfc3339_unix_nanos(&row.observed_at);
    if let Some(at) = at {
        entity.note_activity(&key.0, at, at);
    }
    entity.add(
        key,
        &tokens,
        1,
        row.cost_usd_micros,
        Some(origin),
        None,
        account,
    );
    Some(tokens)
}

/// A complete scoped negative answer, independent of this page's emissions.
/// Birth observations include content-session and path twins, even when they
/// emitted no body. Unknown relevant queue/decode state keeps work owed.
pub(crate) fn telemetry_scope(
    index: &ScanIndex,
    roots: &BTreeSet<String>,
) -> (BTreeSet<String>, BTreeSet<String>) {
    let queued = queued_directory_names(index);
    let mut backed = roots
        .iter()
        .filter(|root| {
            index
                .claude_money_birth_store
                .observations(root)
                .next()
                .is_some()
        })
        .cloned()
        .collect::<BTreeSet<_>>();
    let observed = index
        .traversal
        .iter()
        .flat_map(|walk| walk.observed_index_keys.iter());
    for key in index
        .files
        .keys()
        .chain(index.claude_request_census.records().map(|(key, _)| key))
        .chain(observed)
    {
        if let Some(member) = claude_index_path_member_ref(Path::new(key)) {
            if roots.contains(member.root) {
                backed.insert(member.root.to_owned());
            }
        }
    }
    let absent = roots
        .difference(&backed)
        .filter(|root| !index.decode_holds_family(root) && !queued.contains(*root))
        .cloned()
        .collect();
    (absent, backed)
}
