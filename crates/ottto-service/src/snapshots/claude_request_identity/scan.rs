//! The per-item request scan: counted transcript requests and their
//! classification into a bounded grouping, request-owned activity staged
//! and published per page, and `tag_item`, which installs the tags.

use super::apply::apply_grouped_with_accepted;
#[cfg(test)]
use super::cycle_contract;
#[cfg(not(test))]
use super::COLLECTOR;
use super::{
    accepted, bucket_row_count, classify_ref, copy_derived_rows, from_account_rule,
    request_occurrence_facts, request_owned_grouping, spanless_first_sequence, wire_login_is_valid,
    CopyInvalidation, Grouping, IdentityRef, Ineligible, MarkerVerdict, Refusal, RequestFacts,
    ScanEvidence, Tagged,
};
use crate::snapshots::claude_request_accounts::{local_subscription, normalize_activity};
use crate::snapshots::claude_request_identity::accepted::AcceptedBuckets;
use crate::snapshots::{
    activity_bucket_from_timestamp, build_row_identity, codex_identity_is_uuid_shaped,
    rfc3339_unix_seconds, RowKey, SelectorCapture, SnapshotItem, UsageTotals,
};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

// --- Desktop store inventory digest -----------------------------------------

pub(in crate::snapshots) fn inventory_digest(store_dirs: &BTreeSet<PathBuf>) -> String {
    let mut digest = sha2::Sha256::new();
    for dir in store_dirs {
        digest.update(dir.to_string_lossy().as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

// --- Scan integration -----------------------------------------------------

/// One counted request as today's row builder placed it.
pub(in crate::snapshots) struct Request<'r> {
    pub(in crate::snapshots) request_id: &'r str,
    /// (response sequence, original event clock) of the owned transcript
    /// occurrence; `None` for an auxiliary telemetry-only request.
    pub(in crate::snapshots) occurrence: Option<(u64, bool)>,
    pub(in crate::snapshots) timestamp: &'r str,
    pub(in crate::snapshots) bucket_start: &'r str,
    pub(in crate::snapshots) row_key: &'r RowKey,
    pub(in crate::snapshots) usage: &'r UsageTotals,
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
    /// Request-id hashes the reported rebuild excludes as another root's.
    excluded: Option<&'s BTreeSet<String>>,
    root: String,
    desktop: bool,
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
            excluded: None,
            root: owner_root(item)?.to_string(),
            desktop: item
                .origin
                .as_ref()
                .and_then(|origin| origin.entrypoint.as_deref())
                == Some("claude-desktop"),
            grouping: Grouping::new(max_groups),
        })
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

    pub(in crate::snapshots) fn add(&mut self, item: &SnapshotItem, request: Request<'_>) {
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
        let terminal_unix_seconds = request
            .occurrence
            .and_then(|_| rfc3339_unix_seconds(request.timestamp));
        let facts = RequestFacts {
            root: &self.root,
            source_session_id: &item.source_session_id,
            request_id: request.request_id,
            // Auxiliary (telemetry-only) rows carry `observed_at`, which v2
            // OTLP capture may have taken from the observer clock and does not
            // record which; as in the legacy account path they cannot qualify. The trace span start
            // is event-origin but no existing rule qualifies it, and transcript
            // clocks are not theirs to borrow.
            terminal_unix_seconds,
            event_clock_complete: event_clock_complete.unwrap_or(false),
            marker: match (item.claude_org_markers.as_deref(), sequence) {
                (Some(markers), Some(sequence)) => markers.verdict(
                    sequence,
                    self.desktop || from_account_rule(terminal_unix_seconds),
                ),
                _ => MarkerVerdict::None,
            },
            spanless_first: false,
        };
        let identity = classify_ref(self.evidence, &facts);
        // Activity never overrides stronger request identity. A later Desktop
        // line can, however, qualify a marker flip the session-first CLI origin
        // would refuse solely as UntrustedFlip.
        if !self.grouping.unowned_request {
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
        original: Option<&crate::snapshots::SessionAccountEvidence>,
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
                && crate::snapshots::exact_session_account_hash(item).as_deref()
                    == Some(account) =>
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
    pub(crate) held: BTreeSet<String>,
    /// Copy-derived accepted rows this pass's bodies treat as never accepted,
    /// for the sync loop to tombstone through `AcceptedBuckets` before upload.
    pub(crate) copy_invalidated: Vec<CopyInvalidation>,
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

/// The transcript path's request-count guard: the parser counted exactly the
/// owned occurrences that carry usage, each under its own request id. A
/// response whose every usage field is zero (an API-error record with a
/// request id) adds no row, token or money and is never placed, so its id
/// neither counts nor refuses the item; it makes no claim. Any usage counted
/// without an owned occurrence, or an occurrence the count skipped, still
/// refuses. The census and the legacy account path keep the plain request-id count guard.
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

/// The request-owner root for an item, as the legacy account path derives it.
pub(crate) fn owner_root(item: &SnapshotItem) -> Option<&str> {
    match item.source_session_id.split_once("_agent-") {
        Some((root, agent)) => (!root.is_empty() && !agent.is_empty()).then_some(root),
        None => {
            let root = item.source_session_id.as_str();
            (codex_identity_is_uuid_shaped(root) && root == root.to_ascii_lowercase())
                .then_some(root)
        }
    }
}

/// What the classification tests run: stage, tag and publish one page.
#[cfg(test)]
pub(crate) fn apply_scan(
    snapshots: &mut [SnapshotItem],
    evidence: &ScanEvidence<'_>,
    reported: BTreeMap<String, Grouping>,
) -> ScanOutcome {
    let originals = capture_request_owned_originals(snapshots);
    let activity = stage_request_owned_activity(snapshots, evidence, &originals);
    let outcome = apply_scan_page(snapshots, evidence, reported);
    publish_request_owned_activity(snapshots, activity);
    outcome
}

/// Tag every eligible Claude item of this pass. Runs before the legacy account path, which leaves
/// new-collector items alone; ineligible items stay on today's path untouched.
/// `reported` holds the groupings the reported rebuild produced this pass.
pub(crate) fn apply_scan_page(
    snapshots: &mut [SnapshotItem],
    evidence: &ScanEvidence<'_>,
    mut reported: BTreeMap<String, Grouping>,
) -> ScanOutcome {
    let mut outcome = ScanOutcome::default();
    for item in snapshots {
        if item.provenance.collector != "claude_code_jsonl" {
            continue;
        }
        match tag_item(item, evidence, &mut reported, &mut outcome.copy_invalidated) {
            Some(Ok(Tagged::Held)) => {
                outcome.held.insert(item.source_session_id.clone());
            }
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
    BTreeMap<(String, Option<String>), Option<crate::snapshots::SessionAccountEvidence>>,
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
        if !crate::snapshots::claude_history_upgrade::is_request_owned_literal(item) {
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

pub(crate) fn collect_request_owned_activity(
    item: &SnapshotItem,
    evidence: &ScanEvidence<'_>,
    original: Option<&crate::snapshots::SessionAccountEvidence>,
) -> crate::desktop_recent::RecentActivity {
    let Some(fold) = item.claude_money.as_deref() else {
        return Default::default();
    };
    let spanless_first = spanless_first_sequence(item, fold);
    let mut activity = crate::desktop_recent::RecentActivity::default();
    for (request_id, occurrence) in &item.claude_usage_occurrences {
        if !occurrence.desktop_request
            || occurrence.usage.is_zero()
            || fold.is_skipped(occurrence.sequence)
        {
            continue;
        }
        let Some(timestamp) = occurrence.timestamp.as_deref() else {
            continue;
        };
        let Some(facts) = request_occurrence_facts(item, request_id, occurrence, spanless_first)
        else {
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
        && crate::snapshots::exact_session_account_hash(item).is_some()
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
    invalidated_rows: &mut Vec<CopyInvalidation>,
) -> Option<Result<Tagged, Ineligible>> {
    let accepted = evidence
        .accepted_buckets
        .and_then(|state| state.get(&item.source_session_id));
    // No ledger is the same as no usable key: share protection is off.
    let miss = evidence
        .accepted_buckets
        .map_or(accepted::UnknownCause::NoKey, AcceptedBuckets::miss_cause);
    if crate::snapshots::claude_history_upgrade::is_request_owned_literal(item) {
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
        let mut grouping = request_owned_grouping(item)?;
        grouping.hold_over_cap = true;
        let lifecycle = (
            item.source_started_at.clone(),
            item.source_ended_at.clone(),
            item.source_last_activity_at.clone(),
        );
        normalize_activity(item);
        grouping.extra_wire_bytes = evidence
            .wire_budget
            .reservation
            .map_or(0, |reserve| reserve(item));
        grouping.accepted_miss = miss;
        let copy_derived = copy_derived_rows(item, &grouping, accepted);
        let invalidated = accepted
            .filter(|_| !copy_derived.is_empty())
            .map(|accepted| accepted.invalidated(&copy_derived));
        let tagged = apply_grouped_with_accepted(
            item,
            grouping,
            invalidated.as_ref().or(accepted),
            evidence.wire_budget.max_item_bytes,
        );
        if tagged.is_err() {
            (
                item.source_started_at,
                item.source_ended_at,
                item.source_last_activity_at,
            ) = lifecycle;
        } else {
            invalidated_rows.extend(copy_derived.into_iter().map(|(bucket, row)| {
                CopyInvalidation {
                    session: item.source_session_id.clone(),
                    bucket,
                    row,
                }
            }));
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
        let mut sink = RequestSink::for_item(evidence, item, bucket_row_count(item))?;
        transcript_requests(item, |request| sink.add(item, request))?;
        sink.finish()
    };
    // A fork or resume can copy its predecessor's markers. Neither a settled
    // census nor an open fence makes those markers request-owned evidence.
    // Both grouping sources withdraw them before any identity is installed.
    grouping.withdraw_transcript_tags();
    // The legacy account path leaves new-collector items alone, so the backend UTC lifecycle
    // spelling it applies to every item it qualifies happens here, inside the
    // byte cap; an ineligible item returns to the legacy account path exactly as it arrived.
    let lifecycle = (
        item.source_started_at.clone(),
        item.source_ended_at.clone(),
        item.source_last_activity_at.clone(),
    );
    normalize_activity(item);
    grouping.extra_wire_bytes = evidence
        .wire_budget
        .reservation
        .map_or(0, |reserve| reserve(item));
    let desktop_recent = std::mem::take(&mut grouping.desktop_recent);
    let owned = !grouping.unowned_request;
    grouping.accepted_miss = miss;
    let tagged = apply_grouped_with_accepted(
        item,
        grouping,
        accepted,
        evidence.wire_budget.max_item_bytes,
    );
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
