//! Versioned own-request account qualification, independent of family accounting.
//! No observations or coverage witnesses are added to persistent local state.

use super::{
    claude_api_evidence_fingerprint_is_valid, claude_snapshot_request_id_hashes,
    claude_trace_evidence_fingerprint_is_valid, claude_trace_owner_session_id,
    set_claude_account_hash, snapshot_fingerprint, SnapshotItem, SnapshotSource,
};
use crate::claude_local_otel::{
    ClaudeIdentityAttributeOrigin, ClaudeIdentityDisposition, ClaudeLocalOtelEvidence,
    ClaudeLocalOtelLoadReport, ClaudeTraceOwnershipEvidence, ClaudeTraceOwnershipLoadReport,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const COMPLETE: &str = "claude_code_jsonl:own_request_account:v1";
pub(super) const MIXED: &str = "claude_code_jsonl:own_request_account_mixed:v1";
pub(super) const UNKNOWN: &str = "claude_code_jsonl:own_request_account_unknown:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Coverage {
    Complete,
    MissingRequests,
    UnreadableEvidence,
    InvalidAccountEvidence,
    ConflictingAccounts,
    UnprovedRequestOwner,
    KnownAccountConflict,
    UnsupportedDestination,
    UnprovedEventClock,
}

/// A scan-local capability bound to the freshly qualified semantic and creator
/// body. Never serialized or restored from a collector string / cached index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct MixedUploads {
    bodies: BTreeMap<String, (String, String)>,
}

impl MixedUploads {
    pub(super) fn permits(&self, item: &SnapshotItem) -> bool {
        self.bodies
            .get(&item.source_session_id)
            .is_some_and(|(semantic, body)| {
                item.provenance.collector == MIXED
                    && item.snapshot_fingerprint == *semantic
                    && snapshot_fingerprint(SnapshotSource::ClaudeCode, item) == *semantic
                    && super::snapshot_upload_body_witness(item) == *body
            })
    }
}

#[derive(Debug, Default)]
pub(crate) struct Qualification {
    pub(crate) coverage: Vec<Coverage>,
    pub(crate) mixed: MixedUploads,
}

/// Reuse the scan's strict reports and index each request once. Account proof
/// and original clock qualification remain separate facts: a missing clock
/// withdraws COMPLETE without deleting an independently proved row account.
#[cfg(test)]
pub(crate) fn apply(
    snapshots: &mut [SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
) -> Qualification {
    apply_with_originals(snapshots, api, trace, &BTreeMap::new())
}

pub(crate) fn apply_with_originals(
    snapshots: &mut [SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
    originals: &BTreeMap<String, super::SessionAccountEvidence>,
) -> Qualification {
    let mut requests = BTreeMap::new();
    for (root, rows) in &api.evidence {
        for row in rows {
            requests
                .entry((root.as_str(), row.request_id.as_str()))
                .and_modify(|entry| *entry = None)
                .or_insert(Some(row));
        }
    }
    let mut owners = BTreeMap::new();
    for (root, rows) in &trace.evidence {
        for row in rows {
            owners
                .entry((root.as_str(), row.request_id.as_str()))
                .and_modify(|entry| *entry = None)
                .or_insert(Some(row));
        }
    }
    let healthy = api.health.is_complete() && trace.is_complete();
    let mut result = Qualification::default();
    for item in snapshots {
        if !matches!(
            item.provenance.collector.as_str(),
            "claude_code_jsonl" | COMPLETE | UNKNOWN | MIXED
        ) {
            continue;
        }
        let is_child = item
            .source_session_id
            .split_once("_agent-")
            .is_some_and(|(root, agent)| !root.is_empty() && !agent.is_empty());
        let mut changed = false;
        if is_child {
            let proof = if healthy {
                qualify(item, &requests, &owners)
            } else {
                Err(Coverage::UnreadableEvidence)
            };
            let disposition = match proof {
                Ok(account) => {
                    changed = set_claude_account_hash(item, Some(account.to_string()));
                    if original_event_clocks_complete(item) {
                        Coverage::Complete
                    } else {
                        Coverage::UnprovedEventClock
                    }
                }
                Err(reason) => reason,
            };
            let collector = if disposition == Coverage::Complete {
                COMPLETE
            } else {
                UNKNOWN
            };
            if item.provenance.collector != collector {
                item.provenance.collector = collector.to_string();
                changed = true;
            }
            changed |= normalize_activity(item);
            result.coverage.push(disposition);
        } else {
            // Only genuine existing reported accounting may remove the old
            // current-owner upload veto. Never clear accounts to fit this shape.
            // Request identity is not creator identity. The preceding legacy
            // veto conflates a later login switch with a creator contradiction.
            // Recover ONLY this scan's unchanged original carrier after the
            // complete mixed proof, never a cached owner or malformed identity.
            let original = originals.get(&item.source_session_id).filter(|before| {
                item.session_account_evidence.as_ref().is_some_and(|after| {
                    let mut comparable = after.clone();
                    comparable.identity_disposition = before.identity_disposition;
                    before.identity_disposition == Some("complete")
                        && after.identity_disposition == Some("conflict")
                        && comparable == **before
                })
            });
            let qualified = healthy && qualify_mixed(item, &requests, &owners, original);
            if qualified {
                if let Some(original) = original {
                    item.session_account_evidence = Some(original.clone());
                    changed = true;
                }
            }
            let collector = if qualified {
                MIXED
            } else if item.provenance.collector == MIXED {
                "claude_code_jsonl"
            } else {
                item.provenance.collector.as_str()
            };
            if item.provenance.collector != collector {
                item.provenance.collector = collector.to_string();
                changed = true;
            }
            if qualified || changed {
                changed |= normalize_activity(item);
            }
            if changed {
                item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
            }
            if qualified {
                result.mixed.bodies.insert(
                    item.source_session_id.clone(),
                    (
                        item.snapshot_fingerprint.clone(),
                        super::snapshot_upload_body_witness(item),
                    ),
                );
            }
            continue;
        }
        if changed {
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        }
    }
    result
}

// Preserve each original instant while using the backend's UTC wire spelling
// for lifecycle fields. This changes no timestamp source or semantic hash epoch.
fn normalize_activity(item: &mut SnapshotItem) -> bool {
    let mut changed = false;
    for value in [
        &mut item.source_started_at,
        &mut item.source_ended_at,
        &mut item.source_last_activity_at,
    ] {
        if let Some((_, normalized)) = value
            .as_deref()
            .and_then(super::activity_bucket_from_timestamp)
        {
            if value.as_deref() != Some(normalized.as_str()) {
                *value = Some(normalized);
                changed = true;
            }
        }
    }
    changed
}

/// All counted requests must have genuine original terminal usage-event clocks
/// before any fallback/fold, and must reproduce EVERY represented hourly min/max.
/// Legacy OTLP v2 cannot prove event-vs-observer origin; auxiliary-only rows and
/// timestamps carried across unstamped partials therefore cannot qualify D1.
fn original_event_clocks_complete(item: &SnapshotItem) -> bool {
    if item.request_count == 0
        || item.claude_usage_occurrences.len() as u64 != item.request_count
        || item.claude_usage_occurrences.len() != item.claude_usage_request_ids.len()
    {
        return false;
    }
    let mut expected: BTreeMap<String, (u64, String, String)> = BTreeMap::new();
    for occurrence in item.claude_usage_occurrences.values() {
        if !occurrence.event_clock_complete {
            return false;
        }
        let Some((hour, time)) = occurrence
            .timestamp
            .as_deref()
            .and_then(super::activity_bucket_from_timestamp)
        else {
            return false;
        };
        let entry = expected
            .entry(hour)
            .or_insert((0, time.clone(), time.clone()));
        entry.0 += 1;
        if super::timestamp_is_before(&time, &entry.1) {
            entry.1 = time.clone();
        }
        if super::timestamp_is_after(&time, &entry.2) {
            entry.2 = time;
        }
    }
    item.usage_buckets.len() == expected.len()
        && item.usage_buckets.iter().all(|bucket| {
            expected
                .get(&bucket.bucket_start)
                .is_some_and(|(count, first, last)| {
                    bucket
                        .model_usage
                        .iter()
                        .try_fold(0_u64, |total, row| total.checked_add(row.request_count))
                        == Some(*count)
                        && bucket.first_activity_at.as_deref() == Some(first.as_str())
                        && bucket.last_activity_at.as_deref() == Some(last.as_str())
                })
        })
}

fn qualify_mixed(
    item: &SnapshotItem,
    requests: &BTreeMap<(&str, &str), Option<&ClaudeLocalOtelEvidence>>,
    owners: &BTreeMap<(&str, &str), Option<&ClaudeTraceOwnershipEvidence>>,
    original_before_enrichment: Option<&super::SessionAccountEvidence>,
) -> bool {
    let root = item.source_session_id.as_str();
    let Some(original) = original_before_enrichment.or(item.session_account_evidence.as_ref())
    else {
        return false;
    };
    if !super::codex_identity_is_uuid_shaped(root)
        || root != root.to_ascii_lowercase()
        || item.usage_accounting_contract.as_deref() != Some("session_exclusive_reported_usage:v1")
        || super::validate_snapshot_item(0, item).is_err()
        || original.provider != "anthropic"
        || original.identity_hash_scheme != "provider-sha256:v1"
        || original.evidence_source != "claude_desktop_original:v1"
        || original.identity_disposition != Some("complete")
        || !original
            .account_identifier_hash
            .as_deref()
            .is_some_and(hash_is_valid)
        || !original
            .provider_workspace_hash
            .as_deref()
            .is_some_and(hash_is_valid)
        || item.model_usage.is_empty()
        || item.usage_buckets.is_empty()
        || item
            .cost
            .as_ref()
            .and_then(|cost| cost.total_cost_usd.as_ref())
            .is_none()
        || item
            .model_usage
            .iter()
            .chain(item.usage_buckets.iter().flat_map(|b| &b.model_usage))
            .any(|row| row.account_identifier_hash.is_some() || !local_subscription(row))
    {
        return false;
    }
    let Ok(accounts) = request_accounts(item, root, requests, owners) else {
        return false;
    };
    let creator = original.account_identifier_hash.as_deref().unwrap();
    accounts.len() >= 2
        && accounts.contains(creator)
        && item.claude_usage_request_ids.iter().all(|request| {
            let row = requests[&(root, request.as_str())].unwrap();
            row.request_identity.as_ref().map_or(true, |identity| {
                !matches!(
                    identity.disposition,
                    ClaudeIdentityDisposition::Conflict | ClaudeIdentityDisposition::Invalid
                ) && !matches!(
                    identity.organization.disposition,
                    ClaudeIdentityDisposition::Conflict | ClaudeIdentityDisposition::Invalid
                ) && (row.account_identifier_hash.as_deref() != Some(creator)
                    || identity
                        .organization
                        .resource_hash
                        .iter()
                        .chain(identity.organization.log_record_hash.iter())
                        .all(|hash| {
                            Some(hash.as_str()) == original.provider_workspace_hash.as_deref()
                        }))
            })
        })
}

fn hash_is_valid(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn local_subscription(row: &super::SnapshotModelUsage) -> bool {
    matches!(row.auth_mode.as_deref(), None | Some("oauth"))
        && matches!(row.billing_channel.as_deref(), None | Some("subscription"))
        && matches!(row.billing_provider.as_deref(), None | Some("anthropic"))
        && matches!(row.model_provider.as_deref(), None | Some("anthropic"))
        && matches!(row.gateway_provider.as_deref(), None | Some("anthropic"))
}

fn qualify<'a>(
    item: &SnapshotItem,
    requests: &BTreeMap<(&str, &str), Option<&'a ClaudeLocalOtelEvidence>>,
    owners: &BTreeMap<(&str, &str), Option<&ClaudeTraceOwnershipEvidence>>,
) -> Result<&'a str, Coverage> {
    let (root, _) = item
        .source_session_id
        .split_once("_agent-")
        .expect("checked child");
    let accounts = request_accounts(item, root, requests, owners)?;
    if accounts.len() != 1 {
        return Err(Coverage::ConflictingAccounts);
    }
    let account = *accounts.first().ok_or(Coverage::MissingRequests)?;
    for row in item
        .model_usage
        .iter()
        .chain(item.usage_buckets.iter().flat_map(|b| b.model_usage.iter()))
    {
        if row
            .account_identifier_hash
            .as_deref()
            .is_some_and(|known| known != account)
        {
            return Err(Coverage::KnownAccountConflict);
        }
        if !local_subscription(row) {
            return Err(Coverage::UnsupportedDestination);
        }
    }
    Ok(account)
}

fn request_accounts<'a>(
    item: &SnapshotItem,
    root: &str,
    requests: &BTreeMap<(&str, &str), Option<&'a ClaudeLocalOtelEvidence>>,
    owners: &BTreeMap<(&str, &str), Option<&ClaudeTraceOwnershipEvidence>>,
) -> Result<BTreeSet<&'a str>, Coverage> {
    if !item.claude_context_curve_request_index_complete
        || item.unattributed_total_tokens != 0
        || claude_snapshot_request_id_hashes(item).is_none()
    {
        return Err(Coverage::MissingRequests);
    }
    if item
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "root_session_ref" && fact.value != root)
    {
        return Err(Coverage::UnprovedRequestOwner);
    }
    let mut accounts = BTreeSet::new();
    for request in &item.claude_usage_request_ids {
        let row = requests
            .get(&(root, request.as_str()))
            .and_then(|entry| *entry)
            .ok_or(Coverage::MissingRequests)?;
        if row.session_id != root
            || row.capture_revision != "claude_api_request:v2"
            || row.request_count != 1
            || !row.account_identity_checked
            || !claude_api_evidence_fingerprint_is_valid(row)
        {
            return Err(Coverage::InvalidAccountEvidence);
        }
        let hash = row
            .account_identifier_hash
            .as_deref()
            .ok_or(Coverage::InvalidAccountEvidence)?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || row.request_identity.as_ref().is_some_and(|identity| {
                identity.identity_hash_scheme != "provider-sha256:v1"
                    || identity.account.disposition != ClaudeIdentityDisposition::Complete
                    || match identity.account.origin {
                        ClaudeIdentityAttributeOrigin::LogRecord => {
                            identity.account.log_record_hash.as_deref() != Some(hash)
                                || identity.account.resource_hash.is_some()
                        }
                        ClaudeIdentityAttributeOrigin::Resource => {
                            identity.account.resource_hash.as_deref() != Some(hash)
                                || identity.account.log_record_hash.is_some()
                        }
                        ClaudeIdentityAttributeOrigin::ResourceAndLogRecord => {
                            identity.account.resource_hash.as_deref() != Some(hash)
                                || identity.account.log_record_hash.as_deref() != Some(hash)
                        }
                        ClaudeIdentityAttributeOrigin::Missing => true,
                    }
            })
        {
            return Err(Coverage::InvalidAccountEvidence);
        }
        accounts.insert(hash);
        let owner = owners
            .get(&(root, request.as_str()))
            .and_then(|entry| *entry)
            .ok_or(Coverage::UnprovedRequestOwner)?;
        if owner.session_id != root
            || owner.capture_revision != "claude_llm_request_ownership:v1"
            || !claude_trace_evidence_fingerprint_is_valid(owner)
            || claude_trace_owner_session_id(root, &owner.agent_id) != item.source_session_id
            || owner.client_request_id.is_empty()
            || owner.client_request_id != row.client_request_id
        {
            return Err(Coverage::UnprovedRequestOwner);
        }
    }
    if accounts.is_empty() {
        return Err(Coverage::MissingRequests);
    }
    Ok(accounts)
}
