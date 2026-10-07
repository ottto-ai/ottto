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
use std::collections::BTreeMap;

pub(super) const COMPLETE: &str = "claude_code_jsonl:own_request_account:v1";
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
}

/// Returned dispositions are in subagent order. Roots and unrelated collectors
/// are unchanged. Both inputs are the scan's already-loaded strict reports.
pub(crate) fn apply(
    snapshots: &mut [SnapshotItem],
    api: &ClaudeLocalOtelLoadReport,
    trace: &ClaudeTraceOwnershipLoadReport,
) -> Vec<Coverage> {
    let is_child = |item: &SnapshotItem| {
        matches!(
            item.provenance.collector.as_str(),
            "claude_code_jsonl" | COMPLETE | UNKNOWN
        ) && item
            .source_session_id
            .split_once("_agent-")
            .is_some_and(|(root, agent)| !root.is_empty() && !agent.is_empty())
    };
    if !snapshots.iter().any(is_child) {
        return Vec::new();
    }
    // Borrow the rows; index once rather than scanning/cloning a growing root
    // ledger separately for every child. A repeated request remains ambiguous.
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
    let mut dispositions = Vec::new();
    for item in snapshots.iter_mut().filter(|item| is_child(item)) {
        let qualification = if api.health.is_complete() && trace.is_complete() {
            qualify(item, &requests, &owners)
        } else {
            Err(Coverage::UnreadableEvidence)
        };
        let mut changed = false;
        let disposition = match qualification {
            Ok(account) => {
                changed = set_claude_account_hash(item, Some(account.to_string()));
                Coverage::Complete
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
        if changed {
            item.snapshot_fingerprint = snapshot_fingerprint(SnapshotSource::ClaudeCode, item);
        }
        dispositions.push(disposition);
    }
    dispositions
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
    if item.unattributed_total_tokens != 0 || claude_snapshot_request_id_hashes(item).is_none() {
        return Err(Coverage::MissingRequests);
    }
    if item
        .attribution_facts
        .iter()
        .any(|fact| fact.field == "root_session_ref" && fact.value != root)
    {
        return Err(Coverage::UnprovedRequestOwner);
    }
    let mut account = None;
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
        if account.is_some_and(|prior| prior != hash) {
            return Err(Coverage::ConflictingAccounts);
        }
        account = Some(hash);
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
    let account = account.ok_or(Coverage::MissingRequests)?;
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
        if !matches!(row.auth_mode.as_deref(), None | Some("oauth"))
            || !matches!(row.billing_channel.as_deref(), None | Some("subscription"))
            || !matches!(row.billing_provider.as_deref(), None | Some("anthropic"))
            || !matches!(row.model_provider.as_deref(), None | Some("anthropic"))
            || !matches!(row.gateway_provider.as_deref(), None | Some("anthropic"))
        {
            return Err(Coverage::UnsupportedDestination);
        }
    }
    Ok(account)
}
