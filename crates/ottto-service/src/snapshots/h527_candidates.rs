//! Read-only candidate exporter for one manifest-scoped historical Claude
//! operation (`h527_candidates:v1`).
//!
//! The exporter never scans, parses, uploads, or persists anything. It reads
//! the production pipeline's own post-policy upload set, authority disposition
//! and scan index by shared reference, and turns each approved member into
//! either one exact ordinary batch body or a held row that carries no body.
//!
//! The operator manifest names members; it is never ownership proof. Every
//! eligible verdict comes from evidence those pipeline values already carry:
//! the session-exclusive usage contract, the complete duplicate-request census,
//! its overflow fence, and the existing exact legacy exclusions. Anything the
//! exporter cannot bind to that evidence is held. Items are cloned into the
//! ordinary request unchanged, so contract-5 tags and the untagged no-evidence
//! fallback are whatever the normal pipeline produced.
// The operator entry has no runtime caller until a reviewed read-only pipeline
// seam supplies its inputs; tests drive it with synthetic pipeline values.
#![cfg_attr(not(test), allow(dead_code))]

use super::{
    claude_request_id_set_fingerprint, claude_snapshot_family_root, collector_version,
    validate_snapshot_batch_request, ClaudeUsageAuthorityDisposition, ScanIndex,
    SnapshotBatchRequest, SnapshotItem, SnapshotSource, SnapshotUploadPolicy,
    SNAPSHOT_SCHEMA_VERSION,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const CANDIDATES_CONTRACT_VERSION: &str = "h527_candidates:v1";
pub(crate) const QUALIFICATION_REPORT_CONTRACT_VERSION: &str = "h527_candidate_qualification:v1";
/// What the conservation proof covers. A complete local census cannot see an
/// accepted body whose transcript was deleted or left the census window; the
/// planner decides whether this scope suffices for a member.
pub(crate) const CONSERVATION_SCOPE: &str = "local_complete_census:v1";
pub(crate) const MANIFEST_MEMBER_COUNT: usize = 18;
const SESSION_EXCLUSIVE_USAGE_CONTRACT: &str = "session_exclusive_reported_usage:v1";
const MIN_MACHINE_ID_CHARS: usize = 8;
const MAX_MACHINE_ID_CHARS: usize = 128;
const SNAPSHOT_STORAGE_SEPARATOR: char = '\u{1f}';

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EligibleReason {
    QualifiedSourceOwnership,
    ExactExclusion,
    /// Closed vocabulary only: no retained per-request membership of a
    /// previously acknowledged revision exists, so the exporter never emits it.
    ExactPreviousAckMembership,
}

impl EligibleReason {
    pub(crate) const ALL: [Self; 3] = [
        Self::QualifiedSourceOwnership,
        Self::ExactExclusion,
        Self::ExactPreviousAckMembership,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::QualifiedSourceOwnership => "qualified_source_ownership",
            Self::ExactExclusion => "exact_exclusion",
            Self::ExactPreviousAckMembership => "exact_previous_ack_membership",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldReason {
    UnknownOwner,
    IncompleteCensus,
    CapOverflow,
    CreatorHold,
    MissingEvidence,
    /// Closed vocabulary only: money is priced by the server plan, never here.
    MoneyDecrease,
}

impl HeldReason {
    pub(crate) const ALL: [Self; 6] = [
        Self::UnknownOwner,
        Self::IncompleteCensus,
        Self::CapOverflow,
        Self::CreatorHold,
        Self::MissingEvidence,
        Self::MoneyDecrease,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::UnknownOwner => "unknown_owner",
            Self::IncompleteCensus => "incomplete_census",
            Self::CapOverflow => "cap_overflow",
            Self::CreatorHold => "creator_hold",
            Self::MissingEvidence => "missing_evidence",
            Self::MoneyDecrease => "money_decrease",
        }
    }
}

/// Operator-supplied scope. Format-checked here; authority is checked by the
/// server plan, never inferred from these strings.
#[derive(Debug, Clone)]
pub(crate) struct OperatorScope {
    pub(crate) operation_id: String,
    pub(crate) user_id: String,
    pub(crate) organization_id: String,
    pub(crate) device_id: String,
    pub(crate) machine_id: String,
    pub(crate) producer_revision: String,
    pub(crate) collector_version: String,
}

#[derive(Debug, Clone)]
pub(crate) struct ApprovedMember {
    pub(crate) source_session_id: String,
    pub(crate) session_key_sha256: String,
    /// Copied from the manifest. The exporter cannot verify it.
    pub(crate) prior_refusal_body_witness: String,
}

/// The production pipeline's values after local evidence, account binding,
/// upload policy and backfill cutoff, before any upload. Shared references:
/// the exporter cannot change scan, census or hold state.
pub(crate) struct PipelineEvidence<'a> {
    pub(crate) upload_snapshots: &'a [SnapshotItem],
    pub(crate) disposition: &'a ClaudeUsageAuthorityDisposition,
    pub(crate) index: &'a ScanIndex,
    pub(crate) upload_policy: SnapshotUploadPolicy,
}

#[derive(Debug, Clone)]
pub(crate) struct MemberQualificationReport {
    pub(crate) session_key_sha256: String,
    /// RFC 8785 bytes. Retained by the operator for review; never uploaded.
    pub(crate) canonical_json: Vec<u8>,
    pub(crate) sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct CandidateExport {
    /// Exact packet bytes as produced. `packet_sha256` hashes these bytes.
    pub(crate) packet_json: String,
    pub(crate) packet_sha256: String,
    pub(crate) qualification_reports: Vec<MemberQualificationReport>,
}

#[derive(Serialize)]
struct Packet<'a> {
    contract_version: &'static str,
    operation_id: &'a str,
    user_id: &'a str,
    organization_id: &'a str,
    device_id: &'a str,
    machine_id: &'a str,
    producer_revision: &'a str,
    collector_version: &'a str,
    scope_session_keys: Vec<&'a str>,
    members: Vec<PacketMember<'a>>,
}

#[derive(Serialize)]
struct PacketMember<'a> {
    source_session_id: &'a str,
    session_key_sha256: &'a str,
    prior_refusal_body_witness: &'a str,
    disposition: &'static str,
    reason: &'static str,
    qualification_report_sha256: String,
    cross_session_conservation: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_request_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    batch_request_sha256: Option<String>,
}

enum Verdict {
    Eligible(EligibleReason),
    Held(HeldReason),
}

/// `session_key:v1`: the backend's escaped, pipe-joined
/// (source, machine_id, source_session_id) identity. Backslash doubles and a
/// pipe becomes `\p`; all three parts are present here, so the null token
/// never applies.
pub(crate) fn session_key_v1(source: &str, machine_id: &str, source_session_id: &str) -> String {
    [source, machine_id, source_session_id]
        .map(|part| part.replace('\\', "\\\\").replace('|', "\\p"))
        .join("|")
}

pub(crate) fn session_key_sha256(
    source: &str,
    machine_id: &str,
    source_session_id: &str,
) -> String {
    sha256_hex(session_key_v1(source, machine_id, source_session_id).as_bytes())
}

/// Export with this binary's own collector version.
pub(crate) fn export_candidates(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    evidence: &PipelineEvidence<'_>,
) -> Result<CandidateExport, String> {
    build_candidate_export(scope, members, evidence, &collector_version())
}

fn build_candidate_export(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    evidence: &PipelineEvidence<'_>,
    producer_collector_version: &str,
) -> Result<CandidateExport, String> {
    validate_scope(scope, producer_collector_version)?;
    validate_members(scope, members)?;
    let mut packet_members = Vec::with_capacity(members.len());
    let mut reports = Vec::with_capacity(members.len());
    for member in members {
        let (verdict, facts) = qualify(member, evidence);
        let body = match (&verdict, facts.item) {
            (Verdict::Eligible(_), Some(item)) => Some(ordinary_batch_body(
                scope,
                item,
                evidence.upload_policy,
                producer_collector_version,
            )?),
            _ => None,
        };
        let body_sha256 = body.as_deref().map(|json| sha256_hex(json.as_bytes()));
        let (disposition, reason, conservation) = match verdict {
            Verdict::Eligible(reason) => ("eligible", reason.as_str(), "qualified"),
            Verdict::Held(reason) => ("held", reason.as_str(), "unknown"),
        };
        let report = qualification_report(
            scope,
            member,
            evidence,
            &facts,
            disposition,
            reason,
            conservation,
            body_sha256.as_deref(),
        )?;
        packet_members.push(PacketMember {
            source_session_id: &member.source_session_id,
            session_key_sha256: &member.session_key_sha256,
            prior_refusal_body_witness: &member.prior_refusal_body_witness,
            disposition,
            reason,
            qualification_report_sha256: report.sha256.clone(),
            cross_session_conservation: conservation,
            batch_request_json: body,
            batch_request_sha256: body_sha256,
        });
        reports.push(report);
    }
    let packet = Packet {
        contract_version: CANDIDATES_CONTRACT_VERSION,
        operation_id: &scope.operation_id,
        user_id: &scope.user_id,
        organization_id: &scope.organization_id,
        device_id: &scope.device_id,
        machine_id: &scope.machine_id,
        producer_revision: &scope.producer_revision,
        collector_version: producer_collector_version,
        scope_session_keys: members
            .iter()
            .map(|member| member.session_key_sha256.as_str())
            .collect(),
        members: packet_members,
    };
    let packet_json =
        serde_json::to_string(&packet).map_err(|error| format!("packet encoding: {error}"))?;
    let packet_sha256 = sha256_hex(packet_json.as_bytes());
    Ok(CandidateExport {
        packet_json,
        packet_sha256,
        qualification_reports: reports,
    })
}

#[derive(Default)]
struct MemberFacts<'a> {
    item: Option<&'a SnapshotItem>,
    item_match_count: usize,
    account_deferred: bool,
    authority_quarantined: bool,
    request_id_hash_count: usize,
    request_id_set_fingerprint: Option<String>,
    unresolved_duplicate_request_count: usize,
    exactly_excluded_request_count: usize,
}

fn qualify<'a>(
    member: &ApprovedMember,
    evidence: &PipelineEvidence<'a>,
) -> (Verdict, MemberFacts<'a>) {
    let session_id = member.source_session_id.as_str();
    let disposition = evidence.disposition;
    let mut facts = MemberFacts {
        account_deferred: disposition
            .account_deferred_source_session_ids
            .contains(session_id),
        ..MemberFacts::default()
    };
    facts.authority_quarantined = !facts.account_deferred
        && disposition
            .quarantined_source_session_ids
            .contains(session_id);
    let matches = evidence
        .upload_snapshots
        .iter()
        .filter(|item| item.source_session_id == session_id)
        .collect::<Vec<_>>();
    facts.item_match_count = matches.len();
    if let [item] = matches.as_slice() {
        facts.item = Some(*item);
        record_request_facts(item, evidence.index, &mut facts);
    }

    if facts.account_deferred {
        return (Verdict::Held(HeldReason::CreatorHold), facts);
    }
    if facts.authority_quarantined || facts.item_match_count > 1 {
        return (Verdict::Held(HeldReason::UnknownOwner), facts);
    }
    let Some(item) = facts.item else {
        return (Verdict::Held(HeldReason::MissingEvidence), facts);
    };
    let census = &disposition.duplicate_census;
    if !census.census_complete
        || census.census_invalid
        || !census.coverage_complete
        || !disposition.transcript_ownership_complete
    {
        return (Verdict::Held(HeldReason::IncompleteCensus), facts);
    }
    if census.fence_before
        || census.fence_after
        || census.page_invalidated_cap_count > 0
        || evidence.index.claude_duplicate_request_witness_overflowed
    {
        return (Verdict::Held(HeldReason::CapOverflow), facts);
    }
    if item.usage_accounting_contract.as_deref() != Some(SESSION_EXCLUSIVE_USAGE_CONTRACT)
        || (item.request_count > 0 && facts.request_id_hash_count == 0)
    {
        return (Verdict::Held(HeldReason::MissingEvidence), facts);
    }
    if facts.unresolved_duplicate_request_count > 0 {
        return (Verdict::Held(HeldReason::UnknownOwner), facts);
    }
    let reason = if facts.exactly_excluded_request_count > 0 {
        EligibleReason::ExactExclusion
    } else {
        EligibleReason::QualifiedSourceOwnership
    };
    (Verdict::Eligible(reason), facts)
}

/// Mirrors the pipeline's own duplicate test: a request hash is unresolved
/// when the durable census witness lists it and the member's exact legacy
/// exclusion does not already remove it from the member's usage.
fn record_request_facts(item: &SnapshotItem, index: &ScanIndex, facts: &mut MemberFacts<'_>) {
    let request_hashes = item
        .claude_usage_request_ids
        .iter()
        .map(|request_id| sha256_hex(request_id.as_bytes()))
        .collect::<BTreeSet<_>>();
    let excluded = index
        .claude_usage_family_witnesses
        .get(&claude_snapshot_family_root(item))
        .and_then(|witness| {
            witness
                .legacy_excluded_request_id_hashes
                .get(&item.source_session_id)
        });
    let is_excluded =
        |request_hash: &str| excluded.is_some_and(|hashes| hashes.contains(request_hash));
    facts.request_id_hash_count = request_hashes.len();
    facts.request_id_set_fingerprint = Some(claude_request_id_set_fingerprint(&request_hashes));
    facts.exactly_excluded_request_count = request_hashes
        .iter()
        .filter(|request_hash| is_excluded(request_hash.as_str()))
        .count();
    facts.unresolved_duplicate_request_count = request_hashes
        .iter()
        .filter(|request_hash| {
            index
                .claude_duplicate_request_owners
                .contains_key(request_hash.as_str())
                && !is_excluded(request_hash.as_str())
        })
        .count();
}

/// One item through the ordinary daemon request and serializer: the same
/// semantic envelope, entity-ACK declaration, head-CAS rule and validation as
/// a live upload. The offline client report is empty, as in the snapshot
/// audit's reproduction, because this process observed no delivery losses.
fn ordinary_batch_body(
    scope: &OperatorScope,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
    producer_collector_version: &str,
) -> Result<String, String> {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::ClaudeCode.api_slug().to_string(),
        machine_id: scope.machine_id.clone(),
        collector_version: Some(producer_collector_version.to_string()),
        snapshots: vec![item.clone()],
        upload_policy,
        client_report: crate::client_report::ClientReport::empty(),
    };
    validate_snapshot_batch_request(&request)
        .map_err(|error| format!("member body failed ordinary validation: {error}"))?;
    serde_json::to_string(&request).map_err(|error| format!("member body encoding: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn qualification_report(
    scope: &OperatorScope,
    member: &ApprovedMember,
    evidence: &PipelineEvidence<'_>,
    facts: &MemberFacts<'_>,
    disposition: &str,
    reason: &str,
    conservation: &str,
    batch_request_sha256: Option<&str>,
) -> Result<MemberQualificationReport, String> {
    let census = &evidence.disposition.duplicate_census;
    let report = json!({
        "contract_version": QUALIFICATION_REPORT_CONTRACT_VERSION,
        "operation_id": scope.operation_id,
        "session_key_sha256": member.session_key_sha256,
        "disposition": disposition,
        "reason": reason,
        "cross_session_conservation": conservation,
        "conservation_scope": CONSERVATION_SCOPE,
        "item_match_count": facts.item_match_count,
        "usage_accounting_contract": facts.item.and_then(|item| item.usage_accounting_contract.as_deref()),
        "account_deferred": facts.account_deferred,
        "authority_quarantined": facts.authority_quarantined,
        "census_complete": census.census_complete,
        "census_invalid": census.census_invalid,
        "coverage_complete": census.coverage_complete,
        "coverage_missing_member_count": census.coverage_missing_member_count,
        "transcript_ownership_complete": evidence.disposition.transcript_ownership_complete,
        "fence_before": census.fence_before,
        "fence_after": census.fence_after,
        "page_invalidated_cap_count": census.page_invalidated_cap_count,
        "duplicate_witness_overflowed": evidence.index.claude_duplicate_request_witness_overflowed,
        "request_id_hash_count": facts.request_id_hash_count,
        "request_id_set_fingerprint": facts.request_id_set_fingerprint,
        "unresolved_duplicate_request_count": facts.unresolved_duplicate_request_count,
        "exactly_excluded_request_count": facts.exactly_excluded_request_count,
        "batch_request_sha256": batch_request_sha256,
    });
    let canonical_json = crate::canonical_json::canonicalize(&report)
        .map_err(|error| format!("qualification report: {error}"))?;
    Ok(MemberQualificationReport {
        session_key_sha256: member.session_key_sha256.clone(),
        sha256: sha256_hex(&canonical_json),
        canonical_json,
    })
}

fn validate_scope(scope: &OperatorScope, producer_collector_version: &str) -> Result<(), String> {
    for (field, value) in [
        ("operation_id", &scope.operation_id),
        ("user_id", &scope.user_id),
        ("organization_id", &scope.organization_id),
        ("device_id", &scope.device_id),
    ] {
        if !is_lower_uuid(value) {
            return Err(format!("{field} must be a lowercase canonical UUID"));
        }
    }
    let machine_chars = scope.machine_id.chars().count();
    if !(MIN_MACHINE_ID_CHARS..=MAX_MACHINE_ID_CHARS).contains(&machine_chars)
        || scope.machine_id.contains(SNAPSHOT_STORAGE_SEPARATOR)
    {
        return Err("machine_id is not a registrable snapshot machine id".to_string());
    }
    if !is_lower_hex(&scope.producer_revision, 40) {
        return Err("producer_revision must be a full 40-character commit".to_string());
    }
    if scope.collector_version != producer_collector_version {
        return Err(format!(
            "collector_version {} is not this producer's {producer_collector_version}",
            scope.collector_version
        ));
    }
    Ok(())
}

fn validate_members(scope: &OperatorScope, members: &[ApprovedMember]) -> Result<(), String> {
    if members.len() != MANIFEST_MEMBER_COUNT {
        return Err(format!(
            "manifest must name exactly {MANIFEST_MEMBER_COUNT} members, got {}",
            members.len()
        ));
    }
    let mut session_ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for member in members {
        if !is_full_claude_session_id(&member.source_session_id) {
            return Err("member source_session_id must be a full Claude session id".to_string());
        }
        let expected = session_key_sha256(
            SnapshotSource::ClaudeCode.api_slug(),
            &scope.machine_id,
            &member.source_session_id,
        );
        if member.session_key_sha256 != expected {
            return Err(
                "member session_key_sha256 does not bind its source_session_id".to_string(),
            );
        }
        if !is_lower_hex(&member.prior_refusal_body_witness, 64) {
            return Err("member prior_refusal_body_witness must be 64 lowercase hex".to_string());
        }
        if !session_ids.insert(member.source_session_id.as_str())
            || !keys.insert(member.session_key_sha256.as_str())
        {
            return Err("manifest members must be distinct".to_string());
        }
    }
    Ok(())
}

/// A provider session UUID, optionally followed by the parser's own subagent
/// suffix. Rejects short display selectors and inferred prefixes.
fn is_full_claude_session_id(value: &str) -> bool {
    match value.get(..36) {
        Some(prefix) if is_lower_uuid(prefix) => {
            value.len() == 36 || value[36..].starts_with("_agent-")
        }
        _ => false,
    }
}

fn is_lower_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests;
