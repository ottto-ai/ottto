//! Read-only candidate exporter for one manifest-scoped historical Claude
//! operation (`h527_candidates:v1`).
//!
//! The exporter never scans, parses, uploads, or persists anything. It reads
//! the production pipeline's own post-policy upload set, authority disposition
//! and scan index by shared reference.
//!
//! Every member is held without a body today. Cross-session conservation has to
//! cover the target set and every already-counted accepted session, including
//! accepted bodies whose transcripts were deleted or left the census window.
//! No qualified historical evidence for that exists, and a complete local
//! census cannot prove absence there, so conservation stays `unknown`. The local
//! checks still run so the operator sees which members also fail on local
//! evidence. A transcript body without session-exclusive proof is not
//! disqualified by that alone: truthful unproven bodies are the operation's
//! targets.
//!
//! The operator manifest names members; it is never ownership proof, and no
//! caller flag or report hash can upgrade conservation.
// The operator entry has no runtime caller until a reviewed read-only pipeline
// seam supplies its inputs; tests drive it with synthetic pipeline values.
#![cfg_attr(not(test), allow(dead_code))]

use super::{
    claude_request_id_set_fingerprint, claude_snapshot_family_root, collector_version,
    ClaudeUsageAuthorityDisposition, ScanIndex, SnapshotItem, SnapshotSource,
};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub(crate) const CANDIDATES_CONTRACT_VERSION: &str = "h527_candidates:v1";
pub(crate) const QUALIFICATION_REPORT_CONTRACT_VERSION: &str = "h527_candidate_qualification:v1";
pub(crate) const MANIFEST_MEMBER_COUNT: usize = 18;
/// No interface supplies qualified evidence about historical accepted bodies.
const GLOBAL_CONSERVATION_EVIDENCE: &str = "unavailable";
/// The operator supplies the commit; this binary cannot prove it.
const PRODUCER_REVISION_SOURCE: &str = "operator_supplied_unverified";
/// Manifest fields whose definition is still open. The refusal value is copied
/// as opaque diagnostic metadata: the daemon's additive body witness does not
/// identify a refused body, and no retained refusal record is qualified yet.
const UNRESOLVED_FIELDS: [&str; 1] = ["prior_refusal_body_witness"];
const MIN_MACHINE_ID_CHARS: usize = 8;
const MAX_MACHINE_ID_CHARS: usize = 128;
const SNAPSHOT_STORAGE_SEPARATOR: char = '\u{1f}';

/// Closed vocabulary only. No member qualifies while global conservation
/// evidence is unavailable, so the exporter emits none of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EligibleReason {
    QualifiedSourceOwnership,
    ExactExclusion,
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
}

#[derive(Debug, Clone)]
pub(crate) struct ApprovedMember {
    pub(crate) source_session_id: String,
    pub(crate) session_key_sha256: String,
    /// Copied from the manifest as opaque diagnostic metadata; unverified.
    pub(crate) prior_refusal_body_witness: String,
}

/// The build that actually ran the export, never the installed daemon's.
#[derive(Debug, Clone)]
pub(crate) struct ProducerBuild {
    pub(crate) collector_version: String,
    pub(crate) binary_sha256: String,
}

impl ProducerBuild {
    fn current() -> Result<Self, String> {
        let path = std::env::current_exe().map_err(|error| format!("producer binary: {error}"))?;
        let bytes = std::fs::read(&path).map_err(|error| format!("producer binary: {error}"))?;
        Ok(Self {
            collector_version: collector_version(),
            binary_sha256: sha256_hex(&bytes),
        })
    }
}

/// The production pipeline's values after local evidence, account binding,
/// upload policy and backfill cutoff, before any upload. Shared references:
/// the exporter cannot change scan, census or hold state.
pub(crate) struct PipelineEvidence<'a> {
    pub(crate) upload_snapshots: &'a [SnapshotItem],
    pub(crate) disposition: &'a ClaudeUsageAuthorityDisposition,
    pub(crate) index: &'a ScanIndex,
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
    producer_revision_source: &'static str,
    producer_binary_sha256: &'a str,
    collector_version: &'a str,
    unresolved_fields: [&'static str; 1],
    scope_session_keys: Vec<&'a str>,
    members: Vec<PacketMember<'a>>,
}

/// Held members only: no batch body fields exist until conservation can be
/// qualified.
#[derive(Serialize)]
struct PacketMember<'a> {
    source_session_id: &'a str,
    session_key_sha256: &'a str,
    prior_refusal_body_witness: &'a str,
    disposition: &'static str,
    reason: &'static str,
    qualification_report_sha256: String,
    cross_session_conservation: &'static str,
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

/// Export with this running binary's own version and digest.
pub(crate) fn export_candidates(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    evidence: &PipelineEvidence<'_>,
) -> Result<CandidateExport, String> {
    build_candidate_export(scope, members, evidence, &ProducerBuild::current()?)
}

fn build_candidate_export(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    evidence: &PipelineEvidence<'_>,
    producer: &ProducerBuild,
) -> Result<CandidateExport, String> {
    validate_scope(scope)?;
    validate_members(scope, members)?;
    let mut packet_members = Vec::with_capacity(members.len());
    let mut reports = Vec::with_capacity(members.len());
    for member in members {
        let facts = local_facts(member, evidence);
        let reason = held_reason(&facts, evidence);
        let report = qualification_report(scope, member, evidence, &facts, reason)?;
        packet_members.push(PacketMember {
            source_session_id: &member.source_session_id,
            session_key_sha256: &member.session_key_sha256,
            prior_refusal_body_witness: &member.prior_refusal_body_witness,
            disposition: "held",
            reason: reason.as_str(),
            qualification_report_sha256: report.sha256.clone(),
            cross_session_conservation: "unknown",
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
        producer_revision_source: PRODUCER_REVISION_SOURCE,
        producer_binary_sha256: &producer.binary_sha256,
        collector_version: &producer.collector_version,
        unresolved_fields: UNRESOLVED_FIELDS,
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

fn local_facts<'a>(member: &ApprovedMember, evidence: &PipelineEvidence<'a>) -> MemberFacts<'a> {
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
    facts
}

/// The first local failure, else the global conservation gap. Local evidence
/// can only disqualify; it never qualifies a member.
fn held_reason(facts: &MemberFacts<'_>, evidence: &PipelineEvidence<'_>) -> HeldReason {
    local_failure(facts, evidence).unwrap_or(HeldReason::IncompleteCensus)
}

fn local_failure(facts: &MemberFacts<'_>, evidence: &PipelineEvidence<'_>) -> Option<HeldReason> {
    if facts.account_deferred {
        return Some(HeldReason::CreatorHold);
    }
    if facts.authority_quarantined || facts.item_match_count > 1 {
        return Some(HeldReason::UnknownOwner);
    }
    let Some(item) = facts.item else {
        return Some(HeldReason::MissingEvidence);
    };
    let disposition = evidence.disposition;
    let census = &disposition.duplicate_census;
    if !census.census_complete
        || census.census_invalid
        || !census.coverage_complete
        || !disposition.transcript_ownership_complete
    {
        return Some(HeldReason::IncompleteCensus);
    }
    if census.fence_before
        || census.fence_after
        || census.page_invalidated_cap_count > 0
        || evidence.index.claude_duplicate_request_witness_overflowed
    {
        return Some(HeldReason::CapOverflow);
    }
    // Overlap cannot be checked for counted requests without provider ids.
    if item.request_count > 0 && facts.request_id_hash_count == 0 {
        return Some(HeldReason::MissingEvidence);
    }
    if facts.unresolved_duplicate_request_count > 0 {
        return Some(HeldReason::UnknownOwner);
    }
    None
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

fn qualification_report(
    scope: &OperatorScope,
    member: &ApprovedMember,
    evidence: &PipelineEvidence<'_>,
    facts: &MemberFacts<'_>,
    reason: HeldReason,
) -> Result<MemberQualificationReport, String> {
    let census = &evidence.disposition.duplicate_census;
    let report = json!({
        "contract_version": QUALIFICATION_REPORT_CONTRACT_VERSION,
        "operation_id": scope.operation_id,
        "session_key_sha256": member.session_key_sha256,
        "disposition": "held",
        "reason": reason.as_str(),
        "cross_session_conservation": "unknown",
        "global_conservation_evidence": GLOBAL_CONSERVATION_EVIDENCE,
        "local_checks_passed": local_failure(facts, evidence).is_none(),
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
    });
    let canonical_json = crate::canonical_json::canonicalize(&report)
        .map_err(|error| format!("qualification report: {error}"))?;
    Ok(MemberQualificationReport {
        session_key_sha256: member.session_key_sha256.clone(),
        sha256: sha256_hex(&canonical_json),
        canonical_json,
    })
}

fn validate_scope(scope: &OperatorScope) -> Result<(), String> {
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
