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
//!
//! SOURCE's named `local_exclusion_disclosed_residual:v1` basis is a
//! risk-reviewed alternative to strict proof, not that proof. It needs a
//! reviewed local exclusion artifact covering every local transcript, which
//! nothing here produces, so it does not change any member's disposition.
//! `local_exclusion_disclosure_json` only fixes the shape of the per-target
//! disclosure record that SOURCE reviews.
//!
//! A second, separate output exists for review only:
//! `h527_unqualified_candidates:v1` carries each candidate's exact ordinary
//! batch bytes so SOURCE can inspect whether proof is possible. It is local,
//! has no admission authority, no eligible disposition and no `members` list,
//! so it cannot be read as the operator packet.
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
pub(crate) const UNQUALIFIED_CANDIDATES_CONTRACT_VERSION: &str = "h527_unqualified_candidates:v1";
pub(crate) const MANIFEST_MEMBER_COUNT: usize = 18;
/// Why nothing in the unqualified artifact may be admitted. Closed list.
const UNQUALIFIED_ARTIFACT_GAPS: [&str; 5] = [
    "cross_session_conservation_evidence_unavailable",
    "local_exclusion_artifact_missing",
    "prior_refusal_record_codec_not_frozen",
    "producer_revision_unverified",
    "contract5_permit_provenance_unattested",
];
/// No interface supplies qualified evidence about historical accepted bodies.
const GLOBAL_CONSERVATION_EVIDENCE: &str = "unavailable";
/// The disclosed basis needs a reviewed local exclusion artifact; none exists.
const DISCLOSED_RESIDUAL_EVIDENCE: &str = "exclusion_artifact_missing";
pub(crate) const DISCLOSED_RESIDUAL_BASIS: &str = "local_exclusion_disclosed_residual:v1";
/// Exact text SOURCE's disclosure record requires.
pub(crate) const DISCLOSED_RESIDUAL_STATEMENT: &str = "Some copied requests may count in the session that uploaded first and show under its starting subscription; overlap with ids no longer locally present cannot be ruled out; the residual is unbounded by proof.";
const LOCAL_EXCLUSION_SCOPE: &str = "all_local_transcripts_including_other_17_targets:v1";
/// Shared requests count once; names and tags never move between sessions.
const B2_IDENTITY_RULE: &str = "b2_counting_only_keep_root_owned_evidence:v1";
const MAX_COPY_SCREEN_REASON_CHARS: usize = 1024;
/// The operator supplies the commit; this binary cannot prove it.
const PRODUCER_REVISION_SOURCE: &str = "operator_supplied_unverified";
/// Manifest fields whose definition is still open. The refusal value is copied
/// as opaque diagnostic metadata: the daemon's additive body witness does not
/// identify a refused body, and no retained refusal record is qualified yet.
const UNRESOLVED_FIELDS: [&str; 1] = ["prior_refusal_body_witness"];
const MIN_MACHINE_ID_CHARS: usize = 8;
const MAX_MACHINE_ID_CHARS: usize = 128;
const SNAPSHOT_STORAGE_SEPARATOR: char = '\u{1f}';

/// Closed vocabulary only. No member qualifies while neither strict
/// conservation evidence nor a reviewed exclusion artifact exists, so the
/// exporter emits none of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EligibleReason {
    QualifiedSourceOwnership,
    ExactExclusion,
    ExactPreviousAckMembership,
    LocalExclusionDisclosedResidual,
}

impl EligibleReason {
    pub(crate) const ALL: [Self; 4] = [
        Self::QualifiedSourceOwnership,
        Self::ExactExclusion,
        Self::ExactPreviousAckMembership,
        Self::LocalExclusionDisclosedResidual,
    ];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::QualifiedSourceOwnership => "qualified_source_ownership",
            Self::ExactExclusion => "exact_exclusion",
            Self::ExactPreviousAckMembership => "exact_previous_ack_membership",
            Self::LocalExclusionDisclosedResidual => "local_exclusion_disclosed_residual",
        }
    }

    /// The only conservation state an eligible member with this reason may
    /// carry. The disclosed basis never borrows the strict `qualified` state.
    pub(crate) fn required_conservation(self) -> Conservation {
        match self {
            Self::LocalExclusionDisclosedResidual => Conservation::DisclosedResidual,
            _ => Conservation::Qualified,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Conservation {
    Qualified,
    DisclosedResidual,
    Unknown,
}

impl Conservation {
    pub(crate) const ALL: [Self; 3] = [Self::Qualified, Self::DisclosedResidual, Self::Unknown];

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Qualified => "qualified",
            Self::DisclosedResidual => "disclosed_residual",
            Self::Unknown => "unknown",
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
    /// The policy the pipeline applied; it is part of each item's envelope.
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

/// Exactly SESSION's closed `CandidateBundle` fields; it refuses any other key.
/// The producer binary, the revision's provenance and the unresolved fields
/// travel in each member's qualification report, bound by its SHA.
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
        let report = qualification_report(scope, member, evidence, producer, &facts, reason)?;
        packet_members.push(PacketMember {
            source_session_id: &member.source_session_id,
            session_key_sha256: &member.session_key_sha256,
            prior_refusal_body_witness: &member.prior_refusal_body_witness,
            disposition: "held",
            reason: reason.as_str(),
            qualification_report_sha256: report.sha256.clone(),
            cross_session_conservation: Conservation::Unknown.as_str(),
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
        collector_version: &producer.collector_version,
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

#[derive(Debug, Clone)]
pub(crate) struct UnqualifiedArtifact {
    /// Exact artifact bytes. Local review evidence only; never uploaded.
    pub(crate) json: String,
    pub(crate) sha256: String,
}

#[derive(Serialize)]
struct UnqualifiedCandidates<'a> {
    contract_version: &'static str,
    local_only: bool,
    admission_authority: &'static str,
    operation_id: &'a str,
    user_id: &'a str,
    organization_id: &'a str,
    device_id: &'a str,
    machine_id: &'a str,
    producer_revision: &'a str,
    producer_revision_source: &'static str,
    producer_binary_sha256: &'a str,
    collector_version: &'a str,
    scope_session_keys: Vec<&'a str>,
    qualification_gaps: [&'static str; 5],
    candidates: Vec<UnqualifiedCandidate<'a>>,
}

#[derive(Serialize)]
struct UnqualifiedCandidate<'a> {
    source_session_id: &'a str,
    session_key_sha256: &'a str,
    prior_refusal_body_witness: &'a str,
    cross_session_conservation: &'static str,
    operator_packet_reason: &'static str,
    local_checks_passed: bool,
    body_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    unqualified_batch_request_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unqualified_batch_request_sha256: Option<String>,
}

/// The local review artifact, with this running binary's version and digest.
pub(crate) fn export_unqualified_candidates(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    evidence: &PipelineEvidence<'_>,
) -> Result<UnqualifiedArtifact, String> {
    build_unqualified_artifact(scope, members, evidence, &ProducerBuild::current()?)
}

/// Carries the ordinary bytes of every member that has exactly one upload item
/// the pipeline did not withhold. The operator packet for the same inputs still
/// holds every member without a body.
fn build_unqualified_artifact(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    evidence: &PipelineEvidence<'_>,
    producer: &ProducerBuild,
) -> Result<UnqualifiedArtifact, String> {
    validate_scope(scope)?;
    validate_members(scope, members)?;
    let mut candidates = Vec::with_capacity(members.len());
    for member in members {
        let facts = local_facts(member, evidence);
        let (body_status, body) = if facts.account_deferred || facts.authority_quarantined {
            ("pipeline_hold", None)
        } else if facts.item_match_count > 1 {
            ("ambiguous_upload_item", None)
        } else if let Some(item) = facts.item {
            let body = ordinary_batch_body(scope, item, evidence.upload_policy, producer)?;
            ("unqualified_ordinary_batch", Some(body))
        } else {
            ("no_upload_item", None)
        };
        let body_sha256 = body.as_deref().map(|json| sha256_hex(json.as_bytes()));
        candidates.push(UnqualifiedCandidate {
            source_session_id: &member.source_session_id,
            session_key_sha256: &member.session_key_sha256,
            prior_refusal_body_witness: &member.prior_refusal_body_witness,
            cross_session_conservation: Conservation::Unknown.as_str(),
            operator_packet_reason: held_reason(&facts, evidence).as_str(),
            local_checks_passed: local_failure(&facts, evidence).is_none(),
            body_status,
            unqualified_batch_request_json: body,
            unqualified_batch_request_sha256: body_sha256,
        });
    }
    let artifact = UnqualifiedCandidates {
        contract_version: UNQUALIFIED_CANDIDATES_CONTRACT_VERSION,
        local_only: true,
        admission_authority: "none",
        operation_id: &scope.operation_id,
        user_id: &scope.user_id,
        organization_id: &scope.organization_id,
        device_id: &scope.device_id,
        machine_id: &scope.machine_id,
        producer_revision: &scope.producer_revision,
        producer_revision_source: PRODUCER_REVISION_SOURCE,
        producer_binary_sha256: &producer.binary_sha256,
        collector_version: &producer.collector_version,
        scope_session_keys: members
            .iter()
            .map(|member| member.session_key_sha256.as_str())
            .collect(),
        qualification_gaps: UNQUALIFIED_ARTIFACT_GAPS,
        candidates,
    };
    let json = serde_json::to_string(&artifact)
        .map_err(|error| format!("unqualified artifact encoding: {error}"))?;
    let sha256 = sha256_hex(json.as_bytes());
    Ok(UnqualifiedArtifact { json, sha256 })
}

/// Exclusion totals for one target, as recorded in a reviewed local exclusion
/// artifact. Nothing in this module computes them: that needs an exclusion
/// pass over every local transcript, which this exporter does not run.
#[derive(Debug, Clone)]
pub(crate) struct LocalExclusionSummary {
    pub(crate) exclusion_artifact_sha256: String,
    pub(crate) excluded_request_count: u64,
    pub(crate) excluded_token_counts: ExcludedTokenCounts,
    /// Estimated exclusion money at catalog prices, as an exact decimal
    /// string. It is never the server's canonical admitted money.
    pub(crate) excluded_catalog_cost_usd: String,
    pub(crate) copy_screen: CopyScreen,
}

/// All eight dimensions are always present; zero is evidence, not a default.
#[derive(Debug, Clone, Default, Serialize)]
pub(crate) struct ExcludedTokenCounts {
    pub(crate) input_tokens: u64,
    pub(crate) output_tokens: u64,
    pub(crate) cache_read_tokens: u64,
    pub(crate) cache_creation_5m_tokens: u64,
    pub(crate) cache_creation_1h_tokens: u64,
    pub(crate) cache_creation_unattributed_input_tokens: u64,
    pub(crate) reasoning_output_tokens: u64,
    pub(crate) unattributed_total_tokens: u64,
}

/// The optional server copy screen. Skipping it is explicit, with a reason.
#[derive(Debug, Clone)]
pub(crate) enum CopyScreen {
    NotRun { reason: String },
    NoMatch { artifact_sha256: String },
    ExclusionsApplied { artifact_sha256: String },
}

/// SESSION's `LocalExclusionDisclosure`, field for field. The two nullable
/// screen fields are always written, as explicit nulls when absent.
#[derive(Serialize)]
struct LocalExclusionDisclosure<'a> {
    scope_session_keys_sha256: String,
    exclusion_artifact_sha256: &'a str,
    local_exclusion_scope: &'static str,
    identity_rule: &'static str,
    excluded_request_count: u64,
    excluded_token_counts: &'a ExcludedTokenCounts,
    excluded_catalog_cost_usd: &'a str,
    copy_screen_status: &'static str,
    copy_screen_artifact_sha256: Option<&'a str>,
    copy_screen_not_run_reason: Option<&'a str>,
    residual_statement: &'static str,
}

/// One target's disclosure record for SOURCE's disclosed-residual review.
///
/// It is review evidence, never a disposition: the operator packet for the
/// same scope keeps every member held, and only SOURCE's reviewed certificate
/// can name this basis. The scope digest covers all 18 keys.
pub(crate) fn local_exclusion_disclosure_json(
    scope: &OperatorScope,
    members: &[ApprovedMember],
    summary: &LocalExclusionSummary,
) -> Result<String, String> {
    validate_scope(scope)?;
    validate_members(scope, members)?;
    if !is_lower_hex(&summary.exclusion_artifact_sha256, 64) {
        return Err("exclusion_artifact_sha256 must be 64 lowercase hex".to_string());
    }
    if !is_exact_decimal(&summary.excluded_catalog_cost_usd) {
        return Err(
            "excluded_catalog_cost_usd must be an exact nonnegative decimal string".to_string(),
        );
    }
    let (copy_screen_status, copy_screen_artifact_sha256, copy_screen_not_run_reason) =
        match &summary.copy_screen {
            CopyScreen::NotRun { reason } => {
                let chars = reason.chars().count();
                if reason.trim().is_empty()
                    || chars > MAX_COPY_SCREEN_REASON_CHARS
                    || reason.chars().any(char::is_control)
                {
                    return Err(
                        "copy screen not_run reason must be nonblank plain text of at most 1024 characters"
                            .to_string(),
                    );
                }
                ("not_run", None, Some(reason.as_str()))
            }
            CopyScreen::NoMatch { artifact_sha256 }
            | CopyScreen::ExclusionsApplied { artifact_sha256 } => {
                if !is_lower_hex(artifact_sha256, 64) {
                    return Err("copy screen artifact must be 64 lowercase hex".to_string());
                }
                let status = if matches!(summary.copy_screen, CopyScreen::NoMatch { .. }) {
                    "no_match"
                } else {
                    "exclusions_applied"
                };
                (status, Some(artifact_sha256.as_str()), None)
            }
        };
    let disclosure = LocalExclusionDisclosure {
        scope_session_keys_sha256: scope_session_keys_sha256(members)?,
        exclusion_artifact_sha256: &summary.exclusion_artifact_sha256,
        local_exclusion_scope: LOCAL_EXCLUSION_SCOPE,
        identity_rule: B2_IDENTITY_RULE,
        excluded_request_count: summary.excluded_request_count,
        excluded_token_counts: &summary.excluded_token_counts,
        excluded_catalog_cost_usd: &summary.excluded_catalog_cost_usd,
        copy_screen_status,
        copy_screen_artifact_sha256,
        copy_screen_not_run_reason,
        residual_statement: DISCLOSED_RESIDUAL_STATEMENT,
    };
    serde_json::to_string(&disclosure).map_err(|error| format!("disclosure encoding: {error}"))
}

/// SESSION's `canonical_json_digest(sorted(scope_session_keys))`: SHA-256 of
/// the compact JSON array of the sorted keys.
fn scope_session_keys_sha256(members: &[ApprovedMember]) -> Result<String, String> {
    let mut keys = members
        .iter()
        .map(|member| member.session_key_sha256.as_str())
        .collect::<Vec<_>>();
    keys.sort_unstable();
    let json =
        serde_json::to_string(&keys).map_err(|error| format!("scope digest encoding: {error}"))?;
    Ok(sha256_hex(json.as_bytes()))
}

/// Plain nonnegative decimal without exponent, sign or leading zeros, so the
/// value is exact and has one spelling.
fn is_exact_decimal(value: &str) -> bool {
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) => (whole, Some(fraction)),
        None => (value, None),
    };
    let digits = |part: &str| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
    let fraction_ok = match fraction {
        Some(fraction) => digits(fraction),
        None => true,
    };
    digits(whole) && (whole == "0" || !whole.starts_with('0')) && fraction_ok
}

/// One unchanged item through the ordinary daemon request and serializer: the
/// same semantic envelope, entity-ACK declaration, head-CAS rule and
/// validation as a live upload. The offline client report is empty, as in the
/// snapshot audit's reproduction, because this process observed no delivery.
fn ordinary_batch_body(
    scope: &OperatorScope,
    item: &SnapshotItem,
    upload_policy: SnapshotUploadPolicy,
    producer: &ProducerBuild,
) -> Result<String, String> {
    let request = SnapshotBatchRequest {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        source: SnapshotSource::ClaudeCode.api_slug().to_string(),
        machine_id: scope.machine_id.clone(),
        collector_version: Some(producer.collector_version.clone()),
        snapshots: vec![item.clone()],
        upload_policy,
        client_report: crate::client_report::ClientReport::empty(),
    };
    validate_snapshot_batch_request(&request)
        .map_err(|error| format!("candidate body failed ordinary validation: {error}"))?;
    serde_json::to_string(&request).map_err(|error| format!("candidate body encoding: {error}"))
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

/// The first local failure, else the missing global conservation proof. Local evidence
/// can only disqualify; it never qualifies a member.
fn held_reason(facts: &MemberFacts<'_>, evidence: &PipelineEvidence<'_>) -> HeldReason {
    local_failure(facts, evidence).unwrap_or(HeldReason::MissingEvidence)
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
    producer: &ProducerBuild,
    facts: &MemberFacts<'_>,
    reason: HeldReason,
) -> Result<MemberQualificationReport, String> {
    let census = &evidence.disposition.duplicate_census;
    let report = json!({
        "contract_version": QUALIFICATION_REPORT_CONTRACT_VERSION,
        "operation_id": scope.operation_id,
        "producer_revision_source": PRODUCER_REVISION_SOURCE,
        "producer_binary_sha256": producer.binary_sha256,
        "collector_version": producer.collector_version,
        "unresolved_fields": UNRESOLVED_FIELDS,
        "session_key_sha256": member.session_key_sha256,
        "disposition": "held",
        "reason": reason.as_str(),
        "cross_session_conservation": Conservation::Unknown.as_str(),
        "global_conservation_evidence": GLOBAL_CONSERVATION_EVIDENCE,
        "disclosed_residual_evidence": DISCLOSED_RESIDUAL_EVIDENCE,
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

mod producer;
pub use producer::run_operator_producer;

#[cfg(test)]
mod tests;
