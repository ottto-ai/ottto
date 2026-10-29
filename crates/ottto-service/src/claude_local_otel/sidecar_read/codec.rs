//! Proposed sidecar row for the shared v1 codec (SOURCE approval pending).
use super::super::super::*;
use crate::durable_tail_codec::{
    durable_enum, durable_struct, Corrupt, Dec, Durable, Enc, Refuse, Shape,
};
use crate::transcript_acquisition::DurableCertificate;

durable_struct!(ClaudeLocalOtelEvidence {
    // DECISION(19b-§8-SOURCE): proposed U field.
    U capture_revision: String,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H fingerprint: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L session_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L request_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L client_request_id: String,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N observed_at: String,
    // DECISION(19b-§8-SOURCE): proposed U field.
    U model: String,
    // DECISION(19b-§8-SOURCE): proposed U field.
    U effort: String,
    // DECISION(19b-§8-SOURCE): proposed U field.
    U query_source: String,
    // DECISION(19b-§8-SOURCE): proposed U field.
    U speed: String,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N cost_usd_micros: Option<u64>,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N event_sequence: Option<u64>,
    // DECISION(19b-§8-SOURCE): proposed U field.
    U app_version: String,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N input_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N output_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N cache_read_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N cache_creation_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N cache_creation_5m_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N cache_creation_1h_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N reasoning_output_tokens: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N request_count: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N account_identity_checked: bool,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H account_identifier_hash: Option<String>,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P request_identity: Option<ClaudeRequestIdentityEvidence>,
    // DECISION(19b-§8-SOURCE): proposed I field.
    I fingerprint_check: FingerprintCheck,
});

durable_struct!(ClaudeRequestIdentityEvidence {
    // DECISION(19b-§8-SOURCE): proposed U field.
    U identity_hash_scheme: String,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P account: ClaudeIdentityAttributeEvidence,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P organization: ClaudeIdentityAttributeEvidence,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N disposition: ClaudeIdentityDisposition,
});

durable_struct!(ClaudeIdentityAttributeEvidence {
    // DECISION(19b-§8-SOURCE): proposed N field.
    N origin: ClaudeIdentityAttributeOrigin,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N disposition: ClaudeIdentityDisposition,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H resource_hash: Option<String>,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H log_record_hash: Option<String>,
});

// DECISION(19b-§8-SOURCE): closed enum tags, not provider text.
durable_enum!(ClaudeIdentityAttributeOrigin { 0 => Missing, 1 => Resource, 2 => LogRecord, 3 => ResourceAndLogRecord });
// DECISION(19b-§8-SOURCE): closed enum tags.
durable_enum!(ClaudeIdentityDisposition { 0 => Missing, 1 => Invalid, 2 => Conflict, 3 => Complete });

durable_struct!(ClaudeTraceOwnershipEvidence {
    // DECISION(19b-§8-SOURCE): proposed U field.
    U capture_revision: String,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H fingerprint: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L session_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L request_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L client_request_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L agent_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L parent_agent_id: String,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L workflow_run_id: String,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N observed_at: String,
});

durable_struct!(ClaudeLocalOtelLoadHealth {
    // DECISION(19b-§8-SOURCE): proposed N field.
    N missing_files: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N malformed_lines: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N unreadable_lines: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N oversized_files: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N invalid_session_rows: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N missing_request_ids: u64,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L conflicting_request_ids: BTreeSet<String>,
});

durable_struct!(ClaudeTraceOwnershipLoadReport {
    // DECISION(19b-§8-SOURCE): proposed E field; reject cross-session wiring.
    E evidence: BTreeMap<String, Vec<ClaudeTraceOwnershipEvidence>>,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N missing_files: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N malformed_lines: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N unreadable_lines: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N oversized_files: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N invalid_session_rows: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N missing_request_ids: u64,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L conflicting_request_ids: BTreeSet<String>,
});

durable_struct!(DurableCertificate {
    // DECISION(19b-§8-SOURCE): proposed N field.
    N device: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N inode: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N length: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N modified: (i64, i64),
    // DECISION(19b-§8-SOURCE): proposed N field.
    N birth_nanos: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N sealed_offset: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N sample_len: u32,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H head_sha256: [u8; 32],
    // DECISION(19b-§8-SOURCE): proposed H field.
    H boundary_sha256: [u8; 32],
    // DECISION(19b-§8-SOURCE): proposed N field.
    N verified_unix_seconds: u64,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N audit_debt_unix_seconds: Option<u64>,
});

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ApiState {
    pub(super) rows: Vec<ClaudeLocalOtelEvidence>,
    pub(super) seen: BTreeSet<String>,
    pub(super) requests: BTreeMap<String, usize>,
    pub(super) health: ClaudeLocalOtelLoadHealth,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct TraceState {
    pub(super) rows: Vec<ClaudeTraceOwnershipEvidence>,
    pub(super) seen: BTreeSet<String>,
    pub(super) requests: BTreeMap<String, String>,
    pub(super) health: ClaudeTraceOwnershipLoadReport,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct ApiSlot {
    pub(super) certificate: Option<DurableCertificate>,
    pub(super) state: ApiState,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct TraceSlot {
    pub(super) certificate: Option<DurableCertificate>,
    pub(super) state: TraceState,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Pair {
    pub(super) parser: u16,
    pub(super) session: String,
    pub(super) api: ApiSlot,
    pub(super) trace: TraceSlot,
    pub(super) pending: bool,
}
durable_struct!(ApiState {
    // DECISION(19b-§8-SOURCE): proposed P field.
    P rows: Vec<ClaudeLocalOtelEvidence>,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H seen: BTreeSet<String>,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L requests: BTreeMap<String, usize>,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P health: ClaudeLocalOtelLoadHealth,
});

durable_struct!(TraceState {
    // DECISION(19b-§8-SOURCE): proposed P field.
    P rows: Vec<ClaudeTraceOwnershipEvidence>,
    // DECISION(19b-§8-SOURCE): proposed H field.
    H seen: BTreeSet<String>,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L requests: BTreeMap<String, String>,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P health: ClaudeTraceOwnershipLoadReport,
});

durable_struct!(ApiSlot {
    // DECISION(19b-§8-SOURCE): proposed P field.
    P certificate: Option<DurableCertificate>,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P state: ApiState,
});

durable_struct!(TraceSlot {
    // DECISION(19b-§8-SOURCE): proposed P field.
    P certificate: Option<DurableCertificate>,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P state: TraceState,
});

durable_struct!(Pair {
    // DECISION(19b-§8-SOURCE): proposed N field.
    N parser: u16,
    // DECISION(19b-§8-SOURCE): proposed L field.
    L session: String,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P api: ApiSlot,
    // DECISION(19b-§8-SOURCE): proposed P field.
    P trace: TraceSlot,
    // DECISION(19b-§8-SOURCE): proposed N field.
    N pending: bool,
});

pub(super) const PARSER: u16 = 1;

pub(super) fn allowlist() -> [u8; 32] {
    let mut shape = Shape::default();
    shape.push("claude-sidecar-pair:v1");
    shape.push("fingerprint_tag=sha256:");
    Pair::shape(&mut shape);
    shape.digest()
}
pub(super) fn encode(pair: &Pair) -> Result<Vec<u8>, Refuse> {
    if !valid_continuation(pair) {
        return Err(Refuse::UnknownLabel);
    }
    // The row producers use tagged hashes. Keep the shared H codec's bare
    // digest representation unchanged for native records. This temporary
    // normalized view is part of the pending codec/clone allocation charge.
    let mut pair = pair.clone();
    map_fingerprints(&mut pair, |text| {
        text.strip_prefix("sha256:")
            .map(str::to_owned)
            .ok_or(Refuse::NotDigest("sidecar.fingerprint"))
    })?;
    let mut e = Enc::bytes(
        crate::durable_tail_store::RECORD_BYTES - crate::durable_tail_store::HEADER_BYTES - 32,
    );
    pair.put(&mut e)?;
    Ok(e.into_bytes())
}
pub(super) fn newer(bytes: &[u8]) -> bool {
    let mut d = Dec::new(bytes);
    u16::take(&mut d).is_ok_and(|parser| parser > PARSER)
}
pub(super) fn newer_than_older(bytes: &[u8]) -> bool {
    let mut d = Dec::new(bytes);
    u16::take(&mut d).is_ok_and(|parser| parser > 0)
}
pub(super) fn verify(bytes: &[u8]) -> Result<(), crate::durable_tail_store::Refusal> {
    verify_parser(bytes, PARSER)
}
pub(super) fn verify_older(bytes: &[u8]) -> Result<(), crate::durable_tail_store::Refusal> {
    verify_parser(bytes, 0)
}
fn verify_parser(bytes: &[u8], supported: u16) -> Result<(), crate::durable_tail_store::Refusal> {
    use crate::durable_tail_store::Refusal;
    let mut d = Dec::new(bytes);
    // Dispatch before interpreting the rest of a newer decoder's graph.
    if u16::take(&mut d).map_err(|_| Refusal::Corrupt)? > supported {
        return Err(Refusal::NewerFormat);
    }
    let mut d = Dec::new(bytes);
    Pair::verify(&mut d)
        .and_then(|()| d.finish())
        .map_err(|_| Refusal::Corrupt)
}
pub(super) fn decode(bytes: &[u8]) -> Result<Pair, Corrupt> {
    let mut d = Dec::new(bytes);
    let mut pair = Pair::take(&mut d)?;
    d.finish()?;
    map_fingerprints(&mut pair, |text| Ok::<_, Corrupt>(format!("sha256:{text}")))?;
    if !valid_continuation(&pair)
        || pair.parser != PARSER
        || !pair.trace.state.health.evidence.is_empty()
        || pair.api.state.requests.iter().any(|(id, index)| {
            pair.api
                .state
                .rows
                .get(*index)
                .map_or(true, |row| &row.request_id != id)
        })
        || pair
            .api
            .state
            .rows
            .iter()
            .any(|row| row.session_id != pair.session)
        || pair
            .trace
            .state
            .rows
            .iter()
            .any(|row| row.session_id != pair.session)
    {
        return Err(Corrupt);
    }
    for certificate in [&pair.api.certificate, &pair.trace.certificate]
        .into_iter()
        .flatten()
    {
        if certificate.sealed_offset > certificate.length
            || u64::from(certificate.sample_len)
                != certificate
                    .sealed_offset
                    .min(crate::transcript_acquisition::SAMPLE_BYTES as u64)
        {
            return Err(Corrupt);
        }
    }
    Ok(pair)
}

fn map_fingerprints<E>(pair: &mut Pair, map: impl Fn(&str) -> Result<String, E>) -> Result<(), E> {
    for row in &mut pair.api.state.rows {
        row.fingerprint = map(&row.fingerprint)?;
    }
    for row in &mut pair.trace.state.rows {
        row.fingerprint = map(&row.fingerprint)?;
    }
    pair.api.state.seen = pair
        .api
        .state
        .seen
        .iter()
        .map(|text| map(text))
        .collect::<Result<_, _>>()?;
    pair.trace.state.seen = pair
        .trace
        .state
        .seen
        .iter()
        .map(|text| map(text))
        .collect::<Result<_, _>>()?;
    for value in pair.trace.state.requests.values_mut() {
        *value = map(value)?;
    }
    Ok(())
}

fn valid_continuation(pair: &Pair) -> bool {
    pair.api
        .state
        .rows
        .iter()
        .all(|row| pair.api.state.seen.contains(&row.fingerprint))
        && pair
            .trace
            .state
            .rows
            .iter()
            .all(|row| pair.trace.state.seen.contains(&row.fingerprint))
        && pair
            .trace
            .state
            .requests
            .values()
            .all(|fingerprint| pair.trace.state.seen.contains(fingerprint))
        && (pair.api.certificate.is_some() || pair.api.state == ApiState::default())
        && (pair.trace.certificate.is_some() || pair.trace.state == TraceState::default())
}
