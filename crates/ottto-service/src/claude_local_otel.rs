//! Privacy-safe local Claude Code OTLP account-identity evidence.
//!
//! Claude transcripts do not include the provider account UUID. Claude Code's
//! official `claude_code.api_request` OTLP log does, so the loopback relay
//! reduces `user.account_uuid` to the same privacy-safe billing identity hash
//! used by snapshots and immediately discards the raw identifier. Exact request
//! counters let snapshot enrichment require complete coverage before applying
//! that identity. Raw OTLP payloads, prompts, responses, commands, paths, raw
//! account identifiers, and email addresses are never stored.
//!
//! The sidecar retains its existing serialized fields and historical on-disk
//! location for upgrade compatibility. Reasoning effort is authoritative only
//! when Claude Code records it on the transcript's assistant record.

use anyhow::{Context, Result};
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(unix)]
pub(crate) mod support_health;

#[cfg(test)]
mod decoder_tests;
#[cfg(test)]
mod trace_read_bound_tests;

pub(crate) const STORE_DIR: &str = "local-otel/claude-code-effort";
const TRACE_STORE_DIR: &str = "local-otel/claude-code-trace-ownership";
// Pressure warning only; never an append or completeness limit.
const MAX_EVIDENCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const VALID_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max"];
// Keep the usage-ledger revision: request_identity is additive local evidence,
// and does not change the existing request ownership/counter contract.
const API_REQUEST_CAPTURE_REVISION: &str = "claude_api_request:v2";
const TRACE_OWNERSHIP_CAPTURE_REVISION: &str = "claude_llm_request_ownership:v1";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeLocalOtelEvidence {
    #[serde(default)]
    pub capture_revision: Arc<str>,
    pub fingerprint: String,
    pub session_id: Arc<str>,
    /// Anthropic's per-request id (`req_...`), which the transcript repeats as
    /// `requestId` on every record of that response.
    ///
    /// This is the only field that ties one effort observation to the exact
    /// transcript that recorded it. Claude Code reports the TOP-LEVEL session id
    /// on subagent requests, so `session_id` alone cannot separate a parent turn
    /// from a Task/Workflow subagent turn, while the daemon files each subagent
    /// transcript under its own session id. Empty on evidence captured before
    /// this field existed; those rows stay on the aggregate reconciliation path.
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub client_request_id: String,
    pub observed_at: String,
    pub model: Arc<str>,
    pub effort: Arc<str>,
    #[serde(default)]
    pub query_source: Arc<str>,
    #[serde(default)]
    pub speed: Arc<str>,
    #[serde(default)]
    pub cost_usd_micros: Option<u64>,
    #[serde(default)]
    pub event_sequence: Option<u64>,
    #[serde(default)]
    pub app_version: Arc<str>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    /// Aggregate cache-creation tokens from Claude's public api_request event.
    ///
    /// Claude does not expose the 5-minute/1-hour split on that event. Keep the
    /// aggregate distinct instead of assigning it to a billing TTL we cannot
    /// prove. Snapshot enrichment leaves these tokens on the transcript's
    /// effort-unknown residual row so pricing remains byte-exact and honest.
    #[serde(default)]
    pub cache_creation_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub request_count: u64,
    /// True for records written by a daemon that evaluated the provider's
    /// account attribute. Legacy effort-only rows default false and are neutral
    /// to account attribution during upgrades.
    #[serde(default)]
    pub account_identity_checked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_identifier_hash: Option<Arc<str>>,
    /// Identity observed on this request, not a session creator or entitlement.
    /// Legacy rows have no evaluation; absence never fills an organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_identity: Option<Arc<ClaudeRequestIdentityEvidence>>,
    /// The row's one fingerprint check, kept in memory only.
    #[serde(skip)]
    pub(crate) fingerprint_check: FingerprintCheck,
}

/// Result of a row's fingerprint check, filled by whichever step asks first
/// (`snapshots::claude_api_evidence_fingerprint_is_valid`) so later steps on
/// the same page do not hash it again. Never serialized, ignored by `==`, and
/// cleared on `Clone`: a copy may be edited, so it is checked anew. Rows are
/// not edited after decode. One byte, inside the row's existing padding.
#[derive(Default)]
pub(crate) struct FingerprintCheck(std::sync::atomic::AtomicU8);

impl FingerprintCheck {
    const VALID: u8 = 1;
    const INVALID: u8 = 2;

    pub(crate) fn get_or_check(&self, check: impl FnOnce() -> bool) -> bool {
        use std::sync::atomic::Ordering::Relaxed;
        match self.0.load(Relaxed) {
            Self::VALID => true,
            Self::INVALID => false,
            _ => {
                let valid = check();
                self.0
                    .store(if valid { Self::VALID } else { Self::INVALID }, Relaxed);
                valid
            }
        }
    }
}

impl Clone for FingerprintCheck {
    fn clone(&self) -> Self {
        Self::default()
    }
}

impl PartialEq for FingerprintCheck {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for FingerprintCheck {}

impl std::fmt::Debug for FingerprintCheck {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("_")
    }
}

crate::heap_layout_bound::no_heap!(true; FingerprintCheck);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaudeRequestIdentityEvidence {
    pub identity_hash_scheme: String,
    pub account: ClaudeIdentityAttributeEvidence,
    pub organization: ClaudeIdentityAttributeEvidence,
    /// Complete means full, consistent UUID observations, not provider authority.
    pub disposition: ClaudeIdentityDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClaudeIdentityAttributeEvidence {
    pub origin: ClaudeIdentityAttributeOrigin,
    pub disposition: ClaudeIdentityDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_record_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeIdentityAttributeOrigin {
    Missing,
    Resource,
    LogRecord,
    ResourceAndLogRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeIdentityDisposition {
    Missing,
    Invalid,
    Conflict,
    Complete,
}

impl ClaudeIdentityAttributeEvidence {
    fn unambiguous_hash(&self) -> Option<String> {
        (self.disposition == ClaudeIdentityDisposition::Complete)
            .then(|| {
                self.log_record_hash
                    .clone()
                    .or_else(|| self.resource_hash.clone())
            })
            .flatten()
    }
}

fn request_identity_evidence(
    resource_attrs: &BTreeMap<String, String>,
    log_attrs: &BTreeMap<String, String>,
) -> ClaudeRequestIdentityEvidence {
    let account =
        identity_attribute_evidence(resource_attrs, log_attrs, "user.account_uuid", "account");
    let organization =
        identity_attribute_evidence(resource_attrs, log_attrs, "organization.id", "organization");
    use ClaudeIdentityDisposition::{Complete, Conflict, Invalid, Missing};
    let disposition = if account.disposition == Conflict || organization.disposition == Conflict {
        Conflict
    } else if account.disposition == Invalid || organization.disposition == Invalid {
        Invalid
    } else if account.disposition == Complete && organization.disposition == Complete {
        Complete
    } else {
        Missing
    };
    ClaudeRequestIdentityEvidence {
        identity_hash_scheme: "provider-sha256:v1".to_string(),
        account,
        organization,
        disposition,
    }
}

fn identity_attribute_evidence(
    resource_attrs: &BTreeMap<String, String>,
    log_attrs: &BTreeMap<String, String>,
    key: &str,
    kind: &str,
) -> ClaudeIdentityAttributeEvidence {
    let resource = resource_attrs.get(key);
    let record = log_attrs.get(key);
    let hash = |raw: Option<&String>| {
        raw.and_then(|raw| canonical_uuid(raw))
            .and_then(|uuid| ottto_core::billing_identity_hash("anthropic", kind, &uuid))
    };
    let resource_hash = hash(resource);
    let log_record_hash = hash(record);
    let origin = match (resource.is_some(), record.is_some()) {
        (false, false) => ClaudeIdentityAttributeOrigin::Missing,
        (true, false) => ClaudeIdentityAttributeOrigin::Resource,
        (false, true) => ClaudeIdentityAttributeOrigin::LogRecord,
        (true, true) => ClaudeIdentityAttributeOrigin::ResourceAndLogRecord,
    };
    let disposition = if resource.is_none() && record.is_none() {
        ClaudeIdentityDisposition::Missing
    } else if resource.is_some() && resource_hash.is_none()
        || record.is_some() && log_record_hash.is_none()
    {
        ClaudeIdentityDisposition::Invalid
    } else if resource.is_some() && record.is_some() && resource_hash != log_record_hash {
        ClaudeIdentityDisposition::Conflict
    } else {
        ClaudeIdentityDisposition::Complete
    };
    ClaudeIdentityAttributeEvidence {
        origin,
        disposition,
        resource_hash,
        log_record_hash,
    }
}

impl crate::telemetry_attach::ReportedRequest for ClaudeLocalOtelEvidence {
    fn request_key(&self) -> &str {
        &self.request_id
    }

    fn reported_cost_micros(&self) -> Option<u64> {
        self.cost_usd_micros
    }
}

/// Health diagnostics for a strict sidecar read. The legacy loader intentionally
/// retains its skip-and-continue behavior; completeness-sensitive reconciliation
/// must use this report and fail closed when `is_complete()` is false.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeLocalOtelLoadHealth {
    pub missing_files: u64,
    pub malformed_lines: u64,
    pub unreadable_lines: u64,
    pub oversized_files: u64,
    pub invalid_session_rows: u64,
    pub missing_request_ids: u64,
    pub conflicting_request_ids: BTreeSet<String>,
}

impl ClaudeLocalOtelLoadHealth {
    pub fn is_complete(&self) -> bool {
        self.missing_files == 0
            && self.malformed_lines == 0
            && self.unreadable_lines == 0
            && self.invalid_session_rows == 0
            && self.missing_request_ids == 0
            && self.conflicting_request_ids.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeLocalOtelLoadReport {
    pub evidence: BTreeMap<String, Vec<ClaudeLocalOtelEvidence>>,
    pub health: ClaudeLocalOtelLoadHealth,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeTraceOwnershipEvidence {
    #[serde(default)]
    pub capture_revision: Arc<str>,
    pub fingerprint: String,
    pub session_id: Arc<str>,
    #[serde(default)]
    pub request_id: String,
    #[serde(default)]
    pub client_request_id: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default)]
    pub parent_agent_id: String,
    #[serde(default)]
    pub workflow_run_id: String,
    pub observed_at: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClaudeTraceOwnershipLoadReport {
    pub evidence: BTreeMap<String, Vec<ClaudeTraceOwnershipEvidence>>,
    pub missing_files: u64,
    pub malformed_lines: u64,
    pub unreadable_lines: u64,
    pub oversized_files: u64,
    pub invalid_session_rows: u64,
    pub missing_request_ids: u64,
    pub conflicting_request_ids: BTreeSet<String>,
    pub rows_discarded: ClaudeTraceRowsDiscarded,
}

/// Strict trace reads whose decoded rows were dropped, by reason. These
/// witnesses always make the report incomplete, independently of size warnings.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct ClaudeTraceRowsDiscarded {
    /// Reads that found bytes past the opened length (the file grew).
    pub cap: u64,
    /// Reads whose opened file or path changed generation while read.
    pub generation: u64,
    pub cap_rows: u64,
    pub generation_rows: u64,
}

impl ClaudeTraceRowsDiscarded {
    pub(crate) fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub(crate) fn add(&mut self, other: &Self) {
        self.cap += other.cap;
        self.generation += other.generation;
        self.cap_rows += other.cap_rows;
        self.generation_rows += other.generation_rows;
    }
}

impl ClaudeTraceOwnershipLoadReport {
    pub fn is_complete(&self) -> bool {
        self.missing_files == 0
            && self.malformed_lines == 0
            && self.unreadable_lines == 0
            && self.invalid_session_rows == 0
            && self.missing_request_ids == 0
            && self.conflicting_request_ids.is_empty()
            && self.rows_discarded.is_empty()
    }
}

/// Context attached when a Claude OTLP body cannot be decoded, so the relay
/// can tell a malformed request apart from a local storage failure.
#[derive(Debug, Clone, Copy)]
struct UndecodableClaudeOtlpBody;

impl std::fmt::Display for UndecodableClaudeOtlpBody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Claude OTLP body could not be decoded")
    }
}

/// True when a capture error came from decoding the request body rather than
/// from storing the reduced evidence.
pub fn is_undecodable_body(error: &anyhow::Error) -> bool {
    error.downcast_ref::<UndecodableClaudeOtlpBody>().is_some()
}

pub fn capture_claude_api_request_logs(
    support_dir: &Path,
    body: &[u8],
    content_type: &str,
) -> Result<usize> {
    let content_type = content_type.to_ascii_lowercase();
    let evidence = if content_type.contains("json") {
        api_evidence_from_json(body).context(UndecodableClaudeOtlpBody)?
    } else if content_type.contains("protobuf") || content_type.contains("octet-stream") {
        api_evidence_from_protobuf(body).context(UndecodableClaudeOtlpBody)?
    } else {
        return Ok(0);
    };
    persist_api_evidence(support_dir, evidence)
}

fn api_evidence_from_json(body: &[u8]) -> Result<Vec<ClaudeLocalOtelEvidence>> {
    let payload: Value = serde_json::from_slice(body).context("parse Claude OTLP JSON logs")?;
    let mut evidence = Vec::new();
    for resource_logs in payload
        .get("resourceLogs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let resource_attrs = attributes_at(resource_logs.pointer("/resource/attributes"));
        for scope_logs in resource_logs
            .get("scopeLogs")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for record in scope_logs
                .get("logRecords")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if any_value(record.get("body")).as_deref() != Some("claude_code.api_request") {
                    continue;
                }
                let record_attrs = attributes_at(record.get("attributes"));
                let identity = request_identity_evidence(
                    &json_identity_attributes(resource_logs.pointer("/resource/attributes")),
                    &json_identity_attributes(record.get("attributes")),
                );
                let mut attrs = resource_attrs.clone();
                attrs.extend(record_attrs);
                if let Some(item) = api_evidence_from_attrs(&attrs, timestamp_at(record), identity)
                {
                    evidence.push(item);
                }
            }
        }
    }
    Ok(evidence)
}

fn api_evidence_from_protobuf(body: &[u8]) -> Result<Vec<ClaudeLocalOtelEvidence>> {
    let payload = otlp_proto::ExportLogsServiceRequest::decode(body)
        .context("parse Claude OTLP protobuf logs")?;
    let mut evidence = Vec::new();
    for resource_logs in payload.resource_logs {
        let resource_attrs = proto_attributes(
            resource_logs
                .resource
                .as_ref()
                .map(|resource| resource.attributes.as_slice())
                .unwrap_or_default(),
        );
        for scope_logs in resource_logs.scope_logs {
            for record in scope_logs.log_records {
                if record.body.as_ref().and_then(proto_any_value).as_deref()
                    != Some("claude_code.api_request")
                {
                    continue;
                }
                let record_attrs = proto_attributes(&record.attributes);
                let identity = request_identity_evidence(
                    &proto_identity_attributes(
                        resource_logs
                            .resource
                            .as_ref()
                            .map(|resource| resource.attributes.as_slice())
                            .unwrap_or_default(),
                    ),
                    &proto_identity_attributes(&record.attributes),
                );
                let mut attrs = resource_attrs.clone();
                attrs.extend(record_attrs);
                let observed_at = log_timestamp(
                    Some(record.time_unix_nano),
                    Some(record.observed_time_unix_nano),
                );
                if let Some(item) = api_evidence_from_attrs(&attrs, observed_at, identity) {
                    evidence.push(item);
                }
            }
        }
    }
    Ok(evidence)
}

fn persist_api_evidence(
    support_dir: &Path,
    evidence: Vec<ClaudeLocalOtelEvidence>,
) -> Result<usize> {
    if evidence.is_empty() {
        return Ok(0);
    }
    let _guard = append_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("effort store lock poisoned"))?;
    for item in &evidence {
        append_evidence(support_dir, item)?;
    }
    Ok(evidence.len())
}

/// Reduce Claude Code's enhanced `claude_code.llm_request` spans to a bounded,
/// content-free request owner record. This function only decodes a borrowed
/// byte slice; the raw body is never stored or sent anywhere.
pub fn capture_claude_llm_request_traces(
    support_dir: &Path,
    body: &[u8],
    content_type: &str,
) -> Result<usize> {
    let content_type = content_type.to_ascii_lowercase();
    let evidence = if content_type.contains("json") {
        trace_evidence_from_json(body).context(UndecodableClaudeOtlpBody)?
    } else if content_type.contains("protobuf") || content_type.contains("octet-stream") {
        trace_evidence_from_protobuf(body).context(UndecodableClaudeOtlpBody)?
    } else {
        return Ok(0);
    };
    if evidence.is_empty() {
        return Ok(0);
    }
    let _guard = append_lock()
        .lock()
        .map_err(|_| anyhow::anyhow!("Claude local OTEL store lock poisoned"))?;
    for item in &evidence {
        append_trace_ownership_evidence(support_dir, item)?;
    }
    Ok(evidence.len())
}

fn trace_evidence_from_json(body: &[u8]) -> Result<Vec<ClaudeTraceOwnershipEvidence>> {
    let payload: Value = serde_json::from_slice(body).context("parse Claude OTLP JSON traces")?;
    let mut evidence = Vec::new();
    for resource_spans in payload
        .get("resourceSpans")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let resource_attrs = attributes_at(resource_spans.pointer("/resource/attributes"));
        for scope_spans in resource_spans
            .get("scopeSpans")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            for span in scope_spans
                .get("spans")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if span.get("name").and_then(Value::as_str) != Some("claude_code.llm_request") {
                    continue;
                }
                let mut attrs = resource_attrs.clone();
                attrs.extend(attributes_at(span.get("attributes")));
                let observed_at = span
                    .get("startTimeUnixNano")
                    .and_then(json_nanos)
                    .and_then(format_nanos);
                if let Some(item) = trace_evidence_from_attrs(&attrs, observed_at) {
                    evidence.push(item);
                }
            }
        }
    }
    Ok(evidence)
}

fn trace_evidence_from_protobuf(body: &[u8]) -> Result<Vec<ClaudeTraceOwnershipEvidence>> {
    let payload = otlp_proto::ExportTraceServiceRequest::decode(body)
        .context("parse Claude OTLP protobuf traces")?;
    let mut evidence = Vec::new();
    for resource_spans in payload.resource_spans {
        let resource_attrs = proto_attributes(
            resource_spans
                .resource
                .as_ref()
                .map(|resource| resource.attributes.as_slice())
                .unwrap_or_default(),
        );
        for scope_spans in resource_spans.scope_spans {
            for span in scope_spans.spans {
                if span.name != "claude_code.llm_request" {
                    continue;
                }
                let mut attrs = resource_attrs.clone();
                attrs.extend(proto_attributes(&span.attributes));
                let observed_at = format_nanos(i128::from(span.start_time_unix_nano));
                if let Some(item) = trace_evidence_from_attrs(&attrs, observed_at) {
                    evidence.push(item);
                }
            }
        }
    }
    Ok(evidence)
}

fn trace_evidence_from_attrs(
    attrs: &BTreeMap<String, String>,
    observed_at: Option<String>,
) -> Option<ClaudeTraceOwnershipEvidence> {
    use crate::local_resource_diagnostics::cache_lifecycle::{record, Event};
    if first_attr(attrs, &["success"]).is_some_and(|value| value == "false") {
        record(Event::LlmRequestSpanSuccessFalse);
        return None;
    }
    let session_id = bounded_attr(attrs, &["session.id", "session_id"], 256);
    if session_id.is_empty() {
        record(Event::LlmRequestSpanMissingSessionId);
        return None;
    }
    let Some(observed_at) = observed_at else {
        record(Event::LlmRequestSpanMissingStartTime);
        return None;
    };
    let mut item = ClaudeTraceOwnershipEvidence {
        capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.into(),
        fingerprint: String::new(),
        session_id: session_id.into(),
        request_id: bounded_attr(attrs, &["request_id", "gen_ai.response.id"], 256),
        client_request_id: bounded_attr(attrs, &["client_request_id"], 256),
        agent_id: bounded_attr(attrs, &["agent.id", "agent_id"], 256),
        parent_agent_id: bounded_attr(attrs, &["parent_agent_id", "parent.agent.id"], 256),
        workflow_run_id: bounded_attr(attrs, &["workflow.run_id", "workflow_run_id"], 256),
        observed_at,
    };
    let bytes = serde_json::to_vec(&item).ok()?;
    item.fingerprint = format!("sha256:{:x}", Sha256::digest(bytes));
    Some(item)
}

// Only the additive identity field may differ across a v2 upgrade replay.
// Comparing the whole typed row protects every pre-existing usage/ownership field.
fn identity_upgrade_replay(
    previous: &ClaudeLocalOtelEvidence,
    incoming: &ClaudeLocalOtelEvidence,
) -> bool {
    if *previous.capture_revision != *API_REQUEST_CAPTURE_REVISION
        || *incoming.capture_revision != *API_REQUEST_CAPTURE_REVISION
        || previous.request_identity.is_none() == incoming.request_identity.is_none()
    {
        return false;
    }
    let mut previous = previous.clone();
    let mut incoming = incoming.clone();
    previous.fingerprint.clear();
    incoming.fingerprint.clear();
    previous.request_identity = None;
    incoming.request_identity = None;
    previous == incoming
}

/// One root decode's pool of repeated row values (session, revision, model,
/// identity...). Rows share one allocation per distinct value; values, bytes
/// and fingerprints are unchanged. Dropped with its decoder.
#[derive(Debug, Clone, Default)]
struct SharedValues {
    strs: HashSet<Arc<str>>,
    identities: HashSet<Arc<ClaudeRequestIdentityEvidence>>,
}

fn share<T: Eq + std::hash::Hash + ?Sized>(pool: &mut HashSet<Arc<T>>, value: &mut Arc<T>) {
    match pool.get(&*value) {
        Some(shared) => *value = Arc::clone(shared),
        None => {
            pool.insert(Arc::clone(value));
        }
    }
}

impl SharedValues {
    fn api(&mut self, row: &mut ClaudeLocalOtelEvidence) {
        for value in [
            &mut row.capture_revision,
            &mut row.session_id,
            &mut row.model,
            &mut row.effort,
            &mut row.query_source,
            &mut row.speed,
            &mut row.app_version,
        ] {
            share(&mut self.strs, value);
        }
        if let Some(value) = &mut row.account_identifier_hash {
            share(&mut self.strs, value);
        }
        if let Some(identity) = &mut row.request_identity {
            share(&mut self.identities, identity);
        }
    }

    fn trace(&mut self, row: &mut ClaudeTraceOwnershipEvidence) {
        share(&mut self.strs, &mut row.capture_revision);
        share(&mut self.strs, &mut row.session_id);
    }
}

/// Cumulative arrival-order API projection. Keep even suppressed fingerprints:
/// rebuilding `seen_fingerprints` from surviving rows changes replay semantics.
#[cfg_attr(test, derive(Debug, Clone))]
struct ApiSidecarDecoder<'a> {
    session_id: &'a str,
    rows: Vec<ClaudeLocalOtelEvidence>,
    seen_fingerprints: BTreeSet<String>,
    request_rows: BTreeMap<String, usize>,
    health: ClaudeLocalOtelLoadHealth,
    shared: SharedValues,
}

impl<'a> ApiSidecarDecoder<'a> {
    fn new(session_id: &'a str, rows: Vec<ClaudeLocalOtelEvidence>) -> Self {
        Self {
            session_id,
            rows,
            seen_fingerprints: BTreeSet::new(),
            request_rows: BTreeMap::new(),
            health: ClaudeLocalOtelLoadHealth::default(),
            shared: SharedValues::default(),
        }
    }

    // EOF is terminal for this view; callers retain only complete-line state
    // when they need to extend a previously observed fragment.
    fn finish_eof(&mut self, fragment: Option<&[u8]>) {
        if let Some(fragment) = fragment {
            self.push_line(fragment);
        }
    }

    fn into_output(self) -> (Vec<ClaudeLocalOtelEvidence>, ClaudeLocalOtelLoadHealth) {
        (self.rows, self.health)
    }
}

/// Append one distinct request row; report a same-request fingerprint conflict.
/// A compatible upgrade replay keeps one usage row and the richer local witness.
fn append_request_evidence(
    rows: &mut Vec<ClaudeLocalOtelEvidence>,
    seen_fingerprints: &mut BTreeSet<String>,
    request_rows: &mut BTreeMap<String, usize>,
    item: ClaudeLocalOtelEvidence,
) -> bool {
    if !seen_fingerprints.insert(item.fingerprint.clone()) {
        return false;
    }
    let mut conflict = false;
    if !item.request_id.is_empty() {
        if let Some(index) = request_rows.get(&item.request_id).copied() {
            if identity_upgrade_replay(&rows[index], &item) {
                if item.request_identity.is_some() {
                    rows[index] = item;
                }
                return false;
            }
            conflict = true;
        } else {
            request_rows.insert(item.request_id.clone(), rows.len());
        }
    }
    rows.push(item);
    conflict
}

#[cfg(test)]
thread_local! {
    // Actual API file opens and consumed bytes, isolated from parallel tests.
    static API_READ_RECEIPT: std::cell::Cell<(usize, usize, bool)> = const { std::cell::Cell::new((0, 0, false)) };
}

/// A scan-local owner of one decode and its strict diagnostics. Effort borrows
/// the rows first; only roots selected afterward are retained for usage.
#[derive(Default)]
pub(crate) struct ClaudeApiEvidenceRead {
    pub(crate) evidence: BTreeMap<String, Vec<ClaudeLocalOtelEvidence>>,
    reads: BTreeMap<String, ApiReadWitness>,
}

struct ApiReadWitness {
    health: ClaudeLocalOtelLoadHealth,
    generation: Option<ApiFileGeneration>,
}

// Length/mtime alone cannot detect same-size replacement or restored mtimes.
// This witness never becomes a persisted sidecar/candidate fingerprint.
#[derive(Debug, PartialEq, Eq)]
struct ApiFileGeneration {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn api_file_generation(metadata: &fs::Metadata) -> Option<ApiFileGeneration> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.is_file().then(|| ApiFileGeneration {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        // Without an opened-object generation witness, keep the strict reread.
        None
    }
}

/// Read-only open; O_NONBLOCK so a stat/open race to a FIFO refuses without
/// blocking at open. Each strict reader keeps its own stat/cap/error policy.
fn open_strict(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    options.open(path)
}

/// The opened file, then the path, still carry `generation` (file first).
fn generation_unchanged(file: &File, path: &Path, generation: Option<&ApiFileGeneration>) -> bool {
    let current = |metadata: std::io::Result<fs::Metadata>| {
        metadata.ok().and_then(|m| api_file_generation(&m))
    };
    current(file.metadata()).as_ref() == generation
        && current(fs::metadata(path)).as_ref() == generation
}

impl ClaudeApiEvidenceRead {
    /// Borrow the existing decode and its full health witness without I/O.
    /// Missing/malformed reads remain present but incomplete; a root outside
    /// this reader's cohort has no report. The reader owns strict allowance
    /// exhaustion and conflicting-id detection, including empty-row reads.
    pub(crate) fn session_report(
        &self,
        root: &str,
    ) -> Option<crate::telemetry_attach::SessionReport<'_, ClaudeLocalOtelEvidence>> {
        let health = &self.reads.get(root)?.health;
        Some(crate::telemetry_attach::SessionReport {
            rows: self.evidence.get(root).map(Vec::as_slice).unwrap_or(&[]),
            complete: health.is_complete(),
            duplicate_keys: &health.conflicting_request_ids,
        })
    }

    pub(crate) fn load(
        support_dir: &Path,
        session_ids: impl IntoIterator<Item = String>,
    ) -> Result<Self> {
        let mut read = Self::default();
        for session_id in session_ids {
            // One open failure still discards the entire permissive effort map.
            let (rows, witness) = decode_api_sidecar(support_dir, &session_id)?;
            if !rows.is_empty() {
                read.evidence.insert(session_id.clone(), rows);
            }
            read.reads.insert(session_id, witness);
        }
        Ok(read)
    }

    pub(crate) fn retain_roots(&mut self, roots: &BTreeSet<String>) {
        self.evidence.retain(|root, _| roots.contains(root));
        self.reads.retain(|root, _| roots.contains(root));
    }

    /// Read-only validation of the opened generation; no rows are consumed or
    /// cloned. Unknown/replaced generations are ineligible for preflight reuse.
    pub(crate) fn strict_generation_matches(&self, support_dir: &Path, session_id: &str) -> bool {
        let current = fs::metadata(evidence_path(support_dir, session_id))
            .ok()
            .and_then(|metadata| api_file_generation(&metadata));
        #[cfg(test)]
        let current = if API_READ_RECEIPT.with(|r| r.get().2) {
            None
        } else {
            current
        };
        self.reads.get(session_id).is_some_and(|witness| {
            witness.health.is_complete()
                && witness.generation.is_some()
                && witness.generation == current
        })
    }

    pub(crate) fn take_strict_report(
        &mut self,
        support_dir: &Path,
        session_id: &str,
    ) -> ClaudeLocalOtelLoadReport {
        let reusable = self.strict_generation_matches(support_dir, session_id);
        let witness = self.reads.remove(session_id);
        let rows = self.evidence.remove(session_id);
        if let Some(witness) = witness {
            if reusable {
                let mut report = ClaudeLocalOtelLoadReport {
                    health: witness.health,
                    ..Default::default()
                };
                if let Some(rows) = rows {
                    report.evidence.insert(session_id.to_string(), rows);
                }
                return report;
            }
        }
        // Drop the old owned rows before rereading. Appends, replacement,
        // truncation, non-files and errors cannot reuse stale evidence.
        drop(rows);
        load_claude_api_request_evidence_report(support_dir, [session_id.to_string()])
    }
}

#[cfg(test)]
pub fn load_claude_effort_evidence(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, Vec<ClaudeLocalOtelEvidence>>> {
    ClaudeApiEvidenceRead::load(support_dir, session_ids).map(|read| read.evidence)
}

/// Strict API-request evidence loader for completeness-sensitive accounting.
/// Unlike the compatibility view, this reports all hidden or ambiguous requests.
pub fn load_claude_api_request_evidence_report(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> ClaudeLocalOtelLoadReport {
    let mut report = ClaudeLocalOtelLoadReport::default();
    for session_id in BTreeSet::from_iter(session_ids) {
        let (rows, witness) = match decode_api_sidecar(support_dir, &session_id) {
            Ok(decoded) => decoded,
            Err(_) => {
                report.health.unreadable_lines += 1;
                continue;
            }
        };
        let health = witness.health;
        report.health.missing_files += health.missing_files;
        report.health.malformed_lines += health.malformed_lines;
        report.health.unreadable_lines += health.unreadable_lines;
        report.health.oversized_files += health.oversized_files;
        report.health.invalid_session_rows += health.invalid_session_rows;
        report.health.missing_request_ids += health.missing_request_ids;
        report
            .health
            .conflicting_request_ids
            .extend(health.conflicting_request_ids);
        if !rows.is_empty() {
            report.evidence.insert(session_id, rows);
        }
    }
    report
}

fn decode_api_sidecar(
    support_dir: &Path,
    session_id: &str,
) -> Result<(Vec<ClaudeLocalOtelEvidence>, ApiReadWitness)> {
    let path = evidence_path(support_dir, session_id);
    let mut health = ClaudeLocalOtelLoadHealth::default();
    let empty = |health| {
        (
            Vec::new(),
            ApiReadWitness {
                health,
                generation: None,
            },
        )
    };
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) => {
            if error.kind() == std::io::ErrorKind::NotFound {
                health.missing_files += 1;
            } else {
                health.unreadable_lines += 1;
            }
            return Ok(empty(health));
        }
    };
    // Refuse before opening: a directory/erroring stream must never loop.
    if !metadata.is_file() {
        anyhow::bail!("Claude effort evidence is not a regular file");
    }
    let before_path = api_file_generation(&metadata);
    let file = open_strict(&path).context("open Claude effort evidence")?;
    #[cfg(test)]
    API_READ_RECEIPT.with(|r| {
        let (opens, bytes, force) = r.get();
        r.set((opens + 1, bytes, force));
    });
    let opened = file
        .metadata()
        .context("stat opened Claude effort evidence")?;
    if !opened.is_file() {
        anyhow::bail!("opened Claude effort evidence is not a regular file");
    }
    health.oversized_files = u64::from(opened.len() >= MAX_EVIDENCE_FILE_BYTES);
    let before_opened = api_file_generation(&opened);
    let pair_bytes =
        strict_cohort_bytes(support_dir, session_id).max(opened.len().saturating_add(1));
    note_oversized_pair(pair_bytes);
    let allowance = MAX_EVIDENCE_FILE_BYTES.max(pair_bytes);
    // Preserve ordinary API read-through on concurrent appends within the
    // protected per-pair allowance.
    let mut reader = BufReader::new((&file).take(allowance));
    crate::local_resource_diagnostics::claude_sidecar_reparse(1, 0);
    let rows = decode_api_rows(&mut reader, session_id, &mut health);
    let bytes = allowance - reader.get_ref().limit();
    crate::local_resource_diagnostics::claude_sidecar_reparse(0, bytes);
    health.oversized_files = u64::from(opened.len().max(bytes) >= MAX_EVIDENCE_FILE_BYTES);
    if bytes >= allowance {
        health.unreadable_lines += 1;
        return Ok(empty(health));
    }
    let unchanged = generation_unchanged(&file, &path, before_opened.as_ref());
    let generation = if before_opened.is_some()
        && before_path == before_opened
        && unchanged
        && bytes == opened.len()
        && health.is_complete()
    {
        before_opened
    } else {
        None
    };
    Ok((rows, ApiReadWitness { health, generation }))
}

fn decode_api_rows(
    reader: &mut impl BufRead,
    session_id: &str,
    health: &mut ClaudeLocalOtelLoadHealth,
) -> Vec<ClaudeLocalOtelEvidence> {
    let mut decoder = ApiSidecarDecoder::new(session_id, Vec::new());
    decoder.health = std::mem::take(health);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Ok(_) => {
                #[cfg(test)]
                API_READ_RECEIPT.with(|r| {
                    let (opens, bytes, force) = r.get();
                    r.set((opens, bytes + line.len(), force));
                });
            }
            Err(_) => {
                decoder.health.unreadable_lines += 1;
                break;
            }
        }
        if line.ends_with(b"\n") {
            decoder.push_line(&line);
        } else {
            decoder.finish_eof(Some(&line));
        }
    }
    let (rows, decoded_health) = decoder.into_output();
    *health = decoded_health;
    rows
}

impl ApiSidecarDecoder<'_> {
    fn push_line(&mut self, line: &[u8]) {
        let Ok(line) = std::str::from_utf8(line) else {
            self.health.unreadable_lines += 1;
            return;
        };
        let mut item = match serde_json::from_str::<ClaudeLocalOtelEvidence>(line) {
            Ok(item) => item,
            Err(_) => {
                self.health.malformed_lines += 1;
                return;
            }
        };
        if *item.session_id != *self.session_id {
            self.health.invalid_session_rows += 1;
            return;
        }
        self.shared.api(&mut item);
        if item.request_id.is_empty() {
            self.health.missing_request_ids += 1;
        }
        let request_id = item.request_id.clone();
        if append_request_evidence(
            &mut self.rows,
            &mut self.seen_fingerprints,
            &mut self.request_rows,
            item,
        ) {
            self.health.conflicting_request_ids.insert(request_id);
        }
    }
}

/// Counts a root whose paired sidecars exceed the normal allowance.
fn note_oversized_pair(pair_bytes: u64) {
    if pair_bytes > MAX_EVIDENCE_FILE_BYTES {
        crate::local_resource_diagnostics::traversal_point(
            "claude_sidecar_read",
            "claude_code",
            &std::collections::BTreeMap::from([
                ("oversized_root_alone", 1),
                ("allowance_bytes", pair_bytes),
            ]),
        );
    }
}

/// Metadata-only pre-I/O charge, including an EOF/growth sentinel per file.
pub(crate) fn strict_cohort_bytes(support_dir: &Path, root: &str) -> u64 {
    [
        evidence_path(support_dir, root),
        trace_evidence_path(support_dir, root),
    ]
    .iter()
    .fold(0u64, |sum, path| {
        sum.saturating_add(match fs::metadata(path) {
            Ok(metadata) => metadata.len().saturating_add(1),
            // Absence consumes no input; the loaders still report missing
            // evidence. Do not turn a missing peer into size pressure.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(_) => MAX_EVIDENCE_FILE_BYTES,
        })
    })
}

pub fn load_claude_trace_ownership_evidence(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> ClaudeTraceOwnershipLoadReport {
    let mut report = ClaudeTraceOwnershipLoadReport::default();
    for session_id in BTreeSet::from_iter(session_ids) {
        let path = trace_evidence_path(support_dir, &session_id);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                report.missing_files += 1;
                continue;
            }
            Err(_) => {
                report.unreadable_lines += 1;
                continue;
            }
        };
        if !metadata.is_file() {
            report.unreadable_lines += 1;
            continue;
        }
        let Ok(file) = open_strict(&path) else {
            report.unreadable_lines += 1;
            continue;
        };
        #[cfg(test)]
        TRACE_READ_RECEIPT.with(|count| count.set(count.get() + 1));
        let Ok(opened) = file.metadata() else {
            report.unreadable_lines += 1;
            continue;
        };
        if !opened.is_file() {
            report.unreadable_lines += 1;
            continue;
        }
        report.oversized_files += u64::from(opened.len() >= MAX_EVIDENCE_FILE_BYTES);
        // A concurrent writer must not extend the read past the opened
        // length; one extra byte is the growth sentinel.
        let limit = opened.len().saturating_add(1);
        note_oversized_pair(strict_cohort_bytes(support_dir, &session_id).max(limit));
        #[cfg(test)]
        TRACE_BEFORE_READ.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook(&path);
            }
        });
        let mut reader = BufReader::new((&file).take(limit));
        crate::local_resource_diagnostics::claude_sidecar_reparse(1, 0);
        let mut decoder = TraceSidecarDecoder::new(&session_id, Vec::new());
        decoder.report = report;
        for line in reader.by_ref().lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => {
                    decoder.report.unreadable_lines += 1;
                    continue;
                }
            };
            decoder.push_line(line.as_bytes());
        }
        let bytes = limit - reader.get_ref().limit();
        crate::local_resource_diagnostics::claude_sidecar_reparse(0, bytes);
        #[cfg(test)]
        TRACE_BYTES_FOR_TEST.with(|count| count.set(count.get() + bytes));
        let unchanged = generation_unchanged(&file, &path, api_file_generation(&opened).as_ref());
        // A grown or replaced file is neither complete evidence nor a
        // trustworthy prefix: drop its rows and fail the read's health.
        if bytes >= limit || !unchanged {
            let rows = decoder.rows.len() as u64;
            let discarded = &mut decoder.report.rows_discarded;
            if bytes >= limit {
                discarded.cap += 1;
                discarded.cap_rows += rows;
            } else {
                discarded.generation += 1;
                discarded.generation_rows += rows;
            }
            decoder.rows.clear();
            decoder.report.oversized_files += 1;
        }
        decoder.finish_eof(None);
        let (rows, decoded_report) = decoder.into_output();
        report = decoded_report;
        if !rows.is_empty() {
            report.evidence.insert(session_id, rows);
        }
    }
    report
}

/// Trace conflicts track the last export even when its fingerprint was seen.
#[cfg_attr(test, derive(Debug, Clone))]
struct TraceSidecarDecoder<'a> {
    session_id: &'a str,
    rows: Vec<ClaudeTraceOwnershipEvidence>,
    seen_fingerprints: BTreeSet<String>,
    request_fingerprints: BTreeMap<String, String>,
    report: ClaudeTraceOwnershipLoadReport,
    shared: SharedValues,
}

impl<'a> TraceSidecarDecoder<'a> {
    fn new(session_id: &'a str, rows: Vec<ClaudeTraceOwnershipEvidence>) -> Self {
        Self {
            session_id,
            rows,
            seen_fingerprints: BTreeSet::new(),
            request_fingerprints: BTreeMap::new(),
            report: ClaudeTraceOwnershipLoadReport::default(),
            shared: SharedValues::default(),
        }
    }

    fn finish_eof(&mut self, fragment: Option<&[u8]>) {
        if let Some(fragment) = fragment {
            self.push_line(fragment);
        }
    }

    fn into_output(
        self,
    ) -> (
        Vec<ClaudeTraceOwnershipEvidence>,
        ClaudeTraceOwnershipLoadReport,
    ) {
        (self.rows, self.report)
    }

    fn push_line(&mut self, line: &[u8]) {
        let Ok(line) = std::str::from_utf8(line) else {
            self.report.unreadable_lines += 1;
            return;
        };
        let mut item = match serde_json::from_str::<ClaudeTraceOwnershipEvidence>(line) {
            Ok(item) => item,
            Err(_) => {
                self.report.malformed_lines += 1;
                return;
            }
        };
        if *item.session_id != *self.session_id {
            self.report.invalid_session_rows += 1;
            return;
        }
        self.shared.trace(&mut item);
        if item.request_id.is_empty() {
            self.report.missing_request_ids += 1;
        } else if let Some(previous) = self
            .request_fingerprints
            .insert(item.request_id.clone(), item.fingerprint.clone())
        {
            if previous != item.fingerprint {
                self.report
                    .conflicting_request_ids
                    .insert(item.request_id.clone());
            }
        }
        if self.seen_fingerprints.insert(item.fingerprint.clone()) {
            self.rows.push(item);
        }
    }
}

#[cfg(test)]
type TraceBeforeReadHook = Box<dyn FnOnce(&Path)>;
#[cfg(test)]
thread_local! {
    static TRACE_BYTES_FOR_TEST: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TRACE_BEFORE_READ: std::cell::RefCell<Option<TraceBeforeReadHook>> =
        const { std::cell::RefCell::new(None) };
    static TRACE_READ_RECEIPT: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Runs `hook` once on this thread, after the next strict trace read opens
/// its file and before it reads, to stage a concurrent writer.
#[cfg(test)]
pub(crate) fn before_next_trace_read_for_test(hook: impl FnOnce(&Path) + 'static) {
    TRACE_BEFORE_READ.with(|slot| *slot.borrow_mut() = Some(Box::new(hook)));
}

/// Runs `f`, then puts this thread's read receipts back as they were before
/// it; a pending trace-read hook is set aside so `f` cannot fire it.
#[cfg(test)]
pub(crate) fn without_read_receipts<T>(f: impl FnOnce() -> T) -> T {
    let api = API_READ_RECEIPT.with(std::cell::Cell::get);
    let trace = TRACE_READ_RECEIPT.with(std::cell::Cell::get);
    let bytes = TRACE_BYTES_FOR_TEST.with(std::cell::Cell::get);
    let hook = TRACE_BEFORE_READ.with(|slot| slot.borrow_mut().take());
    let value = f();
    API_READ_RECEIPT.with(|slot| slot.set(api));
    TRACE_READ_RECEIPT.with(|slot| slot.set(trace));
    TRACE_BYTES_FOR_TEST.with(|slot| slot.set(bytes));
    TRACE_BEFORE_READ.with(|slot| *slot.borrow_mut() = hook);
    value
}

#[cfg(test)]
pub(crate) fn evidence_read_counts_for_test() -> (usize, usize) {
    (
        API_READ_RECEIPT.with(|receipt| receipt.get().0),
        TRACE_READ_RECEIPT.with(std::cell::Cell::get),
    )
}

/// Build the legacy effort index by Anthropic request id.
///
/// `session_ids` are the sessions whose sidecars own the evidence, which for a
/// subagent transcript is its PARENT session (Claude Code stamps the top-level
/// `session.id` on subagent OTLP records). Request ids are globally unique, so
/// one flat map serves every transcript in the scan: each request lands on
/// whichever transcript actually recorded it, parent or sidechain alike.
///
/// Rows without a request id (captured before the field existed) are skipped.
/// Production snapshot enrichment no longer consults this index: a transcript
/// record without `effort` stays effort-unknown.
#[cfg(test)]
pub fn load_claude_effort_by_request(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> BTreeMap<String, String> {
    let mut index = BTreeMap::new();
    for session_id in BTreeSet::from_iter(session_ids) {
        let path = evidence_path(support_dir, &session_id);
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if !metadata.is_file() {
            continue;
        }
        let Ok(file) = File::open(&path) else {
            continue;
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            let Ok(item) = serde_json::from_str::<ClaudeLocalOtelEvidence>(&line) else {
                continue;
            };
            if *item.session_id != *session_id
                || item.request_id.is_empty()
                || !VALID_EFFORTS.contains(&item.effort.as_ref())
            {
                continue;
            }
            // One request has exactly one applied tier; a repeated id is the
            // same observation re-exported, so first write wins.
            index
                .entry(item.request_id)
                .or_insert(item.effort.to_string());
        }
    }
    index
}

/// Stat-only fingerprint for one session's local OTLP sidecar.
///
/// Snapshot candidate selection uses this so evidence appended after the
/// transcript's final write still re-selects that transcript. The fingerprint
/// exposes neither the session id nor any sidecar content.
pub fn claude_effort_sidecar_fingerprint(support_dir: &Path, session_id: &str) -> String {
    sidecar_fingerprint(
        evidence_path(support_dir, session_id),
        "claude_effort_sidecar:v1",
    )
}

#[cfg(test)]
pub(crate) fn claude_trace_ownership_evidence_dir(support_dir: &Path) -> PathBuf {
    support_dir.join(TRACE_STORE_DIR)
}

/// True only when neither paired sidecar exists. Existing sidecars of any
/// size, non-files and unreadable sidecars are never absence.
pub(crate) fn claude_sidecars_absent(support_dir: &Path, session_id: &str) -> bool {
    [
        evidence_path(support_dir, session_id),
        trace_evidence_path(support_dir, session_id),
    ]
    .iter()
    .all(|path| matches!(telemetry_member(path), Ok(None)))
}

/// One telemetry pair (API + trace member) as read for retention. Each member
/// is optional: `None` is a confirmed NotFound.
pub(crate) struct TelemetryPair {
    /// Every API and trace request id.
    pub(crate) request_ids: BTreeSet<String>,
    /// Earliest `observed_at` (unix seconds); `u64::MAX` for no rows.
    pub(crate) first_observed: u64,
    /// Latest mtime or ctime of a present member (unix seconds).
    pub(crate) last_write: i64,
    pub(crate) bytes: u64,
    generations: [Option<ApiFileGeneration>; 2],
}

/// Every stem (`sha256(session id)`) in either telemetry directory. A missing
/// directory has none.
pub(crate) fn telemetry_stems(support_dir: &Path) -> std::io::Result<BTreeSet<String>> {
    let mut stems = BTreeSet::new();
    for dir in [STORE_DIR, TRACE_STORE_DIR] {
        let entries = match fs::read_dir(support_dir.join(dir)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            entries => entries?,
        };
        for entry in entries {
            let name = entry?.file_name();
            if let Some(stem) = name.to_str().and_then(|name| name.strip_suffix(".jsonl")) {
                stems.insert(stem.to_owned());
            }
        }
    }
    Ok(stems)
}

/// The one digest naming a session's telemetry members.
pub(crate) fn telemetry_stem(session_id: &str) -> String {
    format!("{:x}", Sha256::digest(session_id.as_bytes()))
}

/// The one layout of a stem's (API, trace) members.
fn telemetry_member_paths(support_dir: &Path, stem: &str) -> [PathBuf; 2] {
    let name = format!("{stem}.jsonl");
    [
        support_dir.join(STORE_DIR).join(&name),
        support_dir.join(TRACE_STORE_DIR).join(name),
    ]
}

/// `Ok(None)`: confirmed NotFound. A symlink, non-file or any other error is
/// a read fault.
fn telemetry_member(path: &Path) -> std::result::Result<Option<ApiFileGeneration>, ()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Ok(metadata) if metadata.file_type().is_file() => {
            api_file_generation(&metadata).map(Some).ok_or(())
        }
        _ => Err(()),
    }
}

/// A pair's present-member bytes from metadata only; no body is opened.
/// `Ok(None)`: both members are NotFound. `Err`: a member is a read fault.
pub(crate) fn telemetry_pair_bytes(
    support_dir: &Path,
    stem: &str,
) -> std::result::Result<Option<u64>, ()> {
    let mut bytes = None;
    for path in telemetry_member_paths(support_dir, stem) {
        if let Some(generation) = telemetry_member(&path)? {
            *bytes.get_or_insert(0) += generation.bytes;
        }
    }
    Ok(bytes)
}

/// Read one pair with the existing decoders. `Ok(None)`: both members are
/// NotFound (the session has no telemetry). `Err`: a read fault (symlink,
/// unreadable, malformed row, session mismatch, or a member that changed while
/// read); only this pair is held.
pub(crate) fn read_telemetry_pair(
    support_dir: &Path,
    stem: &str,
) -> std::result::Result<Option<TelemetryPair>, ()> {
    let paths = telemetry_member_paths(support_dir, stem);
    let generations = [telemetry_member(&paths[0])?, telemetry_member(&paths[1])?];
    // The session id from the first row of a present member; it must hash to
    // the stem.
    let Some(present) = paths
        .iter()
        .zip(&generations)
        .find_map(|(path, generation)| generation.as_ref().map(|_| path))
    else {
        return Ok(None);
    };
    let mut first = String::new();
    BufReader::new(open_strict(present).map_err(|_| ())?)
        .read_line(&mut first)
        .map_err(|_| ())?;
    let session_id = serde_json::from_str::<Value>(&first)
        .ok()
        .and_then(|row| row.get("session_id")?.as_str().map(str::to_owned))
        .filter(|id| telemetry_stem(id) == stem)
        .ok_or(())?;
    let mut request_ids = BTreeSet::new();
    let mut observed = Vec::new();
    if generations[0].is_some() {
        let (rows, witness) = decode_api_sidecar(support_dir, &session_id).map_err(|_| ())?;
        if !witness.health.is_complete() {
            return Err(());
        }
        for row in rows {
            request_ids.insert(row.request_id);
            observed.push(row.observed_at);
        }
    }
    if generations[1].is_some() {
        let mut report = load_claude_trace_ownership_evidence(support_dir, [session_id.clone()]);
        if !report.is_complete() {
            return Err(());
        }
        for row in report.evidence.remove(&session_id).unwrap_or_default() {
            request_ids.insert(row.request_id);
            observed.push(row.observed_at);
        }
    }
    request_ids.remove("");
    let mut first_observed = u64::MAX;
    for at in observed {
        let at = OffsetDateTime::parse(&at, &Rfc3339).map_err(|_| ())?;
        first_observed = first_observed.min(u64::try_from(at.unix_timestamp()).map_err(|_| ())?);
    }
    let present = generations.iter().flatten();
    Ok(Some(TelemetryPair {
        request_ids,
        first_observed,
        last_write: present
            .clone()
            .map(|generation| generation.modified.0.max(generation.changed.0))
            .max()
            .unwrap_or(i64::MAX),
        bytes: present.map(|generation| generation.bytes).sum(),
        generations,
    }))
}

/// Unlink a pair's present members under the relay's append lock, only while
/// each member is still the one that was read (same generation, or still
/// NotFound). `Ok(false)`: it changed and is kept. A pair left half-unlinked
/// by a crash is a candidate again with one optional member.
pub(crate) fn unlink_telemetry_pair(
    support_dir: &Path,
    stem: &str,
    pair: &TelemetryPair,
) -> std::io::Result<bool> {
    let _guard = append_lock()
        .lock()
        .map_err(|_| std::io::Error::other("Claude local OTEL store lock poisoned"))?;
    let paths = telemetry_member_paths(support_dir, stem);
    for (path, generation) in paths.iter().zip(&pair.generations) {
        if telemetry_member(path).map_err(|_| std::io::Error::other("member unreadable"))?
            != *generation
        {
            return Ok(false);
        }
    }
    for (path, generation) in paths.iter().zip(&pair.generations) {
        if generation.is_some() {
            #[cfg(test)]
            if FAIL_TELEMETRY_UNLINK.with(|n| n.replace(n.get().saturating_sub(1)) == 1) {
                return Err(std::io::Error::other("injected unlink failure"));
            }
            fs::remove_file(path)?;
        }
    }
    Ok(true)
}

/// Make a run's unlinks durable: one sync per telemetry directory.
pub(crate) fn sync_telemetry_dirs(support_dir: &Path) -> std::io::Result<()> {
    for dir in [STORE_DIR, TRACE_STORE_DIR] {
        match crate::context_composition::sync_dir(&support_dir.join(dir)) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            synced => synced?,
        }
    }
    Ok(())
}

#[cfg(test)]
thread_local! {
    static FAIL_TELEMETRY_UNLINK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Test seam: the `n`th member unlink from now on this thread fails, as a
/// crash between the two unlinks of a pair would leave it.
#[cfg(test)]
pub(crate) fn fail_telemetry_unlink_for_test(n: u32) {
    FAIL_TELEMETRY_UNLINK.with(|slot| slot.set(n));
}

pub fn claude_trace_ownership_sidecar_fingerprint(support_dir: &Path, session_id: &str) -> String {
    sidecar_fingerprint(
        trace_evidence_path(support_dir, session_id),
        "claude_trace_ownership_sidecar:v1",
    )
}

fn sidecar_fingerprint(path: PathBuf, namespace: &str) -> String {
    let Ok(metadata) = fs::metadata(path) else {
        return String::new();
    };
    if !metadata.is_file() {
        return String::new();
    }
    let modified_nanos = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_nanos())
        .unwrap_or_default();
    let token = format!("{}:{modified_nanos}", metadata.len());
    format!(
        "{:x}",
        Sha256::digest(format!("{namespace}:{token}").as_bytes())
    )
}

fn api_evidence_from_attrs(
    attrs: &BTreeMap<String, String>,
    observed_at: Option<String>,
    request_identity: ClaudeRequestIdentityEvidence,
) -> Option<ClaudeLocalOtelEvidence> {
    let session_id = first_attr(attrs, &["session.id", "session_id"])?;
    let model = first_attr(attrs, &["model", "gen_ai.request.model"])?;
    let effort = first_attr(attrs, &["effort", "effort_level"])
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| VALID_EFFORTS.contains(&value.as_str()))
        .unwrap_or_default();
    let observed_at = observed_at?;
    // Anthropic's own request id, not the client-generated one: the transcript
    // records `requestId` from the response, so only this value joins.
    let request_id = first_attr(attrs, &["request_id", "gen_ai.response.id"])
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let mut item = ClaudeLocalOtelEvidence {
        capture_revision: API_REQUEST_CAPTURE_REVISION.into(),
        fingerprint: String::new(),
        session_id: session_id.into(),
        request_id,
        client_request_id: bounded_attr(attrs, &["client_request_id"], 256),
        observed_at,
        model: model.into(),
        effort: effort.into(),
        query_source: bounded_attr(attrs, &["query_source"], 256).into(),
        speed: bounded_attr(attrs, &["speed", "service_tier"], 64).into(),
        cost_usd_micros: first_u64_option(attrs, &["cost_usd_micros", "estimated_cost_usd_micros"])
            .or_else(|| first_decimal_usd_micros(attrs, &["cost_usd", "estimated_cost_usd"])),
        event_sequence: first_u64_option(attrs, &["event.sequence", "event_sequence", "sequence"]),
        app_version: bounded_attr(
            attrs,
            &["app.version", "service.version", "claude_code.version"],
            128,
        )
        .into(),
        input_tokens: first_u64(
            attrs,
            &[
                "input_tokens",
                "input_token_count",
                "gen_ai.usage.input_tokens",
            ],
        ),
        output_tokens: first_u64(
            attrs,
            &[
                "output_tokens",
                "output_token_count",
                "gen_ai.usage.output_tokens",
            ],
        ),
        cache_read_tokens: first_u64(
            attrs,
            &[
                "cache_read_tokens",
                "cached_token_count",
                "cached_input_tokens",
                "gen_ai.usage.cache_read.input_tokens",
            ],
        ),
        cache_creation_tokens: first_u64(
            attrs,
            &["cache_creation_tokens", "claude.tokens.cache_creation"],
        ),
        cache_creation_5m_tokens: first_u64(
            attrs,
            &[
                "cache_creation_5m_tokens",
                "claude.tokens.cache_creation_5m",
            ],
        ),
        cache_creation_1h_tokens: first_u64(
            attrs,
            &[
                "cache_creation_1h_tokens",
                "claude.tokens.cache_creation_1h",
            ],
        ),
        reasoning_output_tokens: first_u64(
            attrs,
            &[
                "reasoning_output_tokens",
                "reasoning_token_count",
                "reasoning_tokens",
                "output_reasoning_tokens",
            ],
        ),
        request_count: 1,
        account_identity_checked: true,
        account_identifier_hash: request_identity.account.unambiguous_hash().map(Arc::from),
        request_identity: Some(Arc::new(request_identity)),
        fingerprint_check: FingerprintCheck::default(),
    };
    let bytes = serde_json::to_vec(&item).ok()?;
    item.fingerprint = format!("sha256:{:x}", Sha256::digest(bytes));
    Some(item)
}

// Generic usage extraction may ignore opaque values. Identity must preserve
// their presence as invalid, without storing their raw contents.
fn identity_attributes<'a>(
    items: impl Iterator<Item = (&'a str, Option<String>)>,
) -> BTreeMap<String, String> {
    items
        .filter(|(key, _)| matches!(*key, "user.account_uuid" | "organization.id"))
        .map(|(key, value)| (key.to_string(), value.unwrap_or_default()))
        .collect()
}

fn json_identity_attributes(value: Option<&Value>) -> BTreeMap<String, String> {
    identity_attributes(
        value
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| Some((item.get("key")?.as_str()?, any_value(item.get("value"))))),
    )
}

fn proto_identity_attributes(items: &[otlp_proto::KeyValue]) -> BTreeMap<String, String> {
    identity_attributes(items.iter().map(|item| {
        (
            item.key.as_str(),
            item.value.as_ref().and_then(proto_any_value),
        )
    }))
}

fn attributes_at(value: Option<&Value>) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    for item in value.and_then(Value::as_array).into_iter().flatten() {
        let Some(key) = item.get("key").and_then(Value::as_str) else {
            continue;
        };
        let Some(value) = any_value(item.get("value")) else {
            continue;
        };
        attrs.insert(key.to_string(), value);
    }
    attrs
}

fn any_value(value: Option<&Value>) -> Option<String> {
    let value = value?;
    for key in ["stringValue", "intValue", "doubleValue", "boolValue"] {
        if let Some(raw) = value.get(key) {
            return raw
                .as_str()
                .map(str::to_string)
                .or_else(|| Some(raw.to_string()));
        }
    }
    None
}

fn first_attr<'a>(attrs: &'a BTreeMap<String, String>, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| attrs.get(*key).map(String::as_str))
        .filter(|value| !value.trim().is_empty())
}

fn first_u64(attrs: &BTreeMap<String, String>, keys: &[&str]) -> u64 {
    first_u64_option(attrs, keys).unwrap_or(0)
}

fn first_u64_option(attrs: &BTreeMap<String, String>, keys: &[&str]) -> Option<u64> {
    keys.iter()
        .find_map(|key| attrs.get(*key)?.parse::<u64>().ok())
}

fn bounded_attr(attrs: &BTreeMap<String, String>, keys: &[&str], max_len: usize) -> String {
    first_attr(attrs, keys)
        .map(str::trim)
        .filter(|value| {
            value.len() <= max_len && !value.chars().any(|character| character.is_control())
        })
        .unwrap_or_default()
        .to_string()
}

fn first_decimal_usd_micros(attrs: &BTreeMap<String, String>, keys: &[&str]) -> Option<u64> {
    let raw = first_attr(attrs, keys)?.trim();
    if raw.len() > 64 || raw.starts_with('-') || raw.contains(['e', 'E']) {
        return None;
    }
    let (whole, fractional) = raw.split_once('.').unwrap_or((raw, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fractional.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let whole = whole.parse::<u64>().ok()?.checked_mul(1_000_000)?;
    let retained = &fractional[..fractional.len().min(6)];
    let mut fraction = retained.parse::<u64>().unwrap_or(0);
    for _ in retained.len()..6 {
        fraction = fraction.checked_mul(10)?;
    }
    if fractional
        .as_bytes()
        .get(6)
        .is_some_and(|digit| *digit >= b'5')
    {
        fraction = fraction.checked_add(1)?;
    }
    whole.checked_add(fraction)
}

pub(crate) fn canonical_uuid(value: &str) -> Option<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 36 {
        return None;
    }
    for (index, byte) in normalized.bytes().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if byte != b'-' {
                return None;
            }
        } else if !byte.is_ascii_hexdigit() {
            return None;
        }
    }
    Some(normalized)
}

fn timestamp_at(record: &Value) -> Option<String> {
    let nanos = |key| {
        record.get(key).and_then(|raw| {
            raw.as_str()
                .and_then(|value| value.parse::<u64>().ok())
                .or_else(|| raw.as_u64())
        })
    };
    log_timestamp(nanos("timeUnixNano"), nanos("observedTimeUnixNano"))
}

// OTLP LogRecord defines zero as unknown for both fields. The existing v2
// sidecar stores only the selected clock, so an observed fallback is not proof
// of an original provider event clock. No usable clock means no reduced row.
fn log_timestamp(event: Option<u64>, observed: Option<u64>) -> Option<String> {
    event
        .filter(|value| *value > 0)
        .or_else(|| observed.filter(|value| *value > 0))
        .and_then(|value| format_nanos(i128::from(value)))
}

fn json_nanos(value: &Value) -> Option<i128> {
    value
        .as_str()
        .and_then(|value| value.parse::<i128>().ok())
        .or_else(|| value.as_u64().map(i128::from))
}

fn format_nanos(nanos: i128) -> Option<String> {
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn proto_attributes(items: &[otlp_proto::KeyValue]) -> BTreeMap<String, String> {
    let mut attrs = BTreeMap::new();
    for item in items {
        let Some(value) = item.value.as_ref().and_then(proto_any_value) else {
            continue;
        };
        attrs.insert(item.key.clone(), value);
    }
    attrs
}

fn proto_any_value(value: &otlp_proto::AnyValue) -> Option<String> {
    use otlp_proto::any_value::Value;
    match value.value.as_ref()? {
        Value::StringValue(value) => Some(value.clone()),
        Value::BoolValue(value) => Some(value.to_string()),
        Value::IntValue(value) => Some(value.to_string()),
        Value::DoubleValue(value) => Some(value.to_string()),
        // Arrays, maps, and opaque bytes are deliberately outside the
        // privacy-safe ownership allowlist.
        Value::ArrayValue(_) | Value::KvlistValue(_) | Value::BytesValue(_) => None,
    }
}

fn append_evidence(support_dir: &Path, item: &ClaudeLocalOtelEvidence) -> Result<()> {
    let path = evidence_path(support_dir, &item.session_id);
    let dir = path.parent().expect("evidence path has parent");
    fs::create_dir_all(dir).context("create Claude effort evidence directory")?;
    #[cfg(unix)]
    fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("open Claude effort evidence append file")?;
    let mut encoded = serde_json::to_vec(item)?;
    encoded.push(b'\n');
    append_evidence_bytes(&mut file, &encoded).context("append Claude effort evidence")
}

fn append_trace_ownership_evidence(
    support_dir: &Path,
    item: &ClaudeTraceOwnershipEvidence,
) -> Result<()> {
    let path = trace_evidence_path(support_dir, &item.session_id);
    let dir = path.parent().expect("trace evidence path has parent");
    fs::create_dir_all(dir).context("create Claude trace ownership evidence directory")?;
    #[cfg(unix)]
    fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("open Claude trace ownership evidence append file")?;
    let mut encoded = serde_json::to_vec(item)?;
    encoded.push(b'\n');
    append_evidence_bytes(&mut file, &encoded).context("append Claude trace ownership evidence")
}

/// Capture succeeds only after the complete row has been written. The warning
/// threshold never rejects a row; I/O errors still propagate to the relay.
fn append_evidence_bytes(writer: &mut impl Write, encoded: &[u8]) -> Result<()> {
    writer.write_all(encoded)?;
    Ok(())
}

fn evidence_path(support_dir: &Path, session_id: &str) -> PathBuf {
    let [api, _] = telemetry_member_paths(support_dir, &telemetry_stem(session_id));
    api
}

fn trace_evidence_path(support_dir: &Path, session_id: &str) -> PathBuf {
    let [_, trace] = telemetry_member_paths(support_dir, &telemetry_stem(session_id));
    trace
}

fn append_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Minimal OTLP log/trace wire surface. Keeping these definitions local avoids
/// retaining log bodies, span events, links, status, trace ids, or any
/// non-allowlisted content after decoding.
mod otlp_proto {
    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ExportLogsServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_logs: Vec<ResourceLogs>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ResourceLogs {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_logs: Vec<ScopeLogs>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ScopeLogs {
        #[prost(message, repeated, tag = "2")]
        pub log_records: Vec<LogRecord>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct LogRecord {
        #[prost(fixed64, tag = "1")]
        pub time_unix_nano: u64,
        #[prost(message, optional, tag = "5")]
        pub body: Option<AnyValue>,
        #[prost(message, repeated, tag = "6")]
        pub attributes: Vec<KeyValue>,
        #[prost(fixed64, tag = "11")]
        pub observed_time_unix_nano: u64,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ExportTraceServiceRequest {
        #[prost(message, repeated, tag = "1")]
        pub resource_spans: Vec<ResourceSpans>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ResourceSpans {
        #[prost(message, optional, tag = "1")]
        pub resource: Option<Resource>,
        #[prost(message, repeated, tag = "2")]
        pub scope_spans: Vec<ScopeSpans>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Resource {
        #[prost(message, repeated, tag = "1")]
        pub attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ScopeSpans {
        #[prost(message, repeated, tag = "2")]
        pub spans: Vec<Span>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct Span {
        #[prost(string, tag = "5")]
        pub name: String,
        #[prost(fixed64, tag = "7")]
        pub start_time_unix_nano: u64,
        #[prost(message, repeated, tag = "9")]
        pub attributes: Vec<KeyValue>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct KeyValue {
        #[prost(string, tag = "1")]
        pub key: String,
        #[prost(message, optional, tag = "2")]
        pub value: Option<AnyValue>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct AnyValue {
        #[prost(oneof = "any_value::Value", tags = "1, 2, 3, 4, 5, 6, 7")]
        pub value: Option<any_value::Value>,
    }

    pub mod any_value {
        // Variant names mirror the canonical OTLP protobuf schema. Renaming
        // them would make this deliberately minimal wire model harder to audit
        // against opentelemetry-proto.
        #[expect(clippy::enum_variant_names, reason = "names mirror the OTLP schema")]
        #[derive(Clone, PartialEq, ::prost::Oneof)]
        pub enum Value {
            #[prost(string, tag = "1")]
            StringValue(String),
            #[prost(bool, tag = "2")]
            BoolValue(bool),
            #[prost(int64, tag = "3")]
            IntValue(i64),
            #[prost(double, tag = "4")]
            DoubleValue(f64),
            #[prost(message, tag = "5")]
            ArrayValue(super::ArrayValue),
            #[prost(message, tag = "6")]
            KvlistValue(super::KeyValueList),
            #[prost(bytes, tag = "7")]
            BytesValue(Vec<u8>),
        }
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct ArrayValue {
        #[prost(message, repeated, tag = "1")]
        pub values: Vec<AnyValue>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct KeyValueList {
        #[prost(message, repeated, tag = "1")]
        pub values: Vec<KeyValue>,
    }
}

#[cfg(test)]
mod tests {

    /// [regress] Failed writes must never be reported as captured rows.
    #[test]
    fn append_partial_and_zero_byte_write_errors_never_report_capture_success() {
        struct FailingWriter {
            bytes: Vec<u8>,
            remaining: usize,
        }
        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.remaining == 0 {
                    return Err(std::io::Error::other("synthetic disk error"));
                }
                let n = self.remaining.min(bytes.len());
                self.bytes.extend_from_slice(&bytes[..n]);
                self.remaining -= n;
                Ok(n)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let row = b"{\"synthetic\":true}\n";
        for limit in [0, 5] {
            let mut writer = FailingWriter {
                bytes: Vec::new(),
                remaining: limit,
            };
            assert!(append_evidence_bytes(&mut writer, row).is_err());
            assert_eq!(writer.bytes.len(), limit);
            assert!(append_evidence_bytes(&mut writer, row).is_err());
            assert_eq!(writer.bytes.len(), limit);
        }
        // A zero-byte I/O error cannot leave a durable loss signal in this
        // format. This test asserts refusal, not persistent completeness.
    }

    /// [regress] Capture and the shared streaming readers retain every
    /// request after a sidecar crosses its warning threshold, including retries.
    #[test]
    fn api_and_trace_past_warning_threshold_keep_every_request() {
        // Exercise the existing allowance seam cheaply, and the real 64 MiB
        // boundary with only three distinct rows and streamed whitespace.
        for quantum in [128, MAX_EVIDENCE_FILE_BYTES] {
            let scratch = crate::test_scratch::ScratchDir::new("sidecar-no-cap");
            for trace in [false, true] {
                let session = if trace {
                    "sess-traces"
                } else {
                    "identity-session"
                };
                let capture = |request| {
                    if trace {
                        capture_claude_llm_request_traces(
                            &scratch,
                            &trace_body(vec![llm_span(request, None)]),
                            "application/x-protobuf",
                        )
                    } else {
                        capture_claude_api_request_logs(
                            &scratch,
                            &identity_json(&[], &[("request_id", request)]),
                            "application/json",
                        )
                    }
                };
                assert_eq!(capture("request-1").unwrap(), 1);
                let path = if trace {
                    trace_evidence_path(&scratch, session)
                } else {
                    evidence_path(&scratch, session)
                };
                let before = fs::metadata(&path).unwrap().len();
                let mut file = OpenOptions::new().append(true).open(&path).unwrap();
                std::io::copy(
                    &mut std::io::repeat(b' ').take(quantum.saturating_sub(before)),
                    &mut file,
                )
                .unwrap();
                assert_eq!(capture("request-2").unwrap(), 1);
                assert_eq!(capture("request-3").unwrap(), 1);
                // Re-export is still deduplicated by the SAME decoder.
                assert_eq!(capture("request-2").unwrap(), 1);
                assert!(fs::metadata(&path).unwrap().len() > quantum);
                let (requests, oversized) = if trace {
                    assert!(
                        !claude_trace_ownership_sidecar_fingerprint(&scratch, session).is_empty()
                    );
                    let report = load_claude_trace_ownership_evidence(&scratch, [session.into()]);
                    assert!(report.is_complete());
                    (
                        report.evidence[session]
                            .iter()
                            .map(|row| row.request_id.clone())
                            .collect::<Vec<_>>(),
                        report.oversized_files,
                    )
                } else {
                    assert!(!claude_effort_sidecar_fingerprint(&scratch, session).is_empty());
                    let mut read = ClaudeApiEvidenceRead::load(&scratch, [session.into()]).unwrap();
                    let report = read.take_strict_report(&scratch, session);
                    assert!(report.health.is_complete());
                    (
                        report.evidence[session]
                            .iter()
                            .map(|row| row.request_id.clone())
                            .collect::<Vec<_>>(),
                        report.health.oversized_files,
                    )
                };
                assert_eq!(requests, ["request-1", "request-2", "request-3"]);
                assert_eq!(oversized, u64::from(quantum == MAX_EVIDENCE_FILE_BYTES));
            }
        }
    }

    /// [money] Under-cap streaming/reuse preserves exact tokens, reported cost
    /// and request-owned accounts, including duplicate exports.
    #[test]
    fn under_cap_tokens_cost_and_accounts_are_unchanged() {
        let scratch = crate::test_scratch::ScratchDir::new("sidecar-money");
        for (request, account, input, output, cost) in [
            ("request-A", ACCOUNT, "12", "3", "1250"),
            ("request-B", ORGANIZATION, "7", "5", "2000"),
            ("request-A", ACCOUNT, "12", "3", "1250"),
        ] {
            assert_eq!(
                capture_claude_api_request_logs(
                    &scratch,
                    &identity_json(
                        &[],
                        &[
                            ("request_id", request),
                            ("user.account_uuid", account),
                            ("organization.id", OTHER_ORGANIZATION),
                            ("input_tokens", input),
                            ("output_tokens", output),
                            ("cost_usd_micros", cost),
                        ]
                    ),
                    "application/json",
                )
                .unwrap(),
                1
            );
        }
        let mut read = ClaudeApiEvidenceRead::load(&scratch, ["identity-session".into()]).unwrap();
        let report = read.take_strict_report(&scratch, "identity-session");
        assert!(report.health.is_complete());
        assert_eq!(report.health.oversized_files, 0);
        let rows = &report.evidence["identity-session"];
        assert_eq!(rows.len(), 2);
        assert_eq!(rows.iter().map(|row| row.input_tokens).sum::<u64>(), 19);
        assert_eq!(rows.iter().map(|row| row.output_tokens).sum::<u64>(), 8);
        assert_eq!(
            rows.iter()
                .map(|row| row.cost_usd_micros.unwrap())
                .sum::<u64>(),
            3250
        );
        for (row, request, account, input, output, cost) in [
            (&rows[0], "request-A", ACCOUNT, 12, 3, 1250),
            (&rows[1], "request-B", ORGANIZATION, 7, 5, 2000),
        ] {
            assert_eq!(row.request_id, request);
            assert_eq!(
                (row.input_tokens, row.output_tokens, row.cost_usd_micros),
                (input, output, Some(cost))
            );
            let expected = ottto_core::billing_identity_hash("anthropic", "account", account);
            assert_eq!(row.account_identifier_hash.as_deref(), expected.as_deref());
            assert_eq!(
                row.request_identity
                    .as_ref()
                    .unwrap()
                    .account
                    .unambiguous_hash(),
                expected
            );
        }
    }

    use super::*;

    const ACCOUNT: &str = "123e4567-e89b-12d3-a456-426614174000";
    const ORGANIZATION: &str = "123e4567-e89b-12d3-a456-426614174001";
    const OTHER_ORGANIZATION: &str = "123e4567-e89b-12d3-a456-426614174002";

    fn identity_json(resource: &[(&str, &str)], record: &[(&str, &str)]) -> Vec<u8> {
        let attributes = |values: &[(&str, &str)]| {
            values
                .iter()
                .map(|(key, value)| serde_json::json!({"key":key,"value":{"stringValue":value}}))
                .collect::<Vec<_>>()
        };
        let mut record_values = vec![
            ("session.id", "identity-session"),
            ("request_id", "identity-request"),
            ("model", "claude-test"),
            ("input_tokens", "12"),
            ("output_tokens", "3"),
        ];
        record_values.extend_from_slice(record);
        serde_json::to_vec(&serde_json::json!({"resourceLogs":[{
            "resource":{"attributes":attributes(resource)},
            "scopeLogs":[{"logRecords":[{"timeUnixNano":"1783728000000000000",
                "body":{"stringValue":"claude_code.api_request"},
                "attributes":attributes(&record_values)}]}]}]}))
        .unwrap()
    }

    #[test]
    fn request_pair_malformed_protobuf_identity_preserves_presence_both_origins() {
        use otlp_proto::any_value::Value as ProtoValue;
        for key in ["user.account_uuid", "organization.id"] {
            for malformed in [
                Some(ProtoValue::ArrayValue(otlp_proto::ArrayValue {
                    values: vec![],
                })),
                Some(ProtoValue::KvlistValue(otlp_proto::KeyValueList {
                    values: vec![],
                })),
                Some(ProtoValue::BytesValue(vec![0])),
                None,
            ] {
                for resource_invalid in [false, true] {
                    let valid = vec![
                        proto_string("user.account_uuid", ACCOUNT),
                        proto_string("organization.id", ORGANIZATION),
                    ];
                    let mut resource = valid.clone();
                    let mut record = valid;
                    let attrs = if resource_invalid {
                        &mut resource
                    } else {
                        &mut record
                    };
                    attrs.iter_mut().find(|item| item.key == key).unwrap().value =
                        Some(otlp_proto::AnyValue {
                            value: malformed.clone(),
                        });
                    record.extend([
                        proto_string("model", "claude-test"),
                        proto_string("session.id", "identity-session"),
                        proto_string("request_id", "identity-request"),
                        proto_string("input_tokens", "12"),
                        proto_string("output_tokens", "3"),
                    ]);
                    let payload = otlp_proto::ExportLogsServiceRequest {
                        resource_logs: vec![otlp_proto::ResourceLogs {
                            resource: Some(otlp_proto::Resource {
                                attributes: resource,
                            }),
                            scope_logs: vec![otlp_proto::ScopeLogs {
                                log_records: vec![otlp_proto::LogRecord {
                                    time_unix_nano: 1783728000000000000,
                                    observed_time_unix_nano: 0,
                                    body: proto_string("body", "claude_code.api_request").value,
                                    attributes: record,
                                }],
                            }],
                        }],
                    };
                    let row = api_evidence_from_protobuf(&payload.encode_to_vec())
                        .unwrap()
                        .remove(0);
                    assert_eq!(row.input_tokens, 12);
                    assert_eq!(row.output_tokens, 3);
                    let pair = row.request_identity.as_ref().unwrap();
                    let attribute = if key == "user.account_uuid" {
                        &pair.account
                    } else {
                        &pair.organization
                    };
                    assert_eq!(
                        attribute.origin,
                        ClaudeIdentityAttributeOrigin::ResourceAndLogRecord
                    );
                    assert_eq!(attribute.disposition, ClaudeIdentityDisposition::Invalid);
                    assert_eq!(pair.disposition, ClaudeIdentityDisposition::Invalid);
                }
            }
            // Missing AnyValue also means present invalid evidence.
            let missing = otlp_proto::KeyValue {
                key: key.to_string(),
                value: None,
            };
            assert_eq!(proto_identity_attributes(&[missing])[key], "");
        }
    }

    #[test]
    fn request_pair_preserves_json_attribute_origins_and_counters() {
        for (resource, record, expected_origin) in [
            (
                vec![],
                vec![
                    ("user.account_uuid", ACCOUNT),
                    ("organization.id", ORGANIZATION),
                ],
                ClaudeIdentityAttributeOrigin::LogRecord,
            ),
            (
                vec![
                    ("user.account_uuid", ACCOUNT),
                    ("organization.id", ORGANIZATION),
                ],
                vec![],
                ClaudeIdentityAttributeOrigin::Resource,
            ),
            (
                vec![
                    ("user.account_uuid", ACCOUNT),
                    ("organization.id", ORGANIZATION),
                ],
                vec![
                    ("user.account_uuid", ACCOUNT),
                    ("organization.id", ORGANIZATION),
                ],
                ClaudeIdentityAttributeOrigin::ResourceAndLogRecord,
            ),
        ] {
            let row = api_evidence_from_json(&identity_json(&resource, &record))
                .unwrap()
                .remove(0);
            let pair = row.request_identity.as_ref().unwrap();
            assert_eq!(pair.disposition, ClaudeIdentityDisposition::Complete);
            assert_eq!(pair.account.origin, expected_origin);
            assert_eq!(pair.organization.origin, expected_origin);
            assert_eq!(pair.identity_hash_scheme, "provider-sha256:v1");
            assert_eq!(
                pair.organization.unambiguous_hash(),
                ottto_core::billing_identity_hash("anthropic", "organization", ORGANIZATION)
            );
            assert_eq!(
                row.account_identifier_hash.as_deref(),
                ottto_core::billing_identity_hash("anthropic", "account", ACCOUNT).as_deref()
            );
            assert_eq!(
                (row.input_tokens, row.output_tokens, row.request_count),
                (12, 3, 1)
            );
            assert_eq!(row.observed_at, "2026-07-11T00:00:00Z");
            let stored = serde_json::to_string(&row).unwrap();
            assert!(!stored.contains(ACCOUNT));
            assert!(!stored.contains(ORGANIZATION));
        }
    }

    #[test]
    fn request_pair_missing_and_malformed_org_do_not_change_account_evidence() {
        for organization in [
            None,
            Some(""),
            Some("short-org"),
            Some("123e4567-e89b-12d3-a456-42661417400g"),
        ] {
            let mut record = vec![("user.account_uuid", ACCOUNT)];
            if let Some(organization) = organization {
                record.push(("organization.id", organization));
            }
            let row = api_evidence_from_json(&identity_json(&[], &record))
                .unwrap()
                .remove(0);
            let pair = row.request_identity.as_ref().unwrap();
            assert_eq!(
                pair.disposition,
                if organization.is_none() {
                    ClaudeIdentityDisposition::Missing
                } else {
                    ClaudeIdentityDisposition::Invalid
                }
            );
            assert!(pair.organization.unambiguous_hash().is_none());
            assert!(pair.organization.resource_hash.is_none());
            assert!(pair.organization.log_record_hash.is_none());
            assert_eq!(
                row.account_identifier_hash.as_deref(),
                ottto_core::billing_identity_hash("anthropic", "account", ACCOUNT).as_deref()
            );
            assert_eq!((row.input_tokens, row.output_tokens), (12, 3));
        }
    }

    #[test]
    fn request_pair_resource_record_conflict_keeps_both_safe_witnesses() {
        for key in ["user.account_uuid", "organization.id"] {
            let resource = [(key, OTHER_ORGANIZATION)];
            let record = [
                ("user.account_uuid", ACCOUNT),
                ("organization.id", ORGANIZATION),
            ];
            let row = api_evidence_from_json(&identity_json(&resource, &record))
                .unwrap()
                .remove(0);
            let pair = row.request_identity.as_ref().unwrap();
            assert_eq!(pair.disposition, ClaudeIdentityDisposition::Conflict);
            let attribute = if key == "user.account_uuid" {
                &pair.account
            } else {
                &pair.organization
            };
            assert_eq!(
                attribute.origin,
                ClaudeIdentityAttributeOrigin::ResourceAndLogRecord
            );
            assert!(attribute.resource_hash.is_some() && attribute.log_record_hash.is_some());
            assert_ne!(attribute.resource_hash, attribute.log_record_hash);
            assert!(attribute.unambiguous_hash().is_none());
            assert_eq!(
                row.account_identifier_hash.is_none(),
                key == "user.account_uuid"
            );
        }
    }

    #[test]
    fn request_pair_legacy_omission_is_neutral_and_byte_preserved() {
        let row = api_evidence_from_json(&identity_json(&[], &[("user.account_uuid", ACCOUNT)]))
            .unwrap()
            .remove(0);
        let mut legacy = serde_json::to_value(&row).unwrap();
        legacy.as_object_mut().unwrap().remove("request_identity");
        legacy["capture_revision"] = serde_json::json!("claude_api_request:v2");
        let read: ClaudeLocalOtelEvidence = serde_json::from_value(legacy.clone()).unwrap();
        assert!(read.request_identity.is_none());
        assert_eq!(serde_json::to_value(&read).unwrap(), legacy);
        assert_eq!(read.account_identifier_hash, row.account_identifier_hash);
        assert_eq!(read.fingerprint, row.fingerprint);
    }

    fn with_canonical_fingerprint(mut row: ClaudeLocalOtelEvidence) -> ClaudeLocalOtelEvidence {
        row.fingerprint.clear();
        row.fingerprint = format!(
            "sha256:{:x}",
            Sha256::digest(serde_json::to_vec(&row).unwrap())
        );
        row
    }

    fn write_identity_replays(dir: &Path, rows: &[ClaudeLocalOtelEvidence]) {
        let path = evidence_path(dir, "identity-session");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }

    #[test]
    fn request_pair_v2_upgrade_replay_deduplicates_both_orders_without_usage_change() {
        let dir = std::env::temp_dir().join(format!("ottto-org-upgrade-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let richer = api_evidence_from_json(&identity_json(
            &[],
            &[
                ("user.account_uuid", ACCOUNT),
                ("organization.id", ORGANIZATION),
            ],
        ))
        .unwrap()
        .remove(0);
        let mut old = richer.clone();
        old.request_identity = None;
        let old = with_canonical_fingerprint(old);
        assert_eq!(&*old.capture_revision, "claude_api_request:v2");
        assert_ne!(old.fingerprint, richer.fingerprint);
        assert!(!serde_json::to_string(&old)
            .unwrap()
            .contains("request_identity"));
        for rows in [
            vec![old.clone(), richer.clone()],
            vec![richer.clone(), old.clone()],
        ] {
            write_identity_replays(&dir, &rows);
            let report = load_claude_api_request_evidence_report(&dir, ["identity-session".into()]);
            assert!(report.health.is_complete());
            assert_eq!(report.evidence["identity-session"], vec![richer.clone()]);
            let compatibility =
                load_claude_effort_evidence(&dir, ["identity-session".into()]).unwrap();
            assert_eq!(compatibility["identity-session"], vec![richer.clone()]);
            assert_eq!(
                compatibility["identity-session"]
                    .iter()
                    .map(|row| row.input_tokens)
                    .sum::<u64>(),
                12
            );
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn request_pair_upgrade_neutrality_never_hides_known_identity_or_usage_conflicts() {
        let dir =
            std::env::temp_dir().join(format!("ottto-org-upgrade-conflict-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let richer = api_evidence_from_json(&identity_json(
            &[],
            &[
                ("user.account_uuid", ACCOUNT),
                ("organization.id", ORGANIZATION),
            ],
        ))
        .unwrap()
        .remove(0);
        let mut old = richer.clone();
        old.request_identity = None;
        let old = with_canonical_fingerprint(old);
        let different_org = api_evidence_from_json(&identity_json(
            &[],
            &[
                ("user.account_uuid", ACCOUNT),
                ("organization.id", OTHER_ORGANIZATION),
            ],
        ))
        .unwrap()
        .remove(0);
        let different_origin = api_evidence_from_json(&identity_json(
            &[
                ("user.account_uuid", ACCOUNT),
                ("organization.id", ORGANIZATION),
            ],
            &[],
        ))
        .unwrap()
        .remove(0);
        let account_conflict = api_evidence_from_json(&identity_json(
            &[("user.account_uuid", OTHER_ORGANIZATION)],
            &[
                ("user.account_uuid", ACCOUNT),
                ("organization.id", ORGANIZATION),
            ],
        ))
        .unwrap()
        .remove(0);
        assert!(account_conflict.account_identifier_hash.is_none());
        let mut changed_counter = richer.clone();
        changed_counter.input_tokens += 1;
        let changed_counter = with_canonical_fingerprint(changed_counter);
        for rows in [
            vec![old.clone(), richer.clone(), different_org],
            vec![richer.clone(), old.clone(), different_origin],
            vec![old.clone(), changed_counter],
            vec![old, account_conflict],
        ] {
            write_identity_replays(&dir, &rows);
            let report = load_claude_api_request_evidence_report(&dir, ["identity-session".into()]);
            assert!(!report.health.is_complete());
            assert_eq!(
                report.health.conflicting_request_ids,
                BTreeSet::from(["identity-request".into()])
            );
            assert_eq!(report.evidence["identity-session"].len(), 2);
            let persisted = fs::read_to_string(evidence_path(&dir, "identity-session")).unwrap();
            for raw in [ACCOUNT, ORGANIZATION, OTHER_ORGANIZATION] {
                assert!(!persisted.contains(raw));
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// One OTLP export carrying a parent turn and a subagent turn, exactly as
    /// Claude Code emits them: same `session.id`, different `request_id`, and
    /// `query_source` the only hint that one came from a Task agent.
    fn parent_and_subagent_body() -> &'static [u8] {
        br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},"scopeLogs":[{"logRecords":[
        {"timeUnixNano":"1785708000000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-mixed"}},{"key":"model","value":{"stringValue":"claude-opus-5"}},{"key":"effort","value":{"stringValue":"xhigh"}},{"key":"request_id","value":{"stringValue":"req_PARENT"}},{"key":"query_source","value":{"stringValue":"main"}},{"key":"input_tokens","value":{"intValue":"12"}}]},
        {"timeUnixNano":"1785708001000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-mixed"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}},{"key":"effort","value":{"stringValue":"high"}},{"key":"request_id","value":{"stringValue":"req_SUB"}},{"key":"query_source","value":{"stringValue":"agent:builtin:Explore"}},{"key":"input_tokens","value":{"intValue":"9"}}]}
        ]}]}]}"#
    }

    fn proto_string(key: &str, value: &str) -> otlp_proto::KeyValue {
        otlp_proto::KeyValue {
            key: key.to_string(),
            value: Some(otlp_proto::AnyValue {
                value: Some(otlp_proto::any_value::Value::StringValue(value.to_string())),
            }),
        }
    }

    fn llm_span(request_id: &str, agent_id: Option<&str>) -> otlp_proto::Span {
        let mut attributes = vec![
            proto_string("request_id", request_id),
            proto_string("client_request_id", &format!("client-{request_id}")),
            proto_string("prompt", "must-not-persist"),
        ];
        if let Some(agent_id) = agent_id {
            attributes.push(proto_string("agent_id", agent_id));
        }
        otlp_proto::Span {
            name: "claude_code.llm_request".to_string(),
            start_time_unix_nano: 1_785_708_000_000_000_000,
            attributes,
        }
    }

    fn trace_body(spans: Vec<otlp_proto::Span>) -> Vec<u8> {
        otlp_proto::ExportTraceServiceRequest {
            resource_spans: vec![otlp_proto::ResourceSpans {
                resource: Some(otlp_proto::Resource {
                    attributes: vec![proto_string("session.id", "sess-traces")],
                }),
                scope_spans: vec![otlp_proto::ScopeSpans { spans }],
            }],
        }
        .encode_to_vec()
    }

    fn api_log_body() -> Vec<u8> {
        otlp_proto::ExportLogsServiceRequest {
            resource_logs: vec![otlp_proto::ResourceLogs {
                resource: Some(otlp_proto::Resource {
                    attributes: vec![
                        proto_string("session.id", "sess-protobuf"),
                        proto_string("service.version", "2.1.226"),
                    ],
                }),
                scope_logs: vec![otlp_proto::ScopeLogs {
                    log_records: vec![otlp_proto::LogRecord {
                        time_unix_nano: 1_785_708_000_000_000_000,
                        body: Some(otlp_proto::AnyValue {
                            value: Some(otlp_proto::any_value::Value::StringValue(
                                "claude_code.api_request".to_string(),
                            )),
                        }),
                        attributes: vec![
                            proto_string("request_id", "req-protobuf"),
                            proto_string("model", "claude-opus-5"),
                            proto_string("input_tokens", "12"),
                            proto_string("output_tokens", "3"),
                            proto_string("prompt", "must-not-persist"),
                        ],
                        observed_time_unix_nano: 0,
                    }],
                }],
            }],
        }
        .encode_to_vec()
    }

    #[test]
    fn indexes_effort_by_request_id_across_parent_and_subagent_turns() {
        let dir = std::env::temp_dir().join(format!("ottto-effort-req-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            capture_claude_api_request_logs(&dir, parent_and_subagent_body(), "application/json")
                .unwrap(),
            2
        );

        let index = load_claude_effort_by_request(&dir, ["sess-mixed".to_string()]);

        // Both turns are reachable from the ONE sidecar the parent session owns,
        // which is what lets a sidechain transcript resolve its own tier.
        assert_eq!(index.get("req_PARENT").map(String::as_str), Some("xhigh"));
        assert_eq!(index.get("req_SUB").map(String::as_str), Some("high"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn captures_only_allowlisted_api_request_fields_and_dedupes_reads() {
        let dir = std::env::temp_dir().join(format!("ottto-effort-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let body = br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}},{"key":"service.version","value":{"stringValue":"2.1.226"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"1783728000000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-1"}},{"key":"user.account_uuid","value":{"stringValue":"123E4567-E89B-12D3-A456-426614174000"}},{"key":"model","value":{"stringValue":"claude-opus-4-7"}},{"key":"effort","value":{"stringValue":"xhigh"}},{"key":"request_id","value":{"stringValue":"req-1"}},{"key":"client_request_id","value":{"stringValue":"client-1"}},{"key":"query_source","value":{"stringValue":"main"}},{"key":"speed","value":{"stringValue":"fast"}},{"key":"cost_usd","value":{"stringValue":"0.001234"}},{"key":"event.sequence","value":{"intValue":"17"}},{"key":"input_tokens","value":{"intValue":"12"}},{"key":"output_tokens","value":{"intValue":"3"}},{"key":"cache_creation_tokens","value":{"intValue":"2014"}},{"key":"prompt","value":{"stringValue":"must-not-persist"}}]}]}]}]}"#;
        assert_eq!(
            capture_claude_api_request_logs(&dir, body, "application/json").unwrap(),
            1
        );
        assert_eq!(
            capture_claude_api_request_logs(&dir, body, "application/json").unwrap(),
            1
        );
        let loaded = load_claude_effort_evidence(&dir, ["sess-1".to_string()]).unwrap();
        assert_eq!(loaded["sess-1"].len(), 1);
        let row = &loaded["sess-1"][0];
        assert_eq!(&*row.effort, "xhigh");
        assert_eq!(&*row.capture_revision, API_REQUEST_CAPTURE_REVISION);
        assert_eq!(row.client_request_id, "client-1");
        assert_eq!(&*row.query_source, "main");
        assert_eq!(&*row.speed, "fast");
        assert_eq!(row.cost_usd_micros, Some(1_234));
        assert_eq!(row.event_sequence, Some(17));
        assert_eq!(&*row.app_version, "2.1.226");
        assert_eq!(row.input_tokens, 12);
        assert_eq!(row.cache_creation_tokens, 2014);
        assert_eq!(row.cache_creation_5m_tokens, 0);
        assert_eq!(row.cache_creation_1h_tokens, 0);
        assert!(row.account_identity_checked);
        assert_eq!(
            row.account_identifier_hash.as_deref(),
            ottto_core::billing_identity_hash(
                "anthropic",
                "account",
                "123e4567-e89b-12d3-a456-426614174000"
            )
            .as_deref()
        );
        let persisted = fs::read_to_string(evidence_path(&dir, "sess-1")).unwrap();
        assert!(!persisted.contains("must-not-persist"));
        assert!(!persisted.contains("123e4567-e89b-12d3-a456-426614174000"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn captures_protobuf_api_request_for_trace_pairing() {
        let dir = std::env::temp_dir().join(format!("ottto-api-protobuf-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(
            capture_claude_api_request_logs(&dir, &api_log_body(), "application/x-protobuf")
                .unwrap(),
            1
        );

        let report = load_claude_api_request_evidence_report(&dir, ["sess-protobuf".to_string()]);
        assert!(report.health.is_complete(), "{:?}", report.health);
        let row = &report.evidence["sess-protobuf"][0];
        assert_eq!(row.request_id, "req-protobuf");
        assert_eq!(&*row.model, "claude-opus-5");
        assert_eq!((row.input_tokens, row.output_tokens), (12, 3));
        assert!(row.client_request_id.is_empty());
        assert!(row.cost_usd_micros.is_none());
        let persisted = fs::read_to_string(evidence_path(&dir, "sess-protobuf")).unwrap();
        assert!(!persisted.contains("must-not-persist"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn captures_root_agent_nested_and_workflow_trace_ownership() {
        let dir = std::env::temp_dir().join(format!("ottto-trace-owners-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let root = llm_span("req-root", None);
        let agent = llm_span("req-agent", Some("agent-a"));
        let mut nested = llm_span("req-nested", Some("agent-b"));
        nested
            .attributes
            .push(proto_string("parent_agent_id", "agent-a"));
        let mut workflow = llm_span("req-workflow", Some("agent-c"));
        workflow
            .attributes
            .push(proto_string("workflow.run_id", "workflow-7"));
        let body = trace_body(vec![root, agent, nested, workflow]);

        assert_eq!(
            capture_claude_llm_request_traces(&dir, &body, "application/x-protobuf").unwrap(),
            4
        );
        let report = load_claude_trace_ownership_evidence(&dir, ["sess-traces".to_string()]);
        assert!(report.is_complete(), "{report:?}");
        let rows = &report.evidence["sess-traces"];
        assert_eq!(rows.len(), 4);
        let by_request = rows
            .iter()
            .map(|row| (row.request_id.as_str(), row))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(by_request["req-root"].agent_id, "");
        assert_eq!(by_request["req-agent"].agent_id, "agent-a");
        assert_eq!(by_request["req-nested"].agent_id, "agent-b");
        assert_eq!(by_request["req-nested"].parent_agent_id, "agent-a");
        assert_eq!(by_request["req-workflow"].workflow_run_id, "workflow-7");
        assert_eq!(
            &*by_request["req-agent"].capture_revision,
            TRACE_OWNERSHIP_CAPTURE_REVISION
        );
        let persisted = fs::read_to_string(trace_evidence_path(&dir, "sess-traces")).unwrap();
        assert!(!persisted.contains("must-not-persist"));
        assert!(!claude_trace_ownership_sidecar_fingerprint(&dir, "sess-traces").is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn trace_loader_dedupes_reexport_and_fails_closed_on_conflicting_owner() {
        let dir = std::env::temp_dir().join(format!("ottto-trace-dedupe-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let body = trace_body(vec![llm_span("req-same", Some("agent-a"))]);
        capture_claude_llm_request_traces(&dir, &body, "application/x-protobuf").unwrap();
        capture_claude_llm_request_traces(&dir, &body, "application/x-protobuf").unwrap();
        let report = load_claude_trace_ownership_evidence(&dir, ["sess-traces".to_string()]);
        assert!(report.is_complete());
        assert_eq!(report.evidence["sess-traces"].len(), 1);

        let conflicting = trace_body(vec![llm_span("req-same", Some("agent-b"))]);
        capture_claude_llm_request_traces(&dir, &conflicting, "application/x-protobuf").unwrap();
        let report = load_claude_trace_ownership_evidence(&dir, ["sess-traces".to_string()]);
        assert!(!report.is_complete());
        assert!(report.conflicting_request_ids.contains("req-same"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_trace_payload_and_sidecars_fail_closed() {
        let dir = std::env::temp_dir().join(format!("ottto-trace-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(
            capture_claude_llm_request_traces(&dir, b"not protobuf", "application/x-protobuf")
                .is_err()
        );

        let path = trace_evidence_path(&dir, "sess-traces");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, b"not json\n").unwrap();
        let report = load_claude_trace_ownership_evidence(&dir, ["sess-traces".to_string()]);
        assert_eq!(report.malformed_lines, 1);
        assert!(!report.is_complete());
        let _ = fs::remove_dir_all(dir);
    }

    /// [behaviour] Each skipped `claude_code.llm_request` span counts its
    /// closed reason and stores no ownership row.
    #[test]
    fn skipped_llm_request_spans_count_their_reason_without_a_row() {
        use crate::local_resource_diagnostics::cache_lifecycle::observe;
        let dir = std::env::temp_dir().join(format!("ottto-trace-skip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let attr = |key: &str, value: Value| serde_json::json!({"key": key, "value": value});
        let session = attr(
            "session.id",
            serde_json::json!({"stringValue": "sess-skip"}),
        );
        let failed = attr("success", serde_json::json!({"boolValue": false}));
        let start = Some("1785708000000000000");
        let cases = [
            (vec![session.clone(), failed], start),
            (vec![], start),
            (vec![session], None),
        ];
        let (stored, counts) = observe(|| {
            cases.map(|(attributes, start)| {
                let mut span = serde_json::json!({"name": "claude_code.llm_request", "attributes": attributes});
                if let Some(start) = start {
                    span["startTimeUnixNano"] = Value::from(start);
                }
                let body = serde_json::json!({"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]});
                let body = serde_json::to_vec(&body).unwrap();
                capture_claude_llm_request_traces(&dir, &body, "application/json").unwrap()
            })
        });
        assert_eq!(stored, [0; 3]);
        assert_eq!(
            [
                counts.llm_request_span_success_false,
                counts.llm_request_span_missing_session_id,
                counts.llm_request_span_missing_start_time,
            ],
            [1; 3]
        );
        assert!(!dir.exists());
    }

    #[test]
    fn decimal_cost_is_rounded_to_integer_micros_without_float_math() {
        let attrs = BTreeMap::from([
            ("cost_usd".to_string(), "0.00123456".to_string()),
            ("small".to_string(), "0.00000049".to_string()),
            ("carry".to_string(), "1.9999999".to_string()),
        ]);
        assert_eq!(first_decimal_usd_micros(&attrs, &["cost_usd"]), Some(1_235));
        assert_eq!(first_decimal_usd_micros(&attrs, &["small"]), Some(0));
        assert_eq!(
            first_decimal_usd_micros(&attrs, &["carry"]),
            Some(2_000_000)
        );
    }

    #[test]
    fn legacy_evidence_without_aggregate_cache_field_still_loads() {
        let row: ClaudeLocalOtelEvidence = serde_json::from_str(
            r#"{"fingerprint":"legacy","session_id":"sess-1","observed_at":"2026-07-12T15:07:58Z","model":"claude-opus-4-8","effort":"low","input_tokens":2,"output_tokens":9,"cache_read_tokens":0,"cache_creation_5m_tokens":2014,"cache_creation_1h_tokens":0,"reasoning_output_tokens":0,"request_count":1}"#,
        )
        .expect("deserialize v0.1.77 evidence");

        assert_eq!(row.cache_creation_tokens, 0);
        assert_eq!(row.cache_creation_5m_tokens, 2014);
        assert!(!row.account_identity_checked);
    }
    /// One paired root (`sess-mixed`): two API rows, two trace rows and the
    /// transcript that names them, scanned into a page.
    #[cfg(unix)]
    fn mixed_scan_fixture(
        label: &str,
    ) -> (
        PathBuf,
        PathBuf,
        crate::snapshots::ScanIndex,
        crate::snapshots::SourceScanResult,
    ) {
        let dir = crate::test_scratch::private_dir(label);
        let sessions = dir.join("projects");
        fs::create_dir_all(&sessions).unwrap();
        let rows = api_evidence_from_json(parent_and_subagent_body()).unwrap();
        let mut transcript = String::new();
        for (i, row) in rows.iter().enumerate() {
            append_evidence(&dir, row).unwrap();
            append_trace_ownership_evidence(
                &dir,
                &ClaudeTraceOwnershipEvidence {
                    capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.into(),
                    fingerprint: format!("trace-{i}"),
                    session_id: row.session_id.clone(),
                    request_id: row.request_id.clone(),
                    client_request_id: String::new(),
                    agent_id: String::new(),
                    parent_agent_id: String::new(),
                    workflow_run_id: String::new(),
                    observed_at: row.observed_at.clone(),
                },
            )
            .unwrap();
            transcript.push_str(&serde_json::json!({"type":"assistant", "timestamp":row.observed_at,
                "sessionId":row.session_id, "requestId":row.request_id,
                "message":{"id":format!("msg-{i}"),"model":row.model,"usage":{"input_tokens":row.input_tokens,"output_tokens":row.output_tokens}}}).to_string());
            transcript.push('\n');
        }
        fs::write(sessions.join("sess-mixed.jsonl"), transcript).unwrap();
        let mut index = crate::snapshots::ScanIndex::default();
        let scan = crate::snapshots::scan_source_roots_with_test_limit(
            crate::snapshots::SnapshotSource::ClaudeCode,
            std::slice::from_ref(&sessions),
            &mut index,
            "2026-08-02T22:05:00Z",
            crate::snapshots::BACKFILL_WINDOW_DAYS,
            10,
        )
        .unwrap();
        assert!(!scan.snapshots.is_empty());
        (dir, sessions, index, scan)
    }

    /// [behaviour] The evidence_read record carries its memory checkpoints:
    /// the kept rows, the largest root with its actual keep bit, and the
    /// legacy owners; allocator in-use bytes only where the system reports them.
    #[cfg(unix)]
    #[test]
    fn evidence_read_reports_memory_checkpoints() {
        let (dir, _, mut index, mut scan) = mixed_scan_fixture("ottto-evidence-mem");
        // Canonical trace fingerprints, so the legacy owner graph takes both
        // requests instead of refusing the root.
        let traces = load_claude_trace_ownership_evidence(&dir, ["sess-mixed".into()])
            .evidence
            .remove("sess-mixed")
            .unwrap();
        fs::remove_file(trace_evidence_path(&dir, "sess-mixed")).unwrap();
        for mut row in traces {
            row.fingerprint.clear();
            row.fingerprint = format!(
                "sha256:{:x}",
                Sha256::digest(serde_json::to_vec(&row).unwrap())
            );
            append_trace_ownership_evidence(&dir, &row).unwrap();
        }
        let (_, records) = crate::local_resource_diagnostics::capture(|| {
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(&dir, &mut scan, &mut index)
        });
        let reads = records
            .iter()
            .filter(|record| record["stage"] == "evidence_read")
            .collect::<Vec<_>>();
        assert_eq!(reads.len(), 1);
        let mem = &reads[0]["counts"]["evidence_mem"];
        assert_eq!(mem["kept_rows"], 4);
        assert_eq!(mem["largest_root_rows"], 4);
        assert_eq!(mem["largest_root_kept"], true);
        assert_eq!(mem["legacy_owners"], 2);
        let in_use = mem["in_use_bytes"].as_array().unwrap();
        assert_eq!(in_use.len(), 3);
        assert!(in_use
            .iter()
            .all(|bytes| bytes.is_u64() == cfg!(target_os = "macos")));
        assert_eq!(mem["footprint_bytes"].as_array().unwrap().len(), 2);
        // No other record carries the object.
        assert_eq!(
            records
                .iter()
                .filter(|record| !record["counts"]["evidence_mem"].is_null())
                .count(),
            1
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_decode_reuse_unchanged_scan_reads_one_api_file() {
        let (dir, sessions, mut index, mut scan) = mixed_scan_fixture("ottto-decode-overlap");
        let mut reference_scan = scan.clone();
        let mut reference_index = index.clone();
        API_READ_RECEIPT.with(|r| r.set((0, 0, true)));
        let reference = crate::snapshot_sync::apply_claude_local_evidence_to_scan(
            &dir,
            &mut reference_scan,
            &mut reference_index,
        );
        let reference_receipt = API_READ_RECEIPT.with(|r| r.get());
        assert_eq!(reference_receipt.0, 2);
        API_READ_RECEIPT.with(|r| r.set((0, 0, false)));
        let (disposition, withheld, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(&dir, &mut scan, &mut index);
        assert_eq!(disposition, reference.0);
        assert_eq!(withheld, reference.1);
        assert_eq!(stats, reference.2);
        assert_eq!(
            serde_json::to_value(&scan.snapshots).unwrap(),
            serde_json::to_value(&reference_scan.snapshots).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&index).unwrap(),
            serde_json::to_value(&reference_index).unwrap()
        );
        assert_eq!(stats.requested_session_count, 1);
        assert_eq!(stats.candidate_root_count, 1);
        assert_eq!(stats.paired_sidecar_root_count, 1);
        assert_eq!(stats.complete_sidecar_root_count, 1);
        assert_eq!(stats.exact_request_set_root_count, 1);
        assert_eq!(stats.api_evidence_row_count, 2);
        assert_eq!(stats.trace_evidence_row_count, 2);
        let expected_bytes = fs::metadata(evidence_path(&dir, "sess-mixed"))
            .unwrap()
            .len() as usize;
        let (opens, bytes, _) = API_READ_RECEIPT.with(|r| r.get());
        println!("API read receipt: reference_opens={}, reference_bytes={}, reuse_opens={opens}, reuse_bytes={bytes}, one_file_bytes={expected_bytes}", reference_receipt.0, reference_receipt.1);
        assert_eq!(reference_receipt.1, expected_bytes * 2);
        assert_eq!(opens, 1);
        assert_eq!(bytes, expected_bytes);
        // The offline caller must keep the full public audit output and stats.
        use base64::Engine;
        fs::write(dir.join("audit.key"), [7_u8; 32]).unwrap();
        fs::write(
            dir.join("attribution.key"),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([11_u8; 32]),
        )
        .unwrap();
        let options = crate::snapshot_audit::SnapshotAuditOptions {
            source: crate::snapshots::SnapshotSource::ClaudeCode,
            roots: vec![sessions],
            audit_state_dir: dir.join("audit-reference"),
            audit_key_path: dir.join("audit.key"),
            session_attribution_hmac_key_path: dir.join("attribution.key"),
            attribution_home: Some(dir.clone()),
            claude_support_dir: Some(dir.clone()),
            machine_id: "synthetic-machine".into(),
            collected_at: "2026-08-02T22:05:00Z".into(),
            backfill_window_days: crate::snapshots::BACKFILL_WINDOW_DAYS,
            private_upload_payload_out: None,
        };
        API_READ_RECEIPT.with(|r| r.set((0, 0, true)));
        let reference_audit =
            crate::snapshot_audit::run_snapshot_audit(options.clone(), &mut Vec::new()).unwrap();
        let reference_receipt = API_READ_RECEIPT.with(|r| r.get());
        let options = crate::snapshot_audit::SnapshotAuditOptions {
            audit_state_dir: dir.join("audit-reuse"),
            ..options
        };
        API_READ_RECEIPT.with(|r| r.set((0, 0, false)));
        let reuse_audit =
            crate::snapshot_audit::run_snapshot_audit(options, &mut Vec::new()).unwrap();
        // The terminal's wall-clock time is logged, never compared.
        fn without_terminal_ms(mut value: serde_json::Value) -> serde_json::Value {
            match &mut value {
                serde_json::Value::Object(map) => {
                    map.remove("terminal_ms");
                    for child in map.values_mut() {
                        *child = without_terminal_ms(child.take());
                    }
                }
                serde_json::Value::Array(items) => {
                    for child in items {
                        *child = without_terminal_ms(child.take());
                    }
                }
                _ => {}
            }
            value
        }
        assert_eq!(
            without_terminal_ms(serde_json::to_value(reference_audit).unwrap()),
            without_terminal_ms(serde_json::to_value(reuse_audit).unwrap())
        );
        assert_eq!(reference_receipt.0, 2);
        assert_eq!(reference_receipt.1, expected_bytes * 2);
        assert_eq!(API_READ_RECEIPT.with(|r| r.get().0), 1);
        assert_eq!(API_READ_RECEIPT.with(|r| r.get().1), expected_bytes);

        // A malformed paired sibling must not poison the healthy aggregate.
        let mut bad_snapshot = scan.snapshots[0].clone();
        bad_snapshot.source_session_id = "bad-root".into();
        scan.snapshots.push(bad_snapshot);
        fs::write(evidence_path(&dir, "bad-root"), b"not json\n").unwrap();
        let mut bad_trace = load_claude_trace_ownership_evidence(&dir, ["sess-mixed".into()])
            .evidence
            .remove("sess-mixed")
            .unwrap()
            .remove(0);
        bad_trace.session_id = "bad-root".into();
        append_trace_ownership_evidence(&dir, &bad_trace).unwrap();
        let (_, _, stats) =
            crate::snapshot_sync::apply_claude_local_evidence_to_scan(&dir, &mut scan, &mut index);
        assert_eq!(stats.candidate_root_count, 2);
        assert_eq!(stats.paired_sidecar_root_count, 2);
        assert_eq!(stats.api_incomplete_root_count, 1);
        assert_eq!(stats.complete_sidecar_root_count, 1);
        assert_eq!(stats.api_evidence_row_count, 2);
        fs::remove_dir_all(dir).unwrap();
    }
    // [behaviour] Each pass counts real API/trace reads again, including bad
    // rows, while missing inputs add nothing and other sources cannot drain it.
    #[test]
    fn sidecar_reparse_counts_repeat_actual_bytes_per_claude_page() {
        use crate::local_resource_diagnostics::{capture, CollectionCounts, Probe};
        let (dir, _) = decode_reuse_fixture("reparse-counts");
        fs::create_dir_all(dir.join(TRACE_STORE_DIR)).unwrap();
        let trace_path = trace_evidence_path(&dir, "sess-mixed");
        fs::write(&trace_path, b"not json\n").unwrap();
        let expected_bytes = fs::metadata(evidence_path(&dir, "sess-mixed"))
            .unwrap()
            .len()
            + fs::metadata(&trace_path).unwrap().len();
        let page = |source| {
            Probe::start().collection(
                source,
                CollectionCounts {
                    scanned_files: 0,
                    semantic_noops: 0,
                    sampled_acquisition: None,
                    full_causes: Default::default(),
                },
            )
        };
        // Drain any earlier fixture activity on this test thread.
        capture(|| page("claude_code"));
        let (_, records) = capture(|| {
            for _ in 0..2 {
                let api =
                    ClaudeApiEvidenceRead::load(&dir, ["sess-mixed".into(), "missing".into()])
                        .unwrap();
                assert!(!api.evidence.is_empty());
                let trace = load_claude_trace_ownership_evidence(
                    &dir,
                    ["sess-mixed".into(), "missing".into()],
                );
                assert_eq!(trace.malformed_lines, 1);
                page("codex");
                page("claude_code");
            }
            page("claude_code");
        });
        for (i, record) in records.iter().enumerate() {
            let counts = &record["counts"];
            if i == 0 || i == 2 || i == 4 {
                assert!(counts.get("claude_sidecar_reparse_files").is_none());
                assert!(counts.get("claude_sidecar_reparse_bytes").is_none());
            } else {
                assert_eq!(counts["claude_sidecar_reparse_files"], 2);
                assert_eq!(counts["claude_sidecar_reparse_bytes"], expected_bytes);
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    fn decode_reuse_fixture(label: &str) -> (PathBuf, Vec<ClaudeLocalOtelEvidence>) {
        let dir = crate::test_scratch::private_dir(&format!("ottto-decode-{label}"));
        let rows = api_evidence_from_json(parent_and_subagent_body()).unwrap();
        for row in &rows {
            append_evidence(&dir, row).unwrap();
        }
        (dir, rows)
    }

    #[test]
    fn sidecar_decoder_preserves_canonical_real_derived_rows() {
        let (dir, rows) = decode_reuse_fixture("canonical");
        let (actual, witness) = decode_api_sidecar(&dir, "sess-mixed").unwrap();
        assert_eq!(actual, rows);
        assert!(witness.health.is_complete());
        for (ordinal, row) in rows.iter().enumerate() {
            append_trace_ownership_evidence(
                &dir,
                &ClaudeTraceOwnershipEvidence {
                    capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.into(),
                    fingerprint: format!("trace-{ordinal}"),
                    session_id: row.session_id.clone(),
                    request_id: row.request_id.clone(),
                    observed_at: row.observed_at.clone(),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        let trace = load_claude_trace_ownership_evidence(&dir, ["sess-mixed".to_owned()]);
        assert!(trace.is_complete());
        assert_eq!(trace.evidence["sess-mixed"].len(), rows.len());
        for (actual, expected) in trace.evidence["sess-mixed"].iter().zip(&rows) {
            assert_eq!(actual.session_id, expected.session_id);
            assert_eq!(actual.request_id, expected.request_id);
            assert_eq!(actual.observed_at, expected.observed_at);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sidecar_decoder_preserves_escaped_and_unicode_rows() {
        for (ordinal, model) in ["contains\\slash", "containsé"].into_iter().enumerate() {
            let (dir, mut rows) = decode_reuse_fixture(&format!("lexical-{ordinal}"));
            rows[0].model = model.into();
            let path = evidence_path(&dir, "sess-mixed");
            let mut encoded = Vec::new();
            for row in &rows {
                encoded.extend(serde_json::to_vec(row).unwrap());
                encoded.push(b'\n');
            }
            fs::write(&path, encoded).unwrap();
            let (ordinary, health) = decode_api_sidecar(&dir, "sess-mixed").unwrap();
            assert_eq!(ordinary, rows, "decoder preserves usage and identity");
            assert!(health.health.is_complete());
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn sidecar_decoder_identity_replay_and_conflict_keep_canonical_rows() {
        let dir = crate::test_scratch::private_dir("identity-replay");
        let richer = api_evidence_from_json(&identity_json(
            &[],
            &[
                ("user.account_uuid", ACCOUNT),
                ("organization.id", ORGANIZATION),
            ],
        ))
        .unwrap()
        .remove(0);
        let mut old = richer.clone();
        old.request_identity = None;
        let old = with_canonical_fingerprint(old);
        let mut conflict = richer.clone();
        conflict.output_tokens += 1;
        let conflict = with_canonical_fingerprint(conflict);
        for rows in [
            vec![old.clone(), richer.clone()],
            vec![richer.clone(), old],
            vec![richer.clone(), conflict],
        ] {
            write_identity_replays(&dir, &rows);
            let (ordinary, ordinary_witness) =
                decode_api_sidecar(&dir, "identity-session").unwrap();
            let strict = load_claude_api_request_evidence_report(&dir, ["identity-session".into()]);
            let permissive =
                load_claude_effort_evidence(&dir, ["identity-session".into()]).unwrap();
            assert_eq!(strict.evidence["identity-session"], ordinary);
            assert_eq!(permissive, strict.evidence);
            assert_eq!(strict.health, ordinary_witness.health);
            assert!(ordinary.iter().any(|row| row.request_identity.is_some()));
            assert_eq!(
                ordinary.len(),
                if strict.health.is_complete() { 1 } else { 2 }
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sidecar_decode_reuse_preserves_distinct_permissive_and_strict_views() {
        let (dir, rows) = decode_reuse_fixture("views");
        let path = evidence_path(&dir, "sess-mixed");
        let mut bytes = fs::read(&path).unwrap();
        let mut conflict = rows[0].clone();
        conflict.fingerprint = "conflict".into();
        conflict.output_tokens += 1;
        let mut missing = rows[1].clone();
        missing.fingerprint = "legacy".into();
        missing.request_id.clear();
        let mut foreign = rows[0].clone();
        foreign.session_id = "foreign".into();
        for row in [&rows[0], &conflict, &missing, &foreign] {
            bytes.extend(serde_json::to_vec(row).unwrap());
            bytes.push(b'\n');
        }
        bytes.extend(b"not json\n\xff\n");
        fs::write(path, bytes).unwrap();
        let permissive =
            load_claude_effort_evidence(&dir, ["sess-mixed".into(), "absent".into()]).unwrap();
        let strict = load_claude_api_request_evidence_report(&dir, ["sess-mixed".into()]);
        assert_eq!(permissive, strict.evidence);
        assert_eq!(strict.health.malformed_lines, 1);
        assert_eq!(strict.health.unreadable_lines, 1);
        assert_eq!(strict.health.invalid_session_rows, 1);
        assert_eq!(strict.health.missing_request_ids, 1);
        assert_eq!(
            strict.health.conflicting_request_ids,
            BTreeSet::from([rows[0].request_id.clone()])
        );
        let mut read =
            ClaudeApiEvidenceRead::load(&dir, ["sess-mixed".into(), "absent".into()]).unwrap();
        assert_eq!(read.evidence, permissive);
        assert_eq!(read.take_strict_report(&dir, "sess-mixed"), strict);
        assert_eq!(
            read.take_strict_report(&dir, "absent").health.missing_files,
            1
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn sidecar_decode_reuse_rereads_append_truncate_and_same_stat_replacement() {
        for change in ["append", "truncate", "replace", "rewrite"] {
            let (dir, rows) = decode_reuse_fixture(change);
            let path = evidence_path(&dir, "sess-mixed");
            let modified = fs::metadata(&path).unwrap().modified().unwrap();
            let mut read = ClaudeApiEvidenceRead::load(&dir, ["sess-mixed".into()]).unwrap();
            let mut changed = rows[0].clone();
            changed.input_tokens += 1; // same byte length
            if change == "append" {
                changed.fingerprint = "append".into();
                changed.request_id = "req-new".into();
                append_evidence(&dir, &changed).unwrap();
            } else {
                let mut bytes = serde_json::to_vec(&changed).unwrap();
                bytes.push(b'\n');
                if change != "truncate" {
                    bytes.extend(serde_json::to_vec(&rows[1]).unwrap());
                    bytes.push(b'\n');
                    assert_eq!(bytes.len() as u64, fs::metadata(&path).unwrap().len());
                }
                if change == "replace" {
                    let replacement = dir.join("replacement");
                    fs::write(&replacement, &bytes).unwrap();
                    fs::rename(replacement, &path).unwrap();
                } else {
                    fs::write(&path, &bytes).unwrap();
                }
                File::open(&path)
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_modified(modified))
                    .unwrap();
            }
            let expected = load_claude_api_request_evidence_report(&dir, ["sess-mixed".into()]);
            API_READ_RECEIPT.with(|r| r.set((0, 0, false)));
            let actual = read.take_strict_report(&dir, "sess-mixed");
            assert_eq!(actual, expected, "{change}");
            assert_eq!(
                API_READ_RECEIPT.with(|r| r.get().0),
                1,
                "{change} must reread"
            );
            assert_eq!(
                actual.evidence["sess-mixed"]
                    .iter()
                    .find(|row| row.request_id == changed.request_id)
                    .unwrap()
                    .input_tokens,
                changed.input_tokens
            );
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    fn sidecar_decode_reuse_missing_nonfile_and_malformed_never_reuse_rows() {
        for change in ["missing", "nonfile", "malformed"] {
            let (dir, _) = decode_reuse_fixture(change);
            let path = evidence_path(&dir, "sess-mixed");
            let mut read = ClaudeApiEvidenceRead::load(&dir, ["sess-mixed".into()]).unwrap();
            match change {
                "missing" => fs::remove_file(&path).unwrap(),
                "nonfile" => {
                    fs::remove_file(&path).unwrap();
                    fs::create_dir(&path).unwrap();
                }
                _ => fs::write(&path, b"malformed\n").unwrap(),
            }
            let expected = load_claude_api_request_evidence_report(&dir, ["sess-mixed".into()]);
            let actual = read.take_strict_report(&dir, "sess-mixed");
            assert_eq!(actual, expected, "{change}");
            assert!(actual.evidence.is_empty());
            assert!(!actual.health.is_complete());
            assert!(read.evidence.is_empty());
            fs::remove_dir_all(dir).unwrap();
        }
    }
}

crate::heap_layout_bound::fields!(ClaudeApiEvidenceRead; evidence, reads);
crate::heap_layout_bound::fields!(ApiReadWitness; health, generation);
crate::heap_layout_bound::fields!(ApiFileGeneration; device, inode, bytes, modified, changed);
crate::heap_layout_bound::fields!(ClaudeLocalOtelLoadHealth; missing_files, malformed_lines, unreadable_lines, oversized_files, invalid_session_rows, missing_request_ids, conflicting_request_ids);
crate::heap_layout_bound::fields!(ClaudeLocalOtelEvidence; capture_revision, fingerprint, session_id, request_id, client_request_id, observed_at, model, effort, query_source, speed, cost_usd_micros, event_sequence, app_version, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens, cache_creation_5m_tokens, cache_creation_1h_tokens, reasoning_output_tokens, request_count, account_identity_checked, account_identifier_hash, request_identity, fingerprint_check);
crate::heap_layout_bound::fields!(ClaudeRequestIdentityEvidence; identity_hash_scheme, account, organization, disposition);
crate::heap_layout_bound::fields!(ClaudeIdentityAttributeEvidence; origin, disposition, resource_hash, log_record_hash);
crate::heap_layout_bound::fields!(ClaudeTraceOwnershipEvidence; capture_revision, fingerprint, session_id, request_id, client_request_id, agent_id, parent_agent_id, workflow_run_id, observed_at);
crate::heap_layout_bound::fields!(ClaudeTraceOwnershipLoadReport; evidence, missing_files, malformed_lines, unreadable_lines, oversized_files, invalid_session_rows, missing_request_ids, conflicting_request_ids, rows_discarded);
crate::heap_layout_bound::fields!(ClaudeTraceRowsDiscarded; cap, generation, cap_rows, generation_rows);

crate::heap_layout_bound::no_heap!(true;
    ClaudeIdentityDisposition: Missing | Invalid | Conflict | Complete,
    ClaudeIdentityAttributeOrigin: Missing | Resource | LogRecord | ResourceAndLogRecord,
);
