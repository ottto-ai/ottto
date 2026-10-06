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
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

#[cfg(unix)]
pub(crate) mod support_health;

const STORE_DIR: &str = "local-otel/claude-code-effort";
const TRACE_STORE_DIR: &str = "local-otel/claude-code-trace-ownership";
const MAX_EVIDENCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const VALID_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max"];
// Keep the usage-ledger revision: request_identity is additive local evidence,
// and does not change the existing request ownership/counter contract.
const API_REQUEST_CAPTURE_REVISION: &str = "claude_api_request:v2";
const TRACE_OWNERSHIP_CAPTURE_REVISION: &str = "claude_llm_request_ownership:v1";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeLocalOtelEvidence {
    #[serde(default)]
    pub capture_revision: String,
    pub fingerprint: String,
    pub session_id: String,
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
    pub model: String,
    pub effort: String,
    #[serde(default)]
    pub query_source: String,
    #[serde(default)]
    pub speed: String,
    #[serde(default)]
    pub cost_usd_micros: Option<u64>,
    #[serde(default)]
    pub event_sequence: Option<u64>,
    #[serde(default)]
    pub app_version: String,
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
    pub account_identifier_hash: Option<String>,
    /// Identity observed on this request, not a session creator or entitlement.
    /// Legacy rows have no evaluation; absence never fills an organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_identity: Option<ClaudeRequestIdentityEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeRequestIdentityEvidence {
    pub identity_hash_scheme: String,
    pub account: ClaudeIdentityAttributeEvidence,
    pub organization: ClaudeIdentityAttributeEvidence,
    /// Complete means full, consistent UUID observations, not provider authority.
    pub disposition: ClaudeIdentityDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeIdentityAttributeEvidence {
    pub origin: ClaudeIdentityAttributeOrigin,
    pub disposition: ClaudeIdentityDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_record_hash: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeIdentityAttributeOrigin {
    Missing,
    Resource,
    LogRecord,
    ResourceAndLogRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            && self.oversized_files == 0
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
    pub capture_revision: String,
    pub fingerprint: String,
    pub session_id: String,
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
}

impl ClaudeTraceOwnershipLoadReport {
    pub fn is_complete(&self) -> bool {
        self.missing_files == 0
            && self.malformed_lines == 0
            && self.unreadable_lines == 0
            && self.oversized_files == 0
            && self.invalid_session_rows == 0
            && self.missing_request_ids == 0
            && self.conflicting_request_ids.is_empty()
    }
}

pub fn capture_claude_api_request_logs(
    support_dir: &Path,
    body: &[u8],
    content_type: &str,
) -> Result<usize> {
    let content_type = content_type.to_ascii_lowercase();
    let evidence = if content_type.contains("json") {
        api_evidence_from_json(body)?
    } else if content_type.contains("protobuf") || content_type.contains("octet-stream") {
        api_evidence_from_protobuf(body)?
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
                let observed_at = format_nanos(i128::from(if record.time_unix_nano > 0 {
                    record.time_unix_nano
                } else {
                    record.observed_time_unix_nano
                }));
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
/// content-free request owner record. The caller continues forwarding `body`
/// unchanged; this function only decodes a borrowed byte slice.
pub fn capture_claude_llm_request_traces(
    support_dir: &Path,
    body: &[u8],
    content_type: &str,
) -> Result<usize> {
    let content_type = content_type.to_ascii_lowercase();
    let evidence = if content_type.contains("json") {
        trace_evidence_from_json(body)?
    } else if content_type.contains("protobuf") || content_type.contains("octet-stream") {
        trace_evidence_from_protobuf(body)?
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
    if first_attr(attrs, &["success"]).is_some_and(|value| value == "false") {
        return None;
    }
    let session_id = bounded_attr(attrs, &["session.id", "session_id"], 256);
    if session_id.is_empty() {
        return None;
    }
    let mut item = ClaudeTraceOwnershipEvidence {
        capture_revision: TRACE_OWNERSHIP_CAPTURE_REVISION.to_string(),
        fingerprint: String::new(),
        session_id,
        request_id: bounded_attr(attrs, &["request_id", "gen_ai.response.id"], 256),
        client_request_id: bounded_attr(attrs, &["client_request_id"], 256),
        agent_id: bounded_attr(attrs, &["agent.id", "agent_id"], 256),
        parent_agent_id: bounded_attr(attrs, &["parent_agent_id", "parent.agent.id"], 256),
        workflow_run_id: bounded_attr(attrs, &["workflow.run_id", "workflow_run_id"], 256),
        observed_at: observed_at?,
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
    if previous.capture_revision != API_REQUEST_CAPTURE_REVISION
        || incoming.capture_revision != API_REQUEST_CAPTURE_REVISION
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

pub fn load_claude_effort_evidence(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, Vec<ClaudeLocalOtelEvidence>>> {
    let mut result = BTreeMap::new();
    for session_id in session_ids {
        let path = evidence_path(support_dir, &session_id);
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
            continue;
        }
        let file = File::open(&path).context("open Claude effort evidence")?;
        let mut seen = BTreeSet::new();
        let mut request_rows = BTreeMap::new();
        let mut rows = Vec::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            let Ok(item) = serde_json::from_str::<ClaudeLocalOtelEvidence>(&line) else {
                continue;
            };
            if item.session_id != session_id {
                continue;
            }
            append_request_evidence(&mut rows, &mut seen, &mut request_rows, item);
        }
        if !rows.is_empty() {
            result.insert(session_id, rows);
        }
    }
    Ok(result)
}

/// Strict API-request evidence loader for completeness-sensitive accounting.
///
/// Unlike the compatibility loader above, this reports every condition that
/// could hide or ambiguously duplicate one billed request. Callers must require
/// `report.health.is_complete()` before asserting full request coverage.
pub fn load_claude_api_request_evidence_report(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> ClaudeLocalOtelLoadReport {
    let mut report = ClaudeLocalOtelLoadReport::default();
    for session_id in BTreeSet::from_iter(session_ids) {
        let path = evidence_path(support_dir, &session_id);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                report.health.missing_files += 1;
                continue;
            }
            Err(_) => {
                report.health.unreadable_lines += 1;
                continue;
            }
        };
        if !metadata.is_file() {
            report.health.unreadable_lines += 1;
            continue;
        }
        if metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
            report.health.oversized_files += 1;
            continue;
        }
        let Ok(file) = File::open(&path) else {
            report.health.unreadable_lines += 1;
            continue;
        };
        let mut seen_fingerprints = BTreeSet::new();
        let mut request_rows = BTreeMap::new();
        let mut rows = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => {
                    report.health.unreadable_lines += 1;
                    continue;
                }
            };
            let item = match serde_json::from_str::<ClaudeLocalOtelEvidence>(&line) {
                Ok(item) => item,
                Err(_) => {
                    report.health.malformed_lines += 1;
                    continue;
                }
            };
            if item.session_id != session_id {
                report.health.invalid_session_rows += 1;
                continue;
            }
            if item.request_id.is_empty() {
                report.health.missing_request_ids += 1;
            }
            let request_id = item.request_id.clone();
            if append_request_evidence(&mut rows, &mut seen_fingerprints, &mut request_rows, item) {
                report.health.conflicting_request_ids.insert(request_id);
            }
        }
        if !rows.is_empty() {
            report.evidence.insert(session_id, rows);
        }
    }
    report
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
        if metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
            report.oversized_files += 1;
            continue;
        }
        let Ok(file) = File::open(&path) else {
            report.unreadable_lines += 1;
            continue;
        };
        let mut seen_fingerprints = BTreeSet::new();
        let mut request_fingerprints = BTreeMap::<String, String>::new();
        let mut rows = Vec::new();
        for line in BufReader::new(file).lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => {
                    report.unreadable_lines += 1;
                    continue;
                }
            };
            let item = match serde_json::from_str::<ClaudeTraceOwnershipEvidence>(&line) {
                Ok(item) => item,
                Err(_) => {
                    report.malformed_lines += 1;
                    continue;
                }
            };
            if item.session_id != session_id {
                report.invalid_session_rows += 1;
                continue;
            }
            if item.request_id.is_empty() {
                report.missing_request_ids += 1;
            } else if let Some(previous) =
                request_fingerprints.insert(item.request_id.clone(), item.fingerprint.clone())
            {
                if previous != item.fingerprint {
                    report
                        .conflicting_request_ids
                        .insert(item.request_id.clone());
                }
            }
            if seen_fingerprints.insert(item.fingerprint.clone()) {
                rows.push(item);
            }
        }
        if !rows.is_empty() {
            report.evidence.insert(session_id, rows);
        }
    }
    report
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
        if !metadata.is_file() || metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
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
            if item.session_id != session_id
                || item.request_id.is_empty()
                || !VALID_EFFORTS.contains(&item.effort.as_str())
            {
                continue;
            }
            // One request has exactly one applied tier; a repeated id is the
            // same observation re-exported, so first write wins.
            index.entry(item.request_id).or_insert(item.effort);
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
    let path = evidence_path(support_dir, session_id);
    let Ok(metadata) = fs::metadata(path) else {
        return String::new();
    };
    if !metadata.is_file() || metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
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
        Sha256::digest(format!("claude_effort_sidecar:v1:{token}").as_bytes())
    )
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
    if !metadata.is_file() || metadata.len() >= MAX_EVIDENCE_FILE_BYTES {
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
        capture_revision: API_REQUEST_CAPTURE_REVISION.to_string(),
        fingerprint: String::new(),
        session_id: session_id.to_string(),
        request_id,
        client_request_id: bounded_attr(attrs, &["client_request_id"], 256),
        observed_at,
        model: model.to_string(),
        effort,
        query_source: bounded_attr(attrs, &["query_source"], 256),
        speed: bounded_attr(attrs, &["speed", "service_tier"], 64),
        cost_usd_micros: first_u64_option(attrs, &["cost_usd_micros", "estimated_cost_usd_micros"])
            .or_else(|| first_decimal_usd_micros(attrs, &["cost_usd", "estimated_cost_usd"])),
        event_sequence: first_u64_option(attrs, &["event.sequence", "event_sequence", "sequence"]),
        app_version: bounded_attr(
            attrs,
            &["app.version", "service.version", "claude_code.version"],
            128,
        ),
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
        account_identifier_hash: request_identity.account.unambiguous_hash(),
        request_identity: Some(request_identity),
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
    let raw = record
        .get("timeUnixNano")
        .or_else(|| record.get("observedTimeUnixNano"))?;
    let nanos = raw
        .as_str()
        .and_then(|value| value.parse::<i128>().ok())
        .or_else(|| raw.as_u64().map(i128::from))?;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()?
        .format(&Rfc3339)
        .ok()
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
    let current_bytes = file
        .metadata()
        .context("stat Claude effort evidence")?
        .len();
    append_evidence_bytes(&mut file, current_bytes, &encoded)
        .context("append Claude effort evidence")
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
    let current_bytes = file
        .metadata()
        .context("stat Claude trace ownership evidence")?
        .len();
    append_evidence_bytes(&mut file, current_bytes, &encoded)
        .context("append Claude trace ownership evidence")
}

/// Local capture success means the whole row was appended below the strict
/// reader's usable boundary. It is independent of raw OTLP forwarding success.
///
/// Preserve the existing final-row append when it reaches/crosses the boundary:
/// the resulting file size is the existing durable incomplete-evidence signal.
/// Refusing that row *before* writing would leave a readable prefix falsely
/// eligible for complete accounting after an auxiliary request was dropped.
/// This does not provide growth/recovery or crash-durable capture (no fsync).
fn append_evidence_bytes(
    writer: &mut impl Write,
    current_bytes: u64,
    encoded: &[u8],
) -> Result<()> {
    anyhow::ensure!(
        current_bytes < MAX_EVIDENCE_FILE_BYTES,
        "Claude local evidence file is at its byte limit"
    );
    let resulting_bytes = current_bytes
        .checked_add(u64::try_from(encoded.len())?)
        .context("Claude local evidence length overflow")?;
    writer.write_all(encoded)?;
    anyhow::ensure!(
        resulting_bytes < MAX_EVIDENCE_FILE_BYTES,
        "Claude local evidence reached its byte limit; strict proof unavailable"
    );
    Ok(())
}

fn evidence_path(support_dir: &Path, session_id: &str) -> PathBuf {
    let digest = Sha256::digest(session_id.as_bytes());
    support_dir
        .join(STORE_DIR)
        .join(format!("{digest:x}.jsonl"))
}

fn trace_evidence_path(support_dir: &Path, session_id: &str) -> PathBuf {
    let digest = Sha256::digest(session_id.as_bytes());
    support_dir
        .join(TRACE_STORE_DIR)
        .join(format!("{digest:x}.jsonl"))
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
        #[allow(clippy::enum_variant_names)]
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
    #[test]
    fn append_capture_success_requires_complete_write_below_strict_cap() {
        let row = b"{\"synthetic\":true}\n";
        for (before, writes, succeeds) in [
            (MAX_EVIDENCE_FILE_BYTES - row.len() as u64 - 1, true, true),
            (MAX_EVIDENCE_FILE_BYTES - row.len() as u64, true, false),
            (MAX_EVIDENCE_FILE_BYTES - 1, true, false),
            (MAX_EVIDENCE_FILE_BYTES, false, false),
            (MAX_EVIDENCE_FILE_BYTES + 1, false, false),
        ] {
            let mut output = Vec::new();
            let result = append_evidence_bytes(&mut output, before, row);
            assert_eq!(result.is_ok(), succeeds, "before={before}");
            assert_eq!(output.as_slice(), if writes { row.as_slice() } else { &[] });
            if writes && !succeeds {
                // Retry at the persisted boundary must refuse without another
                // duplicate append; the receiver still forwards independently.
                let size = output.len();
                assert!(
                    append_evidence_bytes(&mut output, before + row.len() as u64, row).is_err()
                );
                assert_eq!(output.len(), size);
            }
        }
    }

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
            assert!(append_evidence_bytes(&mut writer, 0, row).is_err());
            assert_eq!(writer.bytes.len(), limit);
            assert!(append_evidence_bytes(&mut writer, limit as u64, row).is_err());
            assert_eq!(writer.bytes.len(), limit);
        }
        // A zero-byte I/O error cannot leave a durable loss signal in this
        // format. This test asserts refusal, not persistent completeness.
    }

    #[test]
    fn api_and_trace_crossing_rows_are_preserved_but_capture_refuses() {
        use std::io::{Read, Seek, SeekFrom};
        let dir = std::env::temp_dir().join(format!("ottto-cap-crossing-{}", std::process::id()));
        let api_body = identity_json(&[], &[]);
        let trace_body = trace_body(vec![llm_span("req-cap", None)]);
        let mut api_row =
            serde_json::to_vec(&api_evidence_from_json(&api_body).unwrap()[0]).unwrap();
        api_row.push(b'\n');
        let mut trace_row =
            serde_json::to_vec(&trace_evidence_from_protobuf(&trace_body).unwrap()[0]).unwrap();
        trace_row.push(b'\n');
        let capture = |trace| {
            if trace {
                capture_claude_llm_request_traces(&dir, &trace_body, "application/x-protobuf")
            } else {
                capture_claude_api_request_logs(&dir, &api_body, "application/json")
            }
        };
        for (trace, row, path) in [
            (false, api_row, evidence_path(&dir, "identity-session")),
            (true, trace_row, trace_evidence_path(&dir, "sess-traces")),
        ] {
            assert_eq!(capture(trace).unwrap(), 1);
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            for before in [
                MAX_EVIDENCE_FILE_BYTES - row.len() as u64,
                MAX_EVIDENCE_FILE_BYTES - 1,
            ] {
                // Sparse synthetic padding tests actual appender/capture I/O;
                // it is not used as a healthy below-cap reader fixture.
                file.set_len(before).unwrap();
                assert!(capture(trace).is_err());
                let after = before + row.len() as u64;
                assert_eq!(file.metadata().unwrap().len(), after);
                let mut found = vec![0; row.len()];
                file.seek(SeekFrom::Start(0)).unwrap();
                file.read_exact(&mut found).unwrap();
                assert_eq!(found, row, "existing bytes preserved");
                file.seek(SeekFrom::End(-(row.len() as i64))).unwrap();
                file.read_exact(&mut found).unwrap();
                assert_eq!(found, row, "final boundary row preserved");
                assert!(capture(trace).is_err());
                assert_eq!(
                    file.metadata().unwrap().len(),
                    after,
                    "retry appends nothing"
                );
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn api_and_trace_capture_refuse_capped_files_with_consistent_reader_health() {
        let dir = std::env::temp_dir().join(format!("ottto-cap-refusal-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let api_body = parent_and_subagent_body();
        let trace_body = trace_body(vec![llm_span("req-cap", None)]);
        // Capture once through both public APIs, then exercise the actual file
        // path at exactly and over the boundary without allocating a giant row.
        assert!(capture_claude_api_request_logs(&dir, api_body, "application/json").unwrap() > 0);
        assert_eq!(
            capture_claude_llm_request_traces(&dir, &trace_body, "application/x-protobuf").unwrap(),
            1
        );
        for bytes in [MAX_EVIDENCE_FILE_BYTES, MAX_EVIDENCE_FILE_BYTES + 1] {
            for entry in fs::read_dir(dir.join(STORE_DIR)).unwrap() {
                let path = entry.unwrap().path();
                OpenOptions::new()
                    .write(true)
                    .open(path)
                    .unwrap()
                    .set_len(bytes)
                    .unwrap();
            }
            let trace_path = trace_evidence_path(&dir, "sess-traces");
            OpenOptions::new()
                .write(true)
                .open(&trace_path)
                .unwrap()
                .set_len(bytes)
                .unwrap();
            assert!(capture_claude_api_request_logs(&dir, api_body, "application/json").is_err());
            assert!(
                capture_claude_llm_request_traces(&dir, &trace_body, "application/x-protobuf")
                    .is_err()
            );
            for entry in fs::read_dir(dir.join(STORE_DIR)).unwrap() {
                assert_eq!(entry.unwrap().metadata().unwrap().len(), bytes);
            }
            assert_eq!(fs::metadata(&trace_path).unwrap().len(), bytes);
            assert!(claude_effort_sidecar_fingerprint(&dir, "sess-mixed").is_empty());
            assert!(claude_trace_ownership_sidecar_fingerprint(&dir, "sess-traces").is_empty());
            let api = load_claude_api_request_evidence_report(&dir, ["sess-mixed".into()]);
            assert_eq!(api.health.oversized_files, 1);
            assert!(!api.health.is_complete());
            assert!(api.evidence.is_empty());
            assert!(load_claude_effort_evidence(&dir, ["sess-mixed".into()])
                .unwrap()
                .is_empty());
            assert!(load_claude_effort_by_request(&dir, ["sess-mixed".into()]).is_empty());
            let trace = load_claude_trace_ownership_evidence(&dir, ["sess-traces".into()]);
            assert_eq!(trace.oversized_files, 1);
            assert!(!trace.is_complete());
            assert!(trace.evidence.is_empty());
        }
        fs::remove_dir_all(dir).unwrap();
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
    fn request_pair_malformed_json_identity_preserves_presence_both_origins() {
        for key in ["user.account_uuid", "organization.id"] {
            for malformed in [
                serde_json::json!({"arrayValue":{"values":[]}}),
                serde_json::json!({"kvlistValue":{"values":[]}}),
                serde_json::json!({"bytesValue":"AA=="}),
                serde_json::json!({}),
                serde_json::Value::Null,
            ] {
                for resource_invalid in [false, true] {
                    let mut payload: Value = serde_json::from_slice(&identity_json(
                        &[
                            ("user.account_uuid", ACCOUNT),
                            ("organization.id", ORGANIZATION),
                        ],
                        &[
                            ("user.account_uuid", ACCOUNT),
                            ("organization.id", ORGANIZATION),
                        ],
                    ))
                    .unwrap();
                    let pointer = if resource_invalid {
                        "/resourceLogs/0/resource/attributes"
                    } else {
                        "/resourceLogs/0/scopeLogs/0/logRecords/0/attributes"
                    };
                    let items = payload
                        .pointer_mut(pointer)
                        .unwrap()
                        .as_array_mut()
                        .unwrap();
                    let item = items.iter_mut().find(|item| item["key"] == key).unwrap();
                    item["value"] = malformed.clone();
                    let row = api_evidence_from_json(&serde_json::to_vec(&payload).unwrap())
                        .unwrap()
                        .remove(0);
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
                    assert_eq!(row.input_tokens, 12);
                    assert_eq!(row.output_tokens, 3);
                }
            }
        }
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
                row.account_identifier_hash,
                ottto_core::billing_identity_hash("anthropic", "account", ACCOUNT)
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
                row.account_identifier_hash,
                ottto_core::billing_identity_hash("anthropic", "account", ACCOUNT)
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
    fn request_pair_protobuf_retains_resource_and_record_origins_and_conflict() {
        for resource_org in [ORGANIZATION, OTHER_ORGANIZATION] {
            let body = otlp_proto::ExportLogsServiceRequest {
                resource_logs: vec![otlp_proto::ResourceLogs {
                    resource: Some(otlp_proto::Resource {
                        attributes: vec![
                            proto_string("user.account_uuid", ACCOUNT),
                            proto_string("organization.id", resource_org),
                        ],
                    }),
                    scope_logs: vec![otlp_proto::ScopeLogs {
                        log_records: vec![otlp_proto::LogRecord {
                            time_unix_nano: 1_783_728_000_000_000_000,
                            observed_time_unix_nano: 0,
                            body: Some(otlp_proto::AnyValue {
                                value: Some(otlp_proto::any_value::Value::StringValue(
                                    "claude_code.api_request".into(),
                                )),
                            }),
                            attributes: vec![
                                proto_string("session.id", "identity-session"),
                                proto_string("request_id", "identity-request"),
                                proto_string("model", "claude-test"),
                                proto_string("organization.id", ORGANIZATION),
                                proto_string("input_tokens", "12"),
                            ],
                        }],
                    }],
                }],
            }
            .encode_to_vec();
            let row = api_evidence_from_protobuf(&body).unwrap().remove(0);
            let pair = row.request_identity.unwrap();
            assert_eq!(pair.account.origin, ClaudeIdentityAttributeOrigin::Resource);
            assert_eq!(
                pair.organization.origin,
                ClaudeIdentityAttributeOrigin::ResourceAndLogRecord
            );
            assert_eq!(
                pair.disposition,
                if resource_org == ORGANIZATION {
                    ClaudeIdentityDisposition::Complete
                } else {
                    ClaudeIdentityDisposition::Conflict
                }
            );
            assert_eq!(row.input_tokens, 12);
        }
    }

    #[test]
    fn request_pair_changes_sidecar_fingerprint_and_strict_request_conflict() {
        let dir = std::env::temp_dir().join(format!("ottto-org-conflict-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for organization in [ORGANIZATION, ORGANIZATION, OTHER_ORGANIZATION] {
            capture_claude_api_request_logs(
                &dir,
                &identity_json(
                    &[],
                    &[
                        ("user.account_uuid", ACCOUNT),
                        ("organization.id", organization),
                    ],
                ),
                "application/json",
            )
            .unwrap();
        }
        let report =
            load_claude_api_request_evidence_report(&dir, ["identity-session".to_string()]);
        let rows = &report.evidence["identity-session"];
        assert_eq!(rows.len(), 2);
        assert_ne!(rows[0].fingerprint, rows[1].fingerprint);
        assert_ne!(
            serde_json::to_vec(&rows[0]).unwrap(),
            serde_json::to_vec(&rows[1]).unwrap()
        );
        assert_eq!(
            report.health.conflicting_request_ids,
            BTreeSet::from(["identity-request".to_string()])
        );
        assert!(!report.health.is_complete());
        let bytes = fs::read_to_string(evidence_path(&dir, "identity-session")).unwrap();
        for raw in [ACCOUNT, ORGANIZATION, OTHER_ORGANIZATION] {
            assert!(!bytes.contains(raw));
        }
        let _ = fs::remove_dir_all(dir);
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
        assert_eq!(old.capture_revision, "claude_api_request:v2");
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
    fn effort_index_skips_rows_without_a_request_id() {
        let dir = std::env::temp_dir().join(format!("ottto-effort-legacy-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // A pre-request-id row: still valid evidence, but only the aggregate
        // path can place it, so it must not enter the per-request index.
        append_evidence(
            &dir,
            &ClaudeLocalOtelEvidence {
                fingerprint: "legacy".to_string(),
                session_id: "sess-legacy".to_string(),
                observed_at: "2026-07-12T15:07:58Z".to_string(),
                model: "claude-opus-4-8".to_string(),
                effort: "low".to_string(),
                ..Default::default()
            },
        )
        .expect("append legacy evidence");

        assert!(load_claude_effort_by_request(&dir, ["sess-legacy".to_string()]).is_empty());
        // The aggregate loader still sees it.
        assert_eq!(
            load_claude_effort_evidence(&dir, ["sess-legacy".to_string()]).unwrap()["sess-legacy"]
                .len(),
            1
        );
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
        assert_eq!(row.effort, "xhigh");
        assert_eq!(row.capture_revision, API_REQUEST_CAPTURE_REVISION);
        assert_eq!(row.client_request_id, "client-1");
        assert_eq!(row.query_source, "main");
        assert_eq!(row.speed, "fast");
        assert_eq!(row.cost_usd_micros, Some(1_234));
        assert_eq!(row.event_sequence, Some(17));
        assert_eq!(row.app_version, "2.1.226");
        assert_eq!(row.input_tokens, 12);
        assert_eq!(row.cache_creation_tokens, 2014);
        assert_eq!(row.cache_creation_5m_tokens, 0);
        assert_eq!(row.cache_creation_1h_tokens, 0);
        assert!(row.account_identity_checked);
        assert_eq!(
            row.account_identifier_hash,
            ottto_core::billing_identity_hash(
                "anthropic",
                "account",
                "123e4567-e89b-12d3-a456-426614174000"
            )
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
        assert_eq!(row.model, "claude-opus-5");
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
            by_request["req-agent"].capture_revision,
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
    fn strict_api_request_loader_reports_malformed_oversized_and_conflicting_rows() {
        let dir = std::env::temp_dir().join(format!("ottto-log-health-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        capture_claude_api_request_logs(&dir, parent_and_subagent_body(), "application/json")
            .unwrap();
        let mut conflicting: ClaudeLocalOtelEvidence =
            load_claude_effort_evidence(&dir, ["sess-mixed".to_string()]).unwrap()["sess-mixed"][0]
                .clone();
        conflicting.model = "different-model".to_string();
        conflicting.fingerprint = "different".to_string();
        append_evidence(&dir, &conflicting).unwrap();
        let path = evidence_path(&dir, "sess-mixed");
        let mut options = OpenOptions::new();
        options.append(true);
        options
            .open(&path)
            .unwrap()
            .write_all(b"not json\n")
            .unwrap();
        let report = load_claude_api_request_evidence_report(&dir, ["sess-mixed".to_string()]);
        assert_eq!(report.health.malformed_lines, 1);
        assert!(report.health.conflicting_request_ids.contains("req_PARENT"));
        assert!(!report.health.is_complete());

        let oversized = evidence_path(&dir, "sess-oversized");
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&oversized)
            .unwrap();
        file.set_len(MAX_EVIDENCE_FILE_BYTES).unwrap();
        let report = load_claude_api_request_evidence_report(&dir, ["sess-oversized".to_string()]);
        assert_eq!(report.health.oversized_files, 1);
        assert!(!report.health.is_complete());
        let _ = fs::remove_dir_all(dir);
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
}
