//! Content-free local Claude Code reasoning-effort evidence.
//!
//! Claude transcripts intentionally omit the effort tier. Claude Code's official
//! `claude_code.api_request` OTLP log carries the actual applied tier and exact
//! request token counts, so the loopback relay reduces only those allowlisted
//! fields into an owner-only sidecar. Raw OTLP payloads, prompts, responses,
//! commands, paths, raw account identifiers, and email addresses are never
//! stored. A provider UUID may be reduced to the same privacy-safe billing
//! identity hash used by snapshots and then discarded.
//!
//! The sidecar also keeps the API request id, which is the join key back to the
//! turn that used the tier. It is an opaque provider-side call identifier, not
//! user content, and Claude Code already writes the same value into the user's
//! own transcripts as `requestId`. It stays local: only the resolved tier ever
//! reaches a snapshot.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const STORE_DIR: &str = "local-otel/claude-code-effort";
const MAX_EVIDENCE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const VALID_EFFORTS: &[&str] = &["low", "medium", "high", "xhigh", "max"];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeEffortEvidence {
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
    pub observed_at: String,
    pub model: String,
    pub effort: String,
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
}

pub fn capture_claude_api_request_logs(
    support_dir: &Path,
    body: &[u8],
    content_type: &str,
) -> Result<usize> {
    if !content_type.to_ascii_lowercase().contains("json") {
        return Ok(0);
    }
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
                let mut attrs = resource_attrs.clone();
                attrs.extend(attributes_at(record.get("attributes")));
                if let Some(item) = evidence_from_record(record, &attrs) {
                    evidence.push(item);
                }
            }
        }
    }
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

pub fn load_claude_effort_evidence(
    support_dir: &Path,
    session_ids: impl IntoIterator<Item = String>,
) -> Result<BTreeMap<String, Vec<ClaudeEffortEvidence>>> {
    let mut result = BTreeMap::new();
    for session_id in session_ids {
        let path = evidence_path(support_dir, &session_id);
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.len() > MAX_EVIDENCE_FILE_BYTES {
            continue;
        }
        let file = File::open(&path).context("open Claude effort evidence")?;
        let mut seen = BTreeSet::new();
        let mut rows = Vec::new();
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            let Ok(item) = serde_json::from_str::<ClaudeEffortEvidence>(&line) else {
                continue;
            };
            if item.session_id != session_id || !seen.insert(item.fingerprint.clone()) {
                continue;
            }
            rows.push(item);
        }
        if !rows.is_empty() {
            result.insert(session_id, rows);
        }
    }
    Ok(result)
}

/// Index one scan's effort evidence by Anthropic request id.
///
/// `session_ids` are the sessions whose sidecars own the evidence, which for a
/// subagent transcript is its PARENT session (Claude Code stamps the top-level
/// `session.id` on subagent OTLP records). Request ids are globally unique, so
/// one flat map serves every transcript in the scan: each request lands on
/// whichever transcript actually recorded it, parent or sidechain alike.
///
/// Rows without a request id (captured before the field existed) are skipped;
/// `apply_claude_effort_evidence` still reconciles those in aggregate.
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
        if !metadata.is_file() || metadata.len() > MAX_EVIDENCE_FILE_BYTES {
            continue;
        }
        let Ok(file) = File::open(&path) else {
            continue;
        };
        for line in BufReader::new(file).lines() {
            let Ok(line) = line else { continue };
            let Ok(item) = serde_json::from_str::<ClaudeEffortEvidence>(&line) else {
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
    if !metadata.is_file() || metadata.len() > MAX_EVIDENCE_FILE_BYTES {
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

fn evidence_from_record(
    record: &Value,
    attrs: &BTreeMap<String, String>,
) -> Option<ClaudeEffortEvidence> {
    let session_id = first_attr(attrs, &["session.id", "session_id"])?;
    let model = first_attr(attrs, &["model", "gen_ai.request.model"])?;
    let effort = first_attr(attrs, &["effort", "effort_level"])
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .filter(|value| VALID_EFFORTS.contains(&value.as_str()))
        .unwrap_or_default();
    let observed_at = timestamp_at(record)?;
    // Anthropic's own request id, not the client-generated one: the transcript
    // records `requestId` from the response, so only this value joins.
    let request_id = first_attr(attrs, &["request_id", "gen_ai.response.id"])
        .map(str::trim)
        .unwrap_or_default()
        .to_string();
    let mut item = ClaudeEffortEvidence {
        fingerprint: String::new(),
        session_id: session_id.to_string(),
        request_id,
        observed_at,
        model: model.to_string(),
        effort,
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
        account_identifier_hash: first_attr(attrs, &["user.account_uuid"])
            .and_then(canonical_uuid)
            .and_then(|uuid| {
                ottto_core::billing_identity_hash("anthropic", "account", uuid.as_str())
            }),
    };
    let bytes = serde_json::to_vec(&item).ok()?;
    item.fingerprint = format!("sha256:{:x}", Sha256::digest(bytes));
    Some(item)
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
    keys.iter()
        .find_map(|key| attrs.get(*key)?.parse::<u64>().ok())
        .unwrap_or(0)
}

fn canonical_uuid(value: &str) -> Option<String> {
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

fn append_evidence(support_dir: &Path, item: &ClaudeEffortEvidence) -> Result<()> {
    let path = evidence_path(support_dir, &item.session_id);
    let dir = path.parent().expect("evidence path has parent");
    fs::create_dir_all(dir).context("create Claude effort evidence directory")?;
    #[cfg(unix)]
    fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))?;
    if fs::metadata(&path).is_ok_and(|metadata| metadata.len() >= MAX_EVIDENCE_FILE_BYTES) {
        return Ok(());
    }
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
    file.write_all(&encoded)
        .context("append Claude effort evidence")
}

fn evidence_path(support_dir: &Path, session_id: &str) -> PathBuf {
    let digest = Sha256::digest(session_id.as_bytes());
    support_dir
        .join(STORE_DIR)
        .join(format!("{digest:x}.jsonl"))
}

fn append_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One OTLP export carrying a parent turn and a subagent turn, exactly as
    /// Claude Code emits them: same `session.id`, different `request_id`, and
    /// `query_source` the only hint that one came from a Task agent.
    fn parent_and_subagent_body() -> &'static [u8] {
        br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},"scopeLogs":[{"logRecords":[
        {"timeUnixNano":"1785708000000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-mixed"}},{"key":"model","value":{"stringValue":"claude-opus-5"}},{"key":"effort","value":{"stringValue":"xhigh"}},{"key":"request_id","value":{"stringValue":"req_PARENT"}},{"key":"query_source","value":{"stringValue":"main"}},{"key":"input_tokens","value":{"intValue":"12"}}]},
        {"timeUnixNano":"1785708001000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-mixed"}},{"key":"model","value":{"stringValue":"claude-sonnet-5"}},{"key":"effort","value":{"stringValue":"high"}},{"key":"request_id","value":{"stringValue":"req_SUB"}},{"key":"query_source","value":{"stringValue":"agent:builtin:Explore"}},{"key":"input_tokens","value":{"intValue":"9"}}]}
        ]}]}]}"#
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
            &ClaudeEffortEvidence {
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
        let body = br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"1783728000000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-1"}},{"key":"user.account_uuid","value":{"stringValue":"123E4567-E89B-12D3-A456-426614174000"}},{"key":"model","value":{"stringValue":"claude-opus-4-7"}},{"key":"effort","value":{"stringValue":"xhigh"}},{"key":"input_tokens","value":{"intValue":"12"}},{"key":"output_tokens","value":{"intValue":"3"}},{"key":"cache_creation_tokens","value":{"intValue":"2014"}},{"key":"prompt","value":{"stringValue":"must-not-persist"}}]}]}]}]}"#;
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
    fn legacy_evidence_without_aggregate_cache_field_still_loads() {
        let row: ClaudeEffortEvidence = serde_json::from_str(
            r#"{"fingerprint":"legacy","session_id":"sess-1","observed_at":"2026-07-12T15:07:58Z","model":"claude-opus-4-8","effort":"low","input_tokens":2,"output_tokens":9,"cache_read_tokens":0,"cache_creation_5m_tokens":2014,"cache_creation_1h_tokens":0,"reasoning_output_tokens":0,"request_count":1}"#,
        )
        .expect("deserialize v0.1.77 evidence");

        assert_eq!(row.cache_creation_tokens, 0);
        assert_eq!(row.cache_creation_5m_tokens, 2014);
        assert!(!row.account_identity_checked);
    }
}
