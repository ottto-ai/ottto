//! Content-free local Claude Code reasoning-effort evidence.
//!
//! Claude transcripts intentionally omit the effort tier. Claude Code's official
//! `claude_code.api_request` OTLP log carries the actual applied tier and exact
//! request token counts, so the loopback relay reduces only those allowlisted
//! fields into an owner-only sidecar. Raw OTLP payloads, prompts, responses,
//! commands, paths, account identifiers, and email addresses are never stored.

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
    pub observed_at: String,
    pub model: String,
    pub effort: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub request_count: u64,
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

fn evidence_from_record(
    record: &Value,
    attrs: &BTreeMap<String, String>,
) -> Option<ClaudeEffortEvidence> {
    let session_id = first_attr(attrs, &["session.id", "session_id"])?;
    let model = first_attr(attrs, &["model", "gen_ai.request.model"])?;
    let effort = first_attr(attrs, &["effort", "effort_level"])?
        .trim()
        .to_ascii_lowercase();
    if !VALID_EFFORTS.contains(&effort.as_str()) {
        return None;
    }
    let observed_at = timestamp_at(record)?;
    let mut item = ClaudeEffortEvidence {
        fingerprint: String::new(),
        session_id: session_id.to_string(),
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
    };
    if item.cache_creation_5m_tokens == 0 && item.cache_creation_1h_tokens == 0 {
        item.cache_creation_5m_tokens = first_u64(
            attrs,
            &["cache_creation_tokens", "claude.tokens.cache_creation"],
        );
    }
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
        .join(format!("{:x}.jsonl", digest))
}

fn append_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captures_only_allowlisted_api_request_fields_and_dedupes_reads() {
        let dir = std::env::temp_dir().join(format!("ottto-effort-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let body = br#"{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"1783728000000000000","body":{"stringValue":"claude_code.api_request"},"attributes":[{"key":"session.id","value":{"stringValue":"sess-1"}},{"key":"model","value":{"stringValue":"claude-opus-4-7"}},{"key":"effort","value":{"stringValue":"xhigh"}},{"key":"input_tokens","value":{"intValue":"12"}},{"key":"output_tokens","value":{"intValue":"3"}},{"key":"prompt","value":{"stringValue":"must-not-persist"}}]}]}]}]}"#;
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
        let persisted = fs::read_to_string(evidence_path(&dir, "sess-1")).unwrap();
        assert!(!persisted.contains("must-not-persist"));
        let _ = fs::remove_dir_all(dir);
    }
}
