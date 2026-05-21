use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

pub const CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION: u16 = 1;
pub const CLAUDE_STATUSLINE_CACHE_FILE_NAME: &str = "claude-code-rate-limits.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineRateLimitCache {
    pub schema_version: u16,
    pub observed_at_epoch_seconds: u64,
    pub windows: Vec<ClaudeStatusLineRateLimitWindow>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaudeStatusLineRateLimitWindow {
    pub name: String,
    pub used_percent: u8,
    pub resets_at_epoch_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeStatusLineIngestResult {
    pub stored: bool,
    pub window_count: usize,
    pub reason: Option<String>,
}

pub fn claude_statusline_cache_path(support_dir: &Path) -> PathBuf {
    support_dir.join(CLAUDE_STATUSLINE_CACHE_FILE_NAME)
}

pub fn ingest_claude_statusline_payload(
    support_dir: &Path,
    payload: &str,
    observed_at_epoch_seconds: u64,
) -> Result<ClaudeStatusLineIngestResult> {
    let Some(cache) = parse_claude_statusline_payload(payload, observed_at_epoch_seconds)? else {
        return Ok(ClaudeStatusLineIngestResult {
            stored: false,
            window_count: 0,
            reason: Some("rate_limits_missing".to_string()),
        });
    };
    let window_count = cache.windows.len();
    write_claude_statusline_cache(support_dir, &cache)?;
    Ok(ClaudeStatusLineIngestResult {
        stored: true,
        window_count,
        reason: None,
    })
}

pub fn parse_claude_statusline_payload(
    payload: &str,
    observed_at_epoch_seconds: u64,
) -> Result<Option<ClaudeStatusLineRateLimitCache>> {
    let value: Value =
        serde_json::from_str(payload).context("parse Claude Code statusLine JSON")?;
    let Some(rate_limits) = value.get("rate_limits").and_then(Value::as_object) else {
        return Ok(None);
    };

    let mut windows = Vec::new();
    for name in ["five_hour", "seven_day"] {
        if let Some(window) = rate_limits
            .get(name)
            .and_then(|value| parse_rate_limit_window(name, value))
        {
            windows.push(window);
        }
    }

    if windows.is_empty() {
        return Ok(None);
    }

    Ok(Some(ClaudeStatusLineRateLimitCache {
        schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
        observed_at_epoch_seconds,
        windows,
    }))
}

pub fn read_claude_statusline_cache(
    support_dir: &Path,
) -> Result<Option<ClaudeStatusLineRateLimitCache>> {
    let path = claude_statusline_cache_path(support_dir);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&path).context("read Claude Code statusLine cache")?;
    let cache: ClaudeStatusLineRateLimitCache =
        serde_json::from_str(&body).context("parse Claude Code statusLine cache")?;
    if cache.schema_version != CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION {
        return Ok(None);
    }
    Ok(Some(cache))
}

pub fn write_claude_statusline_cache(
    support_dir: &Path,
    cache: &ClaudeStatusLineRateLimitCache,
) -> Result<()> {
    fs::create_dir_all(support_dir).context("create Ottto support directory")?;
    let path = claude_statusline_cache_path(support_dir);
    let tmp_path = path.with_extension(format!("json.tmp.{}", std::process::id()));
    let body =
        serde_json::to_vec_pretty(cache).context("serialize Claude Code statusLine cache")?;
    fs::write(&tmp_path, body).context("write Claude Code statusLine cache temp file")?;
    fs::rename(&tmp_path, &path).context("replace Claude Code statusLine cache")?;
    Ok(())
}

fn parse_rate_limit_window(name: &str, value: &Value) -> Option<ClaudeStatusLineRateLimitWindow> {
    let used_percent = value
        .get("used_percentage")
        .and_then(Value::as_f64)
        .and_then(percent_to_u8)?;
    let resets_at_epoch_seconds = value.get("resets_at").and_then(Value::as_u64)?;
    Some(ClaudeStatusLineRateLimitWindow {
        name: name.to_string(),
        used_percent,
        resets_at_epoch_seconds,
    })
}

fn percent_to_u8(value: f64) -> Option<u8> {
    if !value.is_finite() {
        return None;
    }
    Some(value.clamp(0.0, 100.0).round() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn support_dir(name: &str) -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "ottto-claude-statusline-{name}-{}-{counter}",
            std::process::id()
        ))
    }

    #[test]
    fn parses_rate_limits_without_persisting_other_statusline_fields() {
        let payload = r#"{
          "cwd": "/Users/example/private/project",
          "transcript_path": "/Users/example/.claude/projects/session.jsonl",
          "model": { "display_name": "Opus" },
          "rate_limits": {
            "five_hour": { "used_percentage": 23.5, "resets_at": 1738425600 },
            "seven_day": { "used_percentage": 41.2, "resets_at": 1738857600 }
          }
        }"#;

        let cache = parse_claude_statusline_payload(payload, 1738422000)
            .expect("parse")
            .expect("cache");

        assert_eq!(cache.observed_at_epoch_seconds, 1738422000);
        assert_eq!(cache.windows.len(), 2);
        assert_eq!(cache.windows[0].used_percent, 24);
        assert_eq!(cache.windows[1].used_percent, 41);
        let serialized = serde_json::to_string(&cache).expect("serialize");
        assert!(!serialized.contains("/Users/example"));
        assert!(!serialized.contains("transcript_path"));
        assert!(!serialized.contains("Opus"));
    }

    #[test]
    fn missing_rate_limits_does_not_replace_cache() {
        let dir = support_dir("missing");
        let result =
            ingest_claude_statusline_payload(&dir, r#"{"model":{"display_name":"Opus"}}"#, 1)
                .expect("ingest");

        assert!(!result.stored);
        assert_eq!(result.reason.as_deref(), Some("rate_limits_missing"));
        assert!(!claude_statusline_cache_path(&dir).exists());
    }

    #[test]
    fn writes_and_reads_cache_atomically() {
        let dir = support_dir("roundtrip");
        let cache = ClaudeStatusLineRateLimitCache {
            schema_version: CLAUDE_STATUSLINE_CACHE_SCHEMA_VERSION,
            observed_at_epoch_seconds: 10,
            windows: vec![ClaudeStatusLineRateLimitWindow {
                name: "five_hour".to_string(),
                used_percent: 7,
                resets_at_epoch_seconds: 20,
            }],
        };

        write_claude_statusline_cache(&dir, &cache).expect("write");
        assert_eq!(
            read_claude_statusline_cache(&dir).expect("read"),
            Some(cache)
        );
    }
}
