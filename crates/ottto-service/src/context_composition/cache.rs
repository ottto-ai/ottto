//! Incremental watermark and upload cache.

use super::measure::date_ymd;
use super::payload::{composition_config_hash, ContextCompositionIngestRequest};
use super::report::DateWindow;
use super::{COMPOSITION_PARSER_VERSION, CONTEXT_MAX_STALENESS_SECS};
use crate::context_footprint::{transcript_file_metadata, TranscriptFileMetadata};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

// -------------------------------------------------------------------------
// Incremental watermark + upload cache.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct CompositionCacheEntry {
    pub(super) identity: String,
    pub(super) agent_source: String,
    pub(super) files: CompositionFilesSignature,
    pub(super) scan_identity: CompositionScanIdentity,
    pub(super) payload_sha256: String,
    pub(super) posted_at: String,
}

pub(super) type CompositionFilesSignature = BTreeMap<String, TranscriptFileMetadata>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct CompositionScanIdentity {
    pub(super) window_floor: String,
    pub(super) window_today: String,
    pub(super) parser_version: String,
    pub(super) methodology_hash: String,
    pub(super) labels_enabled: bool,
}

pub(super) fn composition_scan_identity(
    agent_source: &str,
    window: DateWindow,
    labels_enabled: bool,
) -> CompositionScanIdentity {
    CompositionScanIdentity {
        window_floor: date_ymd(window.floor),
        window_today: date_ymd(window.today),
        parser_version: COMPOSITION_PARSER_VERSION.to_string(),
        methodology_hash: composition_config_hash(agent_source),
        labels_enabled,
    }
}

pub(super) fn workspace_files_signature(
    files: &[(PathBuf, SystemTime)],
    deadline: Instant,
) -> std::io::Result<CompositionFilesSignature> {
    let mut sig = BTreeMap::new();
    for (path, mtime) in files {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "composition metadata budget expired",
            ));
        }
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.modified()? != *mtime {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "composition source changed since discovery",
            ));
        }
        sig.insert(
            path.to_string_lossy().to_string(),
            transcript_file_metadata(&metadata)?,
        );
    }
    if Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "composition metadata budget expired",
        ));
    }
    Ok(sig)
}

/// A workspace is rescanned when there is no cache for it, the destination or
/// agent, metadata, active date window, parser/methodology or label policy
/// changed, or the cached upload is older than the staleness bound.
pub(super) fn should_rescan(
    cache: Option<&CompositionCacheEntry>,
    identity: &str,
    agent_source: &str,
    signature: &CompositionFilesSignature,
    scan_identity: &CompositionScanIdentity,
    now: OffsetDateTime,
) -> bool {
    let Some(cache) = cache else {
        return true;
    };
    if cache.identity != identity || cache.agent_source != agent_source {
        return true;
    }
    if &cache.files != signature || &cache.scan_identity != scan_identity {
        return true;
    }
    cache_is_stale(cache, now)
}

pub(super) fn cache_is_stale(entry: &CompositionCacheEntry, now: OffsetDateTime) -> bool {
    let Ok(posted) = OffsetDateTime::parse(&entry.posted_at, &Rfc3339) else {
        return true;
    };
    (now - posted).whole_seconds() >= CONTEXT_MAX_STALENESS_SECS
}

/// Content hash over the stable fields (excludes the volatile `captured_at`).
pub(super) fn request_content_hash(request: &ContextCompositionIngestRequest) -> Result<String> {
    let canonical = serde_json::to_vec(&json!({
        "cache_schema": "context_composition_request_v1",
        "agent_source": &request.agent_source,
        "machine_id": &request.machine_id,
        "workspace_hash": &request.workspace_hash,
        "workspace_label": &request.workspace_label,
        "workspace_label_source": &request.workspace_label_source,
        "repository_hash": &request.repository_hash,
        "repository_label": &request.repository_label,
        "repository_label_source": &request.repository_label_source,
        "repository_identity_source": &request.repository_identity_source,
        "workspace_kind": &request.workspace_kind,
        "config_hash": &request.config_hash,
        "window_start": &request.window_start,
        "window_end": &request.window_end,
        "bucket_timezone": &request.bucket_timezone,
        "collector_version": &request.collector_version,
        "counter_source": &request.counter_source,
        "daily_aggregates": &request.daily_aggregates,
        "top_files": &request.top_files,
        "sessions": &request.sessions,
    }))
    .map_err(|error| anyhow!("hash encode failed: {error}"))?;
    Ok(sha256_bytes(&canonical))
}

pub(super) fn sha256_bytes(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

pub(super) fn cache_path(support_dir: &Path, agent_source: &str, workspace_hash: &str) -> PathBuf {
    support_dir
        .join("context_composition")
        .join(format!("{agent_source}-{workspace_hash}.json"))
}

pub(super) fn read_cache(path: &Path) -> Option<CompositionCacheEntry> {
    let bytes = fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub(super) fn write_cache(path: &Path, entry: &CompositionCacheEntry) {
    let Some(dir) = path.parent() else {
        return;
    };
    if fs::create_dir_all(dir).is_err() {
        return;
    }
    let Ok(payload) = serde_json::to_vec(entry) else {
        return;
    };
    let temp = path.with_extension("json.tmp");
    if fs::write(&temp, &payload).is_ok() {
        let _ = fs::rename(&temp, path);
    }
}
