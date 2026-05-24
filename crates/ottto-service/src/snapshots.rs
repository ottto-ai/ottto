use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use toml_edit::{DocumentMut, Item};

pub const COLLECTOR_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const SNAPSHOT_SCHEMA_VERSION: u16 = 5;
pub const CODEX_SNAPSHOT_PARSER_VERSION: &str = "codex_jsonl:v11";
pub const CLAUDE_CODE_SNAPSHOT_PARSER_VERSION: &str = "claude_code_jsonl:v4";
pub const PI_SNAPSHOT_PARSER_VERSION: &str = "pi_jsonl:v4";
pub const MAX_BACKFILL_FILES_PER_SOURCE: usize = 1_000;
pub const BACKFILL_WINDOW_DAYS: u64 = 183;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSource {
    Codex,
    ClaudeCode,
    Pi,
}

impl SnapshotSource {
    pub fn api_slug(self) -> &'static str {
        match self {
            SnapshotSource::Codex => "codex",
            SnapshotSource::ClaudeCode => "claude_code",
            SnapshotSource::Pi => "pi",
        }
    }

    pub fn parser_version(self) -> &'static str {
        match self {
            SnapshotSource::Codex => CODEX_SNAPSHOT_PARSER_VERSION,
            SnapshotSource::ClaudeCode => CLAUDE_CODE_SNAPSHOT_PARSER_VERSION,
            SnapshotSource::Pi => PI_SNAPSHOT_PARSER_VERSION,
        }
    }

    pub fn default_roots(self, home: &Path) -> Vec<PathBuf> {
        match self {
            SnapshotSource::Codex => vec![home.join(".codex").join("sessions")],
            SnapshotSource::ClaudeCode => vec![home.join(".claude").join("projects")],
            SnapshotSource::Pi => {
                if let Some(override_dir) = std::env::var_os("PI_CODING_AGENT_DIR") {
                    vec![PathBuf::from(override_dir).join("sessions")]
                } else {
                    vec![home.join(".pi").join("agent").join("sessions")]
                }
            }
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotBatchRequest {
    pub schema_version: u16,
    pub source: String,
    pub machine_id: String,
    pub collector_version: Option<String>,
    pub snapshots: Vec<SnapshotItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotItem {
    pub source_session_id: String,
    pub snapshot_fingerprint: String,
    pub status: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub request_count: u64,
    pub model_usage: Vec<SnapshotModelUsage>,
    pub activity_buckets: Vec<SnapshotActivityBucket>,
    pub session_display_name: Option<String>,
    pub session_display_name_source: Option<String>,
    pub source_started_at: Option<String>,
    pub source_ended_at: Option<String>,
    pub source_last_activity_at: Option<String>,
    pub collected_at: String,
    pub workspace_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_display_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_label_source: Option<String>,
    pub source_file_fingerprint: Option<String>,
    pub provenance: SnapshotProvenance,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SnapshotActivityBucket {
    pub bucket_start: String,
    pub request_count: u64,
    pub first_activity_at: Option<String>,
    pub last_activity_at: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotModelUsage {
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cache_read_tokens: u64,
    pub cache_creation_5m_tokens: u64,
    pub cache_creation_1h_tokens: u64,
    pub reasoning_output_tokens: u64,
    pub request_count: u64,
    pub selector_context: BTreeMap<String, String>,
    pub selector_sources: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SnapshotProvenance {
    pub collector: String,
    pub source_file_count: u64,
    pub input_token_scope: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanIndex {
    pub files: BTreeMap<String, ScanIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanIndexEntry {
    pub size_bytes: u64,
    pub modified_unix_seconds: u64,
    pub source_file_fingerprint: String,
    pub last_snapshot_fingerprint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SourceScanResult {
    pub source: SnapshotSource,
    pub backfill_window_days: u64,
    pub backfill_file_limit: usize,
    pub discovered_file_count: usize,
    pub skipped_file_count_due_to_limit: usize,
    pub scan_cap_hit: bool,
    pub scanned_file_count: usize,
    pub scanned_session_count: usize,
    pub snapshots: Vec<SnapshotItem>,
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotUploadPolicy {
    pub session_titles_enabled: bool,
    pub workspace_labels_enabled: bool,
}

impl Default for SnapshotUploadPolicy {
    fn default() -> Self {
        Self {
            session_titles_enabled: true,
            workspace_labels_enabled: true,
        }
    }
}

pub fn apply_upload_policy(
    source: SnapshotSource,
    snapshots: &mut [SnapshotItem],
    policy: SnapshotUploadPolicy,
) {
    for item in snapshots {
        let mut fingerprint_needs_refresh = false;
        if !policy.session_titles_enabled
            && (item.session_display_name.is_some() || item.session_display_name_source.is_some())
        {
            item.session_display_name = None;
            item.session_display_name_source = None;
            fingerprint_needs_refresh = true;
        }
        if !policy.workspace_labels_enabled
            && (item.workspace_display_label.is_some() || item.workspace_label_source.is_some())
        {
            item.workspace_display_label = None;
            item.workspace_label_source = None;
            fingerprint_needs_refresh = true;
        }
        if fingerprint_needs_refresh {
            item.snapshot_fingerprint = snapshot_fingerprint(source, item);
        }
    }
}

fn snapshot_fingerprint(source: SnapshotSource, item: &SnapshotItem) -> String {
    let fingerprint_payload = json!({
        "source": source.api_slug(),
        "source_session_id": &item.source_session_id,
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "cache_read_tokens": item.cache_read_tokens,
        "cache_creation_5m_tokens": item.cache_creation_5m_tokens,
        "cache_creation_1h_tokens": item.cache_creation_1h_tokens,
        "reasoning_output_tokens": item.reasoning_output_tokens,
        "request_count": item.request_count,
        "model_usage": &item.model_usage,
        "activity_buckets": &item.activity_buckets,
        "title": &item.session_display_name,
        "title_source": &item.session_display_name_source,
        "workspace_display_label": &item.workspace_display_label,
        "workspace_label_source": &item.workspace_label_source,
    });
    sha256_hex(&[&fingerprint_payload.to_string()])
}

#[derive(Debug, Clone, Default)]
struct UsageTotals {
    input_tokens: u64,
    output_tokens: u64,
    cache_read_tokens: u64,
    cache_creation_5m_tokens: u64,
    cache_creation_1h_tokens: u64,
    reasoning_output_tokens: u64,
    request_count: u64,
}

impl UsageTotals {
    fn is_zero(&self) -> bool {
        self.total_tokens() == 0 && self.reasoning_output_tokens == 0
    }

    fn total_tokens(&self) -> u64 {
        self.input_tokens
            + self.output_tokens
            + self.cache_read_tokens
            + self.cache_creation_5m_tokens
            + self.cache_creation_1h_tokens
    }

    fn add(&mut self, other: &UsageTotals) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_read_tokens += other.cache_read_tokens;
        self.cache_creation_5m_tokens += other.cache_creation_5m_tokens;
        self.cache_creation_1h_tokens += other.cache_creation_1h_tokens;
        self.reasoning_output_tokens += other.reasoning_output_tokens;
        self.request_count += other.request_count;
    }

    fn is_monotonic_after(&self, previous: &UsageTotals) -> bool {
        self.input_tokens >= previous.input_tokens
            && self.output_tokens >= previous.output_tokens
            && self.cache_read_tokens >= previous.cache_read_tokens
            && self.cache_creation_5m_tokens >= previous.cache_creation_5m_tokens
            && self.cache_creation_1h_tokens >= previous.cache_creation_1h_tokens
            && self.reasoning_output_tokens >= previous.reasoning_output_tokens
            && self.request_count >= previous.request_count
    }

    fn delta_from(&self, previous: &UsageTotals) -> UsageTotals {
        UsageTotals {
            input_tokens: self.input_tokens - previous.input_tokens,
            output_tokens: self.output_tokens - previous.output_tokens,
            cache_read_tokens: self.cache_read_tokens - previous.cache_read_tokens,
            cache_creation_5m_tokens: self.cache_creation_5m_tokens
                - previous.cache_creation_5m_tokens,
            cache_creation_1h_tokens: self.cache_creation_1h_tokens
                - previous.cache_creation_1h_tokens,
            reasoning_output_tokens: self.reasoning_output_tokens
                - previous.reasoning_output_tokens,
            request_count: self.request_count - previous.request_count,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct SelectorCapture {
    context: BTreeMap<String, String>,
    sources: BTreeMap<String, String>,
}

impl SelectorCapture {
    fn is_empty(&self) -> bool {
        self.context.is_empty()
    }

    fn insert(&mut self, field: &str, value: String, source: &str) {
        self.context.insert(field.to_string(), value);
        self.sources.insert(field.to_string(), source.to_string());
    }

    fn merge(&mut self, other: SelectorCapture) {
        for (field, value) in other.context {
            self.context.insert(field, value);
        }
        for (field, source) in other.sources {
            self.sources.insert(field, source);
        }
    }

    fn selector_hash(&self) -> String {
        if self.context.is_empty() {
            return "base".to_string();
        }
        let payload = serde_json::to_string(&self.context).unwrap_or_else(|_| "{}".to_string());
        sha256_hex(&[payload.as_str()])[..16].to_string()
    }
}

#[derive(Debug, Clone)]
struct ModelSelectorUsage {
    model: String,
    selector_context: BTreeMap<String, String>,
    selector_sources: BTreeMap<String, String>,
    usage: UsageTotals,
}

#[derive(Debug, Clone)]
struct ActivityBucketAccumulator {
    request_count: u64,
    first_activity_at: String,
    last_activity_at: String,
}

#[derive(Debug, Clone, Default)]
struct CodexTitleMetadata {
    titles: BTreeMap<String, CodexTitleCandidate>,
    sidecar_fingerprint: String,
    default_selector: SelectorCapture,
}

#[derive(Debug, Clone)]
struct CodexTitleCandidate {
    title: String,
    source: String,
}

#[derive(Debug, Clone)]
struct SnapshotAccumulator {
    source: SnapshotSource,
    source_session_id: Option<String>,
    title: Option<String>,
    title_source: Option<String>,
    first_prompt_title: Option<String>,
    started_at: Option<String>,
    ended_at: Option<String>,
    last_activity_at: Option<String>,
    workspace_hash: Option<String>,
    latest_model: Option<String>,
    current_selector: SelectorCapture,
    latest_cumulative_usage: Option<UsageTotals>,
    totals: UsageTotals,
    model_usage: BTreeMap<(String, String), ModelSelectorUsage>,
    activity_buckets: BTreeMap<String, ActivityBucketAccumulator>,
}

impl SnapshotAccumulator {
    fn new(source: SnapshotSource) -> Self {
        Self {
            source,
            source_session_id: None,
            title: None,
            title_source: None,
            first_prompt_title: None,
            started_at: None,
            ended_at: None,
            last_activity_at: None,
            workspace_hash: None,
            latest_model: None,
            current_selector: SelectorCapture::default(),
            latest_cumulative_usage: None,
            totals: UsageTotals::default(),
            model_usage: BTreeMap::new(),
            activity_buckets: BTreeMap::new(),
        }
    }

    fn with_default_selector(source: SnapshotSource, selector: SelectorCapture) -> Self {
        let mut accumulator = Self::new(source);
        accumulator.current_selector = selector;
        accumulator
    }

    fn note_time(&mut self, timestamp: Option<String>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self
            .started_at
            .as_ref()
            .map_or(true, |current| timestamp < *current)
        {
            self.started_at = Some(timestamp.clone());
        }
        if self
            .last_activity_at
            .as_ref()
            .map_or(true, |current| timestamp > *current)
        {
            self.last_activity_at = Some(timestamp);
        }
    }

    fn note_activity(&mut self, timestamp: Option<String>, request_count: u64) {
        if request_count == 0 {
            return;
        }
        let Some(timestamp) = timestamp else {
            return;
        };
        let Some((bucket_start, normalized_timestamp)) = activity_bucket_from_timestamp(&timestamp)
        else {
            return;
        };
        match self.activity_buckets.get_mut(&bucket_start) {
            Some(bucket) => {
                bucket.request_count += request_count;
                if normalized_timestamp < bucket.first_activity_at {
                    bucket.first_activity_at = normalized_timestamp.clone();
                }
                if normalized_timestamp > bucket.last_activity_at {
                    bucket.last_activity_at = normalized_timestamp;
                }
            }
            None => {
                self.activity_buckets.insert(
                    bucket_start,
                    ActivityBucketAccumulator {
                        request_count,
                        first_activity_at: normalized_timestamp.clone(),
                        last_activity_at: normalized_timestamp,
                    },
                );
            }
        }
    }

    fn set_title(&mut self, title: Option<String>, source: &str) {
        let Some(title) = title.and_then(|value| normalize_display_title(value, source)) else {
            return;
        };
        self.title = Some(title);
        self.title_source = Some(source.to_string());
    }

    fn set_title_if_absent(&mut self, title: Option<String>, source: &str) {
        if self.title.is_some() {
            return;
        }
        self.set_title(title, source);
    }

    fn set_first_prompt_title(&mut self, value: Option<String>) {
        if self.first_prompt_title.is_some() {
            return;
        }
        self.first_prompt_title = value.and_then(first_prompt_display_title);
    }

    fn apply_codex_title_metadata(&mut self, path: &Path, metadata: &CodexTitleMetadata) {
        if self.title.is_some() {
            return;
        }
        let session_id = self
            .source_session_id
            .clone()
            .or_else(|| codex_session_id_from_path(path));
        let Some(session_id) = session_id else {
            return;
        };
        if let Some(title) = metadata.titles.get(session_id.as_str()) {
            self.set_title_if_absent(Some(title.title.clone()), title.source.as_str());
        }
    }

    fn apply_first_prompt_fallback(&mut self) {
        if self.title.is_some() {
            return;
        }
        self.set_title_if_absent(self.first_prompt_title.clone(), "first_prompt");
    }

    fn set_workspace_hash(&mut self, value: Option<String>) {
        if self.workspace_hash.is_none() {
            self.workspace_hash = value.map(|raw| sha256_hex(&[raw.as_str()]));
        }
    }

    fn set_model(&mut self, model: Option<String>) {
        if let Some(model) = model.and_then(normalize_title) {
            self.latest_model = Some(model);
        }
    }

    fn set_selector(&mut self, selector: SelectorCapture) {
        if !selector.is_empty() {
            self.current_selector = selector;
        }
    }

    fn add_usage_with_selector(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        selector: SelectorCapture,
    ) {
        if usage.is_zero() {
            return;
        }
        let model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(model.clone());
        self.totals.add(&usage);
        let selector = if selector.is_empty() {
            self.current_selector.clone()
        } else {
            selector
        };
        self.add_model_usage(model, selector, usage);
    }

    fn add_model_usage(&mut self, model: String, selector: SelectorCapture, usage: UsageTotals) {
        let selector_hash = selector.selector_hash();
        let key = (model.clone(), selector_hash);
        if let Some(entry) = self.model_usage.get_mut(&key) {
            entry.selector_sources.extend(selector.sources);
            entry.usage.add(&usage);
            return;
        }
        self.model_usage.insert(
            key,
            ModelSelectorUsage {
                model,
                selector_context: selector.context,
                selector_sources: selector.sources,
                usage,
            },
        );
    }

    fn set_cumulative_usage_with_selector(
        &mut self,
        model: Option<String>,
        usage: UsageTotals,
        selector: SelectorCapture,
    ) -> Option<UsageTotals> {
        if usage.is_zero() {
            return None;
        }
        let model = model
            .or_else(|| self.latest_model.clone())
            .unwrap_or_else(|| "unknown".to_string());
        self.latest_model = Some(model.clone());
        let delta = match self.latest_cumulative_usage.as_ref() {
            Some(previous) if usage.is_monotonic_after(previous) => usage.delta_from(previous),
            Some(_) => {
                self.model_usage.clear();
                usage.clone()
            }
            None => usage.clone(),
        };
        self.latest_cumulative_usage = Some(usage.clone());
        self.totals = usage;
        if delta.is_zero() {
            return None;
        }
        let selector = if selector.is_empty() {
            self.current_selector.clone()
        } else {
            selector
        };
        self.add_model_usage(model, selector, delta.clone());
        Some(delta)
    }

    fn into_item(
        self,
        path: &Path,
        collected_at: &str,
        source_file_fingerprint: String,
    ) -> Option<SnapshotItem> {
        let source_session_id = self
            .source_session_id
            .or_else(|| {
                (self.source == SnapshotSource::Codex)
                    .then(|| codex_session_id_from_path(path))
                    .flatten()
            })
            .or_else(|| {
                path.file_stem()
                    .and_then(|value| value.to_str())
                    .map(|value| value.to_string())
            })?;
        if self.totals.total_tokens() == 0 && self.totals.reasoning_output_tokens == 0 {
            return None;
        }
        let model_usage: Vec<SnapshotModelUsage> = self
            .model_usage
            .into_values()
            .map(|row| SnapshotModelUsage {
                model: row.model,
                input_tokens: row.usage.input_tokens,
                output_tokens: row.usage.output_tokens,
                cache_read_tokens: row.usage.cache_read_tokens,
                cache_creation_5m_tokens: row.usage.cache_creation_5m_tokens,
                cache_creation_1h_tokens: row.usage.cache_creation_1h_tokens,
                reasoning_output_tokens: row.usage.reasoning_output_tokens,
                request_count: row.usage.request_count,
                selector_context: row.selector_context,
                selector_sources: row.selector_sources,
            })
            .collect();
        let activity_buckets: Vec<SnapshotActivityBucket> = self
            .activity_buckets
            .into_iter()
            .map(|(bucket_start, bucket)| SnapshotActivityBucket {
                bucket_start,
                request_count: bucket.request_count,
                first_activity_at: Some(bucket.first_activity_at),
                last_activity_at: Some(bucket.last_activity_at),
            })
            .collect();
        let mut item = SnapshotItem {
            source_session_id,
            snapshot_fingerprint: String::new(),
            status: "final".to_string(),
            input_tokens: self.totals.input_tokens,
            output_tokens: self.totals.output_tokens,
            cache_read_tokens: self.totals.cache_read_tokens,
            cache_creation_5m_tokens: self.totals.cache_creation_5m_tokens,
            cache_creation_1h_tokens: self.totals.cache_creation_1h_tokens,
            reasoning_output_tokens: self.totals.reasoning_output_tokens,
            request_count: self.totals.request_count,
            model_usage,
            activity_buckets,
            session_display_name: self.title,
            session_display_name_source: self.title_source,
            source_started_at: self.started_at,
            source_ended_at: self.ended_at,
            source_last_activity_at: self.last_activity_at,
            collected_at: collected_at.to_string(),
            workspace_hash: self.workspace_hash,
            workspace_display_label: None,
            workspace_label_source: None,
            source_file_fingerprint: Some(source_file_fingerprint),
            provenance: SnapshotProvenance {
                collector: match self.source {
                    SnapshotSource::Codex => "codex_jsonl".to_string(),
                    SnapshotSource::ClaudeCode => "claude_code_jsonl".to_string(),
                    SnapshotSource::Pi => "pi_jsonl".to_string(),
                },
                source_file_count: 1,
                input_token_scope: match self.source {
                    SnapshotSource::Codex => Some("inclusive_cached".to_string()),
                    SnapshotSource::ClaudeCode => Some("uncached".to_string()),
                    SnapshotSource::Pi => Some("uncached".to_string()),
                },
            },
        };
        item.snapshot_fingerprint = snapshot_fingerprint(self.source, &item);
        Some(item)
    }
}

pub fn scan_source_roots(
    source: SnapshotSource,
    roots: &[PathBuf],
    index: &mut ScanIndex,
    collected_at: &str,
    requested_backfill_window_days: u64,
) -> Result<SourceScanResult> {
    let backfill_window_days = effective_backfill_window_days(requested_backfill_window_days);
    let codex_title_metadata = if source == SnapshotSource::Codex {
        CodexTitleMetadata::load_from_roots(roots)
    } else {
        CodexTitleMetadata::default()
    };
    let mut files = Vec::new();
    for root in roots {
        collect_recent_jsonl_files(
            source,
            root,
            &mut files,
            codex_title_metadata.sidecar_fingerprint.as_str(),
            backfill_window_days,
        )?;
    }
    let discovered_file_count = files.len();
    let skipped_file_count_due_to_limit =
        discovered_file_count.saturating_sub(MAX_BACKFILL_FILES_PER_SOURCE);
    files.sort_by_key(|file| Reverse(file.modified_unix_seconds));
    files.truncate(MAX_BACKFILL_FILES_PER_SOURCE);

    let mut snapshots = Vec::new();
    let mut scanned_file_count = 0;
    for candidate in files {
        if !index.should_process(&candidate) {
            continue;
        }
        scanned_file_count += 1;
        let source_file_fingerprint = candidate.source_file_fingerprint.clone();
        let parsed = match source {
            SnapshotSource::Codex => parse_codex_jsonl_file_with_title_metadata(
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
                &codex_title_metadata,
            )?,
            SnapshotSource::ClaudeCode => parse_claude_code_jsonl_file(
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
            )?,
            SnapshotSource::Pi => parse_pi_jsonl_file(
                &candidate.path,
                collected_at,
                source_file_fingerprint.clone(),
            )?,
        };
        let last_snapshot_fingerprint = parsed
            .as_ref()
            .map(|snapshot| snapshot.snapshot_fingerprint.clone());
        index.record(candidate, last_snapshot_fingerprint);
        if let Some(snapshot) = parsed {
            snapshots.push(snapshot);
        }
    }
    Ok(SourceScanResult {
        source,
        backfill_window_days,
        backfill_file_limit: MAX_BACKFILL_FILES_PER_SOURCE,
        discovered_file_count,
        skipped_file_count_due_to_limit,
        scan_cap_hit: skipped_file_count_due_to_limit > 0,
        scanned_file_count,
        scanned_session_count: snapshots.len(),
        snapshots,
    })
}

pub fn parse_codex_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Option<SnapshotItem>> {
    parse_codex_jsonl_file_with_title_metadata(
        path,
        collected_at,
        source_file_fingerprint,
        &CodexTitleMetadata::default(),
    )
}

fn parse_codex_jsonl_file_with_title_metadata(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    title_metadata: &CodexTitleMetadata,
) -> Result<Option<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::Codex,
        apply_codex_line,
        Some(title_metadata),
    )
}

pub fn parse_claude_code_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Option<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::ClaudeCode,
        apply_claude_code_line,
        None,
    )
}

pub fn parse_pi_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
) -> Result<Option<SnapshotItem>> {
    parse_jsonl_file(
        path,
        collected_at,
        source_file_fingerprint,
        SnapshotSource::Pi,
        apply_pi_line,
        None,
    )
}

fn parse_jsonl_file(
    path: &Path,
    collected_at: &str,
    source_file_fingerprint: String,
    source: SnapshotSource,
    apply_line: fn(&Value, &mut SnapshotAccumulator),
    codex_title_metadata: Option<&CodexTitleMetadata>,
) -> Result<Option<SnapshotItem>> {
    let file = File::open(path).with_context(|| format!("open JSONL {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut accumulator = if let Some(metadata) = codex_title_metadata {
        SnapshotAccumulator::with_default_selector(source, metadata.default_selector.clone())
    } else {
        SnapshotAccumulator::new(source)
    };
    for line in reader.lines() {
        let line = line.with_context(|| format!("read JSONL line {}", path.display()))?;
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        apply_line(&value, &mut accumulator);
    }
    if source == SnapshotSource::Codex {
        if let Some(metadata) = codex_title_metadata {
            accumulator.apply_codex_title_metadata(path, metadata);
        }
        accumulator.apply_first_prompt_fallback();
    }
    if source == SnapshotSource::Pi {
        accumulator.apply_first_prompt_fallback();
    }
    Ok(accumulator.into_item(path, collected_at, source_file_fingerprint))
}

fn raw_value_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    Some(current)
}

fn normalize_selector_raw(field: &str, value: &Value) -> Option<String> {
    let normalized = match value {
        Value::Bool(value) => {
            if *value {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.trim().to_ascii_lowercase().replace([' ', '-'], "_"),
        _ => return None,
    };
    if normalized.is_empty() {
        return None;
    }
    let true_values = ["true", "1", "yes", "y", "on", "enabled"];
    let false_values = ["false", "0", "no", "n", "off", "disabled"];
    let standard_values = ["normal", "default", "base"];
    match field {
        "batch_mode" => {
            if true_values.contains(&normalized.as_str()) {
                Some("true".to_string())
            } else if false_values.contains(&normalized.as_str()) {
                Some("false".to_string())
            } else {
                None
            }
        }
        "mode" => {
            if true_values.contains(&normalized.as_str()) || normalized == "fast" {
                Some("fast".to_string())
            } else if false_values.contains(&normalized.as_str())
                || standard_values.contains(&normalized.as_str())
                || normalized == "standard"
            {
                Some("standard".to_string())
            } else if normalized == "priority" || normalized == "flex" {
                Some(normalized)
            } else {
                None
            }
        }
        "service_tier" | "speed_mode" => {
            if standard_values.contains(&normalized.as_str()) {
                Some("standard".to_string())
            } else {
                Some(normalized)
            }
        }
        "region_mode" => match normalized.as_str() {
            "us" | "usa" | "us_only" | "united_states" | "data_residency_us" => {
                Some("us".to_string())
            }
            "eu" | "eu_only" | "european_union" | "data_residency_eu" => Some("eu".to_string()),
            _ => Some(normalized),
        },
        _ => Some(normalized),
    }
}

fn selector_source_path(path: &[&str]) -> String {
    path.join(".")
}

fn insert_selector_raw(capture: &mut SelectorCapture, field: &str, source: &str, value: &Value) {
    let Some(normalized) = normalize_selector_raw(field, value) else {
        return;
    };
    capture.insert(field, normalized.clone(), source);
    if field == "speed_mode" && normalized == "fast" {
        capture.insert("service_tier", "fast".to_string(), "derived_from_speed");
    }
}

fn insert_selector_at(capture: &mut SelectorCapture, value: &Value, field: &str, path: &[&str]) {
    if let Some(raw) = raw_value_at(value, path) {
        insert_selector_raw(capture, field, selector_source_path(path).as_str(), raw);
    }
}

fn selector_from_object(value: &Value, source_prefix: &str) -> SelectorCapture {
    let mut capture = SelectorCapture::default();
    let Value::Object(map) = value else {
        return capture;
    };
    let aliases: &[(&str, &[&str])] = &[
        (
            "service_tier",
            &[
                "service_tier",
                "serviceTier",
                "service.tier",
                "actual_service_tier",
                "tier",
            ],
        ),
        ("speed_mode", &["speed_mode", "speedMode", "speed"]),
        ("batch_mode", &["batch_mode", "batchMode", "batch"]),
        (
            "region_mode",
            &[
                "region_mode",
                "regionMode",
                "data_residency",
                "dataResidency",
                "inference_geo",
                "inferenceGeo",
                "region",
            ],
        ),
        (
            "context_bucket",
            &[
                "context_bucket",
                "contextBucket",
                "context.bucket",
                "context_length_bucket",
                "contextLengthBucket",
            ],
        ),
        (
            "cache_ttl",
            &[
                "cache_ttl",
                "cacheTtl",
                "cache.ttl",
                "cache_write_ttl",
                "cache_write_ttl_seconds",
            ],
        ),
        (
            "mode",
            &[
                "mode",
                "service_mode",
                "serviceMode",
                "performance_mode",
                "performanceMode",
                "codex_mode",
                "codexMode",
                "fast_mode",
                "fastMode",
                "is_fast_mode",
                "isFastMode",
                "codex_fast_mode",
                "codexFastMode",
                "openai.fast_mode",
            ],
        ),
    ];
    for (field, field_aliases) in aliases {
        for alias in *field_aliases {
            let Some(raw) = map.get(*alias) else {
                continue;
            };
            let source = if source_prefix.is_empty() {
                alias.to_string()
            } else {
                format!("{source_prefix}.{alias}")
            };
            insert_selector_raw(&mut capture, field, source.as_str(), raw);
            break;
        }
    }
    for nested_key in ["selector_context", "selector"] {
        if let Some(nested) = map.get(nested_key) {
            let source = if source_prefix.is_empty() {
                nested_key.to_string()
            } else {
                format!("{source_prefix}.{nested_key}")
            };
            capture.merge(selector_from_object(nested, source.as_str()));
        }
    }
    capture
}

fn merge_selector_object_at(capture: &mut SelectorCapture, value: &Value, path: &[&str]) {
    if let Some(raw) = raw_value_at(value, path) {
        capture.merge(selector_from_object(
            raw,
            selector_source_path(path).as_str(),
        ));
    }
}

fn codex_selector_from_line(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    let object_paths: &[&[&str]] = &[
        &[],
        &["payload"],
        &["turn_context", "payload"],
        &["payload", "info"],
        &["token_count", "info"],
    ];
    for path in object_paths {
        merge_selector_object_at(&mut selector, value, path);
    }
    let service_tier_paths: &[&[&str]] = &[
        &["token_count", "info", "service_tier"],
        &["payload", "info", "service_tier"],
        &["turn_context", "payload", "service_tier"],
        &["payload", "service_tier"],
        &["service_tier"],
    ];
    for path in service_tier_paths {
        insert_selector_at(&mut selector, value, "service_tier", path);
    }
    let fast_mode_paths: &[&[&str]] = &[
        &["payload", "fast_mode"],
        &["fast_mode"],
        &["codex_fast_mode"],
    ];
    for path in fast_mode_paths {
        insert_selector_at(&mut selector, value, "mode", path);
    }
    let mode_paths: &[&[&str]] = &[&["payload", "mode"], &["mode"]];
    for path in mode_paths {
        insert_selector_at(&mut selector, value, "mode", path);
    }
    let extra_paths: &[(&str, &[&[&str]])] = &[
        (
            "batch_mode",
            &[
                &["payload", "batch_mode"],
                &["payload", "info", "batch_mode"],
                &["batch_mode"],
            ],
        ),
        (
            "region_mode",
            &[
                &["payload", "inference_geo"],
                &["payload", "info", "inference_geo"],
                &["inference_geo"],
            ],
        ),
        (
            "context_bucket",
            &[
                &["payload", "context_bucket"],
                &["payload", "info", "context_bucket"],
                &["context_bucket"],
            ],
        ),
    ];
    for (field, paths) in extra_paths {
        for path in *paths {
            insert_selector_at(&mut selector, value, field, path);
        }
    }
    selector
}

fn claude_code_selector_from_line(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    let usage_paths: &[&[&str]] = &[&["message", "usage"], &["usage"], &["payload", "usage"]];
    for path in usage_paths {
        if let Some(raw) = raw_value_at(value, path) {
            selector.merge(selector_from_object(
                raw,
                selector_source_path(path).as_str(),
            ));
        }
    }
    selector.merge(selector_from_object(value, ""));
    selector
}

fn pi_selector_from_custom(value: &Value) -> Option<SelectorCapture> {
    let custom_type = string_at(value, &["customType"])
        .or_else(|| string_at(value, &["custom_type"]))
        .or_else(|| string_at(value, &["name"]))?;
    if custom_type != "ottto-selector" && custom_type != "ottto.selector" {
        return None;
    }
    let mut selector = SelectorCapture::default();
    if let Some(data) = raw_value_at(value, &["data"]) {
        selector.merge(selector_from_object(data, "data"));
    }
    selector.merge(selector_from_object(value, ""));
    (!selector.is_empty()).then_some(selector)
}

fn pi_selector_from_message_end(value: &Value) -> SelectorCapture {
    let mut selector = SelectorCapture::default();
    selector.merge(selector_from_object(value, ""));
    if let Some(message) = raw_value_at(value, &["message"]) {
        selector.merge(selector_from_object(message, "message"));
    }
    if let Some(usage) = raw_value_at(value, &["message", "usage"]) {
        selector.merge(selector_from_object(usage, "message.usage"));
    }
    selector
}

fn apply_codex_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = string_at(value, &["session_meta", "payload", "id"])
            .or_else(|| string_at(value, &["payload", "id"]))
            .or_else(|| string_at(value, &["session_id"]))
            .or_else(|| string_at(value, &["sessionId"]));
    }
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["time"]))
        .or_else(|| string_at(value, &["created_at"]));
    accumulator.note_time(timestamp.clone());
    accumulator.set_title(codex_transcript_title(value), "transcript_title");
    accumulator.set_first_prompt_title(codex_first_user_prompt(value));
    accumulator.set_model(
        string_at(value, &["turn_context", "payload", "model"])
            .or_else(|| string_at(value, &["payload", "model"]))
            .or_else(|| string_at(value, &["model"])),
    );
    accumulator.set_workspace_hash(
        string_at(value, &["turn_context", "payload", "cwd"])
            .or_else(|| string_at(value, &["payload", "cwd"]))
            .or_else(|| string_at(value, &["cwd"])),
    );
    let selector = codex_selector_from_line(value);
    accumulator.set_selector(selector.clone());
    if let Some(usage) = codex_total_usage(value) {
        if let Some(delta) = accumulator.set_cumulative_usage_with_selector(
            string_at(value, &["token_count", "info", "model"])
                .or_else(|| string_at(value, &["payload", "info", "model"]))
                .or_else(|| string_at(value, &["turn_context", "payload", "model"]))
                .or_else(|| string_at(value, &["payload", "model"])),
            usage,
            selector,
        ) {
            accumulator.note_activity(timestamp, delta.request_count);
        }
    }
}

fn codex_transcript_title(value: &Value) -> Option<String> {
    if string_eq_at(value, &["payload", "type"], "thread_name_updated") {
        return string_at(value, &["payload", "thread_name"])
            .or_else(|| string_at(value, &["payload", "name"]))
            .or_else(|| string_at(value, &["payload", "title"]));
    }
    if string_eq_at(value, &["type"], "thread_name_updated") {
        return string_at(value, &["thread_name"])
            .or_else(|| string_at(value, &["name"]))
            .or_else(|| string_at(value, &["title"]));
    }
    string_at(value, &["thread_name_updated", "payload", "name"])
        .or_else(|| string_at(value, &["thread_name_updated", "name"]))
}

fn codex_first_user_prompt(value: &Value) -> Option<String> {
    if string_eq_at(value, &["payload", "type"], "user_message") {
        return string_at(value, &["payload", "message"])
            .or_else(|| string_at(value, &["payload", "text"]))
            .or_else(|| text_from_array(value.pointer("/payload/text_elements")));
    }
    if string_eq_at(value, &["type"], "user_message") {
        return string_at(value, &["message"])
            .or_else(|| string_at(value, &["text"]))
            .or_else(|| text_from_array(value.get("text_elements")));
    }
    if string_eq_at(value, &["payload", "type"], "message")
        && string_eq_at(value, &["payload", "role"], "user")
    {
        return text_from_array(value.pointer("/payload/content"));
    }
    None
}

fn text_from_array(value: Option<&Value>) -> Option<String> {
    let Value::Array(items) = value? else {
        return None;
    };
    let mut parts = Vec::new();
    for item in items {
        match item {
            Value::String(text) => parts.push(text.as_str()),
            Value::Object(_) => {
                if let Some(text) = item
                    .get("text")
                    .and_then(Value::as_str)
                    .or_else(|| item.get("input_text").and_then(Value::as_str))
                {
                    parts.push(text);
                }
            }
            _ => {}
        }
    }
    normalize_title(parts.join("\n"))
}

fn apply_claude_code_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    if accumulator.source_session_id.is_none() {
        accumulator.source_session_id = string_at(value, &["sessionId"])
            .or_else(|| string_at(value, &["session_id"]))
            .or_else(|| string_at(value, &["conversation_id"]));
    }
    let timestamp = string_at(value, &["timestamp"])
        .or_else(|| string_at(value, &["created_at"]))
        .or_else(|| string_at(value, &["message", "created_at"]));
    accumulator.note_time(timestamp.clone());
    accumulator.set_title(
        string_at(value, &["summary"])
            .or_else(|| string_at(value, &["title"]))
            .or_else(|| string_at(value, &["metadata", "title"])),
        "summary",
    );
    accumulator.set_model(
        string_at(value, &["message", "model"])
            .or_else(|| string_at(value, &["model"]))
            .or_else(|| string_at(value, &["payload", "model"])),
    );
    accumulator.set_workspace_hash(
        string_at(value, &["cwd"])
            .or_else(|| string_at(value, &["projectPath"]))
            .or_else(|| string_at(value, &["workspace"])),
    );
    if let Some(usage) = claude_code_delta_usage(value) {
        let request_count = usage.request_count;
        accumulator.add_usage_with_selector(
            string_at(value, &["message", "model"])
                .or_else(|| string_at(value, &["model"]))
                .or_else(|| string_at(value, &["payload", "model"])),
            usage,
            claude_code_selector_from_line(value),
        );
        accumulator.note_activity(timestamp, request_count);
    }
}

fn codex_total_usage(value: &Value) -> Option<UsageTotals> {
    let root = value
        .pointer("/token_count/info/total_token_usage")
        .or_else(|| value.pointer("/payload/info/total_token_usage"))
        .or_else(|| value.pointer("/payload/total_token_usage"))
        .or_else(|| value.pointer("/total_token_usage"))?;
    let mut usage = UsageTotals {
        input_tokens: u64_at(root, &["input_tokens"])
            .or_else(|| u64_at(root, &["inputTokens"]))
            .unwrap_or_default(),
        output_tokens: u64_at(root, &["output_tokens"])
            .or_else(|| u64_at(root, &["outputTokens"]))
            .unwrap_or_default(),
        cache_read_tokens: u64_at(root, &["cache_read_tokens"])
            .or_else(|| u64_at(root, &["cached_input_tokens"]))
            .or_else(|| u64_at(root, &["cachedInputTokens"]))
            .unwrap_or_default(),
        // OpenAI / Codex has no cache-write concept (only cached input = cache reads).
        // Any legacy `cache_creation_tokens` we encounter is treated as 0; if some
        // future Codex transcript surfaces it, route to 5m as the safer default.
        cache_creation_5m_tokens: u64_at(root, &["cache_creation_tokens"])
            .or_else(|| u64_at(root, &["cacheCreationInputTokens"]))
            .unwrap_or_default(),
        cache_creation_1h_tokens: 0,
        reasoning_output_tokens: u64_at(root, &["reasoning_output_tokens"]).unwrap_or_default(),
        request_count: u64_at(root, &["request_count"])
            .or_else(|| u64_at(root, &["requests"]))
            .unwrap_or(1),
    };
    if usage.request_count == 0 {
        usage.request_count = 1;
    }
    Some(usage)
}

fn apply_pi_line(value: &Value, accumulator: &mut SnapshotAccumulator) {
    let event_type = string_at(value, &["type"]);
    match event_type.as_deref() {
        Some("custom") => {
            if let Some(selector) = pi_selector_from_custom(value) {
                accumulator.set_selector(selector);
            }
            accumulator.note_time(pi_timestamp_field(value));
        }
        Some("session") => {
            if accumulator.source_session_id.is_none() {
                accumulator.source_session_id =
                    string_at(value, &["session_id"]).or_else(|| string_at(value, &["sessionId"]));
            }
            accumulator.set_workspace_hash(string_at(value, &["cwd"]));
            accumulator.note_time(string_at(value, &["timestamp"]));
        }
        Some("message") => {
            // Pi user prompts arrive as `type: "message"` with role: "user". The
            // backend's message_end event omits prompt text, so this is the only
            // chance to grab a first-prompt title fallback.
            if string_eq_at(value, &["role"], "user") {
                accumulator.set_first_prompt_title(pi_message_text(value));
            }
            accumulator.note_time(pi_timestamp_field(value));
        }
        Some("message_end") => {
            let timestamp = pi_message_end_timestamp(value);
            let model = string_at(value, &["message", "model"]);
            accumulator.set_model(model.clone());
            if let Some(usage) = pi_message_end_usage(value) {
                let request_count = usage.request_count;
                let mut selector = accumulator.current_selector.clone();
                selector.merge(pi_selector_from_message_end(value));
                accumulator.add_usage_with_selector(model, usage, selector);
                accumulator.note_activity(timestamp.clone(), request_count);
            }
            accumulator.note_time(timestamp);
        }
        _ => {}
    }
}

fn pi_message_text(value: &Value) -> Option<String> {
    string_at(value, &["content"])
        .or_else(|| string_at(value, &["text"]))
        .or_else(|| string_at(value, &["message", "content"]))
        .or_else(|| text_from_array(value.get("content")))
}

fn pi_timestamp_field(value: &Value) -> Option<String> {
    string_at(value, &["timestamp"])
        .or_else(|| pi_ms_timestamp(value.get("timestamp")))
        .or_else(|| pi_ms_timestamp(value.pointer("/message/timestamp")))
}

fn pi_message_end_timestamp(value: &Value) -> Option<String> {
    pi_ms_timestamp(value.pointer("/message/timestamp"))
        .or_else(|| string_at(value, &["message", "timestamp"]))
        .or_else(|| string_at(value, &["timestamp"]))
}

fn pi_ms_timestamp(value: Option<&Value>) -> Option<String> {
    let value = value?;
    let ms = match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.parse::<i64>().ok(),
        _ => None,
    }?;
    Some(format_rfc3339_millis(ms))
}

fn format_rfc3339_millis(ms: i64) -> String {
    let total_secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000) as u32;
    let days = total_secs.div_euclid(86_400);
    let time_of_day = total_secs.rem_euclid(86_400) as u32;
    let hour = time_of_day / 3600;
    let minute = (time_of_day % 3600) / 60;
    let second = time_of_day % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

fn activity_bucket_from_timestamp(value: &str) -> Option<(String, String)> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let utc = parsed.to_offset(time::UtcOffset::UTC);
    let bucket_seconds = utc.unix_timestamp().div_euclid(3600) * 3600;
    let bucket_start = OffsetDateTime::from_unix_timestamp(bucket_seconds)
        .ok()?
        .format(&Rfc3339)
        .ok()?;
    let normalized_timestamp = utc.format(&Rfc3339).ok()?;
    Some((bucket_start, normalized_timestamp))
}

// Howard Hinnant's civil_from_days. Returns (year, month, day) from days since 1970-01-01.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

fn pi_message_end_usage(value: &Value) -> Option<UsageTotals> {
    let usage = value.pointer("/message/usage")?;
    // Pi is multi-provider (Anthropic / OpenAI / Gemini). When the underlying
    // model is Anthropic and Pi exposes the nested `cacheCreation` object with
    // ephemeral_5m / ephemeral_1h, prefer that. Otherwise the flat `cacheWrite`
    // total routes to the 5m bucket (Anthropic default TTL, and the safer guess
    // for non-Anthropic providers where the distinction does not apply).
    let (cache_5m, cache_1h) = pi_cache_creation_split(usage);
    let totals = UsageTotals {
        input_tokens: u64_at(usage, &["input"]).unwrap_or_default(),
        output_tokens: u64_at(usage, &["output"]).unwrap_or_default(),
        cache_read_tokens: u64_at(usage, &["cacheRead"])
            .or_else(|| u64_at(usage, &["cache_read"]))
            .unwrap_or_default(),
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens: u64_at(usage, &["reasoning"]).unwrap_or_default(),
        request_count: 1,
    };
    Some(totals)
}

fn pi_cache_creation_split(usage: &Value) -> (u64, u64) {
    if let Some(nested) = usage
        .get("cacheCreation")
        .or_else(|| usage.get("cache_creation"))
    {
        let cache_5m = u64_at(nested, &["ephemeral_5m_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral5mInputTokens"]))
            .unwrap_or_default();
        let cache_1h = u64_at(nested, &["ephemeral_1h_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral1hInputTokens"]))
            .unwrap_or_default();
        if cache_5m > 0 || cache_1h > 0 {
            return (cache_5m, cache_1h);
        }
    }
    let flat = u64_at(usage, &["cacheWrite"])
        .or_else(|| u64_at(usage, &["cache_write"]))
        .unwrap_or_default();
    (flat, 0)
}

fn claude_code_delta_usage(value: &Value) -> Option<UsageTotals> {
    let root = value
        .pointer("/message/usage")
        .or_else(|| value.pointer("/usage"))
        .or_else(|| value.pointer("/payload/usage"))?;
    let (cache_5m, cache_1h) = claude_code_cache_creation_split(root);
    let usage = UsageTotals {
        input_tokens: u64_at(root, &["input_tokens"])
            .or_else(|| u64_at(root, &["inputTokens"]))
            .unwrap_or_default(),
        output_tokens: u64_at(root, &["output_tokens"])
            .or_else(|| u64_at(root, &["outputTokens"]))
            .unwrap_or_default(),
        cache_read_tokens: u64_at(root, &["cache_read_input_tokens"])
            .or_else(|| u64_at(root, &["cache_read_tokens"]))
            .unwrap_or_default(),
        cache_creation_5m_tokens: cache_5m,
        cache_creation_1h_tokens: cache_1h,
        reasoning_output_tokens: u64_at(root, &["reasoning_output_tokens"]).unwrap_or_default(),
        request_count: 1,
    };
    Some(usage)
}

// Anthropic exposes prompt-cache writes as `usage.cache_creation.ephemeral_5m_input_tokens`
// and `ephemeral_1h_input_tokens` (the 5m / 1h TTL split). The pricing page rates those
// at 1.25x and 2x base input respectively, so the split is load-bearing for cost. If only
// the flat `cache_creation_input_tokens` is present (older transcripts), default to the
// 5m bucket which is Anthropic's default TTL.
fn claude_code_cache_creation_split(root: &Value) -> (u64, u64) {
    if let Some(nested) = root
        .get("cache_creation")
        .or_else(|| root.get("cacheCreation"))
    {
        let cache_5m = u64_at(nested, &["ephemeral_5m_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral5mInputTokens"]))
            .unwrap_or_default();
        let cache_1h = u64_at(nested, &["ephemeral_1h_input_tokens"])
            .or_else(|| u64_at(nested, &["ephemeral1hInputTokens"]))
            .unwrap_or_default();
        if cache_5m > 0 || cache_1h > 0 {
            return (cache_5m, cache_1h);
        }
    }
    let flat = u64_at(root, &["cache_creation_input_tokens"])
        .or_else(|| u64_at(root, &["cache_creation_tokens"]))
        .unwrap_or_default();
    (flat, 0)
}

#[derive(Debug, Clone)]
struct CandidateFile {
    path: PathBuf,
    size_bytes: u64,
    modified_unix_seconds: u64,
    source_file_fingerprint: String,
}

impl CodexTitleMetadata {
    fn load_from_roots(roots: &[PathBuf]) -> Self {
        let mut metadata = Self::default();
        let mut sidecar_parts = Vec::new();
        let mut codex_dirs = BTreeSet::new();
        for root in roots {
            if let Some(parent) = root.parent() {
                codex_dirs.insert(parent.to_path_buf());
            }
        }

        for codex_dir in codex_dirs {
            let config_path = codex_dir.join("config.toml");
            sidecar_parts.push(sidecar_stat_fingerprint(&config_path));
            metadata
                .default_selector
                .merge(load_codex_config_selector(&config_path));

            let state_path = codex_dir.join("state_5.sqlite");
            sidecar_parts.push(sidecar_stat_fingerprint(&state_path));
            load_codex_sqlite_titles(&state_path, &mut metadata.titles);

            let index_path = codex_dir.join("session_index.jsonl");
            sidecar_parts.push(sidecar_stat_fingerprint(&index_path));
            load_codex_session_index_titles(&index_path, &mut metadata.titles);
        }

        metadata.sidecar_fingerprint = sha256_hex_owned(&sidecar_parts);
        metadata
    }
}

fn load_codex_session_index_titles(
    path: &Path,
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
) {
    let Ok(file) = File::open(path) else {
        return;
    };
    let reader = BufReader::new(file);
    for line in reader.lines().map_while(|line| line.ok()) {
        let Ok(value) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let Some(id) = string_at(&value, &["id"]) else {
            continue;
        };
        insert_codex_sidecar_title(
            titles,
            id,
            string_at(&value, &["thread_name"])
                .or_else(|| string_at(&value, &["title"]))
                .or_else(|| string_at(&value, &["name"])),
            "session_index",
            true,
        );
    }
}

fn load_codex_sqlite_titles(path: &Path, titles: &mut BTreeMap<String, CodexTitleCandidate>) {
    let Ok(connection) = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY) else {
        return;
    };
    let Ok(mut statement) =
        connection.prepare("SELECT id, title FROM threads WHERE title IS NOT NULL AND title != ''")
    else {
        return;
    };
    let Ok(rows) = statement.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    }) else {
        return;
    };
    for row in rows.flatten() {
        insert_codex_sidecar_title(titles, row.0, Some(row.1), "session_index", false);
    }
}

fn load_codex_config_selector(path: &Path) -> SelectorCapture {
    let Ok(file) = File::open(path) else {
        return SelectorCapture::default();
    };
    let mut raw = String::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else {
            return SelectorCapture::default();
        };
        raw.push_str(line.as_str());
        raw.push('\n');
    }
    let Ok(document) = raw.parse::<DocumentMut>() else {
        return SelectorCapture::default();
    };
    let mut selector = SelectorCapture::default();
    if let Some(service_tier) = document
        .get("service_tier")
        .and_then(Item::as_value)
        .and_then(|value| value.as_str())
    {
        let value = Value::String(service_tier.to_string());
        insert_selector_raw(
            &mut selector,
            "service_tier",
            "codex.config.service_tier",
            &value,
        );
    }
    if let Some(fast_mode) = document
        .get("features")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_mode"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
    {
        let value = Value::Bool(fast_mode);
        insert_selector_raw(
            &mut selector,
            "mode",
            "codex.config.features.fast_mode",
            &value,
        );
    }
    let top_level_fast_default_opt_out = document
        .get("fast_default_opt_out")
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let notice_fast_default_opt_out = document
        .get("notice")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("fast_default_opt_out"))
        .and_then(Item::as_value)
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let fast_default_opt_out_source = if top_level_fast_default_opt_out {
        Some("codex.config.fast_default_opt_out")
    } else if notice_fast_default_opt_out {
        Some("codex.config.notice.fast_default_opt_out")
    } else {
        None
    };
    if selector.is_empty() {
        let Some(source) = fast_default_opt_out_source else {
            return selector;
        };
        let standard = Value::String("standard".to_string());
        insert_selector_raw(&mut selector, "service_tier", source, &standard);
        insert_selector_raw(&mut selector, "mode", source, &standard);
    }
    selector
}

fn insert_codex_sidecar_title(
    titles: &mut BTreeMap<String, CodexTitleCandidate>,
    id: String,
    title: Option<String>,
    source: &str,
    overwrite: bool,
) {
    let id = id.trim();
    if id.is_empty() {
        return;
    }
    let Some(title) = title.and_then(|value| normalize_display_title(value, source)) else {
        return;
    };
    if !overwrite && titles.contains_key(id) {
        return;
    }
    titles.insert(
        id.to_string(),
        CodexTitleCandidate {
            title,
            source: source.to_string(),
        },
    );
}

fn sidecar_stat_fingerprint(path: &Path) -> String {
    match fs::metadata(path) {
        Ok(metadata) => {
            let modified_unix_seconds = metadata
                .modified()
                .ok()
                .and_then(unix_seconds)
                .unwrap_or_default();
            format!(
                "{}:{}:{}",
                path.to_string_lossy(),
                metadata.len(),
                modified_unix_seconds
            )
        }
        Err(_) => format!("{}:missing", path.to_string_lossy()),
    }
}

fn collect_recent_jsonl_files(
    source: SnapshotSource,
    root: &Path,
    files: &mut Vec<CandidateFile>,
    source_fingerprint_context: &str,
    backfill_window_days: u64,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }
    for entry in fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))? {
        let entry = entry.with_context(|| format!("read directory entry {}", root.display()))?;
        let path = entry.path();
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.is_dir() {
            collect_recent_jsonl_files(
                source,
                &path,
                files,
                source_fingerprint_context,
                backfill_window_days,
            )?;
            continue;
        }
        if path.extension().and_then(|value| value.to_str()) != Some("jsonl") {
            continue;
        }
        let modified_unix_seconds = metadata
            .modified()
            .ok()
            .and_then(unix_seconds)
            .unwrap_or_default();
        if !is_recent_enough(modified_unix_seconds, backfill_window_days) {
            continue;
        }
        files.push(CandidateFile {
            source_file_fingerprint: source_file_fingerprint_with_context(
                &path,
                metadata.len(),
                modified_unix_seconds,
                source.parser_version(),
                source_fingerprint_context,
            ),
            path,
            size_bytes: metadata.len(),
            modified_unix_seconds,
        });
    }
    Ok(())
}

fn is_recent_enough(modified_unix_seconds: u64, backfill_window_days: u64) -> bool {
    let Some(now) = unix_seconds(SystemTime::now()) else {
        return true;
    };
    is_recent_enough_at(modified_unix_seconds, now, backfill_window_days)
}

fn is_recent_enough_at(
    modified_unix_seconds: u64,
    now_unix_seconds: u64,
    backfill_window_days: u64,
) -> bool {
    let window_seconds = effective_backfill_window_days(backfill_window_days) * 24 * 60 * 60;
    modified_unix_seconds >= now_unix_seconds.saturating_sub(window_seconds)
}

fn effective_backfill_window_days(requested_backfill_window_days: u64) -> u64 {
    requested_backfill_window_days.min(BACKFILL_WINDOW_DAYS)
}

fn unix_seconds(value: SystemTime) -> Option<u64> {
    value
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

impl ScanIndex {
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let file =
            File::open(path).with_context(|| format!("open scan index {}", path.display()))?;
        serde_json::from_reader(file)
            .with_context(|| format!("parse scan index {}", path.display()))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create scan index directory {}", parent.display()))?;
        }
        let file =
            File::create(path).with_context(|| format!("create scan index {}", path.display()))?;
        serde_json::to_writer_pretty(file, self)
            .with_context(|| format!("write scan index {}", path.display()))
    }

    fn should_process(&self, candidate: &CandidateFile) -> bool {
        let key = local_index_key(&candidate.path);
        self.files.get(&key).map_or(true, |entry| {
            entry.size_bytes != candidate.size_bytes
                || entry.modified_unix_seconds != candidate.modified_unix_seconds
                || entry.source_file_fingerprint != candidate.source_file_fingerprint
        })
    }

    fn record(&mut self, candidate: CandidateFile, last_snapshot_fingerprint: Option<String>) {
        self.files.insert(
            local_index_key(&candidate.path),
            ScanIndexEntry {
                size_bytes: candidate.size_bytes,
                modified_unix_seconds: candidate.modified_unix_seconds,
                source_file_fingerprint: candidate.source_file_fingerprint,
                last_snapshot_fingerprint,
            },
        );
    }
}

pub fn source_file_fingerprint(
    path: &Path,
    size_bytes: u64,
    modified_unix_seconds: u64,
    parser_version: &str,
) -> String {
    source_file_fingerprint_with_context(
        path,
        size_bytes,
        modified_unix_seconds,
        parser_version,
        "",
    )
}

fn source_file_fingerprint_with_context(
    path: &Path,
    size_bytes: u64,
    modified_unix_seconds: u64,
    parser_version: &str,
    source_fingerprint_context: &str,
) -> String {
    sha256_hex(&[
        &path.to_string_lossy(),
        &size_bytes.to_string(),
        &modified_unix_seconds.to_string(),
        parser_version,
        source_fingerprint_context,
    ])
}

fn local_index_key(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn normalize_title(value: String) -> Option<String> {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.is_empty() {
        None
    } else {
        Some(normalized.chars().take(255).collect())
    }
}

fn normalize_display_title(value: String, source: &str) -> Option<String> {
    let normalized = normalize_title(value)?;
    if is_safe_display_title(&normalized, source) {
        Some(normalized)
    } else {
        None
    }
}

fn first_prompt_display_title(value: String) -> Option<String> {
    let raw = value.trim();
    if raw.is_empty() || contains_blocked_prompt_fragment(raw) {
        return None;
    }
    let first_line = raw.lines().find_map(|line| {
        let trimmed = line
            .trim()
            .trim_start_matches(['#', '-', '*', '>', ' '])
            .trim();
        (!trimmed.is_empty()).then_some(trimmed)
    })?;
    let normalized = normalize_title(first_line.to_string())?;
    if normalized.chars().count() > 80 || normalized.split_whitespace().count() > 12 {
        return None;
    }
    normalize_display_title(normalized, "first_prompt")
}

fn is_safe_display_title(value: &str, source: &str) -> bool {
    let char_count = value.chars().count();
    if char_count == 0 || char_count > 120 {
        return false;
    }
    let lowered = value.to_ascii_lowercase();
    if matches!(
        lowered.as_str(),
        "assistant"
            | "chat"
            | "codex"
            | "codex session"
            | "conversation"
            | "new chat"
            | "new session"
            | "session"
            | "untitled"
            | "untitled session"
    ) {
        return false;
    }
    if is_codex_tool_call_name(&lowered)
        || looks_like_raw_identifier(value)
        || looks_like_shell_command(&lowered)
        || looks_like_setup_text(&lowered)
        || contains_blocked_prompt_fragment(value)
    {
        return false;
    }
    if source == "first_prompt"
        && lowered.len() <= 8
        && matches!(
            lowered.as_str(),
            "fix" | "fix it" | "help" | "help me" | "question"
        )
    {
        return false;
    }
    true
}

fn contains_blocked_prompt_fragment(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("<instructions>")
        || lowered.contains("<environment_context>")
        || lowered.contains("agents.md instructions")
        || lowered.contains("a previous agent produced the plan below")
        || (lowered.contains("## summary") && lowered.contains("## test plan"))
        || lowered.contains("knowledge cutoff:")
        || lowered.contains("current date:")
}

fn looks_like_setup_text(lowered: &str) -> bool {
    lowered.starts_with("you are ")
        || lowered.starts_with("system:")
        || lowered.starts_with("developer:")
        || lowered.starts_with("assistant:")
        || lowered.starts_with("tool:")
        || lowered.starts_with("environment_context")
        || lowered.starts_with("<environment_context")
        || lowered.starts_with("<instructions")
}

fn looks_like_shell_command(lowered: &str) -> bool {
    const COMMAND_PREFIXES: &[&str] = &[
        "$ ", "cargo ", "cat ", "cd ", "curl ", "docker ", "gcloud ", "git ", "jq ", "kubectl ",
        "ls ", "npm ", "pnpm ", "python ", "python3 ", "rg ", "sed ", "sqlite3 ", "uv ", "wt ",
        "yarn ",
    ];
    COMMAND_PREFIXES
        .iter()
        .any(|prefix| lowered.starts_with(prefix))
}

fn is_codex_tool_call_name(lowered: &str) -> bool {
    const TOOL_NAMES: &[&str] = &[
        "apply_patch",
        "close_agent",
        "create_goal",
        "exec_command",
        "find",
        "get_goal",
        "imagegen",
        "list_mcp_resource_templates",
        "list_mcp_resources",
        "open",
        "parallel",
        "read_mcp_resource",
        "request_user_input",
        "resume_agent",
        "screenshot",
        "send_input",
        "spawn_agent",
        "tool_search_tool",
        "update_goal",
        "update_plan",
        "view_image",
        "wait_agent",
        "weather",
        "write_stdin",
    ];
    const TOOL_PREFIXES: &[&str] = &[
        "functions.",
        "image_gen.",
        "multi_tool_use.",
        "tool_search.",
        "web.",
    ];
    TOOL_NAMES.contains(&lowered)
        || TOOL_PREFIXES
            .iter()
            .any(|prefix| lowered.starts_with(prefix))
}

fn looks_like_raw_identifier(value: &str) -> bool {
    let trimmed = value.trim();
    if is_uuid_like(trimmed) {
        return true;
    }
    let lowered = trimmed.to_ascii_lowercase();
    if lowered.starts_with("rollout-") && lowered.len() >= 44 {
        return true;
    }
    if lowered.starts_with("session_") || lowered.starts_with("sess_") {
        return true;
    }
    let has_space = trimmed.chars().any(char::is_whitespace);
    let ascii_token = trimmed
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'));
    let has_digit = trimmed.chars().any(|ch| ch.is_ascii_digit());
    !has_space && ascii_token && has_digit && trimmed.len() >= 24
}

fn is_uuid_like(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return false;
    }
    for (index, byte) in bytes.iter().enumerate() {
        match index {
            8 | 13 | 18 | 23 => {
                if *byte != b'-' {
                    return false;
                }
            }
            _ => {
                if !byte.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

fn codex_session_id_from_path(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    if stem.len() >= 36 {
        let suffix = &stem[stem.len() - 36..];
        if is_uuid_like(suffix) {
            return Some(suffix.to_string());
        }
    }
    None
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::String(value) if !value.trim().is_empty() => Some(value.trim().to_string()),
        _ => None,
    }
}

fn string_eq_at(value: &Value, path: &[&str], expected: &str) -> bool {
    string_at(value, path).is_some_and(|value| value == expected)
}

fn u64_at(value: &Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        Value::Number(number) => number.as_u64(),
        Value::String(value) => value.parse::<u64>().ok(),
        _ => None,
    }
}

fn sha256_hex(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn sha256_hex_owned(parts: &[String]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.as_bytes());
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

pub fn paths_from_events(paths: impl IntoIterator<Item = PathBuf>) -> BTreeSet<PathBuf> {
    paths
        .into_iter()
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("jsonl"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("ottto-{name}-{unique}.jsonl"))
    }

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ottto-{name}-{unique}"));
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    #[test]
    fn backfill_window_defaults_to_six_months_and_starts_from_now_when_zero() {
        let now = 1_800_000_000;
        let day_seconds = 24 * 60 * 60;

        assert_eq!(BACKFILL_WINDOW_DAYS, 183);
        assert!(is_recent_enough_at(
            now - BACKFILL_WINDOW_DAYS * day_seconds,
            now,
            BACKFILL_WINDOW_DAYS,
        ));
        assert!(!is_recent_enough_at(
            now - BACKFILL_WINDOW_DAYS * day_seconds - 1,
            now,
            BACKFILL_WINDOW_DAYS,
        ));
        assert!(is_recent_enough_at(now, now, 0));
        assert!(!is_recent_enough_at(now - 1, now, 0));
    }

    #[test]
    fn scan_policy_caps_recent_files_and_reports_partial_state() {
        let root = temp_dir("scan-policy-cap");
        for index in 0..=MAX_BACKFILL_FILES_PER_SOURCE {
            let path = root.join(format!("session-{index:04}.jsonl"));
            fs::write(
                path,
                concat!(
                    "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-4444-7000-9000-dddddddddddd\"}}\n",
                    "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
                ),
            )
            .expect("write fixture");
        }

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            std::slice::from_ref(&root),
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        assert_eq!(scan.backfill_window_days, BACKFILL_WINDOW_DAYS);
        assert_eq!(scan.backfill_file_limit, MAX_BACKFILL_FILES_PER_SOURCE);
        assert_eq!(
            scan.discovered_file_count,
            MAX_BACKFILL_FILES_PER_SOURCE + 1
        );
        assert_eq!(scan.skipped_file_count_due_to_limit, 1);
        assert!(scan.scan_cap_hit);
        assert_eq!(scan.scanned_file_count, MAX_BACKFILL_FILES_PER_SOURCE);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn scan_policy_never_expands_past_default_window() {
        assert_eq!(
            effective_backfill_window_days(BACKFILL_WINDOW_DAYS + 30),
            BACKFILL_WINDOW_DAYS,
        );
        assert_eq!(effective_backfill_window_days(30), 30);
    }

    #[test]
    fn codex_parser_extracts_current_jsonl_shape_without_prompts() {
        let path = temp_file("codex");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019dfb9a-1f58-7580-afe7-e8d4f969b0f7\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"thread_name_updated\",\"thread_id\":\"019dfb9a-1f58-7580-afe7-e8d4f969b0f7\",\"thread_name\":\"Improve sessions UI\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:02:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\",\"cwd\":\"/Users/example/work\"}}\n",
                "{\"timestamp\":\"2026-05-06T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":25,\"reasoning_output_tokens\":7,\"request_count\":3},\"model_context_window\":258400},\"rate_limits\":{\"limit_id\":\"codex\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-06T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(
            item.source_session_id,
            "019dfb9a-1f58-7580-afe7-e8d4f969b0f7"
        );
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Improve sessions UI")
        );
        assert_eq!(item.input_tokens, 100);
        assert_eq!(item.cache_read_tokens, 40);
        assert_eq!(item.output_tokens, 25);
        assert_eq!(item.reasoning_output_tokens, 7);
        assert_eq!(item.request_count, 3);
        assert_eq!(
            item.activity_buckets,
            vec![SnapshotActivityBucket {
                bucket_start: "2026-05-06T10:00:00Z".to_string(),
                request_count: 3,
                first_activity_at: Some("2026-05-06T10:03:00Z".to_string()),
                last_activity_at: Some("2026-05-06T10:03:00Z".to_string()),
            }]
        );
        assert_eq!(item.model_usage[0].model, "gpt-5.5");
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("inclusive_cached")
        );
        assert!(item.workspace_hash.is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_transcript_title_wins_over_sidecar_titles() {
        let path = temp_file("codex-title-priority");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-1111-7000-9000-aaaaaaaaaaaa\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"thread_name_updated\",\"thread_name\":\"Transcript title wins\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"First prompt fallback should not win\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let mut metadata = CodexTitleMetadata::default();
        insert_codex_sidecar_title(
            &mut metadata.titles,
            "019e253c-1111-7000-9000-aaaaaaaaaaaa".to_string(),
            Some("Sidecar title loses".to_string()),
            "session_index",
            true,
        );

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Transcript title wins")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("transcript_title")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_session_index_sidecar_supplies_title_without_jsonl_title() {
        let codex_dir = temp_dir("codex-session-index");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        let path = sessions_dir
            .join("rollout-2026-05-14T10-00-00-019e253c-2222-7000-9000-bbbbbbbbbbbb.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-2222-7000-9000-bbbbbbbbbbbb\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":20,\"output_tokens\":5},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        fs::write(
            codex_dir.join("session_index.jsonl"),
            "{\"id\":\"019e253c-2222-7000-9000-bbbbbbbbbbbb\",\"thread_name\":\"Daily bug scan\",\"updated_at\":1777777777}\n",
        )
        .expect("write session index");

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        assert_eq!(scan.snapshots.len(), 1);
        let item = &scan.snapshots[0];
        assert_eq!(item.session_display_name.as_deref(), Some("Daily bug scan"));
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("session_index")
        );

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_state_sqlite_sidecar_supplies_title_when_session_index_has_none() {
        let codex_dir = temp_dir("codex-state-sqlite");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions dir");
        let path = sessions_dir
            .join("rollout-2026-05-14T10-00-00-019e253c-3333-7000-9000-cccccccccccc.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-3333-7000-9000-cccccccccccc\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":30,\"output_tokens\":6},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let connection = Connection::open(codex_dir.join("state_5.sqlite")).expect("open sqlite");
        connection
            .execute(
                "CREATE TABLE threads (id TEXT PRIMARY KEY, title TEXT NOT NULL)",
                [],
            )
            .expect("create threads");
        connection
            .execute(
                "INSERT INTO threads (id, title) VALUES (?1, ?2)",
                [
                    "019e253c-3333-7000-9000-cccccccccccc",
                    "Pricing Review Guarded Autopilot",
                ],
            )
            .expect("insert thread");
        drop(connection);

        let mut index = ScanIndex::default();
        let scan = scan_source_roots(
            SnapshotSource::Codex,
            &[sessions_dir],
            &mut index,
            "2026-05-14T10:04:00Z",
            BACKFILL_WINDOW_DAYS,
        )
        .expect("scan");

        assert_eq!(scan.snapshots.len(), 1);
        let item = &scan.snapshots[0];
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Pricing Review Guarded Autopilot")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("session_index")
        );

        let _ = fs::remove_dir_all(codex_dir);
    }

    #[test]
    fn codex_first_prompt_fallback_is_filtered() {
        let path = temp_file("codex-first-prompt");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-4444-7000-9000-dddddddddddd\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Fix local telemetry upload\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Fix local telemetry upload")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let noisy_path = temp_file("codex-noisy-first-prompt");
        fs::write(
            &noisy_path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-5555-7000-9000-eeeeeeeeeeee\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"# AGENTS.md instructions for /repo\\n\\n<INSTRUCTIONS>Do not use this as a title</INSTRUCTIONS>\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write noisy fixture");

        let noisy_item = parse_codex_jsonl_file(
            &noisy_path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");
        assert_eq!(noisy_item.session_display_name, None);
        assert_eq!(noisy_item.session_display_name_source, None);

        let _ = fs::remove_file(path);
        let _ = fs::remove_file(noisy_path);
    }

    #[test]
    fn upload_policy_strips_titles_and_workspace_labels_before_upload() {
        let path = temp_file("codex-upload-policy");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-5555-7000-9000-eeeeeeeeeeef\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"thread_name_updated\",\"thread_name\":\"Private task title\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":40,\"output_tokens\":8},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let mut item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");
        item.workspace_display_label = Some("Checkout service".to_string());
        item.workspace_label_source = Some("user_approved".to_string());
        let original_fingerprint = item.snapshot_fingerprint.clone();
        let mut snapshots = vec![item];

        apply_upload_policy(
            SnapshotSource::Codex,
            &mut snapshots,
            SnapshotUploadPolicy {
                session_titles_enabled: false,
                workspace_labels_enabled: false,
            },
        );

        let stripped = &snapshots[0];
        assert_eq!(stripped.session_display_name, None);
        assert_eq!(stripped.session_display_name_source, None);
        assert_eq!(stripped.workspace_display_label, None);
        assert_eq!(stripped.workspace_label_source, None);
        assert_ne!(stripped.snapshot_fingerprint, original_fingerprint);
        let serialized = serde_json::to_string(stripped).expect("serialize");
        assert!(!serialized.contains("Private task title"));
        assert!(!serialized.contains("Checkout service"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_title_changes_affect_snapshot_and_source_file_fingerprints() {
        let path = temp_file("codex-title-fingerprint");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e253c-6666-7000-9000-ffffffffffff\"}}\n",
                "{\"timestamp\":\"2026-05-14T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":50,\"output_tokens\":9},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let mut first = CodexTitleMetadata::default();
        insert_codex_sidecar_title(
            &mut first.titles,
            "019e253c-6666-7000-9000-ffffffffffff".to_string(),
            Some("First title".to_string()),
            "session_index",
            true,
        );
        let mut second = CodexTitleMetadata::default();
        insert_codex_sidecar_title(
            &mut second.titles,
            "019e253c-6666-7000-9000-ffffffffffff".to_string(),
            Some("Second title".to_string()),
            "session_index",
            true,
        );

        let first_item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
            &first,
        )
        .expect("parse first")
        .expect("first snapshot");
        let second_item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-14T10:04:00Z",
            "file-fingerprint".to_string(),
            &second,
        )
        .expect("parse second")
        .expect("second snapshot");
        assert_ne!(
            first_item.snapshot_fingerprint,
            second_item.snapshot_fingerprint
        );

        let source_file = source_file_fingerprint_with_context(
            &path,
            100,
            1_777_777_777,
            CODEX_SNAPSHOT_PARSER_VERSION,
            "sidecar-a",
        );
        let source_file_after_sidecar_change = source_file_fingerprint_with_context(
            &path,
            100,
            1_777_777_777,
            CODEX_SNAPSHOT_PARSER_VERSION,
            "sidecar-b",
        );
        assert_ne!(source_file, source_file_after_sidecar_change);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn source_file_fingerprint_changes_with_parser_version() {
        let path = Path::new("/redacted/session.jsonl");
        let old = source_file_fingerprint(path, 100, 1_777_777_777, "codex_jsonl:v2");
        let current =
            source_file_fingerprint(path, 100, 1_777_777_777, CODEX_SNAPSHOT_PARSER_VERSION);

        assert_ne!(old, current);
    }

    #[test]
    fn codex_parser_ignores_function_call_names_as_titles() {
        let path = temp_file("codex-tool-name");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-14T09:19:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2523-aa35-7b62-a712-00c2a0fea2ff\"}}\n",
                "{\"timestamp\":\"2026-05-14T09:20:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"exec_command\",\"call_id\":\"call-1\",\"arguments\":\"{}\"}}\n",
                "{\"timestamp\":\"2026-05-14T09:21:00Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"function_call\",\"name\":\"write_stdin\",\"call_id\":\"call-2\",\"arguments\":\"{}\"}}\n",
                "{\"timestamp\":\"2026-05-14T09:22:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":100,\"cached_input_tokens\":40,\"output_tokens\":25,\"request_count\":3},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-14T09:23:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(item.session_display_name, None);
        assert_eq!(item.session_display_name_source, None);
        assert_eq!(item.input_tokens, 100);
        assert_eq!(item.model_usage[0].model, "gpt-5.5");

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_splits_cumulative_usage_by_selector() {
        let path = temp_file("codex-selector-split");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-111111111111\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"service_tier\":\"standard\",\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":30,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n",
                "{\"timestamp\":\"2026-05-19T10:03:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"service_tier\":\"fast\",\"total_token_usage\":{\"input_tokens\":300,\"output_tokens\":90,\"request_count\":2},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(item.input_tokens, 300);
        assert_eq!(item.output_tokens, 90);
        assert_eq!(item.request_count, 2);
        assert_eq!(
            item.activity_buckets,
            vec![SnapshotActivityBucket {
                bucket_start: "2026-05-19T10:00:00Z".to_string(),
                request_count: 2,
                first_activity_at: Some("2026-05-19T10:02:00Z".to_string()),
                last_activity_at: Some("2026-05-19T10:03:00Z".to_string()),
            }]
        );
        assert_eq!(item.model_usage.len(), 2);
        let standard = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("standard")
            })
            .expect("standard row");
        let fast = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("fast")
            })
            .expect("fast row");
        assert_eq!(standard.input_tokens, 100);
        assert_eq!(standard.output_tokens, 30);
        assert_eq!(fast.input_tokens, 200);
        assert_eq!(fast.output_tokens, 60);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_reads_nested_selector_aliases_without_reasoning_effort() {
        let path = temp_file("codex-selector-aliases");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-444444444444\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"turn_context\",\"payload\":{\"model\":\"gpt-5.5\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:02:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"actual_service_tier\":\"priority\",\"reasoning_effort\":\"high\",\"selector_context\":{\"batchMode\":true,\"dataResidency\":\"US\",\"cache_write_ttl_seconds\":3600},\"total_token_usage\":{\"input_tokens\":100,\"output_tokens\":30,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_codex_jsonl_file(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("priority")
        );
        assert_eq!(selector.get("batch_mode").map(String::as_str), Some("true"));
        assert_eq!(selector.get("region_mode").map(String::as_str), Some("us"));
        assert_eq!(selector.get("cache_ttl").map(String::as_str), Some("3600"));
        assert_eq!(selector.get("mode"), None);
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("payload.info.actual_service_tier")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn codex_parser_uses_config_fast_mode_as_low_confidence_default() {
        let root = temp_dir("codex-config-selector");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        fs::write(
            codex_dir.join("config.toml"),
            "service_tier = \"fast\"\n[features]\nfast_mode = true\n",
        )
        .expect("write config");
        let path = sessions_dir.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-222222222222\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
        )
        .expect("parse")
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("fast")
        );
        assert_eq!(selector.get("mode").map(String::as_str), Some("fast"));
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("mode")
                .map(String::as_str),
            Some("codex.config.features.fast_mode")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_parser_uses_fast_default_opt_out_as_standard_default() {
        let root = temp_dir("codex-config-standard-selector");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        fs::write(
            codex_dir.join("config.toml"),
            "model = \"gpt-5.5\"\nfast_default_opt_out = true\n",
        )
        .expect("write config");
        let path = sessions_dir.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-333333333333\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
        )
        .expect("parse")
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("standard")
        );
        assert_eq!(selector.get("mode").map(String::as_str), Some("standard"));
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("codex.config.fast_default_opt_out")
        );
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("mode")
                .map(String::as_str),
            Some("codex.config.fast_default_opt_out")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn codex_parser_uses_notice_fast_default_opt_out_as_standard_default() {
        let root = temp_dir("codex-notice-standard-selector");
        let codex_dir = root.join(".codex");
        let sessions_dir = codex_dir.join("sessions");
        fs::create_dir_all(&sessions_dir).expect("create sessions");
        fs::write(
            codex_dir.join("config.toml"),
            "model = \"gpt-5.5\"\n[notice]\nfast_default_opt_out = true\n",
        )
        .expect("write config");
        let path = sessions_dir.join("session.jsonl");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"019e2700-cafe-7000-9000-444444444444\"}}\n",
                "{\"timestamp\":\"2026-05-19T10:01:00Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"token_count\",\"info\":{\"total_token_usage\":{\"input_tokens\":10,\"output_tokens\":4,\"request_count\":1},\"model\":\"gpt-5.5\"}}}\n"
            ),
        )
        .expect("write fixture");
        let metadata = CodexTitleMetadata::load_from_roots(std::slice::from_ref(&sessions_dir));

        let item = parse_codex_jsonl_file_with_title_metadata(
            &path,
            "2026-05-19T10:04:00Z",
            "file-fingerprint".to_string(),
            &metadata,
        )
        .expect("parse")
        .expect("snapshot");

        let selector = &item.model_usage[0].selector_context;
        assert_eq!(
            selector.get("service_tier").map(String::as_str),
            Some("standard")
        );
        assert_eq!(selector.get("mode").map(String::as_str), Some("standard"));
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("service_tier")
                .map(String::as_str),
            Some("codex.config.notice.fast_default_opt_out")
        );
        assert_eq!(
            item.model_usage[0]
                .selector_sources
                .get("mode")
                .map(String::as_str),
            Some("codex.config.notice.fast_default_opt_out")
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn claude_code_parser_sums_message_usage_and_uses_summary_title() {
        let path = temp_file("claude");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:00:00Z\",\"sessionId\":\"claude-session-1\",\"summary\":\"Fix telemetry labels\"}\n",
                "{\"timestamp\":\"2026-05-06T10:01:00Z\",\"sessionId\":\"claude-session-1\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5,\"cache_read_input_tokens\":3}}}\n",
                "{\"timestamp\":\"2026-05-06T10:02:00Z\",\"sessionId\":\"claude-session-1\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9,\"cache_creation_input_tokens\":2}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-06T10:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(item.source_session_id, "claude-session-1");
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Fix telemetry labels")
        );
        assert_eq!(item.input_tokens, 17);
        assert_eq!(item.cache_read_tokens, 3);
        // Flat `cache_creation_input_tokens` with no nested split defaults to the 5m bucket
        // (Anthropic's default TTL).
        assert_eq!(item.cache_creation_5m_tokens, 2);
        assert_eq!(item.cache_creation_1h_tokens, 0);
        assert_eq!(item.output_tokens, 14);
        assert_eq!(item.request_count, 2);
        assert_eq!(
            item.activity_buckets,
            vec![SnapshotActivityBucket {
                bucket_start: "2026-05-06T10:00:00Z".to_string(),
                request_count: 2,
                first_activity_at: Some("2026-05-06T10:01:00Z".to_string()),
                last_activity_at: Some("2026-05-06T10:02:00Z".to_string()),
            }]
        );
        assert_eq!(item.model_usage[0].model, "claude-sonnet-4-6");
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("uncached")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_builds_distinct_hourly_activity_buckets() {
        let path = temp_file("claude-activity-buckets");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-06T10:59:59Z\",\"sessionId\":\"claude-session-buckets\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":10,\"output_tokens\":5}}}\n",
                "{\"timestamp\":\"2026-05-06T11:00:01Z\",\"sessionId\":\"claude-session-buckets\",\"message\":{\"model\":\"claude-sonnet-4-6\",\"usage\":{\"input_tokens\":7,\"output_tokens\":9}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-06T11:04:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(
            item.activity_buckets,
            vec![
                SnapshotActivityBucket {
                    bucket_start: "2026-05-06T10:00:00Z".to_string(),
                    request_count: 1,
                    first_activity_at: Some("2026-05-06T10:59:59Z".to_string()),
                    last_activity_at: Some("2026-05-06T10:59:59Z".to_string()),
                },
                SnapshotActivityBucket {
                    bucket_start: "2026-05-06T11:00:00Z".to_string(),
                    request_count: 1,
                    first_activity_at: Some("2026-05-06T11:00:01Z".to_string()),
                    last_activity_at: Some("2026-05-06T11:00:01Z".to_string()),
                },
            ]
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_preserves_speed_region_and_batch_selectors() {
        let path = temp_file("claude-selectors");
        fs::write(
            &path,
            concat!(
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"sessionId\":\"claude-selector\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":100,\"output_tokens\":30,\"speed\":\"fast\",\"inference_geo\":\"us\"}}}\n",
                "{\"timestamp\":\"2026-05-19T10:05:00Z\",\"sessionId\":\"claude-selector\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":200,\"output_tokens\":60,\"speed\":\"standard\",\"batch_mode\":true,\"context_bucket\":\"long\"}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-19T10:10:00Z",
            "file-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(item.model_usage.len(), 2);
        let fast = item
            .model_usage
            .iter()
            .find(|row| row.selector_context.get("speed_mode").map(String::as_str) == Some("fast"))
            .expect("fast row");
        let batch = item
            .model_usage
            .iter()
            .find(|row| row.selector_context.get("batch_mode").map(String::as_str) == Some("true"))
            .expect("batch row");
        assert_eq!(
            fast.selector_context.get("region_mode").map(String::as_str),
            Some("us")
        );
        assert_eq!(
            fast.selector_context
                .get("service_tier")
                .map(String::as_str),
            Some("fast")
        );
        assert_eq!(
            batch
                .selector_context
                .get("context_bucket")
                .map(String::as_str),
            Some("long")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn claude_code_parser_extracts_ephemeral_cache_creation_split() {
        let path = temp_file("claude-ephemeral");
        fs::write(
            &path,
            concat!(
                // 1h-heavy block (mirrors the real Claude Code transcript on disk).
                "{\"timestamp\":\"2026-05-19T10:00:00Z\",\"sessionId\":\"claude-session-eph\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":6,\"output_tokens\":370,\"cache_read_input_tokens\":0,\"cache_creation_input_tokens\":33383,\"cache_creation\":{\"ephemeral_5m_input_tokens\":0,\"ephemeral_1h_input_tokens\":33383}}}}\n",
                // 5m-heavy block.
                "{\"timestamp\":\"2026-05-19T10:05:00Z\",\"sessionId\":\"claude-session-eph\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":4,\"output_tokens\":120,\"cache_read_input_tokens\":12,\"cache_creation_input_tokens\":2500,\"cache_creation\":{\"ephemeral_5m_input_tokens\":2500,\"ephemeral_1h_input_tokens\":0}}}}\n",
                // Mixed.
                "{\"timestamp\":\"2026-05-19T10:10:00Z\",\"sessionId\":\"claude-session-eph\",\"message\":{\"model\":\"claude-opus-4-7\",\"usage\":{\"input_tokens\":2,\"output_tokens\":60,\"cache_read_input_tokens\":40,\"cache_creation_input_tokens\":3000,\"cache_creation\":{\"ephemeral_5m_input_tokens\":1000,\"ephemeral_1h_input_tokens\":2000}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_claude_code_jsonl_file(
            &path,
            "2026-05-19T10:15:00Z",
            "ephemeral-fingerprint".to_string(),
        )
        .expect("parse")
        .expect("snapshot");

        assert_eq!(item.cache_creation_5m_tokens, 3500);
        assert_eq!(item.cache_creation_1h_tokens, 35383);
        assert_eq!(item.cache_read_tokens, 52);
        // The flat `cache_creation_input_tokens` field must not be double-counted: when
        // nested values are non-zero we trust the split, never both.
        assert_eq!(
            item.cache_creation_5m_tokens + item.cache_creation_1h_tokens,
            38883
        );
        assert_eq!(item.model_usage.len(), 1);
        assert_eq!(item.model_usage[0].cache_creation_5m_tokens, 3500);
        assert_eq!(item.model_usage[0].cache_creation_1h_tokens, 35383);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_applies_selector_custom_entries_to_following_messages() {
        let path = temp_file("pi-selector");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-dddd-7000-9000-333333333333\",\"cwd\":\"/Users/example/work\",\"timestamp\":\"2026-05-19T11:00:00Z\"}\n",
                "{\"type\":\"custom\",\"customType\":\"ottto-selector\",\"data\":{\"selector_context\":{\"service_tier\":\"flex\",\"batch_mode\":true,\"context_bucket\":\"long\"}},\"timestamp\":1779234001000}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779234002000,\"usage\":{\"input\":80,\"output\":20,\"cacheRead\":0,\"cacheWrite\":0}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"openai\",\"model\":\"gpt-5.4\",\"api\":\"responses\",\"timestamp\":1779234003000,\"usage\":{\"input\":40,\"output\":10,\"cacheRead\":0,\"cacheWrite\":0},\"speed\":\"fast\"}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-19T11:05:00Z", "fp".to_string())
            .expect("parse")
            .expect("snapshot");

        assert_eq!(item.model_usage.len(), 2);
        let flex_batch = item
            .model_usage
            .iter()
            .find(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("flex")
            })
            .expect("flex row");
        let fast = item
            .model_usage
            .iter()
            .find(|row| row.selector_context.get("speed_mode").map(String::as_str) == Some("fast"))
            .expect("fast row");
        assert_eq!(flex_batch.input_tokens, 80);
        assert_eq!(
            flex_batch
                .selector_context
                .get("batch_mode")
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(fast.input_tokens, 40);
        assert_eq!(
            fast.selector_context
                .get("service_tier")
                .map(String::as_str),
            Some("fast")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_sums_message_end_usage_and_extracts_session_meta() {
        let path = temp_file("pi-basic");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-aaaa-7000-9000-111111111111\",\"cwd\":\"/Users/example/work\",\"version\":\"0.42\",\"timestamp\":\"2026-05-14T22:00:00Z\"}\n",
                "{\"type\":\"message\",\"role\":\"user\",\"content\":\"Summarize the changes in the diff\",\"timestamp\":1779234001000}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"api\":\"vertex\",\"timestamp\":1779234002000,\"usage\":{\"input\":100,\"output\":40,\"cacheRead\":20,\"cacheWrite\":5,\"cost\":{\"total\":0.0011,\"input\":0.0005,\"output\":0.0004,\"cacheRead\":0.0001,\"cacheWrite\":0.0001}}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"api\":\"vertex\",\"timestamp\":1779234004000,\"usage\":{\"input\":50,\"output\":15,\"cacheRead\":10,\"cacheWrite\":0,\"cost\":{\"total\":0.0006,\"input\":0.0002,\"output\":0.0003,\"cacheRead\":0.0001,\"cacheWrite\":0.0}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-14T22:05:00Z", "fp".to_string())
            .expect("parse")
            .expect("snapshot");

        assert_eq!(
            item.source_session_id,
            "019e2700-aaaa-7000-9000-111111111111"
        );
        assert_eq!(item.input_tokens, 150);
        assert_eq!(item.output_tokens, 55);
        assert_eq!(item.cache_read_tokens, 30);
        // Gemini-backed Pi has no 5m/1h split; flat cacheWrite routes to the 5m bucket.
        assert_eq!(item.cache_creation_5m_tokens, 5);
        assert_eq!(item.cache_creation_1h_tokens, 0);
        assert_eq!(item.request_count, 2);
        assert_eq!(item.activity_buckets.len(), 1);
        assert_eq!(item.activity_buckets[0].request_count, 2);
        assert_eq!(item.model_usage.len(), 1);
        assert_eq!(item.model_usage[0].model, "gemini-2.5-pro");
        assert_eq!(item.model_usage[0].input_tokens, 150);
        assert_eq!(item.provenance.collector, "pi_jsonl");
        assert_eq!(
            item.provenance.input_token_scope.as_deref(),
            Some("uncached")
        );
        assert!(item.workspace_hash.is_some());
        assert_eq!(
            item.session_display_name.as_deref(),
            Some("Summarize the changes in the diff")
        );
        assert_eq!(
            item.session_display_name_source.as_deref(),
            Some("first_prompt")
        );

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_handles_multi_model_sessions() {
        let path = temp_file("pi-multimodel");
        fs::write(
            &path,
            concat!(
                "{\"type\":\"session\",\"session_id\":\"019e2700-bbbb-7000-9000-222222222222\",\"cwd\":\"/Users/example/repo\",\"timestamp\":\"2026-05-14T22:10:00Z\"}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-flash\",\"api\":\"vertex\",\"timestamp\":1779235001000,\"usage\":{\"input\":80,\"output\":20,\"cacheRead\":0,\"cacheWrite\":0,\"cost\":{\"total\":0.0002,\"input\":0.0001,\"output\":0.0001,\"cacheRead\":0.0,\"cacheWrite\":0.0}}}}\n",
                "{\"type\":\"message_end\",\"message\":{\"provider\":\"google\",\"model\":\"gemini-2.5-pro\",\"api\":\"vertex\",\"timestamp\":1779235002000,\"usage\":{\"input\":120,\"output\":35,\"cacheRead\":0,\"cacheWrite\":0,\"cost\":{\"total\":0.0008,\"input\":0.0005,\"output\":0.0003,\"cacheRead\":0.0,\"cacheWrite\":0.0}}}}\n"
            ),
        )
        .expect("write fixture");

        let item = parse_pi_jsonl_file(&path, "2026-05-14T22:11:00Z", "fp".to_string())
            .expect("parse")
            .expect("snapshot");

        assert_eq!(item.input_tokens, 200);
        assert_eq!(item.output_tokens, 55);
        assert_eq!(item.model_usage.len(), 2);
        let model_names: Vec<&str> = item
            .model_usage
            .iter()
            .map(|usage| usage.model.as_str())
            .collect();
        assert!(model_names.contains(&"gemini-2.5-flash"));
        assert!(model_names.contains(&"gemini-2.5-pro"));

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_parser_returns_none_for_empty_session() {
        let path = temp_file("pi-empty");
        fs::write(
            &path,
            "{\"type\":\"session\",\"session_id\":\"019e2700-cccc-7000-9000-333333333333\",\"cwd\":\"/tmp\",\"timestamp\":\"2026-05-14T22:20:00Z\"}\n",
        )
        .expect("write fixture");

        let item =
            parse_pi_jsonl_file(&path, "2026-05-14T22:21:00Z", "fp".to_string()).expect("parse");

        assert!(item.is_none());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn pi_ms_timestamp_formats_rfc3339_with_millis() {
        // Anchor on epoch 0 and a verifiable mid-2024 date.
        assert_eq!(format_rfc3339_millis(0), "1970-01-01T00:00:00.000Z");
        // 2024-01-01T00:00:00.000Z = 1_704_067_200 s = 1_704_067_200_000 ms
        assert_eq!(
            format_rfc3339_millis(1_704_067_200_000),
            "2024-01-01T00:00:00.000Z"
        );
        // Sub-second granularity is preserved.
        assert_eq!(
            format_rfc3339_millis(1_704_067_200_123),
            "2024-01-01T00:00:00.123Z"
        );
    }

    #[test]
    fn snapshot_parser_streaming_guard() {
        let source = include_str!("snapshots.rs");
        let forbidden_std_call = ["fs::", "read", "_to", "_string"].concat();
        let forbidden_reader_call = [".", "read", "_to", "_string("].concat();
        assert!(!source.contains(&forbidden_std_call));
        assert!(!source.contains(&forbidden_reader_call));
    }
}
