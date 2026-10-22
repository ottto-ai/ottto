//! The kinds_version 2 changed-days upload.
//!
//! A scope uploads when a commit changed its totals since the last
//! acknowledged upload, or when its last upload is a week old. The payload
//! carries only the days whose rows changed since that upload, plus
//! `retention_floor` (the oldest day still kept) so the server keeps every
//! day inside it. Parts, tools, files and sessions go as 30-day and
//! everything-kept totals. A state whose content equals the last
//! acknowledged one is not sent again (compared on a hash of the totals
//! without their commit generations, so a re-read that changed nothing does
//! not upload).
//!
//! The payload follows the server's field rules: only kinds_version 2 kinds
//! and parts (anything else is dropped and counted), labels and server names
//! display-safe and at most 64 characters (an unsafe or long add-on server
//! joins the "other add-ons" row; an unsafe tool row is dropped and counted).
//! One refused field would refuse the whole scope's upload every day.

use super::super::measure::date_ymd;
use super::super::{BUCKET_TIMEZONE, CHARS_PER_TOKEN, COUNTER_SOURCE, IMAGE_NOMINAL_TOKENS};
use super::aggregate::{
    date_of, merge_file_totals, AggregateRef, Bucket, Day, FileTotals, Slot, Window,
};
use super::checkpoint::{name_hash, read_json, write_json};
use super::file::Source;
use super::scope::{scope_file_stem, Scope};
use super::{
    COLLECTOR_VERSION, MAX_TOOL_LABEL_CHARS, UPLOAD_MAX_PARTS, UPLOAD_STALENESS_SECS,
    UPLOAD_TOP_FILES, UPLOAD_TOP_SERVERS, UPLOAD_TOP_SESSIONS, UPLOAD_TOP_TOOLS,
};
use crate::composition_kinds::{Kind, Part};
use crate::context_footprint::sha256_hex;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub(super) trait Uploader {
    fn upload(&mut self, request: &Value) -> Result<()>;
}

/// Where and how a source uploads in this run.
pub(super) struct UploadTarget<'a> {
    pub(super) uploader: &'a mut dyn Uploader,
    pub(super) machine_id: &'a str,
    /// Device, machine and server: an upload acknowledged by another
    /// destination does not count here.
    pub(super) destination: &'a str,
    pub(super) labels_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct UploadAck {
    pub(super) generation: u64,
    pub(super) state_sha: String,
    pub(super) posted_at: i64,
    pub(super) destination: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UploadOutcome {
    Uploaded,
    Unchanged,
    Failed,
}

/// What an upload did, and the rows it left out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct UploadResult {
    pub(super) outcome: UploadOutcome,
    /// Rows naming a kind or part outside kinds_version 2.
    pub(super) dropped_non_v2: u64,
    /// Rows or labels the server's text rules would refuse.
    pub(super) dropped_unsafe: u64,
}

impl UploadResult {
    fn only(outcome: UploadOutcome) -> Self {
        Self {
            outcome,
            dropped_non_v2: 0,
            dropped_unsafe: 0,
        }
    }
}

/// Rows left out of one payload.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Dropped {
    pub(super) non_v2: u64,
    pub(super) unsafe_text: u64,
}

pub(super) fn ack_path(state_dir: &Path, source: Source, scope_id: &str) -> PathBuf {
    state_dir
        .join("scopes")
        .join(format!("{}.upload.json", scope_file_stem(source, scope_id)))
}

/// Upload one scope if it changed (or is stale), and record the ack.
pub(super) fn upload_scope(
    state_dir: &Path,
    source: Source,
    scope: &Scope,
    target: &mut UploadTarget,
    now: OffsetDateTime,
    window: Window,
) -> UploadResult {
    let path = ack_path(state_dir, source, &scope.scope_id);
    let ack = read_json::<UploadAck>(&path)
        .ok()
        .flatten()
        .filter(|ack| ack.destination == target.destination);
    let now_secs = now.unix_timestamp();
    let stale = ack.as_ref().map_or(true, |ack| {
        now_secs - ack.posted_at >= UPLOAD_STALENESS_SECS
    });
    let acked_generation = ack.as_ref().map_or(0, |ack| ack.generation);
    let changed = scope
        .agg
        .day_generation
        .values()
        .any(|generation| *generation > acked_generation);
    if !stale && !changed {
        return UploadResult::only(UploadOutcome::Unchanged);
    }
    let state_sha = state_sha(scope, target.labels_enabled);
    if let Some(ack) = ack
        .as_ref()
        .filter(|ack| !stale && ack.state_sha == state_sha)
    {
        // Same content as acknowledged (a re-read that changed nothing):
        // move the acknowledgment forward instead of uploading.
        let _ = write_json(
            &path,
            &UploadAck {
                generation: scope.generation,
                ..ack.clone()
            },
        );
        return UploadResult::only(UploadOutcome::Unchanged);
    }
    let (request, dropped) = build_request(scope, source, target, now, window, acked_generation);
    let failed = UploadResult {
        outcome: UploadOutcome::Failed,
        dropped_non_v2: dropped.non_v2,
        dropped_unsafe: dropped.unsafe_text,
    };
    let Ok(payload) = serde_json::to_value(&request) else {
        return failed;
    };
    if target.uploader.upload(&payload).is_err() {
        return failed;
    }
    let uploaded = UploadResult {
        outcome: UploadOutcome::Uploaded,
        ..failed
    };
    let ack = UploadAck {
        generation: scope.generation,
        state_sha,
        posted_at: now_secs,
        destination: target.destination.to_string(),
    };
    // If this write fails the upload still landed; the next run sends the
    // same days again, which replaces them with the same values.
    let _ = write_json(&path, &ack);
    uploaded
}

/// Hash of everything an upload is built from (not the commit generations),
/// written straight into the hash. The same value as `sha256_hex` over the
/// stored totals, the scope info and the labels setting.
fn state_sha(scope: &Scope, labels_enabled: bool) -> String {
    use sha2::{Digest, Sha256};
    struct Hashing(Sha256);
    impl std::io::Write for Hashing {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hashing = Hashing(Sha256::new());
    let totals = AggregateRef {
        agg: &scope.agg,
        generations: false,
    };
    let _ = serde_json::to_writer(&mut hashing, &totals);
    hashing.0.update([0]);
    let _ = serde_json::to_writer(&mut hashing, &scope.info);
    hashing.0.update([0]);
    let labels = if labels_enabled {
        "labels"
    } else {
        "no-labels"
    };
    hashing.0.update(labels.as_bytes());
    hashing.0.update([0]);
    format!("{:x}", hashing.0.finalize())
}

// -------------------------------------------------------------------------
// Payload.
// -------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct DailyRow {
    pub(super) date: String,
    pub(super) category: String,
    pub(super) events: u64,
    pub(super) tokens_entered_est: u64,
    pub(super) residency_weighted_tokens_est: u64,
    pub(super) image_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct FileRow {
    pub(super) relative_path_or_name: String,
    pub(super) category: String,
    pub(super) events: u64,
    pub(super) tokens_entered_est: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) last_accessed_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) part: Option<String>,
    pub(super) events_30d: u64,
    pub(super) tokens_entered_est_30d: u64,
    /// Sessions that read the file in the window and in the 30-day period;
    /// a subagent's transcript counts as its parent session.
    pub(super) session_count: u64,
    pub(super) session_count_30d: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct SessionRow {
    pub(super) session_id_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) started_at: Option<String>,
    pub(super) total_tokens_entered_est: u64,
    pub(super) top_kind: String,
    pub(super) in_30d: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct PartRow {
    pub(super) kind: String,
    pub(super) part: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) server: Option<String>,
    pub(super) window: &'static str,
    pub(super) events: u64,
    pub(super) tokens_entered_est: u64,
    pub(super) residency_weighted_tokens_est: u64,
    pub(super) image_count: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct ToolRow {
    pub(super) label: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) server: Option<String>,
    pub(super) kind: String,
    pub(super) window: &'static str,
    pub(super) calls: u64,
    pub(super) distinct_sessions: u64,
    pub(super) tokens_entered_est: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub(super) struct RequestV2 {
    pub(super) agent_source: String,
    pub(super) machine_id: String,
    pub(super) workspace_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_label_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) repository_identity_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) workspace_kind: Option<String>,
    pub(super) config_hash: String,
    pub(super) window_start: String,
    pub(super) window_end: String,
    pub(super) bucket_timezone: String,
    pub(super) captured_at: String,
    pub(super) collector_version: String,
    pub(super) counter_source: String,
    pub(super) daily_aggregates: Vec<DailyRow>,
    pub(super) top_files: Vec<FileRow>,
    pub(super) sessions: Vec<SessionRow>,
    pub(super) kinds_version: u8,
    pub(super) parts: Vec<PartRow>,
    pub(super) tools: Vec<ToolRow>,
    pub(super) session_count_window: u64,
    pub(super) session_count_30d: u64,
    pub(super) retention_floor: String,
    pub(super) upload_mode: &'static str,
}

/// Methodology fingerprint of the kinds_version 2 reader.
pub(super) fn config_hash_v2(agent_source: &str) -> String {
    let kinds = Kind::V2
        .iter()
        .map(|kind| kind.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let descriptor = format!(
        "chars_per_token={CHARS_PER_TOKEN};image_nominal={IMAGE_NOMINAL_TOKENS};bucket_tz={BUCKET_TIMEZONE};kinds={kinds};upload=changed_days"
    );
    sha256_hex(&[COUNTER_SOURCE, agent_source, COLLECTOR_VERSION, &descriptor])
}

fn ymd(day: Day) -> String {
    date_of(day).map(date_ymd).unwrap_or_default()
}

fn iso(ts: i64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(ts)
        .ok()
        .and_then(|ts| ts.format(&Rfc3339).ok())
}

// -------------------------------------------------------------------------
// The server's field rules, on the client.
// -------------------------------------------------------------------------

/// The longest tool label or add-on server name the server accepts.
pub(super) const MAX_SERVER_CHARS: usize = 64;
const MAX_LABEL_CHARS: usize = 255;
const MAX_FILE_NAME_CHARS: usize = 512;

/// Display-safe text as the server keeps it: whitespace normalized, no
/// forbidden fragment, at most `max` characters, and no space left at the
/// end by the cap.
fn safe_text(raw: &str, max: usize) -> Option<String> {
    let text = crate::context_footprint::safe_text(raw, max)?;
    let text = text.trim_end();
    (!text.is_empty()).then(|| text.to_string())
}

/// A kinds_version 2 kind. The reader classifies with kinds_version 2 only
/// (a debug build stops on anything else when the line is read); this guard
/// keeps a release build's upload acceptable if one ever slips through.
fn is_v2(kind: Kind) -> bool {
    Kind::V2.contains(&kind)
}

/// A part the server accepts under `kind`.
fn part_of(kind: Kind, part: Part) -> bool {
    is_v2(kind) && part.kind() == Some(kind)
}

/// An add-on server name as sent (whitespace normalized), or `None` when it
/// is unsafe or longer than the server accepts.
pub(super) fn safe_server(raw: &str) -> Option<String> {
    let text = safe_text(raw, usize::MAX)?;
    (text.chars().count() <= MAX_SERVER_CHARS).then_some(text)
}

/// A repository label the server accepts: display-safe text, not a git
/// remote, no path separators.
fn safe_repository_label(raw: &str) -> Option<String> {
    let text = safe_text(raw, MAX_LABEL_CHARS)?;
    let lowered = text.to_ascii_lowercase();
    let remote = lowered.contains("://")
        || text.split_once('@').is_some_and(|(user, rest)| {
            !user.is_empty() && !user.contains(' ') && rest.contains(':')
        });
    (!remote && !text.contains('/') && !text.contains('\\')).then_some(text)
}

/// A file name the server accepts: display-safe, relative, no `..` part.
pub(super) fn safe_file_name(raw: &str) -> Option<String> {
    let text = safe_text(raw, MAX_FILE_NAME_CHARS)?;
    let absolute =
        text.starts_with(['/', '\\', '~']) || text.contains(":/") || text.contains(":\\");
    let parent = text.replace('\\', "/").split('/').any(|part| part == "..");
    (!absolute && !parent).then_some(text)
}

pub(super) fn build_request(
    scope: &Scope,
    source: Source,
    target: &UploadTarget,
    now: OffsetDateTime,
    window: Window,
    acked_generation: u64,
) -> (RequestV2, Dropped) {
    let mut dropped = Dropped::default();
    let agg = &scope.agg;
    let changed_days: BTreeSet<Day> = agg
        .day_generation
        .iter()
        .filter(|(day, generation)| **generation > acked_generation && window.contains(**day))
        .map(|(day, _)| *day)
        .collect();
    let daily_aggregates: Vec<DailyRow> = agg
        .days
        .iter()
        // Zero rows (left by a full re-read) are sent too: they replace
        // the server's earlier values for that day and kind.
        .filter(|((day, _), _)| changed_days.contains(day))
        .filter(|((_, kind), _)| {
            let keep = is_v2(*kind);
            dropped.non_v2 += u64::from(!keep);
            keep
        })
        .map(|((day, kind), bucket)| DailyRow {
            date: ymd(*day),
            category: kind.as_str().to_string(),
            events: bucket.events,
            tokens_entered_est: bucket.tokens,
            residency_weighted_tokens_est: bucket.residency,
            image_count: bucket.images,
        })
        .collect();
    let window_start = changed_days.first().copied().unwrap_or(window.today);
    let labels = target.labels_enabled;
    let identity = &scope.info.identity;
    let mut checked = |label: Option<&String>, safe: fn(&str) -> Option<String>| {
        let label = label.filter(|_| labels)?;
        let safe = safe(label);
        dropped.unsafe_text += u64::from(safe.is_none());
        safe
    };
    let repository_label = checked(identity.repository_label.as_ref(), safe_repository_label);
    let directory_label = checked(identity.workspace_label.as_ref(), |raw| {
        safe_text(raw, MAX_LABEL_CHARS)
    });
    let (workspace_label, workspace_label_source) = match (&repository_label, directory_label) {
        (Some(label), _) => (Some(label.clone()), Some("repository".to_string())),
        (None, Some(label)) => (Some(label), Some("directory_name".to_string())),
        (None, None) => (None, None),
    };
    let (sessions, session_count_window, session_count_30d) =
        build_sessions(scope, window, &mut dropped);
    let request = RequestV2 {
        agent_source: source.label().to_string(),
        machine_id: target.machine_id.to_string(),
        workspace_hash: scope.info.workspace_hash.clone(),
        workspace_label,
        workspace_label_source,
        repository_hash: identity.repository_hash.clone(),
        repository_label_source: repository_label
            .as_ref()
            .and(identity.repository_label_source.clone()),
        repository_label,
        repository_identity_source: identity.repository_identity_source.clone(),
        workspace_kind: identity.workspace_kind.clone(),
        config_hash: config_hash_v2(source.label()),
        window_start: ymd(window_start),
        window_end: ymd(window.today),
        bucket_timezone: BUCKET_TIMEZONE.to_string(),
        captured_at: now
            .format(&Rfc3339)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string()),
        collector_version: COLLECTOR_VERSION.to_string(),
        counter_source: COUNTER_SOURCE.to_string(),
        daily_aggregates,
        top_files: build_files(scope, window, &mut dropped),
        sessions,
        kinds_version: 2,
        parts: build_parts(scope, window, labels, &mut dropped),
        tools: if labels {
            build_tools(scope, window, &mut dropped)
        } else {
            Vec::new()
        },
        session_count_window,
        session_count_30d,
        retention_floor: ymd(window.floor),
        upload_mode: "changed_days",
    };
    (request, dropped)
}

fn build_parts(scope: &Scope, window: Window, labels: bool, dropped: &mut Dropped) -> Vec<PartRow> {
    let agg = &scope.agg;
    let mut period: BTreeMap<Slot, Bucket> = BTreeMap::new();
    for ((day, slot), bucket) in &agg.day_parts {
        if *day >= window.period_floor && *day <= window.today {
            add_bucket(period.entry(slot.clone()).or_default(), bucket);
        }
    }
    let mut rows = part_rows(&period, "30d", labels, dropped);
    rows.extend(part_rows(&agg.all_parts, "all", labels, dropped));
    rows
}

fn add_bucket(into: &mut Bucket, other: &Bucket) {
    into.events += other.events;
    into.tokens += other.tokens;
    into.residency += other.residency;
    into.images += other.images;
}

fn part_rows(
    totals: &BTreeMap<Slot, Bucket>,
    period: &'static str,
    labels: bool,
    dropped: &mut Dropped,
) -> Vec<PartRow> {
    // Add-on servers: the top safe ones by tokens keep their (normalized)
    // name; the rest (and all of them without label consent) merge into
    // the "other add-ons" row.
    let mut servers: BTreeMap<String, u64> = BTreeMap::new();
    let mut unsafe_servers: BTreeSet<&str> = BTreeSet::new();
    for (slot, bucket) in totals {
        if let Some(server) = slot.server.as_deref() {
            match safe_server(server) {
                Some(name) => *servers.entry(name).or_default() += bucket.tokens,
                None => {
                    unsafe_servers.insert(server);
                }
            }
        }
    }
    if labels {
        dropped.unsafe_text += unsafe_servers.len() as u64;
    }
    let mut ranked: Vec<(String, u64)> = servers.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let named: BTreeSet<String> = ranked
        .into_iter()
        .take(if labels { UPLOAD_TOP_SERVERS } else { 0 })
        .map(|(server, _)| server)
        .collect();
    let mut merged: BTreeMap<(Kind, Part, Option<String>), Bucket> = BTreeMap::new();
    for (slot, bucket) in totals {
        if bucket.is_zero() {
            continue;
        }
        if !part_of(slot.kind, slot.part) {
            // kinds_version 1 classification has no parts.
            dropped.non_v2 += 1;
            continue;
        }
        let server = slot
            .server
            .as_deref()
            .and_then(safe_server)
            .filter(|server| slot.part == Part::Addon && named.contains(server));
        add_bucket(
            merged.entry((slot.kind, slot.part, server)).or_default(),
            bucket,
        );
    }
    let mut rows: Vec<PartRow> = merged
        .into_iter()
        .map(|((kind, part, server), bucket)| PartRow {
            kind: kind.as_str().to_string(),
            part: part.as_str().to_string(),
            server,
            window: period,
            events: bucket.events,
            tokens_entered_est: bucket.tokens,
            residency_weighted_tokens_est: bucket.residency,
            image_count: bucket.images,
        })
        .collect();
    rows.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| (&a.kind, &a.part, &a.server).cmp(&(&b.kind, &b.part, &b.server)))
    });
    rows.truncate(UPLOAD_MAX_PARTS);
    rows
}

fn build_tools(scope: &Scope, window: Window, dropped: &mut Dropped) -> Vec<ToolRow> {
    let agg = &scope.agg;
    let mut period: BTreeMap<&str, (u64, u64, Option<Kind>)> = BTreeMap::new();
    for ((day, tool), totals) in &agg.day_tools {
        if *day >= window.period_floor && *day <= window.today {
            let entry = period.entry(tool).or_default();
            entry.0 += totals.calls;
            entry.1 += totals.tokens;
            entry.2 = totals.kind.or(entry.2);
        }
    }
    let mut period_sessions: BTreeMap<&str, u64> = BTreeMap::new();
    for ((tool, _), last) in &agg.tool_sessions {
        if *last >= window.period_floor {
            *period_sessions.entry(tool).or_default() += 1;
        }
    }
    let mut rows: Vec<ToolRow> = Vec::new();
    let mut period_rows = Vec::new();
    for (tool, (calls, tokens, kind)) in period {
        let Some(kind) = kind else { continue };
        let sessions = period_sessions.get(tool).copied().unwrap_or(0);
        if let Some(row) = tool_row(tool, kind, "30d", calls, sessions, tokens, dropped) {
            period_rows.push(row);
        }
    }
    rows.extend(top_tools(period_rows));
    let mut all_rows = Vec::new();
    for (tool, totals) in &agg.all_tools {
        let Some(kind) = totals.kind else { continue };
        if totals.calls == 0 && totals.tokens == 0 {
            continue;
        }
        let row = tool_row(
            tool,
            kind,
            "all",
            totals.calls,
            totals.sessions,
            totals.tokens,
            dropped,
        );
        all_rows.extend(row);
    }
    rows.extend(top_tools(all_rows));
    rows
}

fn top_tools(mut rows: Vec<ToolRow>) -> Vec<ToolRow> {
    rows.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| a.label.cmp(&b.label))
    });
    // One row per (server, label): truncated or normalized labels may
    // collide.
    let mut seen = BTreeSet::new();
    rows.retain(|row| seen.insert((row.server.clone(), row.label.clone())));
    rows.truncate(UPLOAD_TOP_TOOLS);
    rows
}

/// One tool row, or `None` when its kind is outside kinds_version 2 or its
/// label is not display-safe (counted).
fn tool_row(
    tool: &str,
    kind: Kind,
    period: &'static str,
    calls: u64,
    sessions: u64,
    tokens: u64,
    dropped: &mut Dropped,
) -> Option<ToolRow> {
    if !is_v2(kind) {
        dropped.non_v2 += 1;
        return None;
    }
    let Some(label) = safe_text(tool, MAX_TOOL_LABEL_CHARS) else {
        dropped.unsafe_text += 1;
        return None;
    };
    // An add-on tool is `<server>/<tool>`: its server must be safe and fit
    // whole in the label.
    let server = match tool.split_once('/') {
        None => None,
        Some((raw, _)) => match safe_server(raw) {
            Some(server) if label.starts_with(&format!("{server}/")) => Some(server),
            _ => {
                dropped.unsafe_text += 1;
                return None;
            }
        },
    };
    Some(ToolRow {
        label,
        server,
        kind: kind.as_str().to_string(),
        window: period,
        calls,
        distinct_sessions: sessions,
        tokens_entered_est: tokens,
    })
}

fn build_files(scope: &Scope, window: Window, dropped: &mut Dropped) -> Vec<FileRow> {
    let agg = &scope.agg;
    // Names were resolved when their lines were read; this only keeps the
    // server's rules. A top file is a file read (a `files_read` part).
    let mut unsafe_names = 0u64;
    let mut non_v2 = 0u64;
    let mut keep = |path: &str, kind: Kind, part: Part| -> Option<String> {
        if !part_of(kind, part) || kind != Kind::FilesRead {
            non_v2 += 1;
            return None;
        }
        let name = safe_file_name(path);
        unsafe_names += u64::from(name.is_none());
        name
    };
    // name -> per (kind, part) totals, all kept and 30 days.
    type Totals = BTreeMap<(Kind, Part), (FileTotals, FileTotals)>;
    let mut by_name: BTreeMap<String, Totals> = BTreeMap::new();
    for (key, totals) in &agg.all_files {
        let Some(name) = keep(&key.path, key.kind, key.part) else {
            continue;
        };
        let entry = by_name
            .entry(name)
            .or_default()
            .entry((key.kind, key.part))
            .or_default();
        merge_file_totals(&mut entry.0, totals);
    }
    for ((day, key), totals) in &agg.day_files {
        if *day < window.period_floor {
            continue;
        }
        let Some(name) = keep(&key.path, key.kind, key.part) else {
            continue;
        };
        let entry = by_name
            .entry(name)
            .or_default()
            .entry((key.kind, key.part))
            .or_default();
        merge_file_totals(&mut entry.1, totals);
    }
    dropped.non_v2 += non_v2;
    dropped.unsafe_text += unsafe_names;
    let mut rows: Vec<FileRow> = by_name
        .into_iter()
        .filter_map(|(name, slots)| {
            // The file's part is the one it entered the most tokens under.
            let (&(kind, part), _) = slots.iter().max_by(|a, b| {
                (a.1)
                    .0
                    .tokens
                    .cmp(&(b.1).0.tokens)
                    .then_with(|| b.0.cmp(a.0))
            })?;
            let mut all = FileTotals::default();
            let mut recent = FileTotals::default();
            for (totals, period) in slots.values() {
                merge_file_totals(&mut all, totals);
                merge_file_totals(&mut recent, period);
            }
            if all.events == 0 && recent.events == 0 {
                return None;
            }
            Some(FileRow {
                relative_path_or_name: name,
                category: kind.as_str().to_string(),
                events: all.events.max(recent.events),
                tokens_entered_est: all.tokens.max(recent.tokens),
                last_accessed_at: all.last.or(recent.last).and_then(iso),
                part: Some(part.as_str().to_string()),
                events_30d: recent.events,
                tokens_entered_est_30d: recent.tokens,
                session_count: 0,
                session_count_30d: 0,
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| a.relative_path_or_name.cmp(&b.relative_path_or_name))
    });
    rows.truncate(UPLOAD_TOP_FILES);
    count_file_sessions(scope, window, &mut rows);
    rows
}

/// Fill top-file counts from the incremental membership multiset.
fn count_file_sessions(scope: &Scope, window: Window, rows: &mut [FileRow]) {
    let mut sessions: BTreeMap<&str, (BTreeSet<u64>, BTreeSet<u64>)> = rows
        .iter()
        .map(|row| (row.relative_path_or_name.as_str(), Default::default()))
        .collect();
    let by_hash: BTreeMap<u32, &str> = rows
        .iter()
        .map(|row| {
            let name = row.relative_path_or_name.as_str();
            (name_hash(name), name)
        })
        .collect();
    for (hash, session, day) in &scope.file_sessions {
        if !window.contains(*day) {
            continue;
        }
        let Some(path) = by_hash.get(hash) else {
            continue;
        };
        if let Some((all, recent)) = sessions.get_mut(path) {
            all.insert(*session);
            if *day >= window.period_floor {
                recent.insert(*session);
            }
        }
    }
    // In-memory test scopes can be assembled without a persisted manifest.
    for checkpoint in scope.files.values() {
        for (hash, session, day) in super::scope::checkpoint_members(checkpoint) {
            if !window.contains(day) {
                continue;
            }
            if let Some((all, recent)) = by_hash.get(&hash).and_then(|name| sessions.get_mut(name))
            {
                all.insert(session);
                if day >= window.period_floor {
                    recent.insert(session);
                }
            }
        }
    }
    let counts: BTreeMap<String, (u64, u64)> = sessions
        .into_iter()
        .map(|(name, (all, recent))| (name.to_string(), (all.len() as u64, recent.len() as u64)))
        .collect();
    for row in rows {
        if let Some((all, recent)) = counts.get(&row.relative_path_or_name) {
            row.session_count = *all;
            row.session_count_30d = *recent;
        }
    }
}

/// The top sessions of each period (their union), with the period counts.
/// Only kinds_version 2 tokens count; a session with none is left out.
fn build_sessions(
    scope: &Scope,
    window: Window,
    dropped: &mut Dropped,
) -> (Vec<SessionRow>, u64, u64) {
    struct Row<'a> {
        id: &'a str,
        started: Option<i64>,
        total: u64,
        recent: u64,
        top: Kind,
    }
    let mut rows: Vec<Row> = Vec::new();
    for (id, totals) in &scope.agg.sessions {
        let mut per_kind: BTreeMap<Kind, u64> = BTreeMap::new();
        let mut total = 0u64;
        let mut recent = 0u64;
        let mut other = 0u64;
        for (day, kinds) in &totals.days {
            for (kind, tokens) in kinds {
                if !is_v2(*kind) {
                    other += tokens;
                    continue;
                }
                *per_kind.entry(*kind).or_default() += tokens;
                total += tokens;
                if *day >= window.period_floor {
                    recent += tokens;
                }
            }
        }
        let mut top: Option<(Kind, u64)> = None;
        for (kind, tokens) in per_kind {
            if top.is_none_or_less(tokens) {
                top = Some((kind, tokens));
            }
        }
        match top.filter(|_| total > 0) {
            Some((top, _)) => rows.push(Row {
                id,
                started: totals.started,
                total,
                recent,
                top,
            }),
            None if other > 0 => dropped.non_v2 += 1,
            None => {}
        }
    }
    let count_window = rows.len() as u64;
    let count_30d = rows.iter().filter(|row| row.recent > 0).count() as u64;
    let mut by_total: Vec<&Row> = rows.iter().collect();
    by_total.sort_by(|a, b| b.total.cmp(&a.total).then_with(|| a.id.cmp(b.id)));
    let mut by_recent: Vec<&Row> = rows.iter().filter(|row| row.recent > 0).collect();
    by_recent.sort_by(|a, b| b.recent.cmp(&a.recent).then_with(|| a.id.cmp(b.id)));
    let mut picked = BTreeSet::new();
    let mut out = Vec::new();
    for row in by_total
        .into_iter()
        .take(UPLOAD_TOP_SESSIONS)
        .chain(by_recent.into_iter().take(UPLOAD_TOP_SESSIONS))
    {
        if !picked.insert(row.id) {
            continue;
        }
        out.push(SessionRow {
            session_id_hash: format!("sha256:{}", sha256_hex(&[row.id])),
            started_at: row.started.and_then(iso),
            total_tokens_entered_est: row.total,
            top_kind: row.top.as_str().to_string(),
            in_30d: row.recent > 0,
        });
    }
    (out, count_window, count_30d)
}

trait TopKind {
    fn is_none_or_less(&self, tokens: u64) -> bool;
}

impl TopKind for Option<(Kind, u64)> {
    fn is_none_or_less(&self, tokens: u64) -> bool {
        self.map_or(true, |(_, best)| tokens > best)
    }
}
