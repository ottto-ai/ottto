//! The kinds_version 2 changed-days upload.
//!
//! A scope uploads when a commit changed its totals since the last
//! acknowledged upload, or when its last upload is a week old. The payload
//! carries only the days whose rows changed since that upload, plus
//! `retention_floor` (the oldest day still kept) so the server keeps every
//! day inside it. Parts, tools, files and sessions go as 30-day and
//! everything-kept totals. A payload equal to the last acknowledged state is
//! not sent again (compared on a hash of the full state, not the payload).

use super::super::measure::date_ymd;
use super::super::{BUCKET_TIMEZONE, CHARS_PER_TOKEN, COUNTER_SOURCE, IMAGE_NOMINAL_TOKENS};
use super::aggregate::{
    date_of, merge_file_totals, Bucket, Day, FileTotals, Slot, StoredAggregate, Window,
};
use super::checkpoint::{read_json, write_json};
use super::file::Source;
use super::scope::{scope_file_stem, Scope};
use super::{
    COLLECTOR_VERSION, MAX_TOOL_LABEL_CHARS, UPLOAD_MAX_PARTS, UPLOAD_STALENESS_SECS,
    UPLOAD_TOP_FILES, UPLOAD_TOP_SERVERS, UPLOAD_TOP_SESSIONS, UPLOAD_TOP_TOOLS,
};
use crate::composition_kinds::{repo_relative, GitRootCache, Kind, Part};
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
) -> UploadOutcome {
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
    let state_sha = state_sha(scope, target.labels_enabled);
    let changed = scope
        .agg
        .day_generation
        .values()
        .any(|generation| *generation > acked_generation);
    if !stale && (!changed || ack.as_ref().is_some_and(|ack| ack.state_sha == state_sha)) {
        return UploadOutcome::Unchanged;
    }
    let request = build_request(scope, source, target, now, window, acked_generation);
    let Ok(payload) = serde_json::to_value(&request) else {
        return UploadOutcome::Failed;
    };
    if target.uploader.upload(&payload).is_err() {
        return UploadOutcome::Failed;
    }
    let ack = UploadAck {
        generation: scope.generation,
        state_sha,
        posted_at: now_secs,
        destination: target.destination.to_string(),
    };
    if write_json(&path, &ack).is_err() {
        // The upload landed; the next run sends the same days again, which
        // replaces them with the same values.
        return UploadOutcome::Uploaded;
    }
    UploadOutcome::Uploaded
}

/// Hash of everything an upload is built from.
fn state_sha(scope: &Scope, labels_enabled: bool) -> String {
    let stored =
        serde_json::to_string(&StoredAggregate::from_aggregate(&scope.agg)).unwrap_or_default();
    let info = serde_json::to_string(&scope.info).unwrap_or_default();
    let labels = if labels_enabled {
        "labels"
    } else {
        "no-labels"
    };
    sha256_hex(&[&stored, &info, labels])
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

pub(super) fn build_request(
    scope: &Scope,
    source: Source,
    target: &UploadTarget,
    now: OffsetDateTime,
    window: Window,
    acked_generation: u64,
) -> RequestV2 {
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
        .filter(|((day, _), bucket)| {
            changed_days.contains(day) && (bucket.events > 0 || bucket.residency > 0)
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
    let (workspace_label, workspace_label_source) = match (labels, &identity.repository_label) {
        (false, _) => (None, None),
        (true, Some(label)) => (Some(label.clone()), Some("repository".to_string())),
        (true, None) => (
            identity.workspace_label.clone(),
            identity
                .workspace_label
                .as_ref()
                .map(|_| "directory_name".to_string()),
        ),
    };
    let (sessions, session_count_window, session_count_30d) = build_sessions(scope, window);
    RequestV2 {
        agent_source: source.label().to_string(),
        machine_id: target.machine_id.to_string(),
        workspace_hash: scope.info.workspace_hash.clone(),
        workspace_label,
        workspace_label_source,
        repository_hash: identity.repository_hash.clone(),
        repository_label: identity.repository_label.clone().filter(|_| labels),
        repository_label_source: identity.repository_label_source.clone().filter(|_| labels),
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
        top_files: build_files(scope, window),
        sessions,
        kinds_version: 2,
        parts: build_parts(scope, window, labels),
        tools: if labels {
            build_tools(scope, window)
        } else {
            Vec::new()
        },
        session_count_window,
        session_count_30d,
        retention_floor: ymd(window.floor),
        upload_mode: "changed_days",
    }
}

fn build_parts(scope: &Scope, window: Window, labels: bool) -> Vec<PartRow> {
    let agg = &scope.agg;
    let mut period: BTreeMap<Slot, Bucket> = BTreeMap::new();
    for ((day, slot), bucket) in &agg.day_parts {
        if *day >= window.period_floor && *day <= window.today {
            add_bucket(period.entry(slot.clone()).or_default(), bucket);
        }
    }
    let mut rows = part_rows(&period, "30d", labels);
    rows.extend(part_rows(&agg.all_parts, "all", labels));
    rows
}

fn add_bucket(into: &mut Bucket, other: &Bucket) {
    into.events += other.events;
    into.tokens += other.tokens;
    into.residency += other.residency;
    into.images += other.images;
}

fn part_rows(totals: &BTreeMap<Slot, Bucket>, period: &'static str, labels: bool) -> Vec<PartRow> {
    // Add-on servers: the top ones by tokens keep their name; the rest (and
    // all of them without label consent) merge into one row.
    let mut servers: BTreeMap<&str, u64> = BTreeMap::new();
    for (slot, bucket) in totals {
        if let Some(server) = slot.server.as_deref() {
            *servers.entry(server).or_default() += bucket.tokens;
        }
    }
    let mut ranked: Vec<(&str, u64)> = servers.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
    let named: BTreeSet<&str> = ranked
        .iter()
        .take(if labels { UPLOAD_TOP_SERVERS } else { 0 })
        .map(|(server, _)| *server)
        .collect();
    let mut merged: BTreeMap<(Kind, Part, Option<&str>), Bucket> = BTreeMap::new();
    for (slot, bucket) in totals {
        if slot.part.kind().is_none() || bucket.is_zero() {
            // kinds_version 1 classification has no parts.
            continue;
        }
        let server = slot
            .server
            .as_deref()
            .filter(|server| named.contains(server));
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
            server: server.map(str::to_string),
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

fn build_tools(scope: &Scope, window: Window) -> Vec<ToolRow> {
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
    let period_rows = period
        .into_iter()
        .filter_map(|(tool, (calls, tokens, kind))| {
            tool_row(
                tool,
                kind?,
                "30d",
                calls,
                period_sessions.get(tool).copied().unwrap_or(0),
                tokens,
            )
        });
    rows.extend(top_tools(period_rows));
    let all_rows = agg.all_tools.iter().filter_map(|(tool, totals)| {
        tool_row(
            tool,
            totals.kind?,
            "all",
            totals.calls,
            totals.sessions,
            totals.tokens,
        )
    });
    rows.extend(top_tools(all_rows));
    rows
}

fn top_tools(rows: impl Iterator<Item = ToolRow>) -> Vec<ToolRow> {
    let mut rows: Vec<ToolRow> = rows.collect();
    rows.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| a.label.cmp(&b.label))
    });
    // One row per (server, label): truncated labels may collide.
    let mut seen = BTreeSet::new();
    rows.retain(|row| seen.insert((row.server.clone(), row.label.clone())));
    rows.truncate(UPLOAD_TOP_TOOLS);
    rows
}

fn tool_row(
    tool: &str,
    kind: Kind,
    period: &'static str,
    calls: u64,
    sessions: u64,
    tokens: u64,
) -> Option<ToolRow> {
    let label: String = tool.chars().take(MAX_TOOL_LABEL_CHARS).collect();
    if label.trim().is_empty() {
        return None;
    }
    let server = match tool.split_once('/') {
        Some((server, _)) if !server.is_empty() && label.starts_with(&format!("{server}/")) => {
            Some(server.to_string())
        }
        Some(_) => return None,
        None => None,
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

fn build_files(scope: &Scope, window: Window) -> Vec<FileRow> {
    let agg = &scope.agg;
    let workspace = Path::new(&scope.info.workspace_path);
    let repository_hash = scope.info.identity.repository_hash.as_deref();
    let mut cache = GitRootCache::default();
    let mut names: BTreeMap<String, Option<String>> = BTreeMap::new();
    let mut name_of = |path: &str| -> Option<String> {
        names
            .entry(path.to_string())
            .or_insert_with(|| repo_relative(path, workspace, repository_hash, &mut cache))
            .clone()
    };
    // name -> per (kind, part) totals, all kept and 30 days.
    type Totals = BTreeMap<(Kind, Part), (FileTotals, FileTotals)>;
    let mut by_name: BTreeMap<String, Totals> = BTreeMap::new();
    for (key, totals) in &agg.all_files {
        let Some(name) = name_of(&key.path) else {
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
        let Some(name) = name_of(&key.path) else {
            continue;
        };
        let entry = by_name
            .entry(name)
            .or_default()
            .entry((key.kind, key.part))
            .or_default();
        merge_file_totals(&mut entry.1, totals);
    }
    let mut rows: Vec<FileRow> = by_name
        .into_iter()
        .filter_map(|(name, slots)| {
            // The file's kind is the one it entered the most tokens under.
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
                part: part.kind().map(|_| part.as_str().to_string()),
                events_30d: recent.events,
                tokens_entered_est_30d: recent.tokens,
            })
        })
        .collect();
    rows.sort_by(|a, b| {
        b.tokens_entered_est
            .cmp(&a.tokens_entered_est)
            .then_with(|| a.relative_path_or_name.cmp(&b.relative_path_or_name))
    });
    rows.truncate(UPLOAD_TOP_FILES);
    rows
}

/// The top sessions of each period (their union), with the period counts.
fn build_sessions(scope: &Scope, window: Window) -> (Vec<SessionRow>, u64, u64) {
    struct Row<'a> {
        id: &'a str,
        started: Option<i64>,
        total: u64,
        recent: u64,
        top: Kind,
    }
    let rows: Vec<Row> = scope
        .agg
        .sessions
        .iter()
        .filter_map(|(id, totals)| {
            let mut per_kind: BTreeMap<Kind, u64> = BTreeMap::new();
            let mut total = 0u64;
            let mut recent = 0u64;
            for (day, kinds) in &totals.days {
                for (kind, tokens) in kinds {
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
            (total > 0).then_some(Row {
                id,
                started: totals.started,
                total,
                recent,
                top: top?.0,
            })
        })
        .collect();
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
