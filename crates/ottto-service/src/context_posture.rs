//! Machine-local context-posture cache and summary for the Companion app.
//!
//! The snapshot scan already derives per-session context posture watermarks
//! for Claude Code sessions (`peak_context_fill_tokens`,
//! `first_turn_context_tokens`, `compaction_count` — see `snapshots.rs`), but
//! parsed `SnapshotItem`s are scan → upload → discard. This module persists
//! the tiny posture-relevant projection of each Claude Code session into a
//! per-source cache file so the agent-status collector can serve an aggregate
//! [`AgentContextPostureSummary`] to the app without re-parsing transcripts.
//!
//! The daemon's snapshot scan is incremental — a steady-state cycle only
//! re-parses files that changed — so one cycle's snapshots are a *delta*.
//! [`update_context_posture_cache`] folds that delta into the persisted cache
//! (upsert by session id; a re-parsed session's row is complete, so newer rows
//! replace older ones wholesale) and prunes rows outside the retention window.
//!
//! Everything here is measured (token counts, session counts). The daemon has
//! no pricing, so the summary deliberately carries no dollar figures; the
//! backend/web derives cost views from the uploaded snapshots instead.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use ottto_protocol::{AgentContextPostureSummary, AgentContextSessionPeak};
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use crate::snapshots::{SnapshotItem, CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS};

/// Summary lookback: sessions with activity inside this window are analyzed.
pub const POSTURE_SUMMARY_WINDOW_DAYS: i64 = 7;

/// Maximum per-session peak-fill entries surfaced for display (most recent
/// sessions, oldest → newest).
pub const POSTURE_SUMMARY_MAX_SESSION_PEAKS: usize = 14;

/// Cache rows whose last activity is older than this are pruned on merge.
/// Wider than the summary window so a summary computed right after a quiet
/// week still has the trailing edge to reason about.
const POSTURE_CACHE_RETENTION_DAYS: i64 = 14;

/// Hard cap on retained rows (newest kept) so a pathological burst of
/// sessions cannot grow the cache without bound.
const POSTURE_CACHE_MAX_ROWS: usize = 400;

/// Exact long-context window. Claude transcript model identifiers normally use
/// the same base id for standard and 1M variants, so a model-name heuristic is
/// not evidence. A measured peak above the regular 200k cap does prove that the
/// response used the 1M variant; smaller peaks keep their window unknown.
const LONG_CONTEXT_WINDOW_TOKENS: u64 = 1_000_000;

/// One session's posture-relevant projection, persisted in the cache file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextPostureCacheRow {
    pub session_id: String,
    /// RFC3339. Drives window filtering, ordering, and pruning.
    pub last_activity_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// First measured turn context, including the first user input.
    pub first_turn_context_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peak_context_fill_tokens: Option<u64>,
    /// `Some(0)` = observed, none happened; `None` = no compaction evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction_count: Option<u64>,
    /// Session-total cache-read tokens: the measured re-read volume.
    #[serde(default)]
    pub cache_read_tokens: u64,
    /// The session's dominant model (most requests), retained as display-safe
    /// diagnostic context only. It is not peak-model provenance and must never
    /// be used to infer the peak's context-window size.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dominant_model: Option<String>,
}

fn cache_path(support_dir: &Path) -> PathBuf {
    support_dir.join("context_posture").join("claude_code.json")
}

/// Read the persisted posture cache, or empty when missing/unreadable (a
/// fresh machine, or a malformed file we simply rebuild on the next merge).
pub fn read_context_posture_cache(support_dir: &Path) -> Vec<ContextPostureCacheRow> {
    match std::fs::read(cache_path(support_dir)) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Fold one scan cycle's Claude Code snapshots into the persisted cache and
/// write it back atomically (temp + rename, like the detected-uses writer).
pub fn update_context_posture_cache(
    support_dir: &Path,
    snapshots: &[SnapshotItem],
    now: OffsetDateTime,
) -> Result<()> {
    let merged = merge_context_posture_rows(
        read_context_posture_cache(support_dir),
        snapshots.iter().filter_map(cache_row_from_snapshot),
        now,
    );

    let path = cache_path(support_dir);
    let dir = path
        .parent()
        .expect("context posture cache path has a parent directory");
    std::fs::create_dir_all(dir)
        .with_context(|| format!("create context_posture dir {}", dir.display()))?;
    let payload =
        serde_json::to_vec_pretty(&merged).context("serialize context posture cache to JSON")?;
    let temp_path = path.with_extension("json.tmp");
    let mut temp = std::fs::File::create(&temp_path)
        .with_context(|| format!("create context_posture temp {}", temp_path.display()))?;
    temp.write_all(&payload)
        .with_context(|| format!("write context_posture temp {}", temp_path.display()))?;
    temp.sync_all().ok();
    std::fs::rename(&temp_path, &path)
        .with_context(|| format!("rename context_posture cache into place {}", path.display()))?;
    Ok(())
}

/// The convenience the agent-status collector calls: read the cache and
/// summarize it. `None` when nothing analyzable exists (fresh machine, no
/// recent sessions) — the app renders its sparse state.
pub fn claude_context_posture_summary(
    support_dir: &Path,
    now: OffsetDateTime,
) -> Option<AgentContextPostureSummary> {
    summarize_context_posture(&read_context_posture_cache(support_dir), now)
}

/// Project a scanned session onto its cache row. Only rows with posture
/// evidence qualify (`compaction_count` is `Some` even at 0 on a parsed
/// transcript), so a Codex state-only item — or a future regression that stops
/// deriving posture — contributes nothing rather than a fake empty row.
///
/// This does NOT by itself make the cache Claude-only: `snapshots.rs` derives
/// posture for Codex too, so keeping this cache's `claude_code.json` contract
/// honest depends on the caller's `source == ClaudeCode` gate in
/// `snapshot_sync.rs`. Feeding it another source's scan would silently file
/// those sessions under Claude Code.
fn cache_row_from_snapshot(item: &SnapshotItem) -> Option<ContextPostureCacheRow> {
    if item.peak_context_fill_tokens.is_none()
        && item.first_turn_context_tokens.is_none()
        && item.compaction_count.is_none()
    {
        return None;
    }
    let last_activity_at = item
        .source_last_activity_at
        .clone()
        .or_else(|| item.source_ended_at.clone())
        .unwrap_or_else(|| item.collected_at.clone());
    Some(ContextPostureCacheRow {
        session_id: item.source_session_id.clone(),
        last_activity_at,
        first_turn_context_tokens: item.first_turn_context_tokens,
        peak_context_fill_tokens: item.peak_context_fill_tokens,
        compaction_count: item.compaction_count,
        cache_read_tokens: item.cache_read_tokens,
        dominant_model: dominant_model(item),
    })
}

/// The session's most-requested model (ties broken by first occurrence).
fn dominant_model(item: &SnapshotItem) -> Option<String> {
    item.model_usage
        .iter()
        .max_by_key(|row| row.request_count)
        .map(|row| row.model.clone())
}

fn merge_context_posture_rows(
    existing: Vec<ContextPostureCacheRow>,
    updates: impl Iterator<Item = ContextPostureCacheRow>,
    now: OffsetDateTime,
) -> Vec<ContextPostureCacheRow> {
    let mut by_session: BTreeMap<String, ContextPostureCacheRow> = existing
        .into_iter()
        .map(|row| (row.session_id.clone(), row))
        .collect();
    for row in updates {
        // A re-parsed session's row is derived from the full transcript, so it
        // supersedes whatever the cache held for that session.
        by_session.insert(row.session_id.clone(), row);
    }

    let cutoff = now - Duration::days(POSTURE_CACHE_RETENTION_DAYS);
    let mut rows: Vec<ContextPostureCacheRow> = by_session
        .into_values()
        .filter(|row| parse_rfc3339(&row.last_activity_at).is_some_and(|at| at >= cutoff))
        .collect();
    rows.sort_by(|a, b| a.last_activity_at.cmp(&b.last_activity_at));
    if rows.len() > POSTURE_CACHE_MAX_ROWS {
        rows.drain(..rows.len() - POSTURE_CACHE_MAX_ROWS);
    }
    rows
}

/// Aggregate the cached rows into the app-facing summary. `None` when no
/// session has activity inside the summary window.
pub fn summarize_context_posture(
    rows: &[ContextPostureCacheRow],
    now: OffsetDateTime,
) -> Option<AgentContextPostureSummary> {
    let window_start = now - Duration::days(POSTURE_SUMMARY_WINDOW_DAYS);
    let mut analyzed: Vec<(&ContextPostureCacheRow, OffsetDateTime)> = rows
        .iter()
        .filter_map(|row| {
            let at = parse_rfc3339(&row.last_activity_at)?;
            (at >= window_start && at <= now + Duration::minutes(5)).then_some((row, at))
        })
        .collect();
    if analyzed.is_empty() {
        return None;
    }
    analyzed.sort_by_key(|row| row.1);

    let mut first_turns: Vec<u64> = analyzed
        .iter()
        .filter_map(|(row, _)| row.first_turn_context_tokens)
        .collect();
    first_turns.sort_unstable();

    let mut deep_sessions = 0u64;
    let mut over_window_sessions = 0u64;
    let mut peak_sessions = 0u64;
    let mut window_evidenced_sessions = 0u64;
    let mut compactions_observed = false;
    let mut compaction_total = 0u64;
    let mut reread_total = 0u64;
    for (row, _) in &analyzed {
        if let Some(peak) = row.peak_context_fill_tokens {
            peak_sessions += 1;
            if peak > CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS {
                deep_sessions += 1;
            }
            if let Some(window) = evidenced_context_window_tokens(peak) {
                window_evidenced_sessions += 1;
                if peak > window {
                    over_window_sessions += 1;
                }
            }
        }
        if let Some(count) = row.compaction_count {
            compactions_observed = true;
            compaction_total += count;
        }
        reread_total += row.cache_read_tokens;
    }

    // Per-session peaks: the most recent sessions that actually reported a
    // peak, oldest → newest so consumers can draw them left-to-right.
    let peaks_newest_last: Vec<AgentContextSessionPeak> = analyzed
        .iter()
        .filter_map(|(row, _)| {
            let peak = row.peak_context_fill_tokens?;
            let window = evidenced_context_window_tokens(peak);
            Some(AgentContextSessionPeak {
                peak_fill_tokens: peak,
                context_window_tokens: window,
                peak_fill_percent: window.map(|window| peak_fill_percent(peak, window)),
                over_window: window.map(|window| peak > window),
            })
        })
        .collect();
    let skip = peaks_newest_last
        .len()
        .saturating_sub(POSTURE_SUMMARY_MAX_SESSION_PEAKS);
    let session_peaks = peaks_newest_last[skip..].to_vec();

    Some(AgentContextPostureSummary {
        sessions_analyzed: analyzed.len() as u64,
        window_days: POSTURE_SUMMARY_WINDOW_DAYS as u64,
        typical_first_turn_tokens: median(&first_turns),
        peak_session_count: peak_sessions,
        window_evidenced_session_count: window_evidenced_sessions,
        deep_session_count: (peak_sessions > 0).then_some(deep_sessions),
        over_window_session_count: (peak_sessions > 0
            && window_evidenced_sessions == peak_sessions)
            .then_some(over_window_sessions),
        session_peaks,
        compaction_count: compactions_observed.then_some(compaction_total),
        reread_tokens: Some(reread_total),
    })
}

/// Return an exact window only when the measurement itself proves use of the
/// 1M variant. At or below 200k, both the standard and 1M variants are possible,
/// so percent/over-window claims remain unavailable.
fn evidenced_context_window_tokens(peak_tokens: u64) -> Option<u64> {
    (peak_tokens > CLAUDE_CONTEXT_BUCKET_LONG_THRESHOLD_TOKENS)
        .then_some(LONG_CONTEXT_WINDOW_TOKENS)
}

/// Peak fill as percent of the window, rounded, saturating into u16 (an
/// over-window session may legitimately exceed 100).
fn peak_fill_percent(peak_tokens: u64, window_tokens: u64) -> u16 {
    if window_tokens == 0 {
        return 0;
    }
    let percent = ((peak_tokens as f64 / window_tokens as f64) * 100.0).round();
    if percent >= f64::from(u16::MAX) {
        u16::MAX
    } else {
        percent.max(0.0) as u16
    }
}

fn median(sorted: &[u64]) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        Some(sorted[mid])
    } else {
        Some((sorted[mid - 1] + sorted[mid]) / 2)
    }
}

fn parse_rfc3339(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value.trim(), &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_now() -> OffsetDateTime {
        OffsetDateTime::parse("2026-07-12T12:00:00Z", &Rfc3339).unwrap()
    }

    fn row(
        session_id: &str,
        last_activity_at: &str,
        first_turn: Option<u64>,
        peak: Option<u64>,
        compactions: Option<u64>,
        cache_read: u64,
        model: Option<&str>,
    ) -> ContextPostureCacheRow {
        ContextPostureCacheRow {
            session_id: session_id.to_string(),
            last_activity_at: last_activity_at.to_string(),
            first_turn_context_tokens: first_turn,
            peak_context_fill_tokens: peak,
            compaction_count: compactions,
            cache_read_tokens: cache_read,
            dominant_model: model.map(str::to_string),
        }
    }

    #[test]
    fn window_evidence_fails_closed_below_long_context_threshold() {
        assert_eq!(evidenced_context_window_tokens(0), None);
        assert_eq!(evidenced_context_window_tokens(200_000), None);
        assert_eq!(evidenced_context_window_tokens(200_001), Some(1_000_000));
    }

    #[test]
    fn merge_upserts_by_session_and_prunes_old_rows() {
        let now = test_now();
        let existing = vec![
            row(
                "keep",
                "2026-07-10T09:00:00Z",
                Some(10),
                Some(20),
                Some(0),
                5,
                None,
            ),
            row(
                "stale",
                "2026-06-01T09:00:00Z",
                Some(10),
                Some(20),
                Some(0),
                5,
                None,
            ),
            row(
                "replaced",
                "2026-07-11T09:00:00Z",
                Some(1),
                Some(2),
                Some(0),
                1,
                None,
            ),
        ];
        let updates = vec![row(
            "replaced",
            "2026-07-12T09:00:00Z",
            Some(100),
            Some(200),
            Some(3),
            50,
            None,
        )];
        let merged = merge_context_posture_rows(existing, updates.into_iter(), now);
        let ids: Vec<&str> = merged.iter().map(|r| r.session_id.as_str()).collect();
        assert_eq!(ids, vec!["keep", "replaced"]);
        let replaced = merged.iter().find(|r| r.session_id == "replaced").unwrap();
        assert_eq!(replaced.compaction_count, Some(3));
        assert_eq!(replaced.cache_read_tokens, 50);
    }

    #[test]
    fn merge_drops_rows_with_unparsable_timestamps() {
        let now = test_now();
        let merged = merge_context_posture_rows(
            vec![row(
                "bad-ts",
                "not-a-time",
                Some(1),
                Some(1),
                Some(0),
                0,
                None,
            )],
            std::iter::empty(),
            now,
        );
        assert!(merged.is_empty());
    }

    #[test]
    fn summarize_computes_measured_totals_and_gates_window_claims() {
        let now = test_now();
        let rows = vec![
            // Outside the 7-day window: ignored entirely.
            row(
                "old",
                "2026-07-01T09:00:00Z",
                Some(999_999),
                Some(999_999),
                Some(9),
                999,
                None,
            ),
            // A 60k peak cannot distinguish the standard and 1M variants.
            row(
                "a",
                "2026-07-08T09:00:00Z",
                Some(50_000),
                Some(60_000),
                Some(0),
                1_000,
                Some("claude-sonnet-4-5"),
            ),
            // A >200k peak proves the 1M variant (25%), not a 200k overflow.
            row(
                "b",
                "2026-07-10T09:00:00Z",
                Some(70_000),
                Some(250_000),
                Some(2),
                2_000,
                Some("claude-sonnet-4-5"),
            ),
            // Model text is irrelevant; the measured >200k peak proves 1M.
            row(
                "c",
                "2026-07-11T09:00:00Z",
                Some(90_000),
                Some(400_000),
                Some(1),
                3_000,
                Some("claude-opus-4-8[1m]"),
            ),
        ];
        let summary = summarize_context_posture(&rows, now).expect("summary");
        assert_eq!(summary.sessions_analyzed, 3);
        assert_eq!(summary.window_days, 7);
        assert_eq!(summary.typical_first_turn_tokens, Some(70_000));
        assert_eq!(summary.peak_session_count, 3);
        assert_eq!(summary.window_evidenced_session_count, 2);
        assert_eq!(summary.deep_session_count, Some(2));
        assert_eq!(summary.over_window_session_count, None);
        assert_eq!(summary.compaction_count, Some(3));
        assert_eq!(summary.reread_tokens, Some(6_000));
        assert_eq!(
            summary.session_peaks,
            vec![
                AgentContextSessionPeak {
                    peak_fill_tokens: 60_000,
                    context_window_tokens: None,
                    peak_fill_percent: None,
                    over_window: None,
                },
                AgentContextSessionPeak {
                    peak_fill_tokens: 250_000,
                    context_window_tokens: Some(1_000_000),
                    peak_fill_percent: Some(25),
                    over_window: Some(false),
                },
                AgentContextSessionPeak {
                    peak_fill_tokens: 400_000,
                    context_window_tokens: Some(1_000_000),
                    peak_fill_percent: Some(40),
                    over_window: Some(false),
                },
            ]
        );
    }

    #[test]
    fn summarize_reports_over_window_only_with_complete_exact_evidence() {
        let now = test_now();
        let rows = vec![
            row(
                "a",
                "2026-07-10T09:00:00Z",
                Some(70_000),
                Some(400_000),
                Some(0),
                0,
                Some("claude-sonnet-4-5"),
            ),
            row(
                "b",
                "2026-07-11T09:00:00Z",
                Some(90_000),
                Some(1_100_000),
                Some(0),
                0,
                Some("claude-opus-4-8"),
            ),
        ];
        let summary = summarize_context_posture(&rows, now).expect("summary");
        assert_eq!(summary.peak_session_count, 2);
        assert_eq!(summary.window_evidenced_session_count, 2);
        assert_eq!(summary.over_window_session_count, Some(1));
        assert_eq!(summary.session_peaks[1].peak_fill_percent, Some(110));
        assert_eq!(summary.session_peaks[1].over_window, Some(true));
    }

    #[test]
    fn summarize_reports_unknown_compactions_as_none_never_zero() {
        let now = test_now();
        let rows = vec![row(
            "a",
            "2026-07-11T09:00:00Z",
            Some(50_000),
            Some(60_000),
            None,
            0,
            None,
        )];
        let summary = summarize_context_posture(&rows, now).expect("summary");
        assert_eq!(summary.compaction_count, None);

        // But an observed zero IS zero.
        let rows = vec![row(
            "a",
            "2026-07-11T09:00:00Z",
            Some(50_000),
            Some(60_000),
            Some(0),
            0,
            None,
        )];
        let summary = summarize_context_posture(&rows, now).expect("summary");
        assert_eq!(summary.compaction_count, Some(0));
    }

    #[test]
    fn summarize_caps_session_peaks_to_most_recent_oldest_first() {
        let now = test_now();
        let rows: Vec<ContextPostureCacheRow> = (0..20)
            .map(|i| {
                row(
                    &format!("s{i}"),
                    &format!("2026-07-11T09:{i:02}:00Z"),
                    Some(10_000),
                    Some(2_000 * (i as u64 + 1)),
                    Some(0),
                    0,
                    Some("claude-sonnet-4-5"),
                )
            })
            .collect();
        let summary = summarize_context_posture(&rows, now).expect("summary");
        assert_eq!(summary.sessions_analyzed, 20);
        assert_eq!(
            summary.session_peaks.len(),
            POSTURE_SUMMARY_MAX_SESSION_PEAKS
        );
        // The first retained peak is session index 6 (20 - 14), the last is 19.
        assert_eq!(
            summary.session_peaks.first().unwrap().peak_fill_tokens,
            14_000
        );
        assert_eq!(
            summary.session_peaks.last().unwrap().peak_fill_tokens,
            40_000
        );
        assert!(summary
            .session_peaks
            .iter()
            .all(|peak| peak.peak_fill_percent.is_none() && peak.over_window.is_none()));
    }

    #[test]
    fn summarize_returns_none_when_window_is_empty() {
        let now = test_now();
        assert_eq!(summarize_context_posture(&[], now), None);
        let rows = vec![row(
            "old",
            "2026-06-01T09:00:00Z",
            Some(1),
            Some(1),
            Some(0),
            0,
            None,
        )];
        assert_eq!(summarize_context_posture(&rows, now), None);
    }

    fn temp_support_dir(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("ottto-{name}-{unique}"));
        std::fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn snapshot_item(
        session_id: &str,
        last_activity_at: &str,
        posture: (Option<u64>, Option<u64>, Option<u64>),
        cache_read_tokens: u64,
        model: Option<&str>,
    ) -> SnapshotItem {
        let model_usage = model
            .map(|model| {
                vec![crate::snapshots::SnapshotModelUsage {
                    model: model.to_string(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cache_read_tokens,
                    cache_creation_5m_tokens: 0,
                    cache_creation_1h_tokens: 0,
                    reasoning_output_tokens: 0,
                    reasoning_effort: None,
                    unattributed_total_tokens: 0,
                    request_count: 1,
                    selector_context: Default::default(),
                    selector_sources: Default::default(),
                    auth_mode: None,
                    billing_channel: None,
                    billing_provider: None,
                    gateway_provider: None,
                    model_provider: None,
                    subscription_product: None,
                    cost_usd: None,
                    input_cost_usd: None,
                    output_cost_usd: None,
                    cache_read_cost_usd: None,
                    cache_creation_cost_usd: None,
                }]
            })
            .unwrap_or_default();
        SnapshotItem {
            source_session_id: session_id.to_string(),
            snapshot_fingerprint: String::new(),
            status: "final".to_string(),
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens,
            cache_creation_5m_tokens: 0,
            cache_creation_1h_tokens: 0,
            reasoning_output_tokens: 0,
            unattributed_total_tokens: 0,
            request_count: 1,
            avg_duration_ms: None,
            avg_time_to_first_token_ms: None,
            max_duration_ms: None,
            max_time_to_first_token_ms: None,
            first_turn_context_tokens: posture.0,
            peak_context_fill_tokens: posture.1,
            compaction_count: posture.2,
            model_usage,
            usage_buckets: Vec::new(),
            cost: None,
            session_display_name: None,
            session_display_name_source: None,
            source_started_at: None,
            source_ended_at: None,
            source_last_activity_at: Some(last_activity_at.to_string()),
            collected_at: "2026-07-12T10:00:00Z".to_string(),
            workspace_hash: None,
            workspace_display_label: None,
            workspace_label_source: None,
            source_file_fingerprint: None,
            session_artifacts: Vec::new(),
            provenance: crate::snapshots::SnapshotProvenance {
                collector: "claude_code_jsonl".to_string(),
                source_file_count: 1,
                input_token_scope: None,
                state_total_tokens: None,
                state_archived: None,
            },
            origin: None,
        }
    }

    #[test]
    fn cache_round_trips_through_update_and_read() {
        let dir = temp_support_dir("context-posture-roundtrip");
        let now = test_now();
        let items = vec![
            snapshot_item(
                "s1",
                "2026-07-11T09:00:00Z",
                (Some(72_000), Some(150_000), Some(1)),
                9_000,
                Some("claude-sonnet-4-5"),
            ),
            // No posture evidence at all (a Codex/Pi item): contributes nothing.
            snapshot_item(
                "codex",
                "2026-07-11T10:00:00Z",
                (None, None, None),
                500,
                None,
            ),
        ];
        update_context_posture_cache(&dir, &items, now).expect("update cache");
        let rows = read_context_posture_cache(&dir);
        assert_eq!(
            rows,
            vec![row(
                "s1",
                "2026-07-11T09:00:00Z",
                Some(72_000),
                Some(150_000),
                Some(1),
                9_000,
                Some("claude-sonnet-4-5"),
            )]
        );
        let summary = claude_context_posture_summary(&dir, now).expect("summary");
        assert_eq!(summary.sessions_analyzed, 1);
        assert_eq!(summary.typical_first_turn_tokens, Some(72_000));
        assert_eq!(summary.reread_tokens, Some(9_000));
        std::fs::remove_dir_all(&dir).ok();
    }
}
