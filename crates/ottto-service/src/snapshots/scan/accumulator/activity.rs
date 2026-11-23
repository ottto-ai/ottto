//! Session artifacts, features, activity tools, skills and capability calls,
//! and the activity summary.

use super::{ActivityCallTool, SnapshotAccumulator};
use crate::snapshots::{
    activity_bucket_from_timestamp, bounded_activity_counts, bounded_activity_label,
    bounded_tool_usage_name, codex_dictionary_slots, for_each_skill_md_reference,
    nested_unified_exec_tools, timestamp_is_after, timestamp_is_before, SessionArtifact,
    SnapshotActivitySummary, SnapshotCapabilityBucket, SnapshotCapabilityCount, SnapshotSource,
    MAX_ACTIVITY_SKILLS, MAX_SESSION_ARTIFACTS,
};
use std::collections::BTreeMap;

impl SnapshotAccumulator {
    /// Merge newly scraped artifacts, deduping and capping at
    /// ``MAX_SESSION_ARTIFACTS``. Encounter order is preserved; ``into_items``
    /// sorts for a deterministic fingerprint.
    pub(in crate::snapshots) fn add_artifacts(&mut self, artifacts: Vec<SessionArtifact>) {
        for artifact in artifacts {
            if self.artifacts.len() >= MAX_SESSION_ARTIFACTS {
                break;
            }
            if !self.artifacts.iter().any(|existing| existing == &artifact) {
                self.artifacts.push(artifact);
            }
        }
    }

    /// Move independently observed session features into the next member before
    /// projection. Keep transient call matching and all usage state per member.
    pub(in crate::snapshots) fn merge_session_features(&mut self, other: &mut Self) -> Option<()> {
        macro_rules! maps {
            ($($field:ident),+ $(,)?) => {$({
                for (key, count) in std::mem::take(&mut other.$field) {
                    let into = self.$field.entry(key).or_default();
                    *into = into.checked_add(count)?;
                }
            })+};
        }
        maps!(
            activity_tool_counts,
            activity_mcp_tool_counts,
            activity_mcp_tool_usage_counts,
            activity_capability_buckets,
            tool_usage_counts
        );
        macro_rules! counts {
            ($($field:ident),+ $(,)?) => {$({
                self.$field = self.$field.checked_add(std::mem::take(&mut other.$field))?;
            })+};
        }
        counts!(
            activity_patch_operations,
            activity_lines_added,
            activity_lines_deleted,
            activity_web_searches,
            activity_mcp_calls,
            activity_subagent_spawns
        );
        self.activity_changed_file_hashes
            .extend(std::mem::take(&mut other.activity_changed_file_hashes));
        self.activity_skills
            .extend(std::mem::take(&mut other.activity_skills));
        self.provider_skills
            .extend(std::mem::take(&mut other.provider_skills));
        self.skill_detector_incomplete |= other.skill_detector_incomplete;
        self.tool_usage_truncated |= other.tool_usage_truncated;
        self.add_artifacts(std::mem::take(&mut other.artifacts));
        Some(())
    }

    pub(in crate::snapshots) fn note_activity_tool(&mut self, name: &str) {
        let Some(name) = bounded_activity_label(name) else {
            return;
        };
        // `exec` is Codex Desktop's transport wrapper. Its nested `tools.*`
        // calls are counted separately so the UI reports actions, not protocol.
        if name == "exec" {
            return;
        }
        self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::Tool, &name);
        *self.activity_tool_counts.entry(name).or_default() += 1;
    }

    pub(in crate::snapshots) fn reclassify_activity_call_as_mcp(&mut self, call_id: &str) {
        let Some(ActivityCallTool { name }) = self.activity_call_tools.remove(call_id) else {
            return;
        };
        let Some(count) = self.activity_tool_counts.get_mut(&name) else {
            return;
        };
        *count = count.saturating_sub(1);
        if *count == 0 {
            self.activity_tool_counts.remove(&name);
        }
    }

    pub(in crate::snapshots) fn note_activity_mcp_tool(&mut self, server: &str, tool: &str) {
        if let Some(name) = bounded_activity_label(&format!("{server}.{tool}")) {
            self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::McpActivity, &name);
            *self.activity_mcp_tool_counts.entry(name).or_default() += 1;
        }
        if let Some(name) = bounded_tool_usage_name(&format!("mcp__{server}__{tool}")) {
            self.note_codex_name_slot(codex_dictionary_slots::CodexCountMap::McpUsage, &name);
            *self.activity_mcp_tool_usage_counts.entry(name).or_default() += 1;
        }
    }

    /// A Codex name count's stable Tail slot, first seen here.
    fn note_codex_name_slot(&mut self, map: codex_dictionary_slots::CodexCountMap, name: &str) {
        if self.source == SnapshotSource::Codex {
            self.codex_dictionary_slots
                .name_counts
                .note(&(map, name.to_owned()));
        }
    }

    pub(in crate::snapshots) fn note_activity_tools(&mut self, material: &str) {
        for name in nested_unified_exec_tools(material) {
            self.note_activity_tool(&name);
        }
    }

    /// SKILL.md references in tool input (Codex arguments, Claude Read/Bash).
    /// Keeps one name past the wire cap so the backend still sees truncation.
    /// The first spelling wins: `Foo/SKILL.md` and `foo/SKILL.md` are one
    /// skill, and the backend keys uploaded names by their exact bytes.
    pub(in crate::snapshots) fn note_activity_skills(&mut self, material: &str) {
        let skills = &mut self.activity_skills;
        let named_all = for_each_skill_md_reference(material, |name| {
            if skills.len() <= MAX_ACTIVITY_SKILLS
                && !skills.iter().any(|seen| seen.eq_ignore_ascii_case(&name))
            {
                skills.insert(name);
            }
        });
        self.skill_detector_incomplete |= !named_all;
    }

    pub(in crate::snapshots) fn note_capability_call(
        &mut self,
        timestamp: Option<&str>,
        capability_id: &str,
        raw_origin: &str,
    ) {
        let Some((bucket_start, _)) = timestamp.and_then(activity_bucket_from_timestamp) else {
            return;
        };
        *self
            .activity_capability_buckets
            .entry((
                bucket_start,
                capability_id.to_string(),
                raw_origin.to_string(),
            ))
            .or_default() += 1;
    }

    pub(in crate::snapshots) fn activity_summary(&self) -> Option<SnapshotActivitySummary> {
        let capability_buckets = self
            .activity_capability_buckets
            .iter()
            .map(|((bucket_start, capability_id, raw_origin), call_count)| {
                SnapshotCapabilityBucket {
                    bucket_start: bucket_start.clone(),
                    capability_id: capability_id.clone(),
                    raw_origin: raw_origin.clone(),
                    call_count: *call_count,
                }
            })
            .collect::<Vec<_>>();
        let mut capability_totals: BTreeMap<(String, String), u64> = BTreeMap::new();
        for bucket in &capability_buckets {
            *capability_totals
                .entry((bucket.capability_id.clone(), bucket.raw_origin.clone()))
                .or_default() += bucket.call_count;
        }
        let capability_counts = capability_totals
            .into_iter()
            .map(
                |((capability_id, raw_origin), count)| SnapshotCapabilityCount {
                    capability_id,
                    raw_origin,
                    count,
                },
            )
            .collect::<Vec<_>>();
        let codex_tool_calls = self
            .activity_tool_counts
            .values()
            .copied()
            .sum::<u64>()
            .saturating_add(self.activity_mcp_calls);
        // Codex already has a complete local tool-action classifier. Claude's
        // new capability classifier is intentionally narrower, so do not
        // present its allowlisted subset as the session's total tool/MCP use.
        let tool_calls = if self.source == SnapshotSource::Codex {
            codex_tool_calls
        } else {
            0
        };
        // v2: v1's capability counts plus a skill detector that named every
        // SKILL.md reference it saw. Only v2 may later back "no skill used".
        let capability_collection_version = matches!(
            self.source,
            SnapshotSource::Codex | SnapshotSource::ClaudeCode
        )
        .then(|| {
            if self.skill_detector_incomplete {
                "agent_capability_usage:v1"
            } else {
                "agent_capability_usage:v2"
            }
            .to_string()
        });
        let has_activity = capability_collection_version.is_some()
            || tool_calls > 0
            || self.activity_patch_operations > 0
            || self.activity_web_searches > 0
            || self.activity_subagent_spawns > 0
            || !self.activity_skills.is_empty();
        has_activity.then(|| SnapshotActivitySummary {
            capability_collection_version,
            tool_calls,
            shell_commands: self
                .activity_tool_counts
                .get("exec_command")
                .copied()
                .unwrap_or_default(),
            patch_operations: self.activity_patch_operations,
            changed_files: self.activity_changed_file_hashes.len() as u64,
            lines_added: self.activity_lines_added,
            lines_deleted: self.activity_lines_deleted,
            web_searches: self.activity_web_searches,
            mcp_calls: self.activity_mcp_calls,
            subagent_spawns: self.activity_subagent_spawns,
            tool_counts: bounded_activity_counts(&self.activity_tool_counts, 64),
            mcp_tool_counts: bounded_activity_counts(&self.activity_mcp_tool_counts, 32),
            capability_counts,
            capability_buckets,
            // A reference to an invoked skill uploads the invocation's
            // (lowercased) spelling, the one its `skill_id` fact hashes, so
            // backend promotion of these names finds that fact.
            skills: self
                .activity_skills
                .iter()
                .take(MAX_ACTIVITY_SKILLS)
                .map(|skill| {
                    self.provider_skills
                        .get(&skill.to_ascii_lowercase())
                        .unwrap_or(skill)
                        .clone()
                })
                .collect(),
        })
    }

    pub(in crate::snapshots) fn note_time(&mut self, timestamp: Option<String>) {
        let Some(timestamp) = timestamp else {
            return;
        };
        if self
            .started_at
            .as_ref()
            .map_or(true, |current| timestamp_is_before(&timestamp, current))
        {
            self.started_at = Some(timestamp.clone());
        }
        if self
            .last_activity_at
            .as_ref()
            .map_or(true, |current| timestamp_is_after(&timestamp, current))
        {
            self.last_activity_at = Some(timestamp);
        }
    }
}
