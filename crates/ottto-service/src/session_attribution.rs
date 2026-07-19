//! Privacy-safe, evidence-first session attribution.
//!
//! This module converts provider-native metadata already read by the incremental
//! transcript scanner into a compact fact list. It never receives raw paths,
//! scheduler definitions, process arguments, or logs. Prompt/template and skill
//! grouping are intentionally separate follow-up adapters because they require
//! an organization-scoped HMAC key.

use crate::snapshots::{SnapshotOrigin, SnapshotSource};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SESSION_ATTRIBUTION_SCHEMA_VERSION: &str = "session_attribution.v1";
pub const MAX_SESSION_ATTRIBUTION_FACTS: usize = 24;
pub const MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES: usize = 128;
pub const MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES: usize = 32;
pub const MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES: usize = 96;
pub const MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES: usize = 2_048;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionFieldEvidence {
    pub kind: String,
    pub strength: String,
    pub observed_at: String,
    pub source_version: String,
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SessionAttributionFact {
    pub field: String,
    pub value: String,
    pub evidence: SessionFieldEvidence,
}

struct EvidenceContext<'a> {
    source_session_id: &'a str,
    observed_at: &'a str,
    source_version: &'a str,
}

/// Convert direct provider metadata into allowlisted facts.
///
/// Absence means omission. In particular, no fact in this function claims a
/// human launch. Raw Codex transport values such as `vscode` are deliberately
/// not mapped to customer-facing provider surfaces.
pub fn direct_provider_facts(
    source: SnapshotSource,
    origin: Option<&SnapshotOrigin>,
    source_session_id: &str,
    observed_at: &str,
    source_version: &str,
) -> Vec<SessionAttributionFact> {
    let mut facts = Vec::new();
    let origin = origin.cloned().unwrap_or_default();
    let evidence_context = EvidenceContext {
        source_session_id,
        observed_at,
        source_version,
    };

    match source {
        SnapshotSource::Codex => {
            match origin.thread_source.as_deref() {
                Some("automation") => {
                    push_fact(
                        &mut facts,
                        "origin_kind",
                        "provider_scheduled_task",
                        "provider_native",
                        "direct",
                        &evidence_context,
                    );
                    push_fact(
                        &mut facts,
                        "scheduler_kind",
                        "codex_scheduled",
                        "provider_native",
                        "direct",
                        &evidence_context,
                    );
                }
                Some("subagent") => push_fact(
                    &mut facts,
                    "origin_kind",
                    "subagent",
                    "provider_native",
                    "direct",
                    &evidence_context,
                ),
                _ if origin.source_subagent == Some(true) => push_fact(
                    &mut facts,
                    "origin_kind",
                    "subagent",
                    "provider_native",
                    "direct",
                    &evidence_context,
                ),
                _ => {}
            }

            let provider_surface = if origin.originator.as_deref() == Some("Codex Desktop") {
                Some("codex_desktop")
            } else {
                match origin.source.as_deref() {
                    Some("cli") => Some("codex_cli"),
                    Some("exec") => Some("codex_exec"),
                    _ => None,
                }
            };
            if let Some(value) = provider_surface {
                push_fact(
                    &mut facts,
                    "provider_surface",
                    value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
            if origin.source.as_deref() == Some("exec") {
                push_fact(
                    &mut facts,
                    "execution_mode",
                    "headless",
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
        }
        SnapshotSource::ClaudeCode => {
            if origin.is_sidechain == Some(true) {
                push_fact(
                    &mut facts,
                    "origin_kind",
                    "subagent",
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
            let provider_surface = match origin.entrypoint.as_deref() {
                Some("claude-desktop") => Some("claude_desktop"),
                Some("cli") => Some("claude_cli"),
                Some("sdk-cli") => Some("claude_sdk"),
                _ => None,
            };
            if let Some(value) = provider_surface {
                push_fact(
                    &mut facts,
                    "provider_surface",
                    value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
            let execution_mode = if origin.session_kind.as_deref() == Some("bg") {
                Some("background")
            } else if origin.entrypoint.as_deref() == Some("sdk-cli") {
                Some("headless")
            } else {
                None
            };
            if let Some(value) = execution_mode {
                push_fact(
                    &mut facts,
                    "execution_mode",
                    value,
                    "provider_native",
                    "direct",
                    &evidence_context,
                );
            }
        }
        SnapshotSource::Pi => push_fact(
            &mut facts,
            "provider_surface",
            "pi_cli",
            "provider_native",
            "direct",
            &evidence_context,
        ),
    }

    if let Some(parent_session_ref) = origin.parent_session_ref.as_deref() {
        push_fact(
            &mut facts,
            "parent_session_ref",
            parent_session_ref,
            "provider_native",
            "direct",
            &evidence_context,
        );
    }
    if origin.used_workflow_orchestration == Some(true) {
        push_fact(
            &mut facts,
            "workflow_orchestration",
            "dynamic",
            "provider_artifact",
            "direct",
            &evidence_context,
        );
    }

    facts.truncate(MAX_SESSION_ATTRIBUTION_FACTS);
    facts
}

fn push_fact(
    facts: &mut Vec<SessionAttributionFact>,
    field: &str,
    value: &str,
    kind: &str,
    strength: &str,
    context: &EvidenceContext<'_>,
) {
    if facts.len() >= MAX_SESSION_ATTRIBUTION_FACTS
        || value.is_empty()
        || value.len() > MAX_SESSION_ATTRIBUTION_FACT_VALUE_BYTES
        || context.source_version.len() > MAX_SESSION_ATTRIBUTION_SOURCE_VERSION_BYTES
    {
        return;
    }
    let evidence_ref = evidence_ref(context.source_session_id, field, value);
    if evidence_ref.len() > MAX_SESSION_ATTRIBUTION_EVIDENCE_REF_BYTES {
        return;
    }
    facts.push(SessionAttributionFact {
        field: field.to_string(),
        value: value.to_string(),
        evidence: SessionFieldEvidence {
            kind: kind.to_string(),
            strength: strength.to_string(),
            observed_at: context.observed_at.to_string(),
            source_version: context.source_version.to_string(),
            evidence_ref,
        },
    });
}

fn evidence_ref(source_session_id: &str, field: &str, value: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"session-attribution-evidence:v1\0");
    digest.update(source_session_id.as_bytes());
    digest.update(b"\0");
    digest.update(field.as_bytes());
    digest.update(b"\0");
    digest.update(value.as_bytes());
    format!("sha256:{:x}", digest.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn origin() -> SnapshotOrigin {
        SnapshotOrigin::default()
    }

    #[test]
    fn codex_provider_automation_is_direct_scheduled_origin() {
        let mut origin = origin();
        origin.thread_source = Some("automation".to_string());
        origin.originator = Some("Codex Desktop".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-1",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(facts.iter().any(|fact| {
            fact.field == "origin_kind"
                && fact.value == "provider_scheduled_task"
                && fact.evidence.strength == "direct"
        }));
        assert!(facts
            .iter()
            .any(|fact| fact.field == "scheduler_kind" && fact.value == "codex_scheduled"));
        assert!(facts
            .iter()
            .any(|fact| fact.field == "provider_surface" && fact.value == "codex_desktop"));
    }

    #[test]
    fn raw_vscode_transport_does_not_become_provider_surface() {
        let mut origin = origin();
        origin.source = Some("vscode".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-2",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(!facts.iter().any(|fact| fact.field == "provider_surface"));
        assert!(!facts.iter().any(|fact| fact.field == "origin_kind"));
    }

    #[test]
    fn headless_and_workflow_are_neutral_without_origin_fact() {
        let mut origin = origin();
        origin.entrypoint = Some("sdk-cli".to_string());
        origin.used_workflow_orchestration = Some(true);
        let facts = direct_provider_facts(
            SnapshotSource::ClaudeCode,
            Some(&origin),
            "session-3",
            "2026-07-19T00:00:00Z",
            "claude_code_jsonl:v18",
        );
        assert!(facts
            .iter()
            .any(|fact| fact.field == "execution_mode" && fact.value == "headless"));
        assert!(facts
            .iter()
            .any(|fact| fact.field == "workflow_orchestration"));
        assert!(!facts.iter().any(|fact| fact.field == "origin_kind"));
    }

    #[test]
    fn parent_reference_and_subagent_are_separate_direct_facts() {
        let mut origin = origin();
        origin.source_subagent = Some(true);
        origin.parent_session_ref = Some("019f-parent".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-4",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        assert!(facts
            .iter()
            .any(|fact| fact.field == "origin_kind" && fact.value == "subagent"));
        assert!(facts
            .iter()
            .any(|fact| { fact.field == "parent_session_ref" && fact.value == "019f-parent" }));
    }

    #[test]
    fn direct_fact_payload_is_bounded_and_content_free() {
        let mut origin = origin();
        origin.thread_source = Some("automation".to_string());
        origin.originator = Some("Codex Desktop".to_string());
        origin.parent_session_ref = Some("019f-parent".to_string());
        let facts = direct_provider_facts(
            SnapshotSource::Codex,
            Some(&origin),
            "session-5",
            "2026-07-19T00:00:00Z",
            "codex_jsonl:v21",
        );
        let payload = serde_json::to_vec(&facts).expect("serialize facts");
        assert!(payload.len() <= MAX_SESSION_ATTRIBUTION_PAYLOAD_BYTES);
        let text = String::from_utf8(payload).expect("json");
        for forbidden in [
            "prompt_text",
            "transcript_text",
            "filesystem_path",
            "working_directory",
            "remote_url",
            "process_argv",
            "process_environment",
            "scheduler_definition",
            "raw_log",
        ] {
            assert!(!text.contains(forbidden));
        }
    }
}
