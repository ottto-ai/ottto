//! [behaviour] Synthetic vectors shared by all source readers.
use super::*;
use crate::session_attribution::job_template::{self, JobState};
use serde_json::{json, Value};

fn apply(source: SnapshotSource, text: &str, array: bool, acc: &mut SnapshotAccumulator) {
    let content = if array {
        json!([{"type":"text", "text":text}])
    } else {
        json!(text)
    };
    match source {
        SnapshotSource::ClaudeCode => scan::lines::apply::claude_prompt_content(
            &json!({"type":"user", "message":{"role":"user","content":content}}),
            acc,
        ),
        SnapshotSource::Codex => scan::lines::apply::codex_prompt_content(
            &json!({"type":"response_item","payload":{"type":"message","role":"user","content":content}}),
            acc,
        ),
        SnapshotSource::Pi => scan::lines::apply::pi_prompt_content(
            &json!({"message":{"role":"user","content":content}}),
            Some("user"),
            acc,
        ),
    }
}

#[test]
fn job_vectors_across_readers() {
    let vectors: Value =
        serde_json::from_str(include_str!("../../../../../fixtures/job_template_v1.json")).unwrap();
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        for array in [false, true] {
            for v in vectors.as_array().unwrap() {
                if let Ok(Some(task)) = job_template::task(v["prompt"].as_str().unwrap()) {
                    assert_eq!(
                        job_template::material(task).as_deref(),
                        v["material"].as_str()
                    );
                }
                let mut acc = SnapshotAccumulator::new(source);
                // Wrapper-only records keep the independent extractor pending.
                apply(
                    source,
                    "# AGENTS.md instructions\n<INSTRUCTIONS>rules</INSTRUCTIONS>",
                    array,
                    &mut acc,
                );
                apply(source, v["prompt"].as_str().unwrap(), array, &mut acc);
                acc.finish_job_template(Some(&job_template::context(7)));
                assert_eq!(id(&acc), v["id"].as_str(), "{}", v["name"]);
                assert!(acc.job_material.is_none());
            }
        }
    }
}

#[test]
fn job_rejections_and_first_task_are_terminal() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        for bad in [
            "<system_instruction",
            "# AGENTS.md instructions\n<INSTRUCTIONS>broken",
            &"a".repeat(65537),
            "short task",
            "This session is being continued from a previous conversation with many details",
        ] {
            let mut acc = SnapshotAccumulator::new(source);
            apply(source, bad, false, &mut acc);
            apply(
                source,
                "inspect the service and explain every failure with clear evidence",
                false,
                &mut acc,
            );
            acc.finish_job_template(Some(&job_template::context(7)));
            assert_eq!(acc.job_template, Some(JobState::NoId));
        }
        for summary in [
            "<artifact-content-authored-by-others/>",
            "[Request interrupted by user]",
            "<task-notification>task complete</task-notification>",
        ] {
            let mut acc = SnapshotAccumulator::new(source);
            apply(source, summary, false, &mut acc);
            apply(
                source,
                "inspect the service and explain every failure with clear evidence",
                false,
                &mut acc,
            );
            acc.finish_job_template(Some(&job_template::context(7)));
            assert!(id(&acc).is_some());
        }
    }
}

#[test]
fn job_keys_and_offline_state_do_not_reuse_another_epoch() {
    let prompt = "inspect the service and explain every failure with clear evidence";
    let mut acc = SnapshotAccumulator::new(SnapshotSource::Pi);
    apply(SnapshotSource::Pi, prompt, false, &mut acc);
    acc.finish_job_template(Some(&job_template::context(7)));
    assert!(job_template::context(7)
        .job_fact(acc.job_template.as_ref(), "session", "2026-01-01T00:00:00Z")
        .is_some());
    assert!(job_template::context(8)
        .job_fact(acc.job_template.as_ref(), "session", "2026-01-01T00:00:00Z")
        .is_none());
    let mut rotated = SnapshotAccumulator::new(SnapshotSource::Pi);
    apply(SnapshotSource::Pi, prompt, false, &mut rotated);
    rotated.finish_job_template(Some(&job_template::context(8)));
    assert_ne!(id(&rotated), id(&acc));
    let mut offline = SnapshotAccumulator::new(SnapshotSource::Pi);
    apply(SnapshotSource::Pi, prompt, false, &mut offline);
    offline.finish_job_template(None);
    offline.finish_job_template(Some(&job_template::context(7)));
    assert_eq!(offline.job_template, Some(JobState::NoId));
}

/// [regress] A fork's copied prompt is context; its own first task supplies the id.
#[test]
fn pi_fork_uses_its_own_task() {
    let source = SnapshotSource::Pi;
    let mut acc = SnapshotAccumulator::new(source);
    apply_pi_line(
        &json!({"type":"session","id":"fork","parentSession":"parent","timestamp":"2026-01-01T00:00:00Z"}),
        &mut acc,
    );
    apply_pi_line(
        &json!({"type":"message","timestamp":"2025-12-31T23:00:00Z","message":{"role":"user","content":"inspect unrelated parent behavior and preserve all recorded evidence carefully"}}),
        &mut acc,
    );
    let prompt = "inspect the service and explain every failure with clear evidence";
    apply_pi_line(
        &json!({"type":"message","timestamp":"2026-01-01T00:01:00Z","message":{"role":"user","content":prompt}}),
        &mut acc,
    );
    acc.finish_job_template(Some(&job_template::context(7)));
    let expected = job_template::context(7)
        .opaque_id("job_template:v1", &job_template::material(prompt).unwrap());
    assert_eq!(id(&acc), expected.as_deref());
}

#[test]
fn job_cap_measures_stripped_task_and_bounds_raw_record() {
    let prompt = "inspect the service and explain every failure with clear evidence";
    let wrapper = format!(
        "<environment_context>{}</environment_context>",
        "a".repeat(65537)
    );
    assert_eq!(job_template::task(&wrapper), Ok(None));
    assert_eq!(
        job_template::task(&format!("{wrapper}\n{prompt}")),
        Ok(Some(prompt))
    );
    assert_eq!(
        job_template::task(&format!("{wrapper}{}", "a".repeat(65537))),
        Err("oversize")
    );
    assert_eq!(job_template::task(&wrapper.repeat(17)), Err("oversize"));
}

fn id(acc: &SnapshotAccumulator) -> Option<&str> {
    match &acc.job_template {
        Some(JobState::Id { id, .. }) => Some(id),
        _ => None,
    }
}
