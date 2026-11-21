use super::*;

/// Absent job state leaves old prompt facts readable and does not use their
/// display material to make a new decision.
#[test]
fn legacy_first_prompt_fact_does_not_supply_job_state() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut acc = SnapshotAccumulator::new(source);
        acc.first_prompt_material = Some("old truncated prompt".into());
        let old = Enc::count_write(usize::MAX, |e| Fact::FirstPrompt.put(&acc, e)).unwrap();
        let mut restored = SnapshotAccumulator::new(source);
        restored.job_template = None;
        Fact::take(1, &old, &mut restored).unwrap();
        assert_eq!(restored.first_prompt_material, acc.first_prompt_material);
        restored.observe_job("inspect the service and explain every failure with clear evidence");
        assert!(restored.job_template.is_none());
        assert!(restored.job_material.is_none());
    }
}
