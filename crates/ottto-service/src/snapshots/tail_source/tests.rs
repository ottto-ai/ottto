use super::*;
/// [behaviour] New slot roundtrips for every source; absent slots leave
/// old prompt facts readable and never derive an id from stored text.
#[test]
fn job_slot_roundtrips_and_old_facts_decode() {
    for source in [
        SnapshotSource::ClaudeCode,
        SnapshotSource::Codex,
        SnapshotSource::Pi,
    ] {
        let mut acc = SnapshotAccumulator::new(source);
        acc.observe_job(Some(
            "# AGENTS.md instructions\n<INSTRUCTIONS>rules</INSTRUCTIONS>".into(),
        ));
        assert!(acc.job_template_pending);
        assert!(!Fact::JobTemplate.present(&acc));
        acc.first_prompt_material = Some("old truncated prompt".into());
        let old = Enc::count_write(usize::MAX, |e| Fact::FirstPrompt.put(&acc, e)).unwrap();
        let mut restored = SnapshotAccumulator::new(source);
        Fact::take(1, &old, &mut restored).unwrap();
        assert_eq!(restored.first_prompt_material, acc.first_prompt_material);
        assert!(restored.job_template.is_none());
        restored.job_template_pending = false;
        restored.observe_job(Some(
            "inspect the service and explain every failure with clear evidence".into(),
        ));
        assert!(restored.job_template.is_none());
        acc.job_template = Some((Some("hmac-sha256:v1:synthetic".into()), "epoch".into()));
        let bytes = Enc::count_write(usize::MAX, |e| Fact::JobTemplate.put(&acc, e)).unwrap();
        Fact::take(6, &bytes, &mut restored).unwrap();
        assert_eq!(restored.job_template, acc.job_template);
        assert!(restored.job_material.is_none());
    }
}
