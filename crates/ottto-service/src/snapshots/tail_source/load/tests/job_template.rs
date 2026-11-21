/// [behaviour] Save/reload keeps the derived id in its own slot, with no
/// new prompt text. The stored head still permits an unchanged zero-byte read.
#[test]
fn job_survives_database_restart() {
    use super::{loaded, read};
    use crate::snapshots::tail_source::claude::tests::lines;
    use crate::snapshots::tail_source::seam::tests::route;
    let mut route = route();
    let expected = Some((Some("hmac-sha256:v1:synthetic".into()), "epoch".into()));
    let (tail, native) = route.complete("a.jsonl", &lines(3), None, |acc| {
        acc.job_template = expected.clone()
    });
    let key = tail.key_for_test().to_owned();
    assert!(tail.publish(&native));
    route.save(false);
    let (crate::snapshots::tail_source::load::Load::Reused(taken, _), _) =
        loaded(&route, &route.dir.join("a.jsonl"), &key)
    else {
        panic!("head reuses");
    };
    assert_eq!(taken.state.finish_view().0.job_template, expected);
    let (parser, mode, _) = read(&route, &route.dir.join("a.jsonl"), Some(taken));
    assert!(matches!(
        mode,
        crate::transcript_acquisition::ReadMode::Unchanged
    ));
    assert_eq!(parser.reader.consumed_bytes(), 0);
}

const TASK: &str = "inspect the service and explain every failure with clear evidence";

fn job_full(
    route: &super::Route,
    path: &std::path::Path,
    group_siblings: &[crate::snapshots::CandidateFile],
) -> crate::snapshots::OwnedJsonlParser {
    use super::super::settlement_tests::candidate;
    use super::{scope, NOW};
    use crate::snapshots::tail_source::seed_full_job_template;
    use crate::transcript_acquisition::ReadMode;
    use std::os::unix::fs::MetadataExt;
    let mut file = candidate(path);
    let metadata = std::fs::metadata(path).unwrap();
    file.physical_identity = Some([metadata.dev(), metadata.ino()]);
    let mut parser = route.open(path);
    assert!(matches!(
        parser
            .prepare_acquisition(None, &scope(), None, NOW)
            .unwrap(),
        ReadMode::Full(_)
    ));
    seed_full_job_template(&route.index, &file, group_siblings, &mut parser.accumulator);
    while !parser.step().unwrap() {}
    parser
}

fn task_lines() -> Vec<String> {
    let mut rows = crate::snapshots::tail_source::claude::tests::lines(3);
    let mut prompt: serde_json::Value = serde_json::from_str(&rows[0]).unwrap();
    prompt["message"]["content"] = TASK.into();
    rows[0] = prompt.to_string();
    rows
}

#[test]
fn indexed_legacy_run_cannot_mint_during_full() {
    use crate::snapshots::{tail_source::seam::tests::route, ScanIndexEntry};
    let mut route = route();
    let path = route.dir.join("legacy.jsonl");
    let (tail, native) = route.complete("legacy.jsonl", &task_lines(), None, |acc| {
        acc.job_template = None;
        acc.job_template_pending = false;
    });
    let key = tail.key_for_test().to_owned();
    route.index.files.insert(key, ScanIndexEntry::default());
    assert!(tail.publish(&native));
    route.save(false);
    let mut parser = job_full(&route, &path, &[]);
    assert!(parser.accumulator.first_prompt_material.is_some());
    parser
        .accumulator
        .finish_job_template(Some(&crate::session_attribution::job_template::context(7)));
    assert!(parser.accumulator.job_template.is_none());
}

#[test]
fn terminal_offline_run_cannot_mint_during_full_after_reconnect() {
    use crate::snapshots::{tail_source::seam::tests::route, ScanIndexEntry};
    let mut route = route();
    let path = route.dir.join("offline.jsonl");
    let (tail, native) = route.complete("offline.jsonl", &task_lines(), None, |_| {});
    let key = tail.key_for_test().to_owned();
    route.index.files.insert(key, ScanIndexEntry::default());
    assert!(tail.publish(&native));
    route.save(false);
    let mut parser = job_full(&route, &path, &[]);
    parser
        .accumulator
        .finish_job_template(Some(&crate::session_attribution::job_template::context(7)));
    assert_eq!(parser.accumulator.job_template, Some((None, String::new())));
}

#[test]
fn pending_run_has_no_job_slot_and_can_mint_on_full() {
    use crate::snapshots::{
        state_v2::{self, Collection, JOB_TEMPLATE_PAGE},
        tail_source::{seam::tests::route, Fact},
        ScanIndexEntry,
    };
    let mut route = route();
    let path = route.dir.join("pending.jsonl");
    let mut rows = task_lines();
    let task = rows.remove(0);
    let mut wrapper: serde_json::Value = serde_json::from_str(&task).unwrap();
    wrapper["message"]["content"] =
        "# AGENTS.md instructions\n<INSTRUCTIONS>rules</INSTRUCTIONS>".into();
    rows.insert(0, wrapper.to_string());
    let (tail, native) = route.complete("pending.jsonl", &rows, None, |_| {});
    let key = tail.key_for_test().to_owned();
    route
        .index
        .files
        .insert(key.clone(), ScanIndexEntry::default());
    assert!(tail.publish(&native));
    route.save(false);
    let head = route.head(&key).unwrap();
    assert!(head.common.job_template_pending);
    state_v2::load_tail(&route.index, &key, &head, |collection, page, _| {
        assert_ne!(
            (collection, page),
            (Collection::SessionFacts, JOB_TEMPLATE_PAGE)
        );
        Ok(())
    })
    .unwrap();
    rows.push(task);
    std::fs::write(&path, rows.join("\n") + "\n").unwrap();
    let mut parser = job_full(&route, &path, &[]);
    parser
        .accumulator
        .finish_job_template(Some(&crate::session_attribution::job_template::context(7)));
    assert!(!parser.accumulator.job_template_pending);
    assert!(Fact::JobTemplate.present(&parser.accumulator));
    assert!(parser.accumulator.job_template.unwrap().0.is_some());
}

#[test]
fn job_binding_accepts_clamped_birth_on_the_same_inode() {
    use super::super::settlement_tests::candidate;
    use crate::snapshots::tail_source::job_template::same_file;
    let route = crate::snapshots::tail_source::seam::tests::route();
    let path = route.dir.join("clamped.jsonl");
    std::fs::write(&path, "").unwrap();
    let mut file = candidate(&path);
    file.physical_identity = Some([2, 8]);
    file.fingerprint_birth_nanos = 700;
    file.modified_unix_nanos = 700;
    assert!(same_file(&file, 8, 900));
    assert!(!same_file(&file, 9, 900));
    file.modified_unix_nanos = 701;
    assert!(!same_file(&file, 8, 900));
}

#[test]
fn detached_job_survives_native_full_without_a_checkpoint() {
    use super::super::settlement_tests::candidate;
    use crate::snapshots::{
        state_v2,
        tail_source::{job_template_observation, seam::tests::route},
        ScanIndexEntry,
    };
    use std::os::unix::fs::MetadataExt;
    let mut route = route();
    let path = route.dir.join("detached.jsonl");
    std::fs::write(&path, task_lines().join("\n") + "\n").unwrap();
    let mut file = candidate(&path);
    let metadata = std::fs::metadata(&path).unwrap();
    file.physical_identity = Some([metadata.dev(), metadata.ino()]);
    let key = crate::snapshots::local_index_key(&path);
    let mut first = job_full(&route, &path, &[]);
    let context = crate::session_attribution::job_template::context(7);
    first.accumulator.finish_job_template(Some(&context));
    let expected = first.accumulator.job_template.clone().unwrap();
    assert!(expected.0.is_some());
    let job = job_template_observation(&file, &first.accumulator).unwrap();
    state_v2::observe_job_template(&route.path, &key, job).unwrap();
    route
        .index
        .files
        .insert(key.clone(), ScanIndexEntry::default());
    route.save(false);
    assert!(route.head(&key).is_none());
    let mut next = job_full(&route, &path, &[]);
    next.accumulator.finish_job_template(Some(&context));
    assert_eq!(next.accumulator.job_template, Some(expected.clone()));

    // A retained checkpoint takes custody, and later dropping that checkpoint
    // brings the decision back to the detached row.
    let (tail, native) = route.complete("detached.jsonl", &task_lines(), None, |acc| {
        acc.job_template = Some(expected.clone());
        acc.job_template_pending = false;
    });
    assert!(tail.publish(&native));
    let job = job_template_observation(&file, &next.accumulator).unwrap();
    state_v2::observe_job_template(&route.path, &key, job).unwrap();
    route.save(false);
    assert!(state_v2::load_job_template_observation(&route.index, &key)
        .unwrap()
        .is_none());
    state_v2::observe_tail(
        &route.path,
        &key,
        state_v2::Observation {
            representation: state_v2::Representation::NonTail,
            ..Default::default()
        },
    )
    .unwrap();
    route.save(false);
    assert!(route.head(&key).is_none());
    let mut reread = job_full(&route, &path, &[]);
    reread.accumulator.finish_job_template(Some(&context));
    assert_eq!(reread.accumulator.job_template, Some(expected));

    let (heads, decisions) = state_v2::tail_custody_keys(&route.index).unwrap();
    assert!(!heads.contains(&key));
    assert!(decisions.contains(&key));
    route.index.files.remove(&key);
    super::super::retire_absent(
        crate::snapshots::SnapshotSource::ClaudeCode,
        &route.index,
        &Default::default(),
        &Default::default(),
    );
    route.save(false);
    assert!(state_v2::load_job_template_observation(&route.index, &key)
        .unwrap()
        .is_none());
}

#[test]
fn detached_pending_group_can_mint_after_its_first_task() {
    use super::super::settlement_tests::candidate;
    use crate::snapshots::{
        state_v2,
        tail_source::{job_template_observation, seam::tests::route},
        ScanIndexEntry, SnapshotAccumulator, SnapshotSource,
    };
    use std::os::unix::fs::MetadataExt;
    let mut route = route();
    let path = route.dir.join("detached-pending.jsonl");
    std::fs::write(&path, task_lines().join("\n") + "\n").unwrap();
    let mut file = candidate(&path);
    let metadata = std::fs::metadata(&path).unwrap();
    file.physical_identity = Some([metadata.dev(), metadata.ino()]);
    let key = crate::snapshots::local_index_key(&path);
    let sibling_path = route.dir.join("indexed-sibling.jsonl");
    std::fs::write(&sibling_path, "").unwrap();
    let sibling = candidate(&sibling_path);
    route.index.files.insert(
        crate::snapshots::local_index_key(&sibling_path),
        ScanIndexEntry::default(),
    );
    let group_siblings = [sibling];
    let context = crate::session_attribution::job_template::context(7);
    let mut legacy = job_full(&route, &path, &group_siblings);
    legacy.accumulator.finish_job_template(Some(&context));
    assert!(legacy.accumulator.job_template.is_none());

    let pending = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let job = job_template_observation(&file, &pending).unwrap();
    assert!(job.fact.is_none());
    state_v2::observe_job_template(&route.path, &key, job).unwrap();
    route
        .index
        .files
        .insert(key.clone(), ScanIndexEntry::default());
    route.save(false);
    assert!(route.head(&key).is_none());
    let mut parser = job_full(&route, &path, &group_siblings);
    parser.accumulator.finish_job_template(Some(&context));
    assert!(parser.accumulator.job_template.unwrap().0.is_some());
}
