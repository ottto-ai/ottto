use super::{loaded, read, scope, Route, NOW};
use crate::session_attribution::job_template::{context, JobState};
use crate::snapshots::{
    local_index_key, state_v2,
    tail_source::{job_update, seam::tests::route, seed_full_job_template},
    CandidateFile, ScanIndexEntry, SnapshotAccumulator, SnapshotSource,
};
use std::{os::unix::fs::MetadataExt, path::Path};

const TASK: &str = "inspect the service and explain every failure with clear evidence";

pub(super) fn file_candidate(path: &Path) -> CandidateFile {
    let mut file = super::super::settlement_tests::candidate(path);
    let metadata = std::fs::metadata(path).unwrap();
    file.physical_identity = Some([metadata.dev(), metadata.ino()]);
    file.fingerprint_birth_nanos = crate::transcript_acquisition::birth_unix_nanos(&metadata);
    file
}

fn job_full(
    route: &Route,
    path: &Path,
    group_siblings: &[CandidateFile],
) -> crate::snapshots::OwnedJsonlParser {
    use crate::transcript_acquisition::ReadMode;
    let mut parser = route.open(path);
    assert!(matches!(
        parser.prepare_acquisition(None, &scope(), NOW).unwrap(),
        ReadMode::Full(_)
    ));
    seed_full_job_template(
        &route.index,
        &file_candidate(path),
        group_siblings,
        &mut parser.accumulator,
    )
    .unwrap();
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

fn write(path: &Path, rows: &[String]) {
    std::fs::write(path, rows.join("\n") + "\n").unwrap();
}

#[test]
fn job_survives_database_restart_and_unchanged_read_stages_nothing() {
    let mut route = route();
    let path = route.dir.join("a.jsonl");
    write(&path, &task_lines());
    let mut parser = job_full(&route, &path, &[]);
    parser.accumulator.finish_job_template(Some(&context(7)));
    let expected = parser.accumulator.job_template.clone();
    assert!(matches!(expected, Some(JobState::Id { .. })));
    let mut job = job_update(&file_candidate(&path), &parser.accumulator);
    let (tail, native) = route.finish(&path, parser, None, |_| {});
    let key = tail.key_for_test().to_owned();
    assert!(tail.publish_with_job(&native, &mut job));
    assert!(job.is_none());
    route.save(false);
    let (crate::snapshots::tail_source::load::Load::Reused(taken, _), _) =
        loaded(&route, &path, &key)
    else {
        panic!("head reuses");
    };
    assert_eq!(taken.state.finish_view().0.job_template, expected);
    let (parser, mode, _) = read(&route, &path, Some(taken));
    assert!(matches!(
        mode,
        crate::transcript_acquisition::ReadMode::Unchanged
    ));
    assert_eq!(parser.reader.consumed_bytes(), 0);
    assert!(job_update(&file_candidate(&path), &parser.accumulator).is_none());
}

#[test]
fn indexed_legacy_run_cannot_mint_during_full() {
    let mut route = route();
    let path = route.dir.join("legacy.jsonl");
    let (tail, native) = route.complete("legacy.jsonl", &task_lines(), None, |_| {});
    route
        .index
        .files
        .insert(tail.key_for_test().to_owned(), ScanIndexEntry::default());
    assert!(tail.publish(&native));
    route.save(false);
    let mut parser = job_full(&route, &path, &[]);
    assert!(parser.accumulator.first_prompt_material.is_some());
    parser.accumulator.finish_job_template(Some(&context(7)));
    assert!(parser.accumulator.job_template.is_none());
}

#[test]
fn terminal_offline_run_cannot_mint_during_full_after_reconnect() {
    let mut route = route();
    let path = route.dir.join("offline.jsonl");
    write(&path, &task_lines());
    let mut parser = job_full(&route, &path, &[]);
    parser.accumulator.finish_job_template(None);
    let mut job = job_update(&file_candidate(&path), &parser.accumulator);
    let (tail, native) = route.finish(&path, parser, None, |_| {});
    route
        .index
        .files
        .insert(tail.key_for_test().to_owned(), ScanIndexEntry::default());
    assert!(tail.publish_with_job(&native, &mut job));
    route.save(false);
    let mut parser = job_full(&route, &path, &[]);
    parser.accumulator.finish_job_template(Some(&context(7)));
    assert_eq!(parser.accumulator.job_template, Some(JobState::NoId));
}

#[test]
fn pending_job_keeps_waiting_across_restart() {
    let mut route = route();
    let path = route.dir.join("pending.jsonl");
    let mut rows = task_lines();
    let task = rows.remove(0);
    let mut wrapper: serde_json::Value = serde_json::from_str(&task).unwrap();
    wrapper["message"]["content"] =
        "# AGENTS.md instructions\n<INSTRUCTIONS>rules</INSTRUCTIONS>".into();
    rows.insert(0, wrapper.to_string());
    write(&path, &rows);
    let parser = job_full(&route, &path, &[]);
    let mut job = job_update(&file_candidate(&path), &parser.accumulator);
    let (tail, native) = route.finish(&path, parser, None, |_| {});
    let key = tail.key_for_test().to_owned();
    route
        .index
        .files
        .insert(key.clone(), ScanIndexEntry::default());
    assert!(tail.publish_with_job(&native, &mut job));
    route.save(false);
    assert_eq!(
        route.head(&key).unwrap().common.job.unwrap().state,
        JobState::Pending
    );
    rows.push(task);
    write(&path, &rows);
    let mut parser = job_full(&route, &path, &[]);
    parser.accumulator.finish_job_template(Some(&context(7)));
    assert!(matches!(
        parser.accumulator.job_template,
        Some(JobState::Id { .. })
    ));
}

#[test]
fn job_binding_accepts_clamped_birth_on_the_same_inode() {
    use crate::snapshots::tail_source::job_template::same_file;
    let route = route();
    let path = route.dir.join("clamped.jsonl");
    std::fs::write(&path, "").unwrap();
    let mut file = file_candidate(&path);
    file.physical_identity = Some([2, 8]);
    file.fingerprint_birth_nanos = 700;
    file.modified_unix_nanos = 700;
    assert!(same_file(&file, 8, 900));
    assert!(!same_file(&file, 9, 900));
    file.modified_unix_nanos = 701;
    assert!(!same_file(&file, 8, 900));
}

#[test]
fn job_only_head_survives_full_and_checkpoint_changes_until_retirement() {
    let mut route = route();
    let path = route.dir.join("native.jsonl");
    write(&path, &task_lines());
    let file = file_candidate(&path);
    let key = local_index_key(&path);
    let mut first = job_full(&route, &path, &[]);
    let context = context(7);
    first.accumulator.finish_job_template(Some(&context));
    let expected = first.accumulator.job_template.clone().unwrap();
    assert!(matches!(expected, JobState::Id { .. }));
    state_v2::stage_job(
        &route.path,
        &key,
        job_update(&file, &first.accumulator).unwrap(),
    )
    .unwrap();
    route
        .index
        .files
        .insert(key.clone(), ScanIndexEntry::default());
    route.save(false);
    assert!(route.head(&key).unwrap().metadata_only);

    let mut next = job_full(&route, &path, &[]);
    next.accumulator.finish_job_template(Some(&context));
    assert_eq!(next.accumulator.job_template, Some(expected.clone()));
    assert!(job_update(&file, &next.accumulator).is_none());
    let (tail, native) = route.finish(&path, next, None, |_| {});
    assert!(tail.publish(&native));
    route.save(false);
    assert!(!route.head(&key).unwrap().metadata_only);

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
    assert!(route.head(&key).unwrap().metadata_only);
    let mut reread = job_full(&route, &path, &[]);
    reread.accumulator.finish_job_template(Some(&context));
    assert_eq!(reread.accumulator.job_template, Some(expected));

    route.index.files.remove(&key);
    super::super::retire_absent(
        SnapshotSource::ClaudeCode,
        &route.index,
        &Default::default(),
        &Default::default(),
    );
    route.save(false);
    assert!(route.head(&key).is_none());
}

#[test]
fn job_only_pending_group_can_mint_after_its_first_task() {
    let mut route = route();
    let path = route.dir.join("pending-group.jsonl");
    write(&path, &task_lines());
    let key = local_index_key(&path);
    let sibling_path = route.dir.join("indexed-sibling.jsonl");
    std::fs::write(&sibling_path, "").unwrap();
    let group_siblings = [file_candidate(&sibling_path)];
    route
        .index
        .files
        .insert(local_index_key(&sibling_path), ScanIndexEntry::default());
    let context = context(7);
    let mut legacy = job_full(&route, &path, &group_siblings);
    legacy.accumulator.finish_job_template(Some(&context));
    assert!(legacy.accumulator.job_template.is_none());

    let mut pending = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    pending.job_template_changed = true;
    let job = job_update(&file_candidate(&path), &pending).unwrap();
    state_v2::stage_job(&route.path, &key, job).unwrap();
    route
        .index
        .files
        .insert(key.clone(), ScanIndexEntry::default());
    route.save(false);
    assert!(route.head(&key).unwrap().metadata_only);
    let mut parser = job_full(&route, &path, &group_siblings);
    parser.accumulator.finish_job_template(Some(&context));
    assert!(matches!(
        parser.accumulator.job_template,
        Some(JobState::Id { .. })
    ));
}

#[test]
fn fresh_store_leaves_its_preexisting_history_without_jobs() {
    let previous = route();
    let path = previous.dir.join("history.jsonl");
    write(&path, &task_lines());
    let fresh = route();
    let key = local_index_key(&path);
    assert!(!fresh.index.files.contains_key(&key));
    assert!(fresh.head(&key).is_none());
    let mut parser = job_full(&fresh, &path, &[]);
    parser.accumulator.finish_job_template(Some(&context(7)));
    assert_eq!(parser.accumulator.job_template, Some(JobState::NoId));
}

#[test]
fn archived_headless_codex_rollout_stays_ineligible() {
    use crate::snapshots::scan_index_persistence::Source;
    use crate::snapshots::tail_source::seam::tests::route_for;
    let filesystem = route();
    let original = filesystem.dir.join("sessions/rollout.jsonl");
    let archive = filesystem.dir.join("archived_sessions/rollout.jsonl");
    for path in [&original, &archive] {
        std::fs::create_dir(path.parent().unwrap()).unwrap();
    }
    std::fs::write(&original, "").unwrap();
    let born = file_candidate(&original).fingerprint_birth_nanos;
    let mut route = route_for(Source::Codex);
    let old = local_index_key(&original);
    route
        .index
        .files
        .insert(old.clone(), ScanIndexEntry::default());
    route.save(false);
    assert!(route.head(&old).is_none());
    std::fs::rename(original, &archive).unwrap();
    let archived = file_candidate(&archive);
    assert_eq!(archived.fingerprint_birth_nanos, born);
    assert!(!route.index.files.contains_key(&local_index_key(&archive)));

    let mut acc = SnapshotAccumulator::new(SnapshotSource::Codex);
    seed_full_job_template(&route.index, &archived, &[], &mut acc).unwrap();
    acc.observe_job(TASK);
    acc.finish_job_template(Some(&context(7)));
    assert_eq!(acc.job_template, Some(JobState::NoId));
}

#[test]
fn unindexed_file_with_unreadable_head_is_read_and_healed() {
    use crate::snapshots::{
        tail_source::counters, upload::freshness_debt::tests::seed_raw_unread, ScanIndex,
    };
    let mut route = route();
    let path = route.dir.join("unreadable-head.jsonl");
    write(&path, &task_lines());
    let key = local_index_key(&path);
    seed_raw_unread(&route.index, &path);
    route.save(false);
    let before = route.head(&key).unwrap();
    assert_eq!(before.table[&state_v2::Collection::Revisions].pages, 1);
    state_v2::seed_unreadable_tail_head_for_test(&route.index, &key);
    route.index = ScanIndex::load(&route.path).unwrap();
    assert!(!route.index.files.contains_key(&key));
    assert!(matches!(
        loaded(&route, &path, &key).0,
        super::Load::Cold(_)
    ));

    let skipped = counters::total("job_template_skipped", "stored_state");
    let mut parser = job_full(&route, &path, &[]);
    assert_eq!(
        counters::total("job_template_skipped", "stored_state"),
        skipped + 1
    );
    assert_eq!(
        parser.reader.consumed_bytes(),
        std::fs::metadata(&path).unwrap().len()
    );
    assert!(parser.accumulator.first_prompt_material.is_some());
    parser.accumulator.finish_job_template(Some(&context(7)));
    assert!(parser.accumulator.job_template.is_none());
    assert!(job_update(&file_candidate(&path), &parser.accumulator).is_none());
    let (tail, native) = route.finish(&path, parser, None, |_| {});
    assert!(tail.publish(&native));
    route.save(false);
    let after = route.head(&key).unwrap();
    assert!(after.common.job.is_none());
    assert_eq!(after.common.debt, before.common.debt);
    assert!(
        after.table[&state_v2::Collection::Revisions]
            == before.table[&state_v2::Collection::Revisions]
    );
    assert!(matches!(
        loaded(&route, &path, &key).0,
        super::Load::Reused(..)
    ));
}

#[test]
fn unavailable_job_seed_defers_an_unindexed_file() {
    let mut route = route();
    let path = route.dir.join("retry.jsonl");
    write(&path, &task_lines());
    let file = file_candidate(&path);
    route.index.generation += 1; // no matching authenticated store generation
    let mut acc = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    assert!(seed_full_job_template(&route.index, &file, &[], &mut acc).is_err());
    assert!(!acc.job_pending());
    route
        .index
        .files
        .insert(local_index_key(&path), ScanIndexEntry::default());
    seed_full_job_template(&route.index, &file, &[], &mut acc).unwrap();
    assert!(!acc.job_pending());
}
