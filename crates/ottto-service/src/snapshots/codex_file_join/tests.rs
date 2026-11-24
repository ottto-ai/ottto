//! Tests for joining physical Codex rollout files: selectors, ownership,
//! custody and the group job, on synthetic rollouts.

use super::*;

pub(crate) fn usage(input: u64) -> Value {
    json!({"input_tokens":input,"cached_input_tokens":0,"cache_write_input_tokens":0,
        "output_tokens":0,"reasoning_output_tokens":0,"total_tokens":input})
}
/// Bind synthetic native records to explicit task lifetimes, as V2 requires.
pub(crate) fn bound_rows(rows: &[Value]) -> Vec<Value> {
    if rows
        .iter()
        .any(|r| string_eq_at(r, &["payload", "type"], "task_started"))
    {
        return rows.to_vec();
    }
    let mut out = Vec::new();
    let mut active: Option<String> = None;
    let mut at = rows
        .first()
        .map(|row| row["timestamp"].clone())
        .unwrap_or(Value::Null);
    let event = |kind: &str, turn: &str, at: &Value| {
        json!({"type":"event_msg",
        "timestamp":at,"payload":{"type":kind,"turn_id":turn}})
    };
    for row in rows {
        if row["timestamp"].is_string() {
            at = row["timestamp"].clone();
        }
        let context = string_eq_at(row, &["type"], "turn_context");
        let native = string_eq_at(row, &["type"], "token_usage_record");
        if context {
            if let Some(prior) = active.take() {
                out.push(event("task_complete", &prior, &at));
            }
        }
        if (context || native) && active.is_none() {
            let turn = string_at(row, &["payload", "turn_id"])
                .or_else(|| string_at(row, &["payload", "response_id"]))
                .unwrap_or_else(|| "fixture-turn".into());
            out.push(event("task_started", &turn, &at));
            active = Some(turn);
        }
        let mut row = row.clone();
        if native && row["payload"]["turn_id"].is_null() {
            row["payload"]["turn_id"] = json!(active);
        }
        out.push(row);
    }
    if let Some(turn) = active {
        out.push(event("task_complete", &turn, &at));
    }
    out
}
pub(crate) fn member(owner: &str, response: &str, input: u64, cumulative: u64) -> Vec<Value> {
    let mut rows = bound_rows(&unbound_member(owner, response, input, cumulative));
    rows.insert(
        2,
        json!({"type":"turn_context", "timestamp":rows[1]["timestamp"],
        "payload":{"turn_id":response,"model":"gpt-5.2"}}),
    );
    rows
}
fn unbound_member(owner: &str, response: &str, input: u64, cumulative: u64) -> Vec<Value> {
    // Header time follows the counter: equal header bytes and size would
    // be one copied candidate (`CandidateCopy`).
    let created = format!(
        "2026-10-01T10:{:02}:00Z",
        cumulative.saturating_sub(input) / 100
    );
    vec![
        json!({"type":"session_meta","timestamp":created,"payload":{"id":owner}}),
        json!({"type":"token_usage_record","timestamp":"2026-10-01T10:01:00Z","payload":{
            "thread_id":owner,"response_id":response,"usage":usage(input),"thread_token_usage":usage(cumulative)}}),
        json!({"type":"event_msg","timestamp":format!("2026-10-01T10:{:02}:01Z",cumulative / 100),
            "payload":{"type":"token_count","info":{"last_token_usage":usage(input),"total_token_usage":usage(cumulative)}}}),
    ]
}
/// Boot and replay one group in page (no cursor) to its last EOF.
pub(crate) fn replay_group(
    group: Group,
    index: &ScanIndex,
) -> std::result::Result<Box<OwnedActiveFile>, GroupEnd> {
    let mut boot = GroupBoot::new(group, index);
    loop {
        match boot.step(None, index) {
            Boot::Pending => {}
            Boot::Ready => break,
            Boot::Refused(reason) => {
                return Err(GroupEnd::Refused {
                    reason,
                    position: 0,
                    offset: 0,
                    at_eof: false,
                })
            }
            Boot::Strict | Boot::Unchanged => return Err(GroupEnd::Strict),
        }
    }
    let metadata = CodexTitleMetadata::default();
    let mut job = boot.into_job(JobInputs {
        metadata: &metadata,
        cache: None,
        index,
    })?;
    let no_scope = |_: &CandidateFile| None;
    let inputs = StepInputs {
        metadata: &metadata,
        attribution: None,
        live_scope: &no_scope,
        cache: None,
        collected_at: "2026-10-01T12:00:00Z",
    };
    for _ in 0..10_000 {
        match step_group(&mut job, &inputs) {
            GroupStep::Read(Ok(true)) => return Ok(job),
            GroupStep::Read(Ok(false)) => {}
            GroupStep::Read(Err(_)) => return Err(GroupEnd::Strict),
            GroupStep::End(end) => return Err(end),
        }
    }
    panic!("bounded group replay did not finish");
}
pub(crate) fn fixture() -> (PathBuf, HeaderInventory) {
    // Not keyed on the clock: macOS reads it in whole microseconds, so two
    // tests could share (and one remove) the other's root.
    let root = crate::test_scratch::unique_path("ottto-codex-join");
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let mut paths = BTreeSet::new();
    for (name, rows) in [
        ("a", member(owner, "r-a", 100, 100)),
        ("b", member(owner, "r-b", 200, 300)),
    ] {
        let path = sessions.join(format!("{name}.jsonl"));
        let body = rows
            .iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>();
        fs::write(&path, body).unwrap();
        paths.insert(local_index_key(&path));
    }
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    (root, inventory)
}
/// [regress] Failed carry proof constrains only its established owner.
#[test]
fn carry_deferral_holds_only_its_proven_owner() {
    let mut inventory = HeaderInventory::new(&[], &BTreeSet::new(), None);
    inventory.complete = true;
    inventory.held_owners.insert("held".into());
    let affected = inventory.affected_owners();
    assert!(!inventory.membership_complete("held", affected.as_ref()));
    assert!(inventory.membership_complete("independent", affected.as_ref()));
    inventory.complete = false;
    assert!(inventory.affected_owners().is_none());
}
/// [regress] The census line names the writer that made the inventory
/// incomplete, counts only.
#[test]
fn incomplete_inventory_counts_the_writer_that_fired() {
    let paths = BTreeSet::from(["/outside/a.jsonl".to_owned()]);
    let mut inventory = HeaderInventory::new(&[], &paths, Some(&DirectoryCensus::new()));
    assert_eq!(inventory.incomplete_fields((0, false, 0)), None);
    while !inventory.step(&CodexTitleMetadata::default()) {}
    assert!(!inventory.complete);
    assert_eq!(
        inventory.incomplete_fields((1, false, 1)).as_deref(),
        Some(
            " inventory_held=1 inventory_awaiting_directories=0 inventory_outside_roster=1 \
                 inventory_census_unstable=0 inventory_census_walk_pending=0 \
                 inventory_outside_roots=1 inventory_header_error=0 \
                 inventory_funding_refused=0 inventory_selected_not_inventoried=0"
        )
    );
    let absent = HeaderInventory::new(&[], &BTreeSet::new(), None);
    assert_eq!(absent.incomplete_causes.0, [1, 0, 0, 0, 0, 0]);
}

#[test]
fn header_inventory_completes_valid_large_headers_without_a_volume_limit() {
    let (root, _) = fixture();
    let sessions = root.join("sessions");
    let mut paths = BTreeSet::new();
    // Native owning headers carry instructions as well as identity. A
    // supported population of individually bounded headers can therefore
    // exceed 32MiB before any transcript records have been parsed.
    for number in 0..720 {
        let path = sessions.join(format!("large-{number:04}.jsonl"));
        let owner = format!("{number:08x}-1111-4111-8111-ffffffffffff");
        let header = json!({"type":"session_meta","payload":{
            "id":owner,"instructions":"x".repeat(48 * 1024)
        }});
        fs::write(&path, format!("{header}\n")).unwrap();
        paths.insert(local_index_key(&path));
    }
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let metadata = CodexTitleMetadata::default();
    let start = std::time::Instant::now();
    let ((inventory, steps), allocations) = crate::retry_allocation_probe::measure(|| {
        let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        let mut steps = 0;
        while !inventory.step(&metadata) {
            steps += 1;
        }
        (inventory, steps)
    });
    let complete = inventory.complete;
    let header_count = inventory.headers.len();
    let read_bytes = inventory.read_bytes;
    fs::remove_dir_all(root).unwrap();
    assert!(complete, "valid headers must not turn the whole census red");
    assert_eq!(header_count, paths.len());
    assert_eq!(steps, paths.len(), "one bounded header per native step");
    assert!(read_bytes > 32 * 1024 * 1024);
    assert!(read_bytes <= paths.len() * (MAX_HEADER_BYTES + 1));
    eprintln!(
        "CODEX_HEADER_CENSUS_MEASUREMENT {}",
        json!({"synthetic_headers":header_count,"native_steps":steps,
            "header_read_bytes":read_bytes,"wall_microseconds":start.elapsed().as_micros(),
            "requested_allocation_peak":allocations.requested_peak,
            "usable_allocation_peak":allocations.usable_peak,
            "retained_requested_bytes":allocations.requested_live,
            "retained_usable_bytes":allocations.usable_live})
    );
}

#[test]
fn ordinary_compressed_header_retains_pending_on_funding_refusal_and_plain_sibling_wins() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let (root, fixture) = fixture();
    let sessions = root.join("sessions");
    let plain = fixture.headers[0].candidate.path.clone();
    let compressed = plain.with_extension("jsonl.zst");
    fs::write(
        &compressed,
        zstd::stream::encode_all(&fs::read(&plain).unwrap()[..], 1).unwrap(),
    )
    .unwrap();
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let paths = BTreeSet::from([local_index_key(&plain), local_index_key(&compressed)]);
    let metadata = CodexTitleMetadata::default();
    let cache = Arc::new(sampled_scan::SharedCache::default());
    let mut inventory =
        HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
    while !inventory.step_encoded(&metadata, Some(&cache)) {}
    assert!(inventory.complete);
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].candidate.path, plain);
    assert_eq!(inventory.owner_for_path(&compressed), None);

    let paths = BTreeSet::from([local_index_key(&compressed)]);
    let mut inventory =
        HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
    assert!(!inventory.step_encoded(&metadata, None));
    assert!(inventory.pending.is_empty());
    assert!(!inventory.complete);
    assert!(inventory.headers.is_empty());
    assert!(inventory.refused.is_empty());
    assert_eq!(inventory.read_bytes, 0);
    assert!(!inventory.content_unchanged());
    assert!(inventory.affected_owners().is_none());
    // A later ordinary attempt retries after funding returns.
    let mut inventory =
        HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
    while !inventory.step_encoded(&metadata, Some(&cache)) {}
    assert!(
        inventory.complete,
        "funded recognition: read={}, refusals={}, causes={}",
        inventory.read_bytes,
        inventory.refused.len(),
        serde_json::to_string(&inventory.unreadable_causes).unwrap()
    );
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].owner, fixture.headers[0].owner);
    assert_eq!(inventory.headers[0].candidate.path, compressed);
    assert!(inventory.read_bytes > 0);
    assert!(cache
        .with_cursor(|cursor| cursor.headers.get(paths.first().unwrap()))
        .unwrap()
        .is_some());
    fs::remove_dir_all(root).unwrap();
}

/// [regress] Codex compressing a rollout after the roster listed both
/// copies reads the shadowed archive instead of refusing the plaintext.
#[cfg(unix)]
#[test]
fn header_inventory_reads_the_archive_codex_swapped_in_after_listing() {
    let _decoder = sampled_scan::transition_fixture::codex_decoder_test_lock();
    let metadata = CodexTitleMetadata::default();
    let swapped = |write_archive: &dyn Fn(&Path, &Path, &[u8])| {
        let (root, fixture) = fixture();
        let sessions = root.join("sessions");
        let plain = fixture.headers[0].candidate.path.clone();
        let archive = plain.with_extension("jsonl.zst");
        write_archive(&root, &archive, &fs::read(&plain).unwrap()[..]);
        let mut directories = DirectoryCensus::new();
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let paths = BTreeSet::from([local_index_key(&plain), local_index_key(&archive)]);
        let mut inventory =
            HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
        assert_eq!(
            inventory.pending,
            std::slice::from_ref(&plain),
            "the roster shadows the archive"
        );
        // Codex replaces the plaintext between the roster and its open.
        fs::remove_file(&plain).unwrap();
        let cache = Arc::new(sampled_scan::SharedCache::default());
        while !inventory.step_encoded(&metadata, Some(&cache)) {}
        let owner = fixture.headers[0].owner.clone();
        (root, plain, archive, owner, inventory)
    };
    let causes = |inventory: &HeaderInventory| {
        let causes = serde_json::to_value(inventory.unreadable_causes).unwrap();
        serde_json::from_value::<Vec<u64>>(causes["counts"].clone()).unwrap()
    };
    let refused =
        |inventory: &HeaderInventory| inventory.refused.keys().cloned().collect::<Vec<_>>();

    let (root, _, archive, owner, inventory) = swapped(&|_, archive, plain| {
        fs::write(archive, zstd::stream::encode_all(plain, 1).unwrap()).unwrap();
    });
    assert!(inventory.complete);
    assert!(inventory.refused.is_empty());
    assert_eq!(causes(&inventory), [0; 8]);
    assert_eq!(inventory.headers.len(), 1);
    assert_eq!(inventory.headers[0].candidate.path, archive);
    assert_eq!(inventory.owner_for_path(&archive), Some(owner.as_str()));
    fs::remove_dir_all(root).unwrap();

    // An unreadable archive is refused and counted under its own path.
    let (root, _, archive, _, inventory) = swapped(&|_, archive, _| {
        fs::write(archive, b"not a zstd frame").unwrap();
    });
    assert!(!inventory.complete);
    assert!(inventory.headers.is_empty());
    assert_eq!(refused(&inventory), [local_index_key(&archive)]);
    assert_eq!(causes(&inventory).iter().sum::<u64>(), 1);
    fs::remove_dir_all(root).unwrap();

    // No archive, or one that is a symlink (here to a file outside the
    // root): the plaintext stays refused as OpenRead, nothing else read.
    let symlink_out = |root: &Path, archive: &Path, plain: &[u8]| {
        let outside = root.join("outside.jsonl.zst");
        fs::write(&outside, zstd::stream::encode_all(plain, 1).unwrap()).unwrap();
        std::os::unix::fs::symlink(&outside, archive).unwrap();
    };
    let unchanged = |write_archive: &dyn Fn(&Path, &Path, &[u8])| {
        let (root, plain, _, _, inventory) = swapped(write_archive);
        assert!(!inventory.complete);
        assert!(inventory.headers.is_empty());
        assert_eq!(inventory.read_bytes, 0);
        assert_eq!(refused(&inventory), [local_index_key(&plain)]);
        let mut expected = [0; 8];
        expected[UnreadableCause::OpenRead as usize] = 1;
        assert_eq!(causes(&inventory), expected);
        fs::remove_dir_all(root).unwrap();
    };
    unchanged(&|_, _, _| {});
    unchanged(&symlink_out);
}

#[test]
fn header_owner_lookup_uses_complete_path_order() {
    let (root, inventory) = fixture();
    let template = inventory.headers[0].clone();
    let sessions = root.join("sessions");
    fs::create_dir_all(sessions.join("a")).unwrap();
    let mut paths = BTreeSet::new();
    for (name, owner) in [
        ("a.jsonl", "11111111-2222-4333-8444-555555555555"),
        ("a/b.jsonl", "22222222-2222-4333-8444-555555555555"),
        ("b.jsonl", "33333333-2222-4333-8444-555555555555"),
    ] {
        let path = sessions.join(name);
        fs::write(
            &path,
            format!(
                "{}\n",
                json!({"type":"session_meta","payload":{"id":owner}})
            ),
        )
        .unwrap();
        paths.insert(local_index_key(&path));
    }
    let mut actual = HeaderInventory::new(&[sessions], &paths, Some(&inventory.directories));
    while !actual.step(&CodexTitleMetadata::default()) {}
    assert_eq!(actual.headers.len(), 3);
    for header in &actual.headers {
        assert_eq!(
            actual.owner_for_path(&header.candidate.path),
            Some(header.owner.as_str())
        );
    }
    assert!(actual
        .owner_for_path(&root.join("sessions/missing.jsonl"))
        .is_none());
    assert_eq!(
        inventory.owner_for_path(&template.candidate.path),
        Some(template.owner.as_str())
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn header_inventory_detects_late_members_and_owner_changes() {
    let (root, inventory) = fixture();
    let validation = validator(inventory);
    validation.validate_all().unwrap();
    fs::write(root.join("sessions/new.jsonl"), "new member").unwrap();
    assert!(validation.validate_all().is_err());
    fs::remove_dir_all(root).unwrap();
    let (root, inventory) = fixture();
    let rows = member("ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
    fs::write(
        root.join("sessions/b.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    assert!(validator(inventory).validate_all().is_err());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn proven_body_failure_affects_only_its_owner_and_unknown_header_is_a_wildcard() {
    let (root, original) = fixture();
    let sessions = root.join("sessions");
    let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
    let failed = original.headers[0].candidate.path.clone();
    // A reachable body loss AFTER a valid owning header, with a same-id
    // sibling. No cached-header byte read is invented for this fixture.
    let mut body = fs::read(&failed).unwrap();
    body.extend_from_slice(b"\xff\n");
    fs::write(&failed, body).unwrap();
    let healthy_path = sessions.join("healthy.jsonl");
    fs::write(
        &healthy_path,
        member(healthy, "healthy", 100, 100)
            .iter()
            .map(|row| format!("{row}\n"))
            .collect::<String>(),
    )
    .unwrap();
    let paths = original
        .headers
        .iter()
        .map(|header| local_index_key(&header.candidate.path))
        .chain(std::iter::once(local_index_key(&healthy_path)))
        .collect();
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    assert!(
        inventory.complete,
        "body loss does not erase proven header ownership"
    );
    let owner = original.headers[0].owner.clone();
    let group = inventory
        .groups()
        .remove(&group_key(&root, &owner))
        .unwrap();
    assert_eq!(group.members.len(), 2);
    assert!(matches!(
        replay_group(group, &ScanIndex::default()),
        Err(GroupEnd::Strict)
    ));
    let affected = inventory.affected_owners();
    assert!(inventory.membership_complete(&owner, affected.as_ref()));
    assert!(inventory.membership_complete(healthy, affected.as_ref()));
    let validation = Validation::new(
        inventory.clone(),
        Vec::new(),
        &BTreeSet::from([healthy.into()]),
        paths,
    );
    assert!(validation.validate_all().is_ok());
    fs::write(&healthy_path, b"{malformed}\n").unwrap();
    assert!(validation.validate_all().is_err());
    fs::remove_dir_all(root).unwrap();
}

fn write_owner(path: &Path, owner: &str) {
    fs::write(
        path,
        format!(
            "{}\n",
            json!({"type":"session_meta","payload":{"id":owner}})
        ),
    )
    .unwrap();
}
fn roster(inventory: &HeaderInventory) -> BTreeSet<String> {
    inventory
        .headers
        .iter()
        .map(|h| local_index_key(&h.candidate.path))
        .collect()
}
pub(super) fn validator(inventory: HeaderInventory) -> Validation {
    let paths = roster(&inventory);
    let owners = BTreeSet::from([inventory.headers[0].owner.clone()]);
    Validation::new(inventory, Vec::new(), &owners, paths)
}
fn validation_error(validation: &Validation) -> String {
    crate::snapshot_sync::safe_error(&validation.validate_all().unwrap_err())
}

/// [regress] Every home constrains this page's owners. Unrelated changes
/// defer, while cross-home collisions and unreadable headers fail closed.
#[test]
fn surviving_singleton_revalidates_its_owners_across_all_homes() {
    let (root, original) = fixture();
    let sessions = root.join("sessions");
    let other_root = crate::test_scratch::unique_path("ottto-codex-join-other");
    let other = other_root.join("sessions");
    fs::create_dir_all(&other).unwrap();
    let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
    let remote = "dddddddd-1111-4111-8111-dddddddddddd";
    let healthy_path = sessions.join("healthy.jsonl");
    let remote_path = other.join("remote.jsonl");
    write_owner(&healthy_path, healthy);
    write_owner(&remote_path, remote);
    let mut paths = roster(&original);
    paths.extend([
        local_index_key(&healthy_path),
        local_index_key(&remote_path),
    ]);
    let mut directories = DirectoryCensus::new();
    for directory in [&sessions, &other] {
        directories.observe(directory, &fs::metadata(directory).unwrap());
    }
    let roots = [sessions.clone(), other.clone()];
    let mut inventory = HeaderInventory::new(&roots, &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    let owner = original.headers[0].owner.clone();
    let selected = BTreeSet::from([owner.clone(), healthy.into()]);
    let validation = Validation::new(inventory.clone(), Vec::new(), &selected, paths.clone());
    // Count flips 3 -> 4: remote headers now participate too.
    assert_eq!(validation.validate_all().unwrap(), 4);
    write_owner(&remote_path, healthy);
    // Cross-home rewrite flips success -> the ownership phrase.
    assert_eq!(validation_error(&validation), HEADER_OWNERSHIP_CHANGED);
    let mut next = HeaderInventory::new(&roots, &paths, Some(&directories));
    while !next.step(&CodexTitleMetadata::default()) {}
    let affected = next.affected_owners();
    assert!(!next.membership_complete(healthy, affected.as_ref()));
    assert!(next.membership_complete(&owner, affected.as_ref()));
    fs::write(&remote_path, b"{unknown}\n").unwrap();
    fs::write(other.join("late.jsonl"), b"{unknown}\n").unwrap();
    assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
    // Restore remote proof first so malformed files do not mask ownership.
    fs::remove_file(other.join("late.jsonl")).unwrap();
    write_owner(&remote_path, remote);
    write_owner(&healthy_path, remote);
    assert_eq!(
        crate::snapshot_sync::safe_error(
            &validation
                .validate(&BTreeSet::from([healthy.into()]))
                .unwrap_err()
        ),
        HEADER_OWNERSHIP_CHANGED
    );
    // Every owner rewrite remains fail-closed, even for unrelated owners.
    assert_eq!(
        crate::snapshot_sync::safe_error(
            &validation
                .validate(&BTreeSet::from([owner.clone()]))
                .unwrap_err()
        ),
        HEADER_OWNERSHIP_CHANGED
    );
    write_owner(&healthy_path, healthy);
    assert!(validation.validate_all().is_ok());
    // A classified new member names the page owner in either home.
    for directory in [&other, &sessions] {
        let late = directory.join("late.jsonl");
        write_owner(&late, &owner);
        assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
        fs::remove_file(late).unwrap();
    }
    // Phrase flips: an unclassified late header fails its read.
    fs::write(sessions.join("late.jsonl"), b"{unknown}\n").unwrap();
    assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
    fs::remove_dir_all(root).unwrap();
    fs::remove_dir_all(other_root).unwrap();
}

/// [regress] An unrelated session created mid-page no longer rejects the page.
#[test]
fn owner_scoped_unrelated_new_session_mid_page_saves() {
    let (root, _) = fixture();
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    write_owner(&root.join("sessions/new.jsonl"), "unrelated");
    result
        .codex_joining_validator()
        .unwrap()
        .validate(&result.snapshots)
        .unwrap();
    result.validate_codex_checkpoint().unwrap();
    result.finish_codex_capture_boundary(&mut index);
    let state = root.join("index.json");
    index
        .save_fixture_for_source(&state, SnapshotSource::Codex)
        .unwrap();
    assert!(state.is_file());
    fs::remove_dir_all(root).unwrap();
}

/// [regress] A census-complete page that read a joined group leaves its
/// walk to the capture boundary. The boundary logs the retiring row and
/// arms the next walk as a routine re-census.
#[test]
fn capture_boundary_retires_a_deferred_walk_and_arms_routine_recensus() {
    use crate::local_resource_diagnostics::capture;
    fn transitions(rows: &[Value]) -> Vec<&Value> {
        rows.iter()
            .filter(|row| row["stage"] == "bounded_traversal_transition")
            .map(|row| &row["counts"])
            .collect()
    }
    let (root, _) = fixture();
    let ((mut index, mut result), rows) = capture(|| scan(&root, ScanIndex::default(), 100));
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    // Precondition: the joined page completed the census and kept its walk.
    let started = transitions(&rows);
    assert_eq!(started.len(), 1, "{started:?}");
    assert_eq!(started[0]["event"], "starting");
    assert!(result.census_complete);
    assert!(index.traversal.is_some());
    assert!(index
        .files
        .values()
        .any(|entry| entry.codex_joined_member_set.is_some()));

    let ((), rows) = capture(|| result.finish_codex_capture_boundary(&mut index));
    let retired = transitions(&rows);
    assert_eq!(retired.len(), 1, "{retired:?}");
    assert_eq!(retired[0]["event"], "retiring");
    assert_eq!(retired[0]["reason"], "complete");
    assert_eq!(retired[0]["recensus_armed"], true);
    assert!(index.traversal.is_none());
    // A second boundary on the same pass has no walk left to retire.
    let ((), rows) = capture(|| result.finish_codex_capture_boundary(&mut index));
    assert!(transitions(&rows).is_empty());

    let ((_, next), rows) = capture(|| scan(&root, index, 100));
    let restarted = transitions(&rows);
    assert_eq!(restarted[0]["event"], "starting", "{restarted:?}");
    assert_eq!(restarted[0]["reason"], "no_retained_traversal");
    assert_eq!(restarted[0]["recensus_armed"], true);
    assert!(next.routine_recensus);
    fs::remove_dir_all(root).unwrap();
}

/// [money] A midnight directory defers without losing its read obligation.
#[test]
fn owner_scoped_midnight_directory_deferred_then_read_money_oracle() {
    use sampled_scan::transition_fixture::{money_oracle, scan_money};

    let (root, _) = fixture();
    // Use one physical member per owner, as scan_money expects emitted
    // entities rather than the joined group's pre-upload aliases.
    fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
    let old_day = root.join("sessions/2026/10/06");
    fs::create_dir_all(&old_day).unwrap();
    fs::rename(root.join("sessions/a.jsonl"), old_day.join("a.jsonl")).unwrap();
    let write_member = |path: &Path, owner: &str| {
        fs::write(
            path,
            member(owner, "response", 50, 50)
                .iter()
                .map(|row| format!("{row}\n"))
                .collect::<String>(),
        )
        .unwrap();
    };
    // Keep an ordinary census page owed, so catch-up uses retained refresh.
    write_member(
        &old_day.join("z.jsonl"),
        "bbbbbbbb-1111-4111-8111-bbbbbbbbbbbb",
    );
    let previous = ScanIndex::default();
    let (mut index, mut first) = scan(&root, previous.clone(), 1);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut first, &mut index);
    assert!(!first.census_complete);
    assert_eq!(first.snapshots.len(), 1);

    let day = root.join("sessions/2026/10/07");
    let path = day.join("new.jsonl");
    let owner = "cccccccc-1111-4111-8111-cccccccccccc";
    fs::create_dir(&day).unwrap();
    write_member(&path, owner);
    first
        .codex_joining_validator()
        .unwrap()
        .validate(&first.snapshots)
        .unwrap();
    first.validate_codex_checkpoint().unwrap();
    first.finish_codex_capture_boundary(&mut index);
    let accepted = first
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    index = index.committable_subset(&previous, &accepted, &BTreeMap::new());
    let state = root.join("index.json");
    index
        .save_fixture_for_source(&state, SnapshotSource::Codex)
        .unwrap();
    index = ScanIndex::load(&state).unwrap();
    assert!(!index
        .traversal
        .as_ref()
        .unwrap()
        .codex_join_directory_census
        .as_ref()
        .unwrap()
        .contains(&day));
    refresh_retained_codex_roster(SnapshotSource::Codex, &mut index, 7, None);
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .pending_directories
        .iter()
        .any(|queued| queued.path == day));
    assert!(!index.files.contains_key(&local_index_key(&path)));

    let previous = index.clone();
    let (mut index, mut later) = scan(&root, index, 8);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut later, &mut index);
    assert!(later.census_complete);
    later.validate_codex_checkpoint().unwrap();
    assert_eq!(
        later
            .completed_parses()
            .filter(|(key, _)| *key == local_index_key(&path))
            .count(),
        1
    );
    assert_eq!(
        later
            .snapshots
            .iter()
            .filter(|s| s.source_session_id == owner)
            .count(),
        1
    );
    let accepted = later
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect();
    later.finish_codex_capture_boundary(&mut index);
    index = index.committable_subset(&previous, &accepted, &BTreeMap::new());
    index
        .save_fixture_for_source(&state, SnapshotSource::Codex)
        .unwrap();
    let (_, quiet) = scan(&root, ScanIndex::load(&state).unwrap(), 8);
    assert_eq!(
        quiet.scanned_file_count, 0,
        "no repeated body read after catch-up"
    );
    assert!(quiet.snapshots.is_empty());

    let (mut cold_index, mut cold) = scan(&root, ScanIndex::default(), 8);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut cold, &mut cold_index);
    later.snapshots.extend(first.snapshots.clone());
    for items in [&mut cold.snapshots, &mut later.snapshots] {
        items.sort_by(|a, b| a.source_session_id.cmp(&b.source_session_id));
    }
    let expected = scan_money(SnapshotSource::Codex, &cold_index, &cold);
    let deferred = scan_money(SnapshotSource::Codex, &index, &later);
    let prior = scan_money(SnapshotSource::Codex, &index, &first);
    money_oracle::assert_equivalent(&expected, &deferred);
    money_oracle::assert_no_smaller_reemit(owner, &prior, &deferred, &expected, false);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_new_file_naming_page_owner_fails_before_upload() {
    let (root, inventory) = fixture();
    let owner = inventory.headers[0].owner.clone();
    let validation = validator(inventory);
    write_owner(&root.join("sessions/new.jsonl"), &owner);
    assert_eq!(
        crate::snapshot_sync::safe_error(
            &validation.validate(&BTreeSet::from([owner])).unwrap_err()
        ),
        DIRECTORY_MEMBERSHIP_CHANGED
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_unrelated_compression_and_vanishing_defer() {
    let (root, original) = fixture();
    let sessions = root.join("sessions");
    let other = "ffffffff-1111-4111-8111-ffffffffffff";
    let plain = sessions.join(format!("rollout-{other}.jsonl"));
    write_owner(&plain, other);
    let mut paths = roster(&original);
    paths.insert(local_index_key(&plain));
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory =
        HeaderInventory::new(std::slice::from_ref(&sessions), &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    let owners = BTreeSet::from([original.headers[0].owner.clone()]);
    let validation = Validation::new(inventory, Vec::new(), &owners, paths);
    let archive = plain.with_extension("jsonl.zst");
    fs::write(
        &archive,
        zstd::stream::encode_all(fs::read(&plain).unwrap().as_slice(), 0).unwrap(),
    )
    .unwrap();
    assert!(validation.validate_all().is_ok());
    fs::remove_file(&plain).unwrap();
    assert!(validation.validate_all().is_ok());
    fs::remove_file(&archive).unwrap();
    assert!(validation.validate_all().is_ok());
    fs::write(sessions.join("x.jsonl.zst"), b"not zstd").unwrap();
    assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_owner_compression_defers_until_plaintext_vanishes() {
    let (root, inventory) = fixture();
    let validation = validator(inventory);
    let plain = root.join("sessions/a.jsonl");
    fs::write(
        plain.with_extension("jsonl.zst"),
        zstd::stream::encode_all(fs::read(&plain).unwrap().as_slice(), 0).unwrap(),
    )
    .unwrap();
    // A shadow beside an owner's plaintext adds no membership fact.
    assert!(validation.validate_all().is_ok());
    assert!(validation.validate_all().is_ok());
    fs::remove_file(plain).unwrap();
    assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_vanished_page_member_fails() {
    let (root, inventory) = fixture();
    let validation = validator(inventory);
    fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
    assert_eq!(validation_error(&validation), HEADER_STAT_FAILED);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_empty_new_subdirectory_mid_page_saves() {
    let (root, inventory) = fixture();
    let validation = validator(inventory);
    fs::create_dir(root.join("sessions/new-day")).unwrap();
    validation.validate_all().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_nested_new_directories_defer_unrelated_rollouts() {
    let (root, inventory) = fixture();
    let validation = validator(inventory);
    let day = root.join("sessions/2027/01/01");
    fs::create_dir_all(&day).unwrap();
    write_owner(&day.join("unrelated.jsonl"), "unrelated");
    validation.validate_all().unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_new_directory_same_owner_subagent_fails_before_upload() {
    let (root, inventory) = fixture();
    let owner = inventory.headers[0].owner.clone();
    let validation = validator(inventory);
    let day = root.join("sessions/new-day");
    fs::create_dir(&day).unwrap();
    fs::write(
        day.join("subagent.jsonl"),
        format!(
            "{}\n",
            json!({
                "type":"session_meta", "payload":{"id":owner,
                    "source":{"subagent":{"fork":{"parent_thread_id":owner}}}}
            })
        ),
    )
    .unwrap();
    assert_eq!(
        crate::snapshot_sync::safe_error(
            &validation.validate(&BTreeSet::from([owner])).unwrap_err()
        ),
        DIRECTORY_MEMBERSHIP_CHANGED
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_new_directory_unsettled_header_fails_closed() {
    let (root, inventory) = fixture();
    let validation = validator(inventory);
    let day = root.join("sessions/new-day");
    fs::create_dir(&day).unwrap();
    fs::write(day.join("unsettled.jsonl"), b"{\"type\":\"session_meta\"").unwrap();
    assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_vanished_directory_mid_page_fails() {
    let (root, mut inventory) = fixture();
    let sessions = root.join("sessions");
    let directory = sessions.join("old-day");
    fs::create_dir(&directory).unwrap();
    inventory.directories = DirectoryCensus::new();
    for path in [&sessions, &directory] {
        inventory
            .directories
            .observe(path, &fs::metadata(path).unwrap());
    }
    let validation = validator(inventory);
    fs::remove_dir(directory).unwrap();
    assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_known_roster_entries_need_no_header_proof() {
    let (root, original) = fixture();
    let owner = original.headers[0].owner.clone();
    let mut paths = roster(&original);
    // Shadowed, carry-deferred and held files are roster facts, even when
    // there is deliberately no inventory header for their path.
    for name in ["a.jsonl.zst", "deferred.jsonl", "held.jsonl.zst"] {
        let path = root.join("sessions").join(name);
        fs::write(&path, b"held").unwrap();
        paths.insert(local_index_key(&path));
    }
    let mut inventory = original;
    inventory.directories = DirectoryCensus::new();
    inventory.directories.observe(
        &root.join("sessions"),
        &fs::metadata(root.join("sessions")).unwrap(),
    );
    let validation = Validation::new(inventory, Vec::new(), &BTreeSet::from([owner]), paths);
    write_owner(&root.join("sessions/new.jsonl"), "unrelated");
    assert!(validation.validate_all().is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_archive_never_trusts_a_vanished_predecessor_owner() {
    let (root, original) = fixture();
    let owner = original.headers[0].owner.clone();
    let sessions = root.join("sessions");
    let plain = sessions.join(format!("rollout-{owner}.jsonl"));
    write_owner(&plain, "unrelated");
    let mut paths = roster(&original);
    paths.insert(local_index_key(&plain));
    let mut directories = DirectoryCensus::new();
    directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
    let mut inventory = HeaderInventory::new(&[sessions], &paths, Some(&directories));
    while !inventory.step(&CodexTitleMetadata::default()) {}
    let validation = Validation::new(inventory, Vec::new(), &BTreeSet::from([owner]), paths);
    fs::write(plain.with_extension("jsonl.zst"), b"held").unwrap();
    assert!(validation.validate_all().is_ok());
    fs::remove_file(plain).unwrap();
    assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn owner_scoped_unshadowed_roster_archive_fences_only_page_owners() {
    for candidate in [
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "cccccccc-1111-4111-8111-cccccccccccc",
        "",
    ] {
        let (root, original) = fixture();
        let owner = original.headers[0].owner.clone();
        let sessions = root.join("sessions");
        let other = root.join("other-home/sessions");
        fs::create_dir_all(&other).unwrap();
        let name = if candidate.is_empty() {
            "anonymous.jsonl".into()
        } else {
            format!("rollout-{candidate}.jsonl")
        };
        let plain = other.join(name);
        write_owner(&plain, "unrelated-b");
        let archive = plain.with_extension("jsonl.zst");
        // Undecodable bytes prove this boundary uses the filename only.
        fs::write(&archive, b"held archive, no decoding").unwrap();
        let mut paths = roster(&original);
        paths.extend([local_index_key(&plain), local_index_key(&archive)]);
        let mut directories = DirectoryCensus::new();
        for directory in [&sessions, &other] {
            directories.observe(directory, &fs::metadata(directory).unwrap());
        }
        let mut inventory =
            HeaderInventory::new(&[sessions, other], &paths, Some(&directories));
        while !inventory.step(&CodexTitleMetadata::default()) {}
        assert!(
            inventory.owner_for_path(&archive).is_none(),
            "roster archive starts shadowed"
        );
        let validation = Validation::new(
            inventory,
            Vec::new(),
            &BTreeSet::from([owner.clone()]),
            paths,
        );
        assert!(validation.validate_all().is_ok());
        fs::remove_file(plain).unwrap();
        let selected = BTreeSet::from([owner.clone()]);
        if candidate == owner {
            assert_eq!(
                crate::snapshot_sync::safe_error(&validation.validate(&selected).unwrap_err()),
                DIRECTORY_MEMBERSHIP_CHANGED
            );
            assert_eq!(validation_error(&validation), DIRECTORY_MEMBERSHIP_CHANGED);
        } else if candidate.is_empty() {
            assert_eq!(validation_error(&validation), HEADER_REREAD_FAILED);
        } else {
            assert!(validation.validate(&selected).is_ok());
            assert!(validation.validate_all().is_ok());
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn group_replay_uses_native_parser_and_revalidates_both_passes() {
    let (root, inventory) = fixture();
    let group = inventory.groups().into_values().next().unwrap();
    let job = replay_group(group, &ScanIndex::default()).unwrap();
    let OwnedActiveFile {
        parser,
        candidate: last,
        aliases: members,
        ..
    } = *job;
    assert_eq!(members.len(), 2);
    let parsed = parser
        .finish(
            &last.opened_object_identity,
            &last.path,
            "2026-10-01T12:00:00Z",
            last.source_file_fingerprint,
            Some(&CodexTitleMetadata::default()),
            None,
            None,
        )
        .unwrap();
    assert!(parsed.progress_complete());
    assert_eq!(parsed.snapshots.len(), 1);
    assert_eq!(parsed.snapshots[0].input_tokens, 300);
    assert_eq!(parsed.report.parsed_json_line_count, 12);
    fs::remove_dir_all(root).unwrap();
}
thread_local! {
    static OLDER_BUILD_LOGS_PRIORITY: std::cell::RefCell<BTreeSet<String>> =
        const { std::cell::RefCell::new(BTreeSet::new()) };
}
/// The turns an older build priced as priority from Codex logs on this
/// test thread, so tests can seed the protected receipts it wrote.
pub(crate) fn older_build_logs_priority(turn: &str) {
    OLDER_BUILD_LOGS_PRIORITY.with(|turns| turns.borrow_mut().insert(turn.to_owned()));
}
/// The older build's logs evidence is gone: only receipts protect it.
pub(crate) fn older_build_logs_expired() {
    OLDER_BUILD_LOGS_PRIORITY.with(|turns| turns.borrow_mut().clear());
}
/// The older build's per-row stamp, where it ran: before tier replay.
pub(in crate::snapshots) fn older_build_logs_tier(
    selector: &mut SelectorCapture,
    turn: Option<&str>,
) {
    if turn.is_some_and(|turn| {
        OLDER_BUILD_LOGS_PRIORITY.with(|turns| turns.borrow().contains(turn))
    }) {
        selector.insert("service_tier", "priority".into(), "derived_from_logs_2");
    }
}
pub(crate) fn native_join_fixture_root(priority: bool) -> PathBuf {
    let root = fixture().0;
    if priority {
        let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
        let mut rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
        for row in &mut rows {
            if !row["payload"]["turn_id"].is_null() {
                row["payload"]["turn_id"] = json!(turn);
            }
        }
        rows.insert(
            2,
            json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
        );
        fs::write(
            root.join("sessions/b.jsonl"),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
        older_build_logs_priority(turn);
    }
    root
}
pub(crate) fn scan(
    root: &Path,
    index: ScanIndex,
    limit: usize,
) -> (ScanIndex, SourceScanResult) {
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        limit,
        None,
        &[],
        false,
    );
    // A reader step is one line; one fixture member holds ~1,030 lines.
    for _ in 0..10_000 {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
    panic!("bounded native scan did not finish");
}
/// The two-member fixture with b's usage under `turn` and a Codex logs
/// database holding a priority request for that turn, as Codex
/// 0.119-0.142.x wrote it. `tier`, when set, is on b's usage lines, or
/// with `inherited` on its `turn_context` only (the running selector).
fn logs_priority_request_fixture(turn: &str, tier: Option<&str>, inherited: bool) -> PathBuf {
    let (root, _) = fixture();
    let mut rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 200, 300);
    if let Some(tier) = tier.filter(|_| !inherited) {
        for row in &mut rows[1..] {
            if row["type"] == "token_usage_record" {
                row["payload"]["service_tier"] = json!(tier);
            } else {
                row["payload"]["info"]["service_tier"] = json!(tier);
            }
        }
    }
    let mut context =
        json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}});
    if let Some(tier) = tier.filter(|_| inherited) {
        // An earlier non-usage line's tier, carried by the running selector.
        context["payload"]["service_tier"] = json!(tier);
    }
    for row in &mut rows {
        if !row["payload"]["turn_id"].is_null() {
            row["payload"]["turn_id"] = json!(turn);
        }
    }
    rows.insert(2, context);
    fs::write(
        root.join("sessions/b.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let connection = rusqlite::Connection::open(root.join("logs_2.sqlite")).unwrap();
    connection
        .execute(
            "CREATE TABLE logs (id INTEGER PRIMARY KEY, ts INTEGER, feedback_log_body TEXT)",
            [],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO logs (ts, feedback_log_body) VALUES (?1, ?2)",
            rusqlite::params![
                now,
                format!(
                    "turn{{turn.id={turn}}}: websocket request: \
                         {{\"type\":\"response.create\",\"service_tier\":\"priority\",\
                         \"model\":\"gpt-5.2\"}}"
                )
            ],
        )
        .unwrap();
    root
}
/// [money] Codex logs no longer price a turn: a logs priority request for a
/// new turn, with no tier receipt, leaves every row at the default tier.
#[test]
fn codex_logs_priority_request_no_longer_prices_a_new_turn() {
    let root =
        logs_priority_request_fixture("aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa", None, false);
    let (_, result) = scan(&root, ScanIndex::default(), 2);
    assert_eq!(result.snapshots.len(), 2, "one alias per group member");
    for item in &result.snapshots {
        assert_eq!(item.input_tokens, 300);
        assert!(
            item.model_usage
                .iter()
                .all(|row| !row.selector_context.contains_key("service_tier")),
            "{:?}",
            item.model_usage
        );
    }
    fs::remove_dir_all(root).unwrap();
}
/// [money] An explicit tier on the rollout's own usage lines, or inherited
/// from its `turn_context`, now prices its turn beside a logs priority
/// request, where the logs stamp used to
/// replace it: each explicit value prices at its own (normalized) tier
/// under the rollout line's own source; `priority` keeps its price.
#[test]
fn explicit_rollout_tier_is_no_longer_replaced_by_codex_logs() {
    for (explicit, tier, inherited) in [false, true].into_iter().flat_map(|inherited| {
        [
            ("flex", "flex"),
            ("priority", "priority"),
            ("fast", "fast"),
            ("standard", "standard"),
            ("default", "standard"),
        ]
        .map(|(explicit, tier)| (explicit, tier, inherited))
    }) {
        let root = logs_priority_request_fixture(
            "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa",
            Some(explicit),
            inherited,
        );
        let (_, result) = scan(&root, ScanIndex::default(), 2);
        assert_eq!(result.snapshots.len(), 2, "one alias per group member");
        for item in &result.snapshots {
            assert_eq!(item.input_tokens, 300);
            let tiered = item
                .model_usage
                .iter()
                .filter(|row| {
                    row.selector_context.get("service_tier").map(String::as_str) == Some(tier)
                })
                .map(|row| row.input_tokens)
                .sum::<u64>();
            assert_eq!(
                tiered, 200,
                "{tier} (inherited {inherited}): b at its own tier"
            );
            assert!(
                item.model_usage.iter().all(|row| {
                    row.selector_sources
                        .get("service_tier")
                        .is_none_or(|source| source.starts_with("payload."))
                }),
                "{tier} (inherited {inherited}): {:?}",
                item.model_usage
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}
/// Scan `root` as an older build that priced `turn` priority from Codex
/// logs, accept the read, save the index, then retire that evidence.
/// Returns the saved index path.
fn accept_as_older_build(root: &Path, turn: &str) -> PathBuf {
    older_build_logs_priority(turn);
    let (mut working, mut first) = scan(root, ScanIndex::default(), 3);
    assert!(
        first
            .snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .any(|row| {
                row.selector_sources.get("service_tier").map(String::as_str)
                    == Some("derived_from_logs_2")
            }),
        "positive control: the older build priced priority from logs"
    );
    finalize_scan_after_policy(SnapshotSource::Codex, &mut first, &mut working);
    first.finish_codex_capture_boundary(&mut working);
    let fingerprints = first
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let mut committed =
        working.committable_subset(&ScanIndex::default(), &fingerprints, &BTreeMap::new());
    let saved = root.join("index.json");
    committed
        .save_fixture_for_source(&saved, SnapshotSource::Codex)
        .unwrap();
    older_build_logs_expired();
    saved
}
/// Input tokens by emitted `service_tier` and its source, over `owner`'s rows.
fn tiers_of(
    scan: &SourceScanResult,
    owner: &str,
) -> BTreeMap<(Option<String>, Option<String>), u64> {
    let mut tiers = BTreeMap::new();
    for row in scan
        .snapshots
        .iter()
        .filter(|item| item.source_session_id == owner)
        .flat_map(|item| &item.model_usage)
    {
        *tiers
            .entry((
                row.selector_context.get("service_tier").cloned(),
                row.selector_sources.get("service_tier").cloned(),
            ))
            .or_default() += row.input_tokens;
    }
    tiers
}
/// [money] Rows an older build accepted priority from logs over an explicit
/// tier on the rollout's usage lines or inherited from its `turn_context`,
/// re-read in a byte-zero replay: an
/// explicit `priority` keeps its price under the line's own source; an
/// explicit non-priority tier fails the receipt's key match, so the
/// replay emits nothing below priority.
#[test]
fn accepted_logs_priority_over_an_explicit_tier_replays_or_holds() {
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
    for (explicit, inherited) in [
        ("priority", false),
        ("flex", false),
        ("priority", true),
        ("flex", true),
    ] {
        let root = logs_priority_request_fixture(turn, Some(explicit), inherited);
        let saved = accept_as_older_build(&root, turn);
        let mut loaded = ScanIndex::load(&saved).unwrap();
        loaded.prepare_historical_replay("logs-explicit-upgrade".into());
        let (_, replayed) = scan(&root, loaded, 2);
        let tiers = tiers_of(&replayed, owner);
        eprintln!(
            "LOGS_EXPLICIT_REPLAY explicit={explicit} inherited={inherited} emitted={} tiers={tiers:?}",
            replayed.snapshots.len()
        );
        let below_priority = tiers
            .iter()
            .filter(|((tier, _), _)| {
                tier.as_deref() == Some(explicit) && explicit != "priority"
            })
            .map(|(_, tokens)| *tokens)
            .sum::<u64>();
        assert_eq!(below_priority, 0, "{explicit}: no smaller re-emit");
        if explicit == "priority" && !replayed.snapshots.is_empty() {
            for ((tier, source), tokens) in &tiers {
                if tier.as_deref() == Some("priority") {
                    assert!(
                        source.as_deref().is_some_and(|s| s.starts_with("payload.")),
                        "{source:?}"
                    );
                    assert_eq!(*tokens, 400, "both aliases keep b's 200 at priority");
                }
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
}
/// [money] A singleton accepted priority from logs whose index entry holds
/// no tier receipt and no receipt requirement (an entry from before
/// receipts) re-reads at the default tier on a later Full; base would
/// have kept priority while the turn's logs request was live.
#[test]
fn receipt_less_accepted_singleton_prices_default_on_a_later_full() {
    let owner = "cccccccc-dddd-4eee-8fff-000000000000";
    let turn = "cccccccc-1111-4111-8111-cccccccccccc";
    let (root, _) = fixture();
    let mut rows = member(owner, "r-c", 200, 200);
    for row in &mut rows {
        if !row["payload"]["turn_id"].is_null() {
            row["payload"]["turn_id"] = json!(turn);
        }
    }
    rows.insert(
        2,
        json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
    );
    let path = root.join("sessions/c.jsonl");
    fs::write(
        &path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let saved = accept_as_older_build(&root, turn);
    let mut legacy = ScanIndex::load(&saved).unwrap();
    let entry = legacy.files.get_mut(&local_index_key(&path)).unwrap();
    entry.codex_applied_tier_receipt = None;
    entry.codex_applied_tier_receipt_required = false;
    entry.codex_captured_tier_receipt = None;
    entry.codex_captured_tier_receipt_required = false;
    legacy
        .save_fixture_for_source(&saved, SnapshotSource::Codex)
        .unwrap();
    let mut loaded = ScanIndex::load(&saved).unwrap();
    loaded.prepare_historical_replay("receipt-less-upgrade".into());
    let (_, replayed) = scan(&root, loaded, 3);
    let tiers = tiers_of(&replayed, owner);
    eprintln!(
        "LOGS_RECEIPT_LESS_REPLAY emitted={} tiers={tiers:?}",
        replayed.snapshots.len()
    );
    assert_eq!(tiers, BTreeMap::from([((None, None), 200)]), "default tier");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn production_scanner_aliases_need_common_settlement_and_skip_on_restart() {
    let (root, _) = fixture();
    let previous = ScanIndex::default();
    let (mut index, mut result) = scan(&root, previous.clone(), 2);
    assert_eq!(result.scanned_file_count, 2);
    assert_eq!(result.snapshots.len(), 2, "one alias per physical member");
    assert!(result.snapshots.iter().all(|item| item.input_tokens == 300));
    assert!(result.census_complete, "{result:?}");
    result
        .codex_joining_validator()
        .unwrap()
        .validate(&result.snapshots)
        .unwrap();
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        accepted.len(),
        1,
        "physical aliases share one body identity"
    );
    assert_eq!(
        index
            .committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new())
            .files
            .len(),
        0,
        "lost ACK cannot settle either new physical member"
    );
    let mut settled = index.committable_subset(&previous, &accepted, &BTreeMap::new());
    assert_eq!(settled.files.len(), 2);
    let path = root.join("index.json");
    settled
        .save_fixture_for_source(&path, SnapshotSource::Codex)
        .unwrap();
    let loaded = ScanIndex::load(&path).unwrap();
    let (_index, restarted) = scan(&root, loaded, 2);
    assert!(
        restarted.snapshots.is_empty(),
        "an acknowledged group needs no new upload"
    );
    assert_eq!(restarted.semantic_noop_count, 2);
    fs::remove_dir_all(root).unwrap();
}
/// The two-member fixture with creation times, so a cutover can select V2.
/// Each member's native and UI share one bound turn, which a V2 group
/// can use to prove native-turn UI.
pub(crate) fn counting_v2_fixture() -> (PathBuf, [String; 2]) {
    counting_v2_fixture_with(true)
}
/// The original fixture has UI in an unbound span, which a V2 group holds.
pub(crate) fn counting_v2_unbound_fixture() -> (PathBuf, [String; 2]) {
    counting_v2_fixture_with(false)
}
fn counting_v2_fixture_with(bound: bool) -> (PathBuf, [String; 2]) {
    let (root, _) = fixture();
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let rows = if bound { member } else { unbound_member };
    for (name, rows) in [
        ("a", rows(owner, "r-a", 100, 100)),
        ("b", rows(owner, "r-b", 200, 300)),
    ] {
        let body = rows
            .into_iter()
            .map(|mut row| {
                if row["type"] == "session_meta" {
                    row["payload"]["timestamp"] = json!("2026-10-01T10:00:00Z");
                }
                serde_json::to_string(&row).unwrap() + "\n"
            })
            .collect::<String>();
        fs::write(root.join("sessions").join(format!("{name}.jsonl")), body).unwrap();
    }
    let keys = ["a", "b"]
        .map(|name| local_index_key(&root.join("sessions").join(format!("{name}.jsonl"))));
    (root, keys)
}
#[test]
fn counting_v2_group_is_configured_once_and_folded_once() {
    let (root, keys) = counting_v2_fixture();
    let (index, counted) = scan(&root, ScanIndex::default(), 2);
    assert_eq!(counted.snapshots.len(), 2, "one alias per physical member");
    let receipts = counted
        .codex_counting_v2
        .as_deref()
        .expect("an executed configured group parse owns receipts");
    assert_eq!(receipts.v2_sessions, 1, "a joined group folds once");
    // One carried accumulator saw both members' records, each inside
    // its member's bound turn.
    assert_eq!(receipts.native_counted, 2, "both members' natives");
    assert_eq!(receipts.native_outside_open_turn, 0);
    assert_eq!(receipts.ui_in_unbound_span, 0);
    for key in &keys {
        assert!(index.files[key].codex_counting_v2, "V2 marks every member");
    }
    for counted in &counted.snapshots {
        assert_eq!(counted.input_tokens, 300);
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn applied_priority_survives_trace_expiry_without_pricing_appended_same_turn() {
    let (root, inventory) = fixture();
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let turn = "aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa";
    let mut rows = member(owner, "r-b", 200, 300);
    for row in &mut rows {
        if !row["payload"]["turn_id"].is_null() {
            row["payload"]["turn_id"] = json!(turn);
        }
    }
    rows.insert(
        2,
        json!({"type":"turn_context","payload":{"turn_id":turn,"model":"gpt-5.2"}}),
    );
    rows.pop(); // Leave the native-backed task open across the accepted prefix.
    fs::write(
        root.join("sessions/b.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    older_build_logs_priority(turn);
    let job = replay_group(
        inventory.groups().into_values().next().unwrap(),
        &ScanIndex::default(),
    )
    .unwrap();
    older_build_logs_expired();
    let OwnedActiveFile {
        aliases: members,
        applied_receipts: receipts,
        ..
    } = *job;
    let mut index = ScanIndex::default();
    for member in members {
        let key = local_index_key(&member.path);
        index.record(member, None, ScanParseOutcome::Snapshot);
        let entry = index.files.get_mut(&key).unwrap();
        entry.codex_applied_tier_receipt = receipts[&key].clone();
        entry.codex_applied_tier_receipt_required = entry.codex_applied_tier_receipt.is_some();
    }
    let appended = member(owner, "r-c", 200, 500);
    rows.extend(appended.into_iter().filter_map(|mut row| {
        if row["type"] == "token_usage_record" {
            row["payload"]["turn_id"] = json!(turn);
            Some(row)
        } else if string_eq_at(&row, &["payload", "type"], "token_count") {
            Some(row)
        } else {
            None
        }
    }));
    rows.push(json!({"type":"event_msg","payload":{"type":"task_complete","turn_id":turn}}));
    fs::write(
        root.join("sessions/b.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let (_, fresh) = {
        // Reuse the real roots and make a fresh header census after append.
        let paths = inventory
            .headers
            .iter()
            .map(|header| local_index_key(&header.candidate.path))
            .collect();
        let mut directories = DirectoryCensus::new();
        let sessions = root.join("sessions");
        directories.observe(&sessions, &fs::metadata(&sessions).unwrap());
        let mut fresh = HeaderInventory::new(&[sessions], &paths, Some(&directories));
        while !fresh.step(&CodexTitleMetadata::default()) {}
        ((), fresh)
    };
    let job = replay_group(fresh.groups().into_values().next().unwrap(), &index).unwrap();
    let OwnedActiveFile {
        parser,
        candidate: last,
        applied_receipts: receipts,
        ..
    } = *job;
    let parsed = parser
        .finish(
            &last.opened_object_identity,
            &last.path,
            "2026-10-06T23:00:00Z",
            last.source_file_fingerprint,
            Some(&CodexTitleMetadata::default()),
            None,
            None,
        )
        .unwrap();
    assert!(parsed.progress_complete());
    let item = &parsed.snapshots[0];
    assert_eq!(item.input_tokens, 500);
    let priority = item
        .model_usage
        .iter()
        .filter(|row| {
            row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
        })
        .map(|row| row.input_tokens)
        .sum::<u64>();
    assert_eq!(
        priority, 200,
        "only the previously applied physical contribution stays priority"
    );
    assert_eq!(
        receipts[&local_index_key(&root.join("sessions/b.jsonl"))]
            .as_ref()
            .unwrap()
            .tiers
            .len(),
        2
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn singleton_headers_across_distinct_homes_cannot_overwrite_one_owner() {
    let (root, _) = fixture();
    let other = root.join("other-home/sessions");
    fs::create_dir_all(&other).unwrap();
    fs::rename(root.join("sessions/b.jsonl"), other.join("b.jsonl")).unwrap();
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions"), other],
        ScanIndex::default(),
        "2026-10-06T23:00:00Z",
        7,
        2,
        None,
        &[],
        false,
    );
    loop {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => {
                assert!(scan.snapshots.is_empty());
                assert_eq!(scan.ownership_incomplete_file_count, 2);
                assert!(index.files.is_empty());
                break;
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn bad_native_record_preserves_the_complete_joined_replacement() {
    let (root, _) = fixture();
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let bad = json!({"type":"event_msg","payload":{"type":"token_count","info":{
        "total_token_usage":{"input_tokens":"not-a-number","output_tokens":"not-a-number"}}}});
    assert!(codex_total_usage(&bad).is_none());
    let path = root.join("sessions/b.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push_str(&(serde_json::to_string(&bad).unwrap() + "\n"));
    // A valid new occurrence makes this a new body, rather than an
    // unchanged accepted300 body that policy correctly suppresses.
    for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 100, 400)
        .into_iter()
        .skip(1)
    {
        text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
    }
    fs::write(&path, text).unwrap();
    let (mut after, mut current) = scan(&root, previous.clone(), 2);
    let (mut cold_index, mut cold) = scan(&root, ScanIndex::default(), 2);
    assert_eq!(current.snapshots.len(), 2, "one alias per physical member");
    assert!(current.snapshots.iter().all(|s| s.input_tokens == 400));
    assert_eq!(current.recognized_usage_drop_count, 1);
    assert_eq!(current.ownership_incomplete_file_count, 0);
    current
        .codex_joining_validator()
        .unwrap()
        .validate(&current.snapshots)
        .unwrap();
    finalize_scan_after_policy(SnapshotSource::Codex, &mut current, &mut after);
    current.finish_codex_capture_boundary(&mut after);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut cold, &mut cold_index);
    cold.finish_codex_capture_boundary(&mut cold_index);
    assert_eq!(
        serde_json::to_value(&current.snapshots).unwrap(),
        serde_json::to_value(&cold.snapshots).unwrap()
    );
    let accepted = current
        .snapshots
        .iter()
        .map(|s| s.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(accepted.len(), 1, "one body identity across both aliases");
    assert_eq!(
        serde_json::to_value(
            &after
                .committable_subset(&previous, &BTreeSet::new(), &BTreeMap::new())
                .files
        )
        .unwrap(),
        serde_json::to_value(&previous.files).unwrap(),
        "no ACK cannot settle either alias"
    );
    let mut settled = after.committable_subset(&previous, &accepted, &BTreeMap::new());
    let state = root.join("index.json");
    settled
        .save_fixture_for_source(&state, SnapshotSource::Codex)
        .unwrap();
    let (_, quiet) = scan(&root, ScanIndex::load(&state).unwrap(), 2);
    assert!(quiet.snapshots.is_empty());
    assert_eq!(quiet.semantic_noop_count, 2);
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn losing_a_joined_member_cannot_replace_history_with_the_remaining_tail() {
    let (root, _) = fixture();
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    fs::remove_file(root.join("sessions/a.jsonl")).unwrap();
    let path = root.join("sessions/b.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 200, 500)
        .into_iter()
        .skip(1)
    {
        text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
    }
    fs::write(path, text).unwrap();
    let (after, held) = scan(&root, previous.clone(), 2);
    assert!(held.snapshots.is_empty());
    assert!(!held.census_complete);
    assert_eq!(
        held.ownership_incomplete_file_count, 2,
        "both the absent member and the remaining tail are held"
    );
    assert_eq!(
        serde_json::to_value(&after.files).unwrap(),
        serde_json::to_value(&previous.files).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn losing_last_of_three_joined_members_holds_contiguous_prefix_and_allows_sibling() {
    let (root, _) = fixture();
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let write = |name: &str, rows: Vec<Value>| {
        fs::write(
            root.join("sessions").join(name),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    };
    write("c.jsonl", member(owner, "r-c", 100, 400));
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 4);
    assert!(result.snapshots.iter().all(|item| item.input_tokens == 400));
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    fs::remove_file(root.join("sessions/c.jsonl")).unwrap();
    let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
    write("d.jsonl", member(healthy, "healthy", 100, 100));
    let (after, held) = scan(&root, previous.clone(), 4);
    assert!(!held.census_complete);
    assert_eq!(held.ownership_incomplete_file_count, 3);
    assert_eq!(held.snapshots.len(), 1);
    assert_eq!(held.snapshots[0].source_session_id, healthy);
    for (key, entry) in &previous.files {
        assert_eq!(
            serde_json::to_value(&after.files[key]).unwrap(),
            serde_json::to_value(entry).unwrap()
        );
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn contradictory_creator_pairs_hold_joined_body_before_account_fallback() {
    let (root, _) = fixture();
    for (name, creator) in [("a.jsonl", "first"), ("b.jsonl", "second")] {
        let path = root.join("sessions").join(name);
        let mut rows = fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        rows[0]["payload"]["creator_user_id"] = json!(creator);
        rows[0]["payload"]["creator_account_id"] = json!("synthetic-workspace");
        fs::write(
            path,
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    let (index, held) = scan(&root, ScanIndex::default(), 2);
    assert!(
        held.snapshots.is_empty(),
        "no conflicted item can reach cached or current-home binding"
    );
    assert_eq!(held.ownership_incomplete_file_count, 2);
    assert!(!held.census_complete);
    let causes = serde_json::to_value(
        held.local_codex_diagnostics
            .unwrap()
            .unreadable_causes
            .projection(held.unreadable_path_count as u64),
    )
    .unwrap();
    assert_eq!(
        causes["counts"][5], 1,
        "one alias guard event, not two files"
    );
    assert_eq!(causes["unattributed"], 0);

    assert!(index.files.is_empty());
    fs::remove_dir_all(root).unwrap();
}
#[cfg(unix)]
#[test]
fn configured_root_symlink_uses_resolved_inventory_roots() {
    let (root, _) = fixture();
    let configured = root.join("configured-sessions");
    std::os::unix::fs::symlink(root.join("sessions"), &configured).unwrap();
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[configured],
        ScanIndex::default(),
        "2026-10-06T23:00:00Z",
        7,
        2,
        None,
        &[],
        false,
    );
    loop {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { scan, .. } => {
                assert!(scan.census_complete, "{scan:?}");
                assert_eq!(scan.snapshots.len(), 2);
                assert!(scan.snapshots.iter().all(|item| item.input_tokens == 300));
                scan.codex_joining_validator()
                    .unwrap()
                    .validate(&scan.snapshots)
                    .unwrap();
                break;
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn replay_owner_rewrite_after_inventory_cannot_escape_validation() {
    let (root, _) = fixture();
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        ScanIndex::default(),
        "2026-10-06T23:00:00Z",
        7,
        2,
        None,
        &[],
        false,
    );
    let changed = "ffffffff-1111-4111-8111-ffffffffffff";
    let mut rewritten = false;
    loop {
        if owned.codex_join_prepared && !owned.codex_join_groups.is_empty() && !rewritten {
            for (name, response, input, after) in [
                ("a.jsonl", "a-new", 100, 100),
                ("b.jsonl", "b-new", 200, 300),
            ] {
                let rows = member(changed, response, input, after);
                fs::write(
                    root.join("sessions").join(name),
                    rows.iter()
                        .map(|row| serde_json::to_string(row).unwrap() + "\n")
                        .collect::<String>(),
                )
                .unwrap();
            }
            rewritten = true;
        }
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => {
                assert!(rewritten);
                assert!(scan.snapshots.is_empty());
                assert_eq!(scan.ownership_incomplete_file_count, 2);
                assert!(index.files.is_empty());
                break;
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn protected_files_cannot_be_repurposed_under_a_new_inventoried_owner() {
    let (root, _) = fixture();
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let changed = "ffffffff-1111-4111-8111-ffffffffffff";
    for (name, response, input, after) in [
        ("a.jsonl", "a-new", 100, 100),
        ("b.jsonl", "b-new", 200, 300),
    ] {
        let rows = member(changed, response, input, after);
        fs::write(
            root.join("sessions").join(name),
            rows.iter()
                .map(|row| serde_json::to_string(row).unwrap() + "\n")
                .collect::<String>(),
        )
        .unwrap();
    }
    let (after, held) = scan(&root, previous.clone(), 2);
    assert!(held.snapshots.is_empty());
    assert!(!held.census_complete);
    assert_eq!(
        serde_json::to_value(&after.files).unwrap(),
        serde_json::to_value(&previous.files).unwrap()
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn semantic_noop_checkpoint_still_checks_late_member_roster() {
    let (root, _) = fixture();
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let path = root.join("sessions/a.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    text.push('\n');
    fs::write(path, text).unwrap();
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        previous,
        "2026-10-06T23:00:00Z",
        7,
        2,
        None,
        &[],
        false,
    );
    let mut added = false;
    loop {
        if !added && owned.codex_join_active.is_some() {
            let rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "late", 100, 400);
            fs::write(
                root.join("sessions/c.jsonl"),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            added = true;
        }
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete {
                mut index,
                mut scan,
                ..
            } => {
                assert!(added);
                finalize_scan_after_policy(SnapshotSource::Codex, &mut scan, &mut index);
                assert!(scan.snapshots.is_empty());
                scan.codex_joining_validator()
                    .unwrap()
                    .validate(&scan.snapshots)
                    .unwrap();
                let error = scan
                    .validate_codex_checkpoint()
                    .expect_err("no-op suppression cannot make a stale checkpoint eligible");
                // The failure names its own check, never the bare phrase.
                let shown = crate::snapshot_sync::safe_error(&error);
                assert_ne!(shown, "sync failed");
                assert!(CODEX_JOIN_VALIDATION_FAILURES.contains(&shown.as_str()));
                break;
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn held_group_does_not_poison_known_healthy_owner_on_the_next_page() {
    let (root, _) = fixture();
    let bad = member(
        "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        "bad-overlap",
        200,
        250,
    );
    fs::write(
        root.join("sessions/b.jsonl"),
        bad.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let healthy = "ffffffff-1111-4111-8111-ffffffffffff";
    let rows = member(healthy, "healthy", 100, 100);
    fs::write(
        root.join("sessions/c.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let (index, first) = scan(&root, ScanIndex::default(), 2);
    assert!(first.snapshots.is_empty());
    assert!(!first.census_complete);
    let (_, next) = scan(&root, index, 2);
    assert_eq!(next.snapshots.len(), 1);
    assert_eq!(next.snapshots[0].source_session_id, healthy);
    fs::remove_dir_all(root).unwrap();
}
const RETAINED_AT: &str = "2026-10-06T23:00:00Z";
const KNOWN: &str = "11111111-1111-4111-8111-111111111111";
const UNRELATED: &str = "22222222-2222-4222-8222-222222222222";
fn write_rows(path: &Path, rows: &[Value]) {
    fs::write(
        path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
}
fn retained_page(
    root: &Path,
    index: ScanIndex,
    hints: &[PathBuf],
) -> (ScanIndex, SourceScanResult) {
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        RETAINED_AT,
        7,
        10,
        None,
        hints,
        false,
    );
    for _ in 0..1000 {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
    panic!("bounded native scan did not finish");
}
/// A settled `known` rollout beside one whose malformed line keeps the
/// generation red, so it is retained behind its bounded retry deadline.
fn retained_red_generation(known: Vec<Value>) -> (PathBuf, ScanIndex) {
    let root = crate::test_scratch::unique_path("ottto-codex-retained");
    let sessions = root.join("sessions");
    fs::create_dir_all(&sessions).unwrap();
    write_rows(&sessions.join("a.jsonl"), &known);
    let red = "33333333-3333-4333-8333-333333333333";
    fs::write(
        sessions.join("red.jsonl"),
        serde_json::to_string(&member(red, "r-red", 10, 10)[0]).unwrap() + "\n{not json\n",
    )
    .unwrap();
    let (mut index, mut result) = retained_page(&root, ScanIndex::default(), &[]);
    assert!(!result.census_complete);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let settled = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let deadline = settled
        .traversal
        .as_ref()
        .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds)
        .expect("red generation keeps a retry deadline");
    assert!(deadline > rfc3339_unix_seconds(RETAINED_AT).unwrap());
    (root, settled)
}
fn retry_deadline(index: &ScanIndex) -> Option<u64> {
    index
        .traversal
        .as_ref()
        .and_then(|traversal| traversal.unhealthy_retry_not_before_unix_seconds)
}
#[test]
fn retained_generation_admits_new_rollout_without_holding_known_update() {
    let (root, settled) = retained_red_generation(member(KNOWN, "k-1", 100, 100));
    let deadline = retry_deadline(&settled);
    let known = root.join("sessions/a.jsonl");
    let mut text = fs::read_to_string(&known).unwrap();
    for row in &member(KNOWN, "k-2", 150, 250)[1..] {
        text.push_str(&(serde_json::to_string(row).unwrap() + "\n"));
    }
    fs::write(&known, text).unwrap();
    let new = root.join("sessions/new.jsonl");
    write_rows(&new, &member(UNRELATED, "n-1", 70, 70));
    let (index, page) = retained_page(&root, settled, &[known, new.clone()]);
    let mut totals = page
        .snapshots
        .iter()
        .map(|item| (item.source_session_id.clone(), item.input_tokens))
        .collect::<Vec<_>>();
    totals.sort();
    assert_eq!(
        totals,
        vec![(KNOWN.to_string(), 250), (UNRELATED.to_string(), 70)],
        "a rollout created after the walk must not hold the known update"
    );
    assert_eq!(page.scanned_file_count, 2, "only the changed and new files");
    assert_eq!(retry_deadline(&index), deadline, "no re-walk was forced");
    assert!(index
        .traversal
        .as_ref()
        .unwrap()
        .codex_rollout_paths
        .contains(&local_index_key(&new)));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn retained_generation_discovers_new_rollout_without_a_watcher_hint() {
    let (root, settled) = retained_red_generation(member(KNOWN, "k-1", 100, 100));
    let deadline = retry_deadline(&settled);
    let (idle, quiet) = retained_page(&root, settled, &[]);
    assert_eq!(
        quiet.scanned_file_count, 0,
        "unchanged directories re-list nothing"
    );
    assert!(quiet.snapshots.is_empty());
    write_rows(
        &root.join("sessions/new.jsonl"),
        &member(UNRELATED, "n-1", 70, 70),
    );
    let (index, page) = retained_page(&root, idle, &[]);
    assert_eq!(page.scanned_file_count, 1);
    assert_eq!(page.snapshots.len(), 1);
    assert_eq!(page.snapshots[0].source_session_id, UNRELATED);
    assert_eq!(retry_deadline(&index), deadline);
    let (_, again) = retained_page(&root, index, &[]);
    assert_eq!(
        again.scanned_file_count, 0,
        "an admitted file is not re-read"
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn retained_generation_never_sends_a_settled_segment_without_its_new_sibling() {
    // The known owner's second physical segment appears after the walk.
    // Emitting the settled first segment alone would replace the session
    // with part of its usage; it must be joined or held, while an
    // unrelated new rollout on the same page is still admitted.
    let (root, settled) = retained_red_generation(member(KNOWN, "r-a", 100, 100));
    let segment = root.join("sessions/b.jsonl");
    write_rows(&segment, &member(KNOWN, "r-b", 200, 300));
    let new = root.join("sessions/new.jsonl");
    write_rows(&new, &member(UNRELATED, "n-1", 70, 70));
    let (index, page) = retained_page(&root, settled, &[segment.clone(), new]);
    let known = page
        .snapshots
        .iter()
        .filter(|item| item.source_session_id == KNOWN)
        .collect::<Vec<_>>();
    assert!(
        known.iter().all(|item| item.input_tokens == 300),
        "a known segment cannot be sent alone once its sibling exists: {known:?}"
    );
    assert!(
        !known.is_empty()
            || page.ownership_incomplete_file_count >= 2
            || inventory_hold(&index)
                .is_some_and(|hold| hold.owed.contains(&local_index_key(&segment)))
    );
    assert!(page
        .snapshots
        .iter()
        .any(|item| item.source_session_id == UNRELATED && item.input_tokens == 70));
    fs::remove_dir_all(root).unwrap();
}
fn inventory_hold(index: &ScanIndex) -> Option<&super::super::CodexInventoryHold> {
    index
        .traversal
        .as_ref()
        .and_then(|traversal| traversal.residue.codex_inventory_hold.as_ref())
}
/// A retained red generation where a new unreadable first record and a
/// valid unrelated rollout arrive together, so the page holds both.
fn held_behind_unreadable_header() -> (PathBuf, ScanIndex, PathBuf, PathBuf, String) {
    let (root, settled) = retained_red_generation(member(KNOWN, "k-1", 100, 100));
    let unreadable = root.join("sessions/unreadable.jsonl");
    fs::write(&unreadable, "not a header\n").unwrap();
    let new = root.join("sessions/new.jsonl");
    write_rows(&new, &member(UNRELATED, "n-1", 70, 70));
    let before = settled.traversal.as_ref().unwrap().counts.clone();
    let (held_index, held) = retained_page(&root, settled, &[unreadable.clone(), new.clone()]);
    assert!(held.snapshots.is_empty(), "{:?}", held.snapshots);
    // The hold owes the held candidates; they add no ownership or
    // unreadable count. Only the refused header itself is unreadable.
    assert_eq!(held.ownership_incomplete_file_count, 0);
    let (c, _) = held.causes.summary(0);
    assert_eq!(c[ownership::INVENTORY], 0);
    assert!(held.unreadable_path_count > 0, "the refused header counts");
    let after = &held_index.traversal.as_ref().unwrap().counts;
    assert_eq!(
        after.ownership_incomplete_file_count,
        before.ownership_incomplete_file_count
    );
    assert_eq!(
        after.unreadable_path_count,
        before.unreadable_path_count + held.unreadable_path_count
    );
    let hold = inventory_hold(&held_index).expect("the held page is owed a retry");
    assert!(hold.owed.contains(&local_index_key(&new)));
    assert!(!held_index
        .traversal
        .as_ref()
        .unwrap()
        .residue
        .index_keys
        .contains(&local_index_key(&new)));
    assert!(hold
        .refused_headers
        .contains_key(&local_index_key(&unreadable)));
    let witness = path_witness(&new).unwrap();
    (root, held_index, unreadable, new, witness)
}
#[test]
fn held_page_reports_its_prepared_hold_on_the_census_line() {
    // Preparation records the hold and yields before the fold, which
    // writes the census line. The line still counts the held page, once.
    let (counts, (root, index, _, _, _)) =
        observe_reported_hold_counts(held_behind_unreadable_header);
    let hold = inventory_hold(&index).unwrap();
    let &(held, _, outside) = counts
        .last()
        .expect("the held page writes an incomplete census line");
    assert!(held > 0, "{counts:?}");
    assert_eq!(held, hold.owed.len(), "{counts:?}");
    assert_eq!(outside, hold.outside_roster.len(), "{counts:?}");
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn unreadable_new_header_holds_the_page_only_while_it_is_unreadable() {
    // An unreadable header has no provable owner, so it may belong to any
    // selected session: the page stays held, and an idle tick re-reads
    // nothing. Once it is gone, the valid session held with it is admitted
    // on the next ordinary tick: no write to it, no hint for it, no walk.
    let (root, held_index, unreadable, new, witness) = held_behind_unreadable_header();
    let deadline = retry_deadline(&held_index);
    let (idle_index, idle) = retained_page(&root, held_index, &[]);
    assert_eq!(
        idle.scanned_file_count, 0,
        "unmoved evidence re-reads nothing"
    );
    assert!(idle.snapshots.is_empty());
    assert!(inventory_hold(&idle_index).is_some());
    // The hold is durable state: it survives a service restart.
    let restarted: ScanIndex =
        serde_json::from_slice(&serde_json::to_vec(&idle_index).unwrap()).unwrap();
    assert_eq!(inventory_hold(&restarted), inventory_hold(&idle_index));
    fs::remove_file(&unreadable).unwrap();
    let (index, page) = retained_page(&root, restarted, &[]);
    assert_eq!(
        page.snapshots
            .iter()
            .map(|item| (item.source_session_id.as_str(), item.input_tokens))
            .collect::<Vec<_>>(),
        vec![(UNRELATED, 70)],
        "the originally held valid session recovers"
    );
    assert_eq!(page.scanned_file_count, 1);
    assert_eq!(
        path_witness(&new).unwrap(),
        witness,
        "the held file was not rewritten"
    );
    assert_eq!(retry_deadline(&index), deadline, "no re-walk was forced");
    assert!(inventory_hold(&index).is_none());
    let (_, again) = retained_page(&root, index, &[]);
    assert_eq!(
        again.scanned_file_count, 0,
        "a recovered file is not re-read"
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn header_that_vanished_before_its_read_releases_the_hold_once_unlisted() {
    // The refused record was already gone when the inventory reached it,
    // so its recorded witness is absent and can never change. Leaving the
    // roster is the evidence that releases the held valid session.
    let (root, mut held_index, unreadable, _, _) = held_behind_unreadable_header();
    let key = local_index_key(&unreadable);
    let hold = held_index
        .traversal
        .as_mut()
        .and_then(|traversal| traversal.residue.codex_inventory_hold.as_mut())
        .unwrap();
    *hold.refused_headers.get_mut(&key).unwrap() = None;
    fs::remove_file(&unreadable).unwrap();
    let (index, page) = retained_page(&root, held_index, &[]);
    assert!(!index
        .traversal
        .as_ref()
        .unwrap()
        .codex_rollout_paths
        .contains(&key));
    assert_eq!(
        page.snapshots
            .iter()
            .map(|item| (item.source_session_id.as_str(), item.input_tokens))
            .collect::<Vec<_>>(),
        vec![(UNRELATED, 70)]
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn repaired_header_releases_the_held_page_and_a_still_unreadable_one_does_not() {
    let (root, held_index, unreadable, new, witness) = held_behind_unreadable_header();
    let deadline = retry_deadline(&held_index);
    let owed = inventory_hold(&held_index).unwrap().owed.clone();
    // The blocker changes but still proves no owner: the owed candidates
    // are tried again once, held again, and nothing is emitted.
    fs::write(&unreadable, "still not a header\n").unwrap();
    let (still_index, still) =
        retained_page(&root, held_index, std::slice::from_ref(&unreadable));
    assert!(still.snapshots.is_empty(), "{:?}", still.snapshots);
    // The release does not clear the still-refused header: it counts
    // again, and the hold keeps the generation red.
    assert!(still.unreadable_path_count > 0);
    assert!(still_index
        .traversal
        .as_ref()
        .unwrap()
        .has_retryable_problems());
    assert_eq!(still.ownership_incomplete_file_count, 0);
    assert_eq!(
        inventory_hold(&still_index).map(|hold| &hold.owed),
        Some(&owed),
        "a re-hold owes the same set"
    );
    let (idle_index, idle) = retained_page(&root, still_index, &[]);
    assert_eq!(
        idle.scanned_file_count, 0,
        "unmoved evidence re-reads nothing"
    );
    // Repaired in place: same directory, same inode, a provable owner.
    let repaired_owner = "44444444-4444-4444-8444-444444444444";
    write_rows(&unreadable, &member(repaired_owner, "l-1", 30, 30));
    let (index, page) = retained_page(&root, idle_index, &[unreadable]);
    let mut totals = page
        .snapshots
        .iter()
        .map(|item| (item.source_session_id.clone(), item.input_tokens))
        .collect::<Vec<_>>();
    totals.sort();
    assert_eq!(
        totals,
        vec![
            (UNRELATED.to_string(), 70),
            (repaired_owner.to_string(), 30)
        ],
        "the held valid session and the repaired one are both admitted"
    );
    assert_eq!(page.scanned_file_count, 2);
    assert_eq!(
        path_witness(&new).unwrap(),
        witness,
        "the held file was not rewritten"
    );
    assert_eq!(retry_deadline(&index), deadline, "no re-walk was forced");
    assert!(inventory_hold(&index).is_none());
    fs::remove_dir_all(root).unwrap();
}
/// One `scan` page whose header inventory `prepare` adjusts first.
fn scan_with_inventory(
    root: &Path,
    index: ScanIndex,
    prepare: impl FnOnce(&mut HeaderInventory),
) -> (ScanIndex, SourceScanResult) {
    let mut owned = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        index,
        "2026-10-06T23:00:00Z",
        7,
        4,
        None,
        &[],
        false,
    );
    prepare(
        owned
            .codex_join_inventory
            .as_mut()
            .expect("a selecting page"),
    );
    for _ in 0..10_000 {
        match owned.step(None) {
            OwnedSourceScanStep::Pending(next) => owned = next,
            OwnedSourceScanStep::Complete { index, scan, .. } => return (index, scan),
        }
    }
    panic!("bounded native scan did not finish");
}
/// [money] An incomplete inventory holds a whole joined group: the changed
/// member and its unchanged, checkpointed sibling are both owed. A re-hold
/// owes the same set and still adds no count. The release reads exactly
/// what an unheld page reads and leaves the generation healthy.
#[test]
fn held_group_owes_every_member_and_release_reads_like_an_unheld_page() {
    use sampled_scan::transition_fixture::observe_consumed;
    let (root, _) = fixture();
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 4);
    assert!(!result.snapshots.is_empty());
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous = index.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let b = root.join("sessions/b.jsonl");
    let mut text = fs::read_to_string(&b).unwrap();
    for row in &member(owner, "r-b2", 150, 450)[1..] {
        text.push_str(&(serde_json::to_string(row).unwrap() + "\n"));
    }
    fs::write(&b, text).unwrap();
    let members = BTreeSet::from(
        ["a.jsonl", "b.jsonl"].map(|name| local_index_key(&root.join("sessions").join(name))),
    );
    let totals = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .map(|item| (item.source_session_id.clone(), item.input_tokens))
            .collect::<Vec<_>>()
    };
    // As an unstable directory census leaves it.
    let incomplete = |inventory: &mut HeaderInventory| inventory.complete = false;
    // A complete inventory with a real group reason (an affected owner)
    // still charges the group: ownership per member, one AliasParser,
    // residue and no hold.
    let (charged_index, charged) = scan_with_inventory(&root, previous.clone(), |inventory| {
        inventory.held_owners.insert(owner.to_string());
    });
    assert!(charged.snapshots.is_empty());
    assert_eq!(charged.ownership_incomplete_file_count, 2);
    assert_eq!(charged.unreadable_path_count, 1);
    let (c, _) = charged.causes.summary(2);
    assert_eq!(c[ownership::INVENTORY], 2);
    let causes = serde_json::to_value(
        charged
            .local_codex_diagnostics
            .unwrap()
            .unreadable_causes
            .projection(1),
    )
    .unwrap();
    assert_eq!(causes["counts"][5], 1, "one AliasParser event");
    assert!(inventory_hold(&charged_index).is_none());
    let ((_, control), control_bytes) = observe_consumed(|| scan(&root, previous.clone(), 4));
    assert!(!control.snapshots.is_empty());
    // The hold, then a re-hold of the held store: each owes every member
    // and adds no count.
    let mut held_index = previous.clone();
    for round in ["held", "re-held"] {
        let (index, held) = scan_with_inventory(&root, held_index, incomplete);
        assert!(held.snapshots.is_empty(), "{round}");
        assert_eq!(
            (
                held.ownership_incomplete_file_count,
                held.unreadable_path_count
            ),
            (0, 0),
            "{round}"
        );
        assert_eq!(
            inventory_hold(&index).map(|hold| &hold.owed),
            Some(&members),
            "{round}"
        );
        held_index = index;
    }
    let ((index, released), released_bytes) = observe_consumed(|| scan(&root, held_index, 4));
    assert_eq!(totals(&released), totals(&control));
    assert_eq!(
        (released.scanned_file_count, released_bytes),
        (control.scanned_file_count, control_bytes),
        "the release reads what an unheld page reads"
    );
    assert!(inventory_hold(&index).is_none());
    assert!(index.traversal.as_ref().is_none_or(|t| !t.has_errors()));
    fs::remove_dir_all(root).unwrap();
}
/// [money] Protected history survives retirement; quiet retries acquire,
/// enqueue and count nothing.
#[test]
fn retired_sources_keep_protected_history_and_quiet_retry_is_idempotent() {
    let root = native_join_fixture_root(true);
    let (mut working, mut result) = scan(&root, ScanIndex::default(), 3);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    result.finish_codex_capture_boundary(&mut working);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous =
        working.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    assert_eq!(previous.files.len(), 2);
    assert!(previous
        .files
        .values()
        .all(|entry| entry.codex_protected_owner.is_some()));
    let originals = ["a.jsonl", "b.jsonl"].map(|name| {
        (
            name,
            fs::read_to_string(root.join("sessions").join(name)).unwrap(),
        )
    });
    for name in ["a.jsonl", "b.jsonl"] {
        fs::remove_file(root.join("sessions").join(name)).unwrap();
    }
    let healthy_owner = "ffffffff-1111-4111-8111-ffffffffffff";
    let body = member(healthy_owner, "healthy", 100, 100)
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    fs::write(root.join("sessions/c.jsonl"), body).unwrap();
    let (after, held) = scan(&root, previous.clone(), 3);
    assert!(!held.census_complete);
    assert_eq!(held.ownership_incomplete_file_count, 2);
    let (c, [unknown, _, _]) = held.causes.summary(held.ownership_incomplete_file_count);
    assert_eq!(c[ownership::ABSENT], 2);
    assert_eq!(c[..6].iter().sum::<usize>() + unknown, 2);
    assert!(held
        .snapshots
        .iter()
        .all(|item| item.source_session_id == healthy_owner));
    assert_eq!(
        held.snapshots.len(),
        1,
        "healthy physical owner remains uploadable"
    );
    for (key, entry) in &previous.files {
        assert_eq!(
            serde_json::to_value(&after.files[key]).unwrap(),
            serde_json::to_value(entry).unwrap()
        );
    }
    let counts = after.traversal.as_ref().unwrap().counts.clone();
    let causes = serde_json::to_value(
        counts
            .unreadable_causes
            .projection(counts.unreadable_path_count as u64),
    )
    .unwrap();
    assert_eq!(
        causes["counts"][6], 1,
        "one protected-absence event for newly missing group"
    );
    assert_eq!(causes["unattributed"], 0);

    let deadline = after
        .traversal
        .as_ref()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds;
    let quiet = OwnedSourceScan::new(
        SnapshotSource::Codex,
        &[root.join("sessions")],
        after.clone(),
        "2026-10-06T23:00:00Z",
        7,
        3,
        None,
        &[],
        false,
    );
    assert!(
        quiet.codex_join_inventory.is_none(),
        "quiet red tick must not rescan headers"
    );
    let (quiet_index, quiet_result) = scan(&root, after.clone(), 3);
    assert_eq!(quiet_result.scanned_file_count, 0);
    assert_eq!(
        serde_json::to_value(&quiet_index.traversal.as_ref().unwrap().counts).unwrap(),
        serde_json::to_value(&counts).unwrap()
    );
    assert_eq!(
        quiet_index
            .traversal
            .as_ref()
            .unwrap()
            .unhealthy_retry_not_before_unix_seconds,
        deadline
    );
    // The existing age/missing-source reconciler cannot evict file-owned
    // selectors even when its observation set no longer includes the files.
    let mut aged = after;
    aged.traversal.as_mut().unwrap().observed_index_keys.clear();
    assert!(reconcile_missing_index_entries_with_limit(&mut aged, 10));
    for key in previous.files.keys() {
        assert!(aged.files.contains_key(key));
    }
    for (name, text) in originals {
        fs::write(root.join("sessions").join(name), text).unwrap();
    }
    older_build_logs_expired();
    aged.traversal
        .as_mut()
        .unwrap()
        .unhealthy_retry_not_before_unix_seconds = Some(0);
    let (recovered, restored) = scan(&root, aged, 3);
    assert!(
        restored.census_complete,
        "a due fresh census can clear the source-loss hold"
    );
    let priced_key = local_index_key(&root.join("sessions/b.jsonl"));
    assert_eq!(
        recovered.files[&priced_key].codex_applied_tier_receipt,
        previous.files[&priced_key].codex_applied_tier_receipt
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn missing_protected_receipt_rewrite_holds_correction_but_scope_does_not() {
    let rows = member("owner", "r", 100, 100);
    let mut replay = TierReplay::new(None, false, "scope".into());
    for row in &rows {
        replay.observe(row);
    }
    replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
    let receipt = replay.finish().unwrap().unwrap();
    assert!(TierReplay::new(None, true, "scope".into())
        .finish()
        .is_err());
    let mut changed = rows.clone();
    changed[0]["payload"]["id"] = json!("other");
    for (rows, scope, holds) in [
        (changed.as_slice(), "scope", true),
        (rows.as_slice(), "other-scope", false),
    ] {
        let mut replay = TierReplay::new(Some(receipt.clone()), true, scope.into());
        for row in rows {
            replay.observe(row);
        }
        replay.admitted(Some(("a".repeat(64), "derived_from_logs_2".into())));
        assert_eq!(replay.finish().is_err(), holds, "{scope}");
    }
    // [regress] No per-file tier cap: 513 priority contributions (one past
    // the former 512) finish, and their receipt replays as valid.
    let many = (0..513)
        .map(|i| (format!("{i:064x}"), "derived_from_logs_2".to_string()))
        .collect::<Vec<_>>();
    let mut replay = TierReplay::new(None, false, "scope".into());
    for row in &rows {
        replay.observe(row);
    }
    for tier in &many {
        replay.admitted(Some(tier.clone()));
    }
    let receipt = replay.finish().unwrap().unwrap();
    assert_eq!(receipt.tiers.len(), 513);
    let mut replay = TierReplay::new(Some(receipt.clone()), true, "scope".into());
    assert!(!replay.invalid, "a receipt past 512 tiers is valid");
    for row in &rows {
        replay.observe(row);
    }
    for tier in &many {
        replay.admitted(Some(tier.clone()));
    }
    assert_eq!(replay.finish().unwrap(), Some(receipt));
}
#[test]
fn malformed_or_missing_captured_metadata_holds_without_resetting_index() {
    for malformed in [Value::Null, json!({"version":"future","opaque":true})] {
        let root = native_join_fixture_root(true);
        let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
        finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
        let (mut captured, changed) =
            working.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
        assert_eq!(changed.len(), 1);
        let path = root.join("capture.json");
        captured
            .save_fixture_for_source(&path, SnapshotSource::Codex)
            .unwrap();
        let key = captured
            .files
            .iter()
            .find(|(_, entry)| entry.codex_captured_tier_receipt_required)
            .unwrap()
            .0
            .clone();
        let mut value = serde_json::to_value(&captured).unwrap();
        value["files"][&key]["codex_captured_tier_receipt"] = malformed;
        e2_pipeline_scan_fixture::seed_json_for_test(
            &path,
            &serde_json::to_vec(&value).unwrap(),
        );
        let loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(
            loaded.files.len(),
            2,
            "receipt damage must not reset protected state"
        );
        older_build_logs_expired();
        let (after, held) = scan(&root, loaded, 2);
        assert!(held.snapshots.is_empty());
        assert_eq!(held.ownership_incomplete_file_count, 2);
        assert!(after.files[&key].codex_captured_uncommitted);
        fs::remove_dir_all(root).unwrap();
    }
}
/// `receipt` with 512 (the former per-file cap) synthetic priority
/// contributions.
fn full_receipt(receipt: &AppliedTierReceipt) -> AppliedTierReceipt {
    let mut full = receipt.clone();
    full.tiers = (0..512)
        .map(|n| {
            (
                sha256_hex(&["synthetic-tier", &n.to_string()]),
                "derived_from_logs_2".into(),
            )
        })
        .collect();
    full
}
/// [regress] Receipts past the former 2 MiB index aggregate no longer hold
/// a recovery capture: the owner stages and every known selector stays.
#[test]
fn capture_past_former_receipt_aggregate_stages_owner_without_hold() {
    let root = native_join_fixture_root(true);
    let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    let priced_key = local_index_key(&root.join("sessions/b.jsonl"));
    let priced = working.files[&priced_key]
        .codex_applied_tier_receipt
        .clone()
        .unwrap();
    let mut full = working.files[&priced_key].clone();
    full.codex_applied_tier_receipt = Some(full_receipt(&priced));
    let bytes = serde_json::to_vec(full.codex_applied_tier_receipt.as_ref().unwrap())
        .unwrap()
        .len();
    let former_aggregate = 2 * 1024 * 1024;
    let mut previous = ScanIndex::default();
    for n in 0..=(former_aggregate / bytes) {
        previous
            .files
            .insert(format!("synthetic-existing-{n}"), full.clone());
    }
    let (captured, changed) =
        working.stage_codex_recovery_capture(&previous, &result.snapshots);
    assert_eq!(changed.len(), 1, "the owner stages");
    assert_eq!(captured.files.len(), previous.files.len() + 2);
    assert_eq!(
        captured.files[&priced_key].codex_captured_tier_receipt,
        Some(priced)
    );
    assert!(captured.files[&priced_key].codex_captured_tier_receipt_required);
    for (key, entry) in &previous.files {
        assert_eq!(
            serde_json::to_value(&captured.files[key]).unwrap(),
            serde_json::to_value(entry).unwrap()
        );
    }
    fs::remove_dir_all(root).unwrap();
}
/// [regress] A scan whose previous index retains more than the former
/// 2 MiB of receipts emits the protected group, with no residue or hold.
#[test]
fn scan_past_former_receipt_aggregate_emits_protected_group() {
    let root = native_join_fixture_root(true);
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    // Other joined pairs: unchanged on the rescan, they only retain receipts.
    for pair in 1..=24u32 {
        let other = format!("{pair:08x}-bbbb-4ccc-8ddd-eeeeeeeeeeee");
        for (name, rows) in [
            ("a", member(&other, &format!("r-{pair}-a"), 100, 100)),
            ("b", member(&other, &format!("r-{pair}-b"), 200, 300)),
        ] {
            fs::write(
                root.join(format!("sessions/x{pair}{name}.jsonl")),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
        }
    }
    let (mut working, mut result) = scan(&root, ScanIndex::default(), 64);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    result.finish_codex_capture_boundary(&mut working);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let mut previous =
        working.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    assert_eq!(previous.files.len(), 50);
    // The same index with only its real receipts: below the former aggregate.
    let below = previous.clone();
    let group =
        ["a", "b"].map(|name| local_index_key(&root.join(format!("sessions/{name}.jsonl"))));
    let full = full_receipt(
        previous.files[&group[1]]
            .codex_applied_tier_receipt
            .as_ref()
            .unwrap(),
    );
    let others = previous
        .files
        .keys()
        .filter(|key| !group.contains(*key))
        .cloned()
        .collect::<Vec<_>>();
    for key in &others {
        previous
            .files
            .get_mut(key)
            .unwrap()
            .codex_applied_tier_receipt = Some(full.clone());
    }
    assert!(others.len() * serde_json::to_vec(&full).unwrap().len() > 2 * 1024 * 1024);
    let path = root.join("sessions/b.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    for row in member(owner, "r-c", 200, 500).into_iter().skip(1) {
        text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
    }
    fs::write(&path, text).unwrap();
    let (after, rescanned) = scan(&root, previous, 64);
    let (below_after, below_rescanned) = scan(&root, below, 64);
    assert_eq!(rescanned.ownership_incomplete_file_count, 0);
    assert!(rescanned.census_complete);
    assert_eq!(rescanned.snapshots.len(), 2, "one alias per group member");
    assert!(rescanned
        .snapshots
        .iter()
        .all(|item| item.source_session_id == owner && item.input_tokens == 500));
    // Exact tokens and body: identical to the run below the former aggregate.
    assert_eq!(
        rescanned
            .snapshots
            .iter()
            .map(|item| serde_json::to_value(item).unwrap())
            .collect::<Vec<_>>(),
        below_rescanned
            .snapshots
            .iter()
            .map(|item| serde_json::to_value(item).unwrap())
            .collect::<Vec<_>>()
    );
    // A protected group defers traversal retirement to the capture
    // boundary, so the traversal is still present, with no residue.
    for index in [&after, &below_after] {
        assert!(index
            .traversal
            .as_ref()
            .expect("retirement waits for the capture boundary")
            .residue
            .index_keys
            .is_empty());
    }
    fs::remove_dir_all(root).unwrap();
}
/// [regress] T2: a joined group whose priced member grows past the former
/// 512-tier cap still uploads, with no hold and every priced row priority.
/// T3: with the older build's logs evidence gone, a replay from the saved
/// index restores every tier from the receipt and emits a byte-identical
/// body.
#[test]
fn joined_group_past_former_tier_cap_uploads_and_replays_without_downgrade() {
    let root = native_join_fixture_root(true);
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    result.finish_codex_capture_boundary(&mut working);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous =
        working.committable_subset(&ScanIndex::default(), &accepted, &BTreeMap::new());
    let path = root.join("sessions/b.jsonl");
    let key = local_index_key(&path);
    let tiers = |index: &ScanIndex| {
        receipt_state(index.files.get(&key))
            .0
            .map_or(0, |receipt| receipt.tiers.len())
    };
    assert_eq!(tiers(&previous), 2);
    // 513 more native/UI pairs in explicitly priority turns, 1 input each.
    let mut text = fs::read_to_string(&path).unwrap();
    for i in 0..513u64 {
        older_build_logs_priority(&format!("r-t{i}"));
        for row in member(owner, &format!("r-t{i}"), 1, 301 + i)
            .into_iter()
            .skip(1)
        {
            text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
        }
    }
    fs::write(&path, text).unwrap();
    let (mut after, mut rescanned) = scan(&root, previous.clone(), 2);
    assert_eq!(rescanned.ownership_incomplete_file_count, 0);
    assert!(rescanned.census_complete);
    assert_eq!(rescanned.snapshots.len(), 2, "one alias per group member");
    for item in &rescanned.snapshots {
        assert_eq!(item.source_session_id, owner);
        // Fixture sum: a 100 + b 200 + 513 x 1.
        assert_eq!(item.input_tokens, 813);
        let priority = item
            .model_usage
            .iter()
            .filter(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
            })
            .map(|row| row.input_tokens)
            .sum::<u64>();
        assert_eq!(priority, 713, "every b row is priced priority");
    }
    let body = rescanned
        .snapshots
        .iter()
        .map(|item| serde_json::to_value(item).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        tiers(&after),
        1028,
        "2 fixture witnesses + 513 native/UI pairs"
    );
    finalize_scan_after_policy(SnapshotSource::Codex, &mut rescanned, &mut after);
    let (capture, _) = after.stage_codex_recovery_capture(&previous, &rescanned.snapshots);
    rescanned.finish_codex_capture_boundary(&mut after);
    let accepted = rescanned
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let mut committed = after.committable_subset(&capture, &accepted, &BTreeMap::new());
    let saved = root.join("index.json");
    committed
        .save_fixture_for_source(&saved, SnapshotSource::Codex)
        .unwrap();
    let mut loaded = ScanIndex::load(&saved).unwrap();
    assert_eq!(tiers(&loaded), 1028);
    // T3: the trace source expires; only the saved receipt can price b.
    older_build_logs_expired();
    loaded.prepare_historical_replay("tier-cap-replay".into());
    let (_, replayed) = scan(&root, loaded, 2);
    assert_eq!(replayed.ownership_incomplete_file_count, 0);
    assert_eq!(
        replayed
            .snapshots
            .iter()
            .map(|item| serde_json::to_value(item).unwrap())
            .collect::<Vec<_>>(),
        body,
        "restored from the receipt: no tier downgraded"
    );
    fs::remove_dir_all(root).unwrap();
}
/// [money] Rows accepted with an older build's logs-derived priority tier
/// keep it once Codex logs supply none: a restart re-emits nothing, and an
/// upgrade's historical replay (a byte-zero re-read) restores every tier
/// from the protected receipt, equal in money and placement to the accepted
/// read with no smaller re-emit. A read with no receipt prices the same turn
/// at the default tier.
#[test]
fn logs_priority_receipt_survives_restart_and_replay_money_oracle() {
    use sampled_scan::transition_fixture::{money_oracle, scan_money};
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let priority = |scan: &SourceScanResult| {
        scan.snapshots
            .iter()
            .flat_map(|item| &item.model_usage)
            .filter(|row| {
                row.selector_context.get("service_tier").map(String::as_str) == Some("priority")
            })
            .map(|row| row.input_tokens)
            .sum::<u64>()
    };
    // The joined members' aliases share one body; the wire carries it once.
    let one_body_each = |scan: &mut SourceScanResult| {
        let mut seen = BTreeSet::new();
        scan.snapshots
            .retain(|item| seen.insert(item.snapshot_fingerprint.clone()));
        assert_eq!(scan.snapshots.len(), 1);
    };
    let root = native_join_fixture_root(true);
    // The accepted read's raw rows, compared with the replay's raw rows.
    let (_, mut accepted_rows) = scan(&root, ScanIndex::default(), 2);
    let (mut working, mut first) = scan(&root, ScanIndex::default(), 2);
    assert_eq!(priority(&first), 400, "positive control: b priced priority");
    finalize_scan_after_policy(SnapshotSource::Codex, &mut first, &mut working);
    first.finish_codex_capture_boundary(&mut working);
    let fingerprints = first
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let mut committed =
        working.committable_subset(&ScanIndex::default(), &fingerprints, &BTreeMap::new());
    let saved = root.join("index.json");
    committed
        .save_fixture_for_source(&saved, SnapshotSource::Codex)
        .unwrap();
    // Both routes take their receipt evidence from the saved index, which
    // the replay reads; what can differ is the replayed rows' money and
    // placement.
    one_body_each(&mut accepted_rows);
    let accepted = scan_money(SnapshotSource::Codex, &committed, &accepted_rows);
    older_build_logs_expired();

    let (_, restarted) = scan(&root, ScanIndex::load(&saved).unwrap(), 2);
    assert!(restarted.snapshots.is_empty(), "restart re-emits nothing");

    let mut loaded = ScanIndex::load(&saved).unwrap();
    loaded.prepare_historical_replay("logs-priority-upgrade".into());
    let (_, mut replayed) = scan(&root, loaded, 2);
    assert_eq!(replayed.ownership_incomplete_file_count, 0);
    assert_eq!(priority(&replayed), 400, "restored from the receipt");
    one_body_each(&mut replayed);
    let replayed = scan_money(SnapshotSource::Codex, &committed, &replayed);
    money_oracle::assert_equivalent(&accepted, &replayed);
    money_oracle::assert_placement_equivalent(&accepted, &replayed);
    money_oracle::assert_no_smaller_reemit(owner, &accepted, &replayed, &accepted, false);

    let (_, fresh) = scan(&root, ScanIndex::default(), 2);
    assert_eq!(priority(&fresh), 0, "no receipt: the default tier");
    assert!(fresh.snapshots.iter().all(|item| item.input_tokens == 300));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn older_body_acceptance_or_rollback_cannot_discard_new_captured_facts() {
    let root = native_join_fixture_root(true);
    let (mut old_index, mut old_result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut old_result, &mut old_index);
    old_result.finish_codex_capture_boundary(&mut old_index);
    let old_accepted = old_result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let previous =
        old_index.committable_subset(&ScanIndex::default(), &old_accepted, &BTreeMap::new());
    let path = root.join("sessions/b.jsonl");
    let mut text = fs::read_to_string(&path).unwrap();
    for row in member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 200, 500)
        .into_iter()
        .skip(1)
    {
        text.push_str(&(serde_json::to_string(&row).unwrap() + "\n"));
    }
    fs::write(&path, text).unwrap();
    older_build_logs_priority("r-c");
    let (mut working, mut result) = scan(&root, previous.clone(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    let (captured, changed) =
        working.stage_codex_recovery_capture(&previous, &result.snapshots);
    assert_eq!(changed.len(), 1);
    let key = local_index_key(&path);
    assert_eq!(
        captured.files[&key]
            .codex_captured_tier_receipt
            .as_ref()
            .unwrap()
            .tiers
            .len(),
        4
    );
    for accepted in [&old_accepted, &BTreeSet::new()] {
        let mut rollback = captured.clone();
        rollback.reconcile_codex_recovery_settlement(&captured, accepted);
        assert_eq!(
            rollback.files[&key].codex_captured_tier_receipt,
            captured.files[&key].codex_captured_tier_receipt
        );
        assert_eq!(
            rollback.files[&key].codex_applied_tier_receipt,
            previous.files[&key].codex_applied_tier_receipt
        );
        let mut damaged = captured.clone();
        damaged
            .files
            .get_mut(&key)
            .unwrap()
            .codex_captured_tier_receipt = None;
        let mut rollback = damaged.clone();
        rollback.reconcile_codex_recovery_settlement(&damaged, accepted);
        assert!(rollback.files[&key].codex_captured_tier_receipt_required);
        assert!(rollback.files[&key].codex_captured_tier_receipt.is_none());
    }
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    working.reconcile_codex_recovery_settlement(&captured, &accepted);
    assert!(!working.files[&key].codex_captured_tier_receipt_required);
    assert_eq!(
        working.files[&key]
            .codex_applied_tier_receipt
            .as_ref()
            .unwrap()
            .tiers
            .len(),
        4
    );
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn pending_membership_expansion_loss_stale_ack_and_supported_correction() {
    let root = native_join_fixture_root(false);
    let owner = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let (mut first, mut result) = scan(&root, ScanIndex::default(), 3);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut first);
    let old_accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let (pending, _) =
        first.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
    assert_eq!(pending.files.len(), 2);
    assert!(pending.current_snapshot_fingerprints().is_empty());
    let text = member(owner, "r-c", 100, 400)
        .iter()
        .map(|row| serde_json::to_string(row).unwrap() + "\n")
        .collect::<String>();
    fs::write(root.join("sessions/c.jsonl"), text).unwrap();
    let (mut expanded, mut result) = scan(&root, pending.clone(), 3);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut expanded);
    assert_eq!(result.snapshots.len(), 3);
    let (new_pending, changed) =
        expanded.stage_codex_recovery_capture(&pending, &result.snapshots);
    assert_eq!(changed.len(), 1);
    assert_eq!(new_pending.files.len(), 3);
    let mut stale = first.clone();
    stale.reconcile_codex_recovery_settlement(&new_pending, &old_accepted);
    for (key, entry) in &stale.files {
        assert_eq!(
            entry.codex_captured_joined_member_set,
            new_pending.files[key].codex_captured_joined_member_set
        );
    }
    fs::remove_file(root.join("sessions/b.jsonl")).unwrap();
    let (held_index, held) = scan(&root, new_pending.clone(), 3);
    assert!(held.snapshots.is_empty());
    assert!(!held.census_complete);
    assert_eq!(held_index.files.len(), 3);
    // All known physical members present and independently proved: a real
    // correction may replace usage, rather than waiting for a timeout.
    let rows = member(owner, "r-b", 50, 150);
    fs::write(
        root.join("sessions/b.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let rows = member(owner, "r-c", 100, 250);
    fs::write(
        root.join("sessions/c.jsonl"),
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let (mut corrected, mut result) = scan(&root, new_pending.clone(), 3);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut corrected);
    assert_eq!(result.snapshots.len(), 3);
    assert!(result.snapshots.iter().all(|item| item.input_tokens == 250));
    let (capture, _) = corrected.stage_codex_recovery_capture(&new_pending, &result.snapshots);
    result.finish_codex_capture_boundary(&mut corrected);
    let accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect();
    let settled = corrected.committable_subset(&capture, &accepted, &BTreeMap::new());
    assert!(settled.files.values().all(|entry| entry
        .codex_captured_joined_member_set
        .is_none()
        && !entry.codex_captured_uncommitted
        && entry.codex_joined_member_set.is_some()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn unknown_version_preserves_protected_state() {
    let root = native_join_fixture_root(false);
    let (mut working, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    let (captured, _) =
        working.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
    for malformed in [
        json!("codex_captured_join:v2:future"),
        json!({"opaque":true}),
        Value::Null,
    ] {
        let mut value = serde_json::to_value(&captured).unwrap();
        let key = captured.files.keys().next().unwrap();
        value["files"][key]["codex_captured_joined_member_set"] = malformed;
        let path = root.join("malformed.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = ScanIndex::load(&path).unwrap();
        assert_eq!(loaded.files.len(), 2);
        let (_, result) = scan(&root, loaded, 2);
        assert!(result.snapshots.is_empty());
        assert!(!result.census_complete);
    }
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn pending_correction_return_to_old_accepted_body_is_not_a_noop() {
    let root = native_join_fixture_root(false);
    let path = root.join("sessions/b.jsonl");
    let original = fs::read(&path).unwrap();
    let (mut index, mut result) = scan(&root, ScanIndex::default(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
    result.finish_codex_capture_boundary(&mut index);
    let old_accepted = result
        .snapshots
        .iter()
        .map(|item| item.snapshot_fingerprint.clone())
        .collect::<BTreeSet<_>>();
    let previous =
        index.committable_subset(&ScanIndex::default(), &old_accepted, &BTreeMap::new());
    let rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-b", 400, 500);
    fs::write(
        &path,
        rows.iter()
            .map(|row| serde_json::to_string(row).unwrap() + "\n")
            .collect::<String>(),
    )
    .unwrap();
    let (mut working, mut result) = scan(&root, previous.clone(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut working);
    assert!(result.snapshots.iter().all(|item| item.input_tokens == 500));
    let (pending, _) = working.stage_codex_recovery_capture(&previous, &result.snapshots);
    // The server may hold500 after a lost response. The old local300 ACK
    // therefore cannot suppress an independently proved return to300.
    fs::write(&path, original).unwrap();
    let (mut corrected, mut result) = scan(&root, pending.clone(), 2);
    finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut corrected);
    assert_eq!(
        result.snapshots.len(),
        2,
        "pending capture must not suppress a correction to an older body"
    );
    assert!(result.snapshots.iter().all(|item| item.input_tokens == 300));
    let (capture, changed) =
        corrected.stage_codex_recovery_capture(&pending, &result.snapshots);
    assert_eq!(changed.len(), 1);
    result.finish_codex_capture_boundary(&mut corrected);
    let settled = corrected.committable_subset(&capture, &old_accepted, &BTreeMap::new());
    assert!(settled
        .files
        .values()
        .all(|entry| entry.codex_captured_joined_member_set.is_none()));
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn historical_replay_preserves_pending_and_applied_protection() {
    for priority in [false, true] {
        for applied in [false, true] {
            let root = native_join_fixture_root(priority);
            let rows = member("aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "r-c", 100, 400);
            fs::write(
                root.join("sessions/c.jsonl"),
                rows.iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            let (mut index, mut result) = scan(&root, ScanIndex::default(), 3);
            finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut index);
            let (capture, _) =
                index.stage_codex_recovery_capture(&ScanIndex::default(), &result.snapshots);
            result.finish_codex_capture_boundary(&mut index);
            let accepted = result
                .snapshots
                .iter()
                .map(|item| item.snapshot_fingerprint.clone())
                .collect();
            let mut previous = if applied {
                index.committable_subset(&capture, &accepted, &BTreeMap::new())
            } else {
                capture
            };
            let before = previous.clone();
            previous.prepare_historical_replay("new-context-curve-replay".into());
            assert_eq!(
                previous.files.len(),
                3,
                "replay must retain file-owned recovery facts"
            );
            for (key, entry) in &previous.files {
                let old = &before.files[key];
                assert_eq!(entry.codex_joined_member_set, old.codex_joined_member_set);
                assert_eq!(
                    entry.codex_captured_joined_member_set,
                    old.codex_captured_joined_member_set
                );
                assert_eq!(
                    entry.codex_applied_tier_receipt,
                    old.codex_applied_tier_receipt
                );
                assert_eq!(
                    entry.codex_captured_tier_receipt,
                    old.codex_captured_tier_receipt
                );
                assert!(entry.last_snapshot_fingerprint.is_none());
                assert!(entry.last_upload_body_witness.is_none());
            }
            assert!(previous.current_snapshot_fingerprints().is_empty());
            if priority {
                older_build_logs_expired();
            }
            let (mut rebuilt, mut result) = scan(&root, previous.clone(), 3);
            finalize_scan_after_policy(SnapshotSource::Codex, &mut result, &mut rebuilt);
            assert_eq!(
                result.snapshots.len(),
                3,
                "intact protected replay must reoffer all aliases"
            );
            assert!(result.snapshots.iter().all(|item| item.input_tokens == 400));
            let healthy = member("bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee", "healthy", 100, 100);
            fs::write(
                root.join("sessions/d.jsonl"),
                healthy
                    .iter()
                    .map(|row| serde_json::to_string(row).unwrap() + "\n")
                    .collect::<String>(),
            )
            .unwrap();
            fs::remove_file(root.join("sessions/c.jsonl")).unwrap();
            let (held_index, result) = scan(&root, previous, 3);
            assert!(!result.census_complete);
            assert_eq!(result.snapshots.len(), 1);
            assert_eq!(
                result.snapshots[0].source_session_id,
                "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"
            );
            assert_eq!(held_index.files.len(), 4);
            fs::remove_dir_all(root).unwrap();
        }
    }
}

const OWNER: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
/// Feed members in order through one `StreamProof`, with the parser's
/// `admitted_usage` tap after every UI usage record.
pub(crate) fn stream(members: &[Vec<Value>]) -> Option<(JoinRefusal, usize)> {
    let mut proof = StreamProof::new(OWNER.into(), vec![MemberPlan::default(); members.len()]);
    for (position, rows) in members.iter().enumerate() {
        proof.begin_member(position);
        let mut turn = None;
        for row in rows {
            if row["payload"]["type"] == "task_started" {
                turn = row["payload"]["turn_id"].as_str();
            }
            proof.observe(row);
            if codex_last_usage(row).is_some() {
                let identity = codex_usage_event_identity(row);
                proof.admitted_usage(row, true, identity.as_deref(), turn);
            }
        }
        proof.end_member(0);
    }
    proof.finish_group();
    proof.refusal()
}
#[test]
fn disjoint_continuation_uses_counter_order() {
    let a = member(OWNER, "response-a", 100, 100);
    let b = member(OWNER, "response-b", 200, 300);
    assert_eq!(stream(&[a.clone(), b.clone()]), None);
    let probes = [probe_before(&b[3]), probe_before(&a[3])];
    assert_eq!(order_by_probes(&[0, 1], &probes), Ok(vec![1, 0]));
}
#[test]
fn overlapping_identity_gap_reset_or_different_owner_is_refused() {
    let a = member(OWNER, "response-a", 100, 100);
    for (b, reason) in [
        (member(OWNER, "response-a", 200, 300), JoinRefusal::Overlap),
        (member(OWNER, "response-b", 200, 400), JoinRefusal::Gap),
        (member(OWNER, "response-b", 200, 200), JoinRefusal::Overlap),
        (
            member(
                "ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee",
                "response-b",
                200,
                300,
            ),
            JoinRefusal::Overlap,
        ),
    ] {
        assert_eq!(stream(&[a.clone(), b]), Some((reason, 1)));
    }
}
#[test]
fn copied_ui_contribution_cannot_gain_a_second_member() {
    let a = member(OWNER, "response-a", 100, 100);
    let mut b = member(OWNER, "response-b", 100, 200);
    b[4] = a[4].clone();
    assert_eq!(stream(&[a, b]), Some((JoinRefusal::Overlap, 1)));
}
#[test]
fn missing_owner_or_native_fields_are_not_accepted() {
    let rows = member(OWNER, "response", 100, 100);
    for field in ["thread_id", "response_id", "usage", "thread_token_usage"] {
        let mut changed = rows.clone();
        changed[3]["payload"].as_object_mut().unwrap().remove(field);
        assert_eq!(
            stream(&[changed]),
            Some((JoinRefusal::Corrupt, 0)),
            "{field}"
        );
    }
}
