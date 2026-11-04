// Claude cache rows on the file birth verdict: an Admitted file ships rows
// for its own requests only, those not more than the copy slack before its
// content birth (its first own response's provider time). Synthetic,
// content-free fixtures; the parent module's helpers stamp own records just
// before the test file's real birth and copied ones days earlier.
use super::*;

/// The parent's [`assistant`] as a 100,000-token prompt with `read` tokens
/// from cache (90,000 is warm, 0 is cold).
fn cached(session: &str, request: &str, timestamp: &str, read: u64) -> String {
    with_cache_read(assistant(session, request, timestamp, 100_000 - read), read)
}

/// The parent's [`subagent_assistant`], read as in [`cached`].
fn subagent_cached(
    session: &str,
    agent: &str,
    request: &str,
    timestamp: &str,
    read: u64,
) -> String {
    let line = subagent_assistant(session, agent, request, timestamp);
    let line = line.replace(
        "\"input_tokens\":40,",
        &format!("\"input_tokens\":{},", 100_000 - read),
    );
    with_cache_read(line, read)
}

fn with_cache_read(line: String, read: u64) -> String {
    line.replace(
        "\"output_tokens\":1",
        &format!("\"cache_read_input_tokens\":{read},\"cache_creation_input_tokens\":0,\"output_tokens\":1"),
    )
}

fn prompt(session: &str, timestamp: &str) -> String {
    format!(
        "{{\"timestamp\":\"{timestamp}\",\"type\":\"user\",\"sessionId\":\"{session}\",\"message\":{{\"role\":\"user\",\"content\":\"next\"}}}}\n"
    )
}

fn rows(item: &SnapshotItem) -> Vec<cache_observations::Observation> {
    item.cache_observations
        .as_ref()
        .expect("cache rows")
        .operations
        .iter()
        .map(|operation| match operation {
            cache_observations::Operation::Upsert { observation } => observation.as_ref().clone(),
            cache_observations::Operation::Retract { event_id } => {
                panic!("a first pass never retracts: {event_id}")
            }
        })
        .collect()
}

/// The affected request of each row, sorted.
fn affected(item: &SnapshotItem) -> Vec<String> {
    let mut refs = rows(item)
        .into_iter()
        .map(|row| row.affected_request_ref)
        .collect::<Vec<_>>();
    refs.sort();
    refs
}

/// Every request a row names: previous, affected and next.
fn named(item: &SnapshotItem) -> BTreeSet<String> {
    rows(item)
        .into_iter()
        .flat_map(|row| [row.previous, Some(row.affected), row.immediate_next])
        .flatten()
        .map(|slot| slot.request_ref)
        .collect()
}

fn write(path: &Path, lines: &[String]) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create fixture dir");
    fs::write(path, lines.concat()).expect("write fixture");
}

/// [money] Positive control and body oracle: an Admitted root with a copied
/// prefix ships rows for its own requests only, and the rows leave the
/// semantic hashes, the fingerprint and the witness version unchanged.
#[test]
fn admitted_file_ships_cache_rows_for_its_own_requests_only() {
    let dir = temp_dir("claude-cache-gate-own");
    let now = OffsetDateTime::now_utc();
    let lines = [
        cached(ROOT, "req_c1", &stamp(now, COPIED), 90_000),
        cached(ROOT, "req_c2", &stamp(now, COPIED + 1), 0),
        cached(ROOT, "req_c3", &stamp(now, COPIED + 2), 90_000),
        cached(ROOT, "req_a1", &stamp(now, -30), 90_000),
        cached(ROOT, "req_a2", &stamp(now, -29), 0),
        cached(ROOT, "req_a3", &stamp(now, -28), 90_000),
    ];
    let (path, parsed) = root_session(&dir, ROOT, &lines);
    let fold_with = |rule_on: bool| {
        let mut items = vec![parsed.clone()];
        let mut index = indexed(&[&path], true);
        let disposition = if rule_on {
            fold(&mut items, &no_reports(), &mut index, true)
        } else {
            claude_context_file_birth::with_file_birth_rule_disabled_for_test(|| {
                fold(&mut items, &no_reports(), &mut index, true)
            })
        };
        (disposition, items.remove(0))
    };
    let (disposition, item) = fold_with(true);
    let (_, control) = fold_with(false);
    assert_eq!(disposition.posture_admission(ROOT), Some("file_birth_rule"));
    assert_eq!(affected(&item), ["req_a2"]);
    assert!(
        named(&item).iter().all(|id| id.starts_with("req_a")),
        "no copied request in any slot: {:?}",
        named(&item)
    );
    assert!(control.cache_observations.is_none());
    let differing = differing_keys(&item, &control);
    assert!(differing.contains("cache_observations"));
    assert!(differing.is_subset(&allowed_difference()), "{differing:?}");
    let claude = SnapshotSource::ClaudeCode;
    let mut bare = item.clone();
    bare.cache_observations = None;
    assert_eq!(
        snapshot_semantic_component_hashes(claude, &item),
        snapshot_semantic_component_hashes(claude, &bare)
    );
    assert_eq!(
        item.snapshot_fingerprint,
        snapshot_fingerprint(claude, &bare)
    );
    assert_eq!(
        snapshot_upload_body_witness_version(&item),
        snapshot_upload_body_witness_version(&bare)
    );
    let _ = fs::remove_dir_all(dir);
}

/// [money] The strict owned-start arm takes the same copy filter. A fork
/// marker proves the owned start; the copied prefix the parser keeps
/// (unmarked, days before the file's birth) has a break of its own. Only
/// the own suffix ships rows; without the filter the prefix break would
/// ship too.
#[test]
fn strict_owned_start_ships_cache_rows_for_its_own_suffix_only() {
    let dir = temp_dir("claude-cache-gate-strict-owned");
    let now = OffsetDateTime::now_utc();
    let forked = cached(ROOT, "req_f0", &stamp(now, COPIED - 10), 90_000).replacen(
        "\"type\":\"assistant\",",
        &format!(
            "\"type\":\"assistant\",\"forkedFrom\":{{\"sessionId\":\"{OTHER_ROOT}\",\"messageUuid\":\"m-0\"}},"
        ),
        1,
    );
    let lines = [
        forked,
        cached(ROOT, "req_c1", &stamp(now, COPIED), 90_000),
        cached(ROOT, "req_c2", &stamp(now, COPIED + 1), 0),
        cached(ROOT, "req_c3", &stamp(now, COPIED + 2), 90_000),
        cached(ROOT, "req_a1", &stamp(now, -30), 90_000),
        cached(ROOT, "req_a2", &stamp(now, -29), 0),
        cached(ROOT, "req_a3", &stamp(now, -28), 90_000),
    ];
    let (path, parsed) = root_session(&dir, ROOT, &lines);
    assert!(parsed.claude_context_curve_owned_start_proven);
    let mut items = vec![parsed.clone()];
    let mut index = indexed(&[&path], false);
    let disposition = fold(&mut items, &no_reports(), &mut index, true);
    let item = items.remove(0);
    assert_eq!(disposition.posture_admission(ROOT), Some("strict"));
    assert_eq!(item.claude_file_birth_verdict(), None);
    assert_eq!(affected(&item), ["req_a2"]);
    assert!(
        named(&item).iter().all(|id| id.starts_with("req_a")),
        "no copied request in any slot: {:?}",
        named(&item)
    );
    // Control: the same requests without the filter ship the prefix break.
    let mut unfiltered = item.clone();
    unfiltered.cache_observations = Some(cache_wire(
        ROOT,
        parsed.cache_requests.iter(),
        parsed.cache_requests_complete,
    ));
    assert!(affected(&unfiltered).contains(&"req_c2".to_string()));
    let _ = fs::remove_dir_all(dir);
}

/// [money] A resumed root copies its original's requests with their
/// timestamps. Folded on one page, each request ships once: the copy's
/// rows are its own, and the original's rows equal its rows alone.
#[test]
fn copy_family_emits_each_request_once() {
    let dir = temp_dir("claude-cache-gate-copy-family");
    let now = OffsetDateTime::now_utc().unix_timestamp_nanos();
    let original_birth = now - 3 * 24 * 3_600 * 1_000_000_000;
    let copy_birth = now - 3_600 * 1_000_000_000;
    let original_path = dir.join(format!("{OTHER_ROOT}.jsonl"));
    let copy_path = dir.join(format!("{ROOT}.jsonl"));
    let original_turns = [("req_o1", 90_000), ("req_o2", 0), ("req_o3", 90_000)];
    let turns = |session: &str| {
        original_turns
            .iter()
            .enumerate()
            .map(|(at, (request, read))| {
                cached(
                    session,
                    request,
                    &from_birth(original_birth, 10_000 + 1_000 * at as i64),
                    *read,
                )
            })
            .collect::<Vec<_>>()
    };
    write(&original_path, &turns(OTHER_ROOT));
    let mut copy = turns(ROOT);
    for (at, (request, read)) in [("req_g1", 90_000), ("req_g2", 0), ("req_g3", 90_000)]
        .into_iter()
        .enumerate()
    {
        copy.push(cached(
            ROOT,
            request,
            &from_birth(copy_birth, 10_000 + 1_000 * at as i64),
            read,
        ));
    }
    write(&copy_path, &copy);
    let births = BTreeMap::from([
        (local_index_key(&original_path), original_birth as u64),
        (local_index_key(&copy_path), copy_birth as u64),
    ]);
    let now = OffsetDateTime::now_utc();
    let (original, copied) =
        crate::snapshots::claude_history_upgrade::with_staged_births_for_test(births, || {
            (parse(&original_path, now), parse(&copy_path, now))
        });
    let folded = |items: Vec<SnapshotItem>| {
        let mut items = items;
        let paths = [&original_path, &copy_path];
        let mut index = indexed(&paths.map(PathBuf::as_path), true);
        let disposition = fold(&mut items, &no_reports(), &mut index, true);
        for item in &items {
            assert_eq!(
                disposition.posture_admission(&item.source_session_id),
                Some("file_birth_rule")
            );
        }
        items
    };
    let page = folded(vec![original.clone(), copied]);
    let alone = folded(vec![original]);
    assert_eq!(affected(&page[0]), ["req_o2"]);
    assert_eq!(affected(&page[1]), ["req_g2"]);
    assert!(named(&page[1]).iter().all(|id| id.starts_with("req_g")));
    assert_eq!(page[0].cache_observations, alone[0].cache_observations);
    let _ = fs::remove_dir_all(dir);
}

/// [money] Subagent B copies subagent A's turns. B's content birth is its
/// first response A does not hold, so A's turns stay with A; a copied turn
/// within the 60 s slack before B's first own one ships in both (the
/// disclosed residual, pinned here). A file A holds entirely ships nothing.
#[test]
fn subagent_copy_emits_each_request_once_outside_the_slack() {
    let dir = temp_dir("claude-cache-gate-subagent-copy");
    let now = OffsetDateTime::now_utc();
    let agents = [
        "a000000000000000a",
        "b000000000000000b",
        "c000000000000000c",
    ];
    let path = |agent: &str| {
        dir.join(ROOT)
            .join("subagents")
            .join(format!("agent-{agent}.jsonl"))
    };
    let original = [
        ("req_a1", -600, 90_000),
        ("req_a2", -599, 0),
        ("req_a3", -598, 90_000),
        // Within 60 s of B's first own turn.
        ("req_a4", -50, 0),
    ];
    let own = [
        ("req_b1", -30, 90_000),
        ("req_b2", -29, 0),
        ("req_b3", -28, 90_000),
    ];
    let lines = |agent: &str, turns: &[(&str, i64, u64)]| {
        turns
            .iter()
            .map(|(request, offset, read)| {
                subagent_cached(ROOT, agent, request, &stamp(now, *offset), *read)
            })
            .collect::<Vec<_>>()
    };
    write(&path(agents[0]), &lines(agents[0], &original[..]));
    let mut copy = lines(agents[1], &original[..]);
    copy.extend(lines(agents[1], &own[..]));
    write(&path(agents[1]), &copy);
    write(&path(agents[2]), &lines(agents[2], &original[..3]));
    let mut items = agents
        .into_iter()
        .map(|agent| parse(&path(agent), now))
        .collect::<Vec<_>>();
    let paths = agents.map(path);
    let mut index = indexed(&paths.each_ref().map(PathBuf::as_path), true);
    fold(&mut items, &no_reports(), &mut index, true);
    for item in &items {
        assert_eq!(
            item.claude_file_birth_verdict(),
            Some(ClaudeFileBirthVerdict::Admitted)
        );
    }
    assert_eq!(affected(&items[0]), ["req_a2", "req_a4"]);
    assert_eq!(affected(&items[1]), ["req_a4", "req_b2"]);
    assert!(!named(&items[1]).contains("req_a2"));
    assert!(items[2].cache_observations.is_none());
    let _ = fs::remove_dir_all(dir);
}

/// [money] Cold, Tail and replayed uploads give the same rows. A Tail read
/// after any append boundary folds to the full read's rows, idle included.
/// A replay after a lost ACK sends the same patch, and the server's state
/// after applying it twice equals the state after once.
#[test]
fn cold_tail_and_ack_replay_give_the_same_cache_rows() {
    if !crate::heap_layout_bound::layout_supported() {
        return;
    }
    let dir = temp_dir("claude-cache-gate-tail");
    fs::create_dir_all(&dir).expect("create project dir");
    let now = OffsetDateTime::now_utc();
    let collected_at = stamp(now, 0);
    let lines = [
        prompt(ROOT, &stamp(now, -40)),
        cached(ROOT, "req_1", &stamp(now, -39), 90_000),
        prompt(ROOT, &stamp(now, -34)),
        cached(ROOT, "req_2", &stamp(now, -33), 0),
        prompt(ROOT, &stamp(now, -30)),
        cached(ROOT, "req_3", &stamp(now, -29), 90_000),
    ];
    let path = dir.join(format!("{ROOT}.jsonl"));
    let fold_one = |item: SnapshotItem| {
        let mut items = vec![item];
        let mut index = indexed(&[&path], true);
        fold(&mut items, &no_reports(), &mut index, true);
        items.remove(0)
    };
    for split in 2..lines.len() {
        let _ = fs::remove_file(&path);
        fs::write(&path, lines[..split].concat()).expect("write prefix");
        let (retained, _, _) = native_read(&path, None, 100, &collected_at);
        let mut file = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open for append");
        std::io::Write::write_all(&mut file, lines[split..].concat().as_bytes())
            .expect("append rest");
        drop(file);
        let (_, mode, tailed) = native_read(&path, retained, 101, &collected_at);
        assert_eq!(
            mode,
            crate::transcript_acquisition::ReadMode::Tail,
            "split {split}"
        );
        let (_, _, full) = native_read(&path, None, 102, &collected_at);
        let (tailed, full) = (fold_one(tailed), fold_one(full));
        assert_eq!(
            tailed.cache_observations, full.cache_observations,
            "split {split}"
        );
        let cold = rows(&full);
        assert_eq!(affected(&full), ["req_2"], "split {split}");
        assert_eq!(cold[0].idle_seconds, Some(5), "split {split}");

        // Crash before the ACK: the replay sends the same patch.
        let mut sent = full.clone();
        prepare_cache_observations(&mut sent, None);
        let mut replay = full.clone();
        prepare_cache_observations(&mut replay, None);
        assert_eq!(sent.cache_observations, replay.cache_observations);
        // Crash after the server stored it, before the ACK was saved: the
        // same patch applied again leaves the server's state unchanged.
        let stored = sent.cache_observations_state.clone().expect("state");
        assert_eq!(
            cache_state_from_patch(Some(&stored), replay.cache_observations.as_ref().unwrap()),
            Some(stored.clone())
        );
        // Once the ACK is saved, the next pass changes nothing.
        let mut next = full.clone();
        prepare_cache_observations(&mut next, Some(&stored));
        assert_eq!(next.cache_observations_state, Some(stored));
    }
    let _ = fs::remove_dir_all(dir);
}

/// [behaviour] Idle time fills only a response that starts a turn: the
/// previous response ended its turn (no tool use) and a newer prompt
/// follows it. After a tool use, or with a prompt older than that end, it
/// stays empty. Two hours idle before a cold request adds
/// `long_task_inactivity`.
#[test]
fn claude_idle_time_fills_turn_starts_only() {
    let mut parser = SnapshotAccumulator::new(SnapshotSource::ClaudeCode);
    let assistant = |request: &str, at: &str, read: u64, tool: bool| {
        let content = if tool {
            json!([{"type":"tool_use","id":format!("tool_{request}"),"name":"Read","input":{}}])
        } else {
            json!([{"type":"text","text":"done"}])
        };
        json!({"type":"assistant","sessionId":"session","requestId":request,"timestamp":at,
            "message":{"id":format!("msg_{request}"),"role":"assistant","model":"claude","content":content,
            "usage":{"input_tokens":100_000 - read,"cache_read_input_tokens":read,
            "cache_creation_input_tokens":0,"output_tokens":1}}})
    };
    let user = |at: &str| {
        json!({"type":"user","sessionId":"session","timestamp":at,
            "message":{"role":"user","content":"next"}})
    };
    for line in [
        user("2026-09-30T10:00:00Z"),
        assistant("req_1", "2026-09-30T10:00:01Z", 90_000, false),
        user("2026-09-30T12:00:01Z"),
        assistant("req_2", "2026-09-30T12:00:02Z", 0, true),
        user("2026-09-30T12:00:05Z"),
        assistant("req_3", "2026-09-30T12:00:06Z", 90_000, false),
        user("2026-09-30T12:00:03Z"),
        assistant("req_4", "2026-09-30T12:00:10Z", 90_000, false),
    ] {
        apply_claude_code_line(&line, &mut parser);
    }
    parser.finalize_claude_responses();
    let idle = parser
        .cache_requests
        .iter()
        .map(|request| (request.slot.request_ref.as_str(), request.idle_seconds))
        .collect::<Vec<_>>();
    assert_eq!(
        idle,
        [
            ("req_1", None),
            ("req_2", Some(7_200)),
            ("req_3", None),
            ("req_4", None)
        ]
    );
    let wire = cache_wire("session", parser.cache_requests.iter(), true);
    let row = wire
        .operations
        .iter()
        .find_map(|operation| match operation {
            cache_observations::Operation::Upsert { observation }
                if observation.affected_request_ref == "req_2" =>
            {
                Some(observation)
            }
            _ => None,
        })
        .expect("the cold request is a row");
    assert_eq!(row.idle_seconds, Some(7_200));
    assert!(row
        .supporting_conditions
        .contains(&"long_task_inactivity".to_string()));
}

/// [money] A request's effort now comes only from its transcript. A missing
/// effort next to a recorded one is a configuration change: an expected
/// rebuild, never an unexpected loss, so the rebuild money can only fall.
#[test]
fn missing_effort_never_adds_an_unexpected_loss() {
    let request = |id: &str, read: u64, effort: Option<&str>| OwnedRequest {
        slot: RequestSlot {
            request_ref: id.into(),
            occurred_at: "2026-09-30T10:00:00Z".into(),
            model: Some("m".into()),
            effort: effort.map(str::to_string),
            prompt_tokens: Some(100_000),
            cache_read_tokens: Some(read),
            ..Default::default()
        },
        ordering: "sequential".into(),
        compaction_before: false,
        configuration_changed: false,
        configuration_witness: None,
        idle_seconds: None,
    };
    let cold_row = |effort: Option<&str>| {
        let rows = cache_observations::detect(
            "s",
            &[request("A", 90_000, Some("high")), request("B", 0, effort)],
        );
        let row = &rows[&cache_observations::event_id("s", "B")];
        (row.observation_kind.clone(), row.explanation_code.clone())
    };
    assert_eq!(
        cold_row(Some("high")),
        ("unexpected_loss".to_string(), "unclear".to_string())
    );
    assert_eq!(
        cold_row(None),
        (
            "expected_rebuild".to_string(),
            "configuration_change".to_string()
        )
    );
}
