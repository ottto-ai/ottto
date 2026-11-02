use super::*;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ottto-codex-prepare-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn db(&self, name: &str, sql: &str) -> PathBuf {
        let path = self.0.join(name);
        Connection::open(&path).unwrap().execute_batch(sql).unwrap();
        path
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

/// [behaviour] Borrowed selector reads match the former whole-document parser,
/// including last-key-wins, malformed payloads and incomplete database reads.
#[test]
fn selector_reads_match_document_verdicts() {
    fn reference(body: &str) -> Option<String> {
        let at = body.rfind("websocket request:")?;
        let value: Value = serde_json::from_str(body[at + 18..].trim()).ok()?;
        if value.get("type").and_then(Value::as_str) != Some("response.create")
            || !value
                .get("service_tier")
                .and_then(Value::as_str)?
                .eq_ignore_ascii_case("priority")
        {
            return None;
        }
        codex_logs2_span_field(&body[..at], "turn.id")
            .or_else(|| codex_logs2_span_field(&body[..at], "turn_id"))
            .filter(|id| !id.is_empty())
    }
    let mut documents = vec![
        r#"{"type":"response.create","service_tier":"PrIoRiTy","input":[{"text":"synthetic"}],"tools":{},"instructions":null}"#.to_string(),
        r#"{"type":"other","type":"response.create","service_tier":false,"service_tier":"priority"}"#.into(),
        r#"{"type":"response.create","type":null,"service_tier":"priority"}"#.into(),
        r#"{"type":"response.create","service_tier":"priority","service_tier":{"nested":[]}}"#.into(),
        r#"{"type":"response.create","service_tier":"pri\u006frity"}"#.into(),
        r#"{"type":"response.create","service_tier":"priority","input":[}"#.into(),
        r#"{"type":"response.create","service_tier":"priority","input":1e999}"#.into(),
        r#"{"type":"response.create","service_tier":"priority","input":"\uD800"}"#.into(),
        r#"{"type":"response.create","service_tier":"priority"} false"#.into(),
        "null".into(),
        "[]".into(),
    ];
    documents.push(format!(
        r#"{{"type":"response.create","service_tier":"priority","input":{}{}}}"#,
        "[".repeat(128),
        "]".repeat(128)
    ));
    documents.push(format!(
        r#"{{"type":"response.create","service_tier":"priority","input":"{}"}}"#,
        "synthetic ".repeat(100_000)
    ));
    let fixture = Fixture::new();
    let path = fixture.db(
        "logs.sqlite",
        "CREATE TABLE logs(ts INTEGER, feedback_log_body TEXT);",
    );
    let connection = Connection::open(&path).unwrap();
    let mut expected = BTreeSet::new();
    for (i, json) in documents.iter().enumerate() {
        let body = format!("turn{{turn.id=turn-{i}}} websocket request: {json}");
        let old = reference(&body);
        assert_eq!(
            codex_logs2_priority_turn_from_body(&body),
            old,
            "fixture {i}"
        );
        expected.extend(old);
        connection
            .execute("INSERT INTO logs VALUES(1, ?1)", [&body])
            .unwrap();
    }
    assert!(!expected.is_empty());
    drop(connection);
    let mut turns = BTreeSet::new();
    assert!(load_codex_logs2_priority_turns(&path, 0, &mut turns));
    assert_eq!(turns, expected);
    Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO logs VALUES(1, ?1)",
            [b"websocket request:".as_slice()],
        )
        .unwrap();
    turns.clear();
    assert!(!load_codex_logs2_priority_turns(&path, 0, &mut turns));
    assert_eq!(turns, expected, "a bad row keeps the known part unknown");
}

/// [behaviour] Streaming census preserves aliases, row conflicts, lineage,
/// home-specific evidence and complete/unknown publication boundaries.
#[test]
fn streamed_metadata_matches_census_fixtures() {
    const PARENT: &str = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const CHILD: &str = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const ALIAS: &str = "cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const DUP: &str = "dddddddd-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    const CROSS: &str = "eeeeeeee-bbbb-4ccc-8ddd-eeeeeeeeeeee";
    let fixture = Fixture::new();
    let schema = "CREATE TABLE threads(id TEXT, title TEXT, tokens_used INTEGER, thread_source TEXT, first_user_message TEXT);
                  CREATE TABLE thread_spawn_edges(parent_thread_id TEXT, child_thread_id TEXT);";
    let path = fixture.db("state.sqlite", schema);
    let connection = Connection::open(&path).unwrap();
    for (id, title, tokens) in [
        (PARENT, "parent", 100),
        (CHILD, "child", 20),
        (ALIAS, "alias", 30),
        (DUP, "duplicate", 40),
        (DUP, "different", 41),
        (CROSS, "cross", 50),
    ] {
        connection
            .execute(
                "INSERT INTO threads VALUES(?1,?2,?3,'cli',NULL)",
                rusqlite::params![id, title, tokens],
            )
            .unwrap();
    }
    connection
        .execute(
            "INSERT INTO threads VALUES(?1,'alias',30,'cli',NULL)",
            [ALIAS.to_ascii_uppercase()],
        )
        .unwrap();
    let message = format!("<codex_delegation>\n  <source_thread_id>{PARENT}</source_thread_id>\n  <input>{}</input>\n</codex_delegation>", "synthetic ".repeat(100_000));
    connection.execute("UPDATE threads SET thread_source='agent_created_thread', first_user_message=?1 WHERE id=?2", rusqlite::params![message,CHILD]).unwrap();
    drop(connection);
    let mut open = SidecarOpenCounts::default();
    let mut metadata = CodexTitleMetadata::default();
    load_codex_sqlite_titles(
        &path,
        &mut open,
        &mut metadata.titles,
        &mut metadata.identity_conflicts,
    )
    .unwrap();
    assert_eq!(metadata.titles.len(), 4);
    assert!(!metadata.titles.contains_key(ALIAS));
    assert_eq!(metadata.titles[DUP].title, "duplicate");
    let mut incoming = codex_root_copies::RootSidecar::default();
    load_codex_sqlite_state_threads(
        &path,
        &mut open,
        &mut incoming.threads,
        &mut metadata.identity_conflicts,
        &mut metadata.local_diagnostics.identity_conflict_taxonomy,
    )
    .unwrap();
    assert_eq!(
        incoming.threads.keys().cloned().collect::<BTreeSet<_>>(),
        BTreeSet::from([PARENT.into(), CHILD.into(), CROSS.into()])
    );
    assert_eq!(
        metadata.identity_conflicts,
        BTreeSet::from([ALIAS.into(), DUP.into()])
    );
    let mut parentless = BTreeSet::new();
    load_codex_sqlite_spawn_edges(
        &path,
        &mut open,
        &mut metadata.state_created_threads,
        &mut metadata.spawn_parents,
        &mut metadata.spawn_parent_conflicts,
        &mut metadata.identity_conflicts,
        &mut parentless,
    )
    .unwrap();
    assert_eq!(
        metadata.state_created_threads,
        BTreeSet::from([CHILD.into()])
    );
    assert_eq!(
        metadata.spawn_parents,
        BTreeMap::from([(CHILD.into(), PARENT.into())])
    );
    assert!(parentless.is_empty());
    codex_root_copies::merge_threads(&mut metadata, &fixture.0, &incoming.threads);
    assert!(Arc::ptr_eq(
        &incoming.threads[PARENT],
        &metadata.state_threads[PARENT]
    ));
    metadata.root_sidecars.insert(fixture.0.clone(), incoming);
    let mut second = metadata.root_sidecars[&fixture.0].clone();
    Arc::make_mut(second.threads.get_mut(CROSS).unwrap()).tokens_used = 51;
    codex_root_copies::merge_threads(&mut metadata, &fixture.0.join("second"), &second.threads);
    assert!(!metadata.state_threads.contains_key(CROSS));
    assert!(metadata.identity_conflicts.contains(CROSS));
    assert_eq!(metadata.state_threads[PARENT].tokens_used, 100);

    // A late row decoding failure publishes neither earlier rows nor aliases.
    Connection::open(&path)
        .unwrap()
        .execute_batch("INSERT INTO threads VALUES('late',x'FF',1,'agent_created_thread',x'FF');")
        .unwrap();
    let before = format!("{:?}", metadata);
    assert!(load_codex_sqlite_titles(
        &path,
        &mut open,
        &mut metadata.titles,
        &mut metadata.identity_conflicts
    )
    .is_err());
    assert!(load_codex_sqlite_state_threads(
        &path,
        &mut open,
        &mut metadata.state_threads,
        &mut metadata.identity_conflicts,
        &mut metadata.local_diagnostics.identity_conflict_taxonomy
    )
    .is_err());
    assert!(load_codex_sqlite_spawn_edges(
        &path,
        &mut open,
        &mut metadata.state_created_threads,
        &mut metadata.spawn_parents,
        &mut metadata.spawn_parent_conflicts,
        &mut metadata.identity_conflicts,
        &mut parentless
    )
    .is_err());
    assert_eq!(format!("{:?}", metadata), before);
    assert!(parentless.is_empty());
    let history = fixture.db("history.sqlite", &format!("CREATE TABLE thread_history_projection_state(thread_id TEXT, next_rollout_byte_offset INTEGER, next_rollout_ordinal INTEGER); INSERT INTO thread_history_projection_state VALUES('{PARENT}',10,1),('{PARENT}',10,1),('{ALIAS}',20,2),('{}',20,2);", ALIAS.to_ascii_uppercase()));
    load_codex_rollout_extents(
        &history,
        &mut open,
        &mut metadata.rollout_extents,
        &mut metadata.identity_conflicts,
    )
    .unwrap();
    assert_eq!(
        metadata.rollout_extents,
        BTreeMap::from([(
            PARENT.into(),
            CodexRolloutExtent {
                next_byte_offset: 10,
                next_ordinal: 1
            }
        )])
    );
    Connection::open(&history)
        .unwrap()
        .execute_batch(
            "INSERT INTO thread_history_projection_state VALUES('negative',-1,0),('bad',x'FF',0);",
        )
        .unwrap();
    let before = format!("{:?}", metadata);
    let error = load_codex_rollout_extents(
        &history,
        &mut open,
        &mut metadata.rollout_extents,
        &mut metadata.identity_conflicts,
    )
    .unwrap_err();
    assert!(
        error.downcast_ref::<rusqlite::Error>().is_some(),
        "row error precedes negative extent"
    );
    assert_eq!(format!("{:?}", metadata), before);
}
