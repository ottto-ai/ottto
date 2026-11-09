//! RAM-only home facts; acquisition is separate from ordered per-pass merging.
use super::*;
use crate::codex_scan_diagnostics::{LoaderEvidence, LoaderStage};
use crate::heap_layout_bound::{Counter, HeapLayoutBound};
use std::cell::Cell;

type ThreadRows = Vec<(String, Shared<CodexStateThread>)>;
type TitleRows = Vec<(String, Option<String>)>;
type CreatedRows = Vec<(String, Option<String>)>;

#[derive(Clone, Default)]
pub(in crate::snapshots) struct RawRows {
    pub titles: TitleRows,
    pub threads: ThreadRows,
    pub created: CreatedRows,
    pub edges: Option<Vec<(String, String)>>,
    pub edges_complete: bool,
    pub history: Vec<(String, i64, i64)>,
    pub index: CreatedRows,
    pub evidence: [LoaderEvidence; 5],
}
impl std::fmt::Debug for RawRows {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RawSidecarRows")
    }
}

#[derive(Default)]
pub(in crate::snapshots) struct SidecarFacts {
    pub homes: StampedFacts<PathBuf, Arc<codex_root_copies::RootSidecar>, [SourceStamp; 3]>,
    pub logs: BTreeMap<PathBuf, logs_cursor::LogCursor>,
    heap_bytes: usize,
    home_heap_bytes: usize,
}
impl HeapLayoutBound for SidecarFacts {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        c.add(self.heap_bytes)
    }
}

fn capture(root: &Path) -> [Option<SourceStamp>; 3] {
    [
        SourceStamp::capture_sqlite(&root.join("state_5.sqlite")),
        SourceStamp::capture_sqlite(&root.join("thread_history_1.sqlite")),
        SourceStamp::capture_file(&root.join("session_index.jsonl")).ok(),
    ]
}
fn witness(stamps: &[Option<SourceStamp>; 3]) -> Option<[SourceStamp; 3]> {
    Some([stamps[0].clone()?, stamps[1].clone()?, stamps[2].clone()?])
}

impl SidecarFacts {
    pub fn load(&mut self, roots: &[PathBuf]) -> CodexTitleMetadata {
        let listed = roots
            .iter()
            .filter_map(|root| root.parent().map(Path::to_path_buf))
            .collect::<BTreeSet<_>>();
        let before = listed
            .iter()
            .map(|home| (home.clone(), capture(home)))
            .collect::<BTreeMap<_, _>>();
        // Every retained prefix depends on the complete merged group. A
        // changed roster, failed pass or changed input reloads the group.
        let reuse = listed.len() == self.homes.kept.len() && before.iter().all(|(home, stamp)| {
            matches!((witness(stamp), self.homes.kept.get(home)), (Some(now), Some((old, _))) if now.same(old))
        });
        self.homes.retain_listed(&listed);
        if !reuse {
            self.homes.retain_listed(&BTreeSet::new());
        }
        let mut after = BTreeMap::new();
        let mut loaded = BTreeMap::new();
        for home in &listed {
            let stamp = witness(&before[home]);
            let raw = if reuse {
                let value: Result<_> = self.homes.reuse_or_load(
                    home.clone(),
                    || {
                        stamp
                            .clone()
                            .ok_or_else(|| std::io::Error::other("noncacheable sidecar"))
                    },
                    || unreachable!("the complete group was checked"),
                );
                value.expect("reuse does not acquire")
            } else {
                let (facts, witness) = load_home(home, &before[home]);
                after.insert(home.clone(), witness);
                Arc::new(facts)
            };
            loaded.insert(home.clone(), raw);
        }
        let mut metadata = CodexTitleMetadata::merge_roots(loaded, reuse);
        metadata.compact_titles();
        if metadata.state_census_incomplete || metadata.sidecar_census_incomplete {
            for witness in after.values_mut() {
                *witness = None;
            }
        }
        if !reuse {
            for (home, facts) in &metadata.root_sidecars {
                let first = Cell::new(true);
                let value: Result<_> = self.homes.reuse_or_load(
                    home.clone(),
                    || {
                        let witness = if first.replace(false) {
                            witness(&before[home])
                        } else {
                            after[home].clone()
                        };
                        witness.ok_or_else(|| std::io::Error::other("noncacheable sidecar"))
                    },
                    || Ok(facts.clone()),
                );
                // Acquisition's partial successes belong to this pass even
                // when the helper refuses to keep its witness.
                let _ = value.expect("facts already acquired");
            }
        }
        if !reuse {
            self.charge_homes();
        }
        self.charge_heap();
        metadata
    }

    fn charge_homes(&mut self) {
        // Charge immutable entry heaps only on insertion/replacement.
        self.home_heap_bytes =
            self.homes
                .kept
                .iter()
                .fold(0usize, |total, (home, (stamp, facts))| {
                    let facts = crate::heap_layout_bound::completed_bound(&**facts, usize::MAX)
                        .unwrap_or(usize::MAX);
                    let stamp = stamp
                        .iter()
                        .map(|stamp| match stamp {
                            SourceStamp::Sqlite { target, .. } => target.capacity(),
                            _ => 0,
                        })
                        .sum::<usize>();
                    total
                        .saturating_add(home.capacity())
                        .saturating_add(stamp)
                        .saturating_add(
                            crate::heap_layout_bound::tree_node_bytes::<
                                PathBuf,
                                ([SourceStamp; 3], Arc<codex_root_copies::RootSidecar>),
                            >()
                            .unwrap_or(usize::MAX),
                        )
                        .saturating_add(facts)
                        .saturating_add(2 * std::mem::size_of::<usize>())
                });
    }
    pub fn charge_heap(&mut self) {
        self.heap_bytes = self.home_heap_bytes;
        for (path, cursor) in &self.logs {
            self.heap_bytes = self
                .heap_bytes
                .saturating_add(path.capacity())
                .saturating_add(
                    crate::heap_layout_bound::completed_bound(cursor, usize::MAX)
                        .unwrap_or(usize::MAX),
                )
                .saturating_add(
                    crate::heap_layout_bound::tree_node_bytes::<PathBuf, logs_cursor::LogCursor>()
                        .unwrap_or(usize::MAX),
                );
        }
    }
}

fn observe(result: &Result<()>, open: SidecarOpenCounts) -> LoaderEvidence {
    let mut evidence = LoaderEvidence::default();
    evidence.observe_root(result, open, false, "");
    evidence
}

fn finish<T: Default>(result: Result<T>, counts: SidecarOpenCounts) -> (T, LoaderEvidence) {
    match result {
        Ok(value) => (value, observe(&Ok(()), counts)),
        Err(error) => (T::default(), observe(&Err(error), counts)),
    }
}

fn open(
    path: &Path,
    before: Option<&SourceStamp>,
    counts: &mut SidecarOpenCounts,
) -> Result<codex_sqlite_read::CodexSqliteRead> {
    let Some(before) = before else {
        return open_codex_sidecar_database(path, counts);
    };
    let mut first = true;
    let read = retry_transient_sqlite(&mut counts.retries, || {
        if std::mem::take(&mut first) {
            codex_sqlite_read::CodexSqliteRead::open_stamped(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY,
                CODEX_SIDECAR_BUSY_TIMEOUT,
                Some(before),
            )
        } else {
            // Retry with today's fresh routing after a transient open/probe
            // failure. The plain entry returns no reusable after witness.
            codex_sqlite_read::CodexSqliteRead::open(
                path,
                OpenFlags::SQLITE_OPEN_READ_ONLY,
                CODEX_SIDECAR_BUSY_TIMEOUT,
            )
        }
    })?;
    if read.is_snapshot() {
        counts.snapshots = counts.snapshots.saturating_add(1);
    }
    Ok(read)
}

fn load_home(
    home: &Path,
    before: &[Option<SourceStamp>; 3],
) -> (codex_root_copies::RootSidecar, Option<[SourceStamp; 3]>) {
    let mut facts = codex_root_copies::RootSidecar::default();
    let raw = &mut facts.raw;
    let mut after: [Option<SourceStamp>; 3] = [None, None, None];
    let state_path = home.join("state_5.sqlite");
    if state_path.exists() {
        let mut counts = SidecarOpenCounts::default();
        match open(&state_path, before[0].as_ref(), &mut counts) {
            Err(error) => {
                let result = Err(error);
                for evidence in &mut raw.evidence[..3] {
                    *evidence = observe(&result, counts);
                }
            }
            Ok(read) => {
                match read.read(thread_rows) {
                    Err(error) => {
                        let result = Err(error);
                        for evidence in &mut raw.evidence[..3] {
                            *evidence = observe(&result, counts);
                        }
                    }
                    Ok((titles, threads, created)) => {
                        let created_ok = created.is_ok();
                        (raw.titles, raw.evidence[0]) = finish(titles, counts);
                        (raw.threads, raw.evidence[1]) =
                            finish(threads, SidecarOpenCounts::default());
                        (raw.created, raw.evidence[2]) =
                            finish(created, SidecarOpenCounts::default());
                        if created_ok {
                            let edges = read.read(|db| {
                                let columns = sqlite_table_columns(db, "thread_spawn_edges")?;
                                if !columns.contains("parent_thread_id") || !columns.contains("child_thread_id") { return Ok(None); }
                                census_rows(db, "SELECT parent_thread_id, child_thread_id FROM thread_spawn_edges", "Codex spawn-edge census", |row| Ok((row.get(0)?, row.get(1)?))).map(Some)
                            });
                            raw.edges_complete = edges.is_ok();
                            if edges.is_ok() {
                                raw.edges = edges.unwrap_or_default();
                            } else {
                                raw.evidence[2] =
                                    observe(&edges.map(|_| ()), SidecarOpenCounts::default());
                            }
                        }
                    }
                }
                after[0] = read.after_stamp();
            }
        }
    } else {
        for evidence in &mut raw.evidence[..3] {
            *evidence = observe(&Ok(()), SidecarOpenCounts::default());
        }
        raw.edges_complete = true;
        after[0] = SourceStamp::capture_sqlite(&state_path);
    }
    let path = home.join("thread_history_1.sqlite");
    let mut counts = SidecarOpenCounts::default();
    let result = if path.exists() {
        open(&path, before[1].as_ref(), &mut counts).and_then(|read| {
            let result = read.read(history_rows);
            after[1] = read.after_stamp();
            raw.history = result?;
            Ok(())
        })
    } else {
        after[1] = SourceStamp::capture_sqlite(&path);
        Ok(())
    };
    raw.evidence[3] = observe(&result, counts);
    let path = home.join("session_index.jsonl");
    let result = index_rows(&path, &mut raw.index);
    raw.evidence[4] = observe(&result, SidecarOpenCounts::default());
    after[2] = SourceStamp::capture_file(&path).ok();
    // Preserve the existing checked integer conversion boundary.
    let result = apply_extents(&raw.history, &mut facts.extents, &mut BTreeSet::new());
    if result.is_err() {
        raw.evidence[3] = observe(&result, counts);
    }
    apply_threads(
        &raw.threads,
        &mut facts.threads,
        &mut BTreeSet::new(),
        &mut IdentityConflictTaxonomy::default(),
    );
    for outcome in &mut raw.evidence[..3] {
        outcome.absent_roots = u32::from(matches!(&after[0], Some(SourceStamp::Absent)));
    }
    raw.evidence[3].absent_roots = u32::from(matches!(&after[1], Some(SourceStamp::Absent)));
    raw.evidence[4].absent_roots = u32::from(matches!(&after[2], Some(SourceStamp::Absent)));
    let complete = raw.evidence.iter().all(|outcome| outcome.failed_roots == 0);
    let witness = complete
        .then(|| Some([after[0].take()?, after[1].take()?, after[2].take()?]))
        .flatten();
    (facts, witness)
}

pub(super) fn history_rows(db: &Connection) -> Result<Vec<(String, i64, i64)>> {
    let columns = sqlite_table_columns(db, "thread_history_projection_state")?;
    if columns.is_empty() {
        return Ok(Vec::new());
    }
    if ![
        "thread_id",
        "next_rollout_byte_offset",
        "next_rollout_ordinal",
    ]
    .iter()
    .all(|column| columns.contains(*column))
    {
        return Err(anyhow::Error::new(IncompleteShape));
    }
    census_rows(db, "SELECT thread_id, next_rollout_byte_offset, next_rollout_ordinal FROM thread_history_projection_state", "Codex rollout-extent census", |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
}

fn index_rows(path: &Path, rows: &mut CreatedRows) -> Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let mut invalid = false;
    let report = read_bounded_jsonl_lines(BufReader::new(file), |value| {
        if let Some(id) = codex_identity_at(value, &["id"]) {
            rows.push((
                id,
                string_at(value, &["thread_name"])
                    .or_else(|| string_at(value, &["title"]))
                    .or_else(|| string_at(value, &["name"])),
            ));
        } else {
            invalid = true;
        }
    })?;
    if invalid || !report.complete() {
        return Err(anyhow::Error::new(IncompleteShape));
    }
    Ok(())
}

/// Evaluate membership with SQLite itself, then stage/decode each sub-census
/// independently. A bad Q1/Q2 row discards only its own complete-query effects.
fn thread_rows(
    db: &Connection,
) -> Result<(Result<TitleRows>, Result<ThreadRows>, Result<CreatedRows>)> {
    let columns = sqlite_table_columns(db, "threads")?;
    let complete = [
        columns.contains("id") && columns.contains("title"),
        columns.contains("id") && columns.contains("tokens_used"),
        ["id", "thread_source", "first_user_message"]
            .iter()
            .all(|c| columns.contains(*c)),
    ];
    let mut statuses: [Result<()>; 3] = std::array::from_fn(|i| {
        if complete[i] {
            Ok(())
        } else {
            Err(anyhow::Error::new(IncompleteShape))
        }
    });
    if !complete[0] {
        statuses[0] = db
            .prepare("SELECT id, title FROM threads WHERE title IS NOT NULL AND title != ''")
            .context(LoaderStage::Prepare)
            .map(|_| ());
    }
    let fields = [
        "id",
        "title",
        "tokens_used",
        "archived",
        "created_at",
        "updated_at",
        "created_at_ms",
        "updated_at_ms",
        "model",
        "rollout_path",
    ]
    .iter()
    .map(|column| {
        sqlite_select_expr(
            &columns,
            column,
            if *column == "archived" { "0" } else { "NULL" },
        )
    })
    .collect::<Vec<_>>();
    let sql = format!(
        "SELECT {}, {}, {}, {}, {} FROM threads",
        fields.join(", "),
        if complete[0] {
            "CASE WHEN title IS NOT NULL AND title != '' THEN 1 ELSE 0 END"
        } else {
            "0"
        },
        if complete[1] {
            "CASE WHEN tokens_used > 0 THEN 1 ELSE 0 END"
        } else {
            "0"
        },
        if complete[2] {
            "CASE WHEN thread_source = 'agent_created_thread' THEN 1 ELSE 0 END"
        } else {
            "0"
        },
        if complete[2] {
            "CASE WHEN thread_source = 'agent_created_thread' THEN first_user_message END"
        } else {
            "NULL"
        }
    );
    let mut statement = db.prepare(&sql).context(LoaderStage::Prepare)?;
    let mut rows = statement.query([]).context(LoaderStage::Query)?;
    let (mut titles, mut threads, mut created) = (Vec::new(), Vec::new(), Vec::new());
    while let Some(row) = rows.next().context(LoaderStage::Row)? {
        if statuses[0].is_ok() && row.get::<_, i64>(10)? != 0 {
            match (|| -> rusqlite::Result<_> {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })() {
                Ok((id, title)) => {
                    titles.push((id, normalize_display_title(title, "session_index")))
                }
                Err(error) => {
                    statuses[0] = Err(anyhow::Error::new(error).context(LoaderStage::Row))
                }
            }
        }
        if statuses[1].is_ok() && row.get::<_, i64>(11)? != 0 {
            match (|| -> rusqlite::Result<_> {
                Ok((
                    row.get(0)?,
                    Shared::from(CodexStateThread {
                        title: row.get(1)?,
                        tokens_used: non_negative_i64_to_u64(row.get(2)?),
                        archived: row.get::<_, i64>(3)? != 0,
                        created_at: codex_state_timestamp(row.get(6)?, row.get(4)?),
                        updated_at: codex_state_timestamp(row.get(7)?, row.get(5)?),
                        model: row.get(8)?,
                        rollout_path: row.get(9)?,
                        ..Default::default()
                    }),
                ))
            })() {
                Ok(value) => threads.push(value),
                Err(error) => {
                    statuses[1] = Err(anyhow::Error::new(error).context(LoaderStage::Row))
                }
            }
        }
        if statuses[2].is_ok() && row.get::<_, i64>(12)? != 0 {
            match (|| -> rusqlite::Result<_> { Ok((row.get(0)?, row.get(13)?)) })() {
                Ok(value) => created.push(value),
                Err(error) => {
                    statuses[2] = Err(anyhow::Error::new(error).context(LoaderStage::Row))
                }
            }
        }
    }
    let [title, thread, create] = statuses;
    Ok((
        title.map(|_| titles),
        thread.map(|_| threads),
        create.map(|_| created),
    ))
}

crate::heap_layout_bound::fields!(RawRows; titles, threads, created, edges, edges_complete, history, index, evidence);
