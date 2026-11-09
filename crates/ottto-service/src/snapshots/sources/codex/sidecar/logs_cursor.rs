//! Logs-only cursors. Retained ids include LIKE matches without a priority turn.
use super::*;
use crate::codex_scan_diagnostics::LoaderEvidence;
use crate::heap_layout_bound::{Counter, HeapLayoutBound};

pub(in crate::snapshots) struct LogCursor {
    stamp: SourceStamp,
    watermark: i64,
    since: i64,
    complete: bool,
    rows: BTreeMap<i64, (i64, Option<String>)>,
}
impl HeapLayoutBound for LogCursor {
    fn heap_bound(&self, c: &mut Counter) -> Option<()> {
        if let SourceStamp::Sqlite { target, .. } = &self.stamp {
            c.add(target.capacity())?;
        }
        self.rows.heap_bound(c)
    }
    fn completed_heap_bound(&self, c: &mut Counter) -> Option<()> {
        if let SourceStamp::Sqlite { target, .. } = &self.stamp {
            c.add(target.capacity())?;
        }
        self.rows.completed_heap_bound(c)
    }
}

pub(super) fn load(
    roots: &[PathBuf],
    since: i64,
    facts: &mut SidecarFacts,
) -> (CodexTurnTraceMap, LoaderEvidence) {
    let paths = roots
        .iter()
        .filter_map(|root| root.parent())
        .flat_map(|home| {
            [
                home.join("logs_2.sqlite"),
                home.join("sqlite/logs_2.sqlite"),
            ]
        })
        .collect::<BTreeSet<_>>();
    facts.logs.retain(|path, _| paths.contains(path));
    let mut map = CodexTurnTraceMap {
        since_epoch: since,
        ..Default::default()
    };
    let mut evidence = LoaderEvidence::default();
    for path in paths {
        let previous = facts.logs.remove(&path);
        let stamp = SourceStamp::capture_sqlite(&path);
        if matches!(stamp, Some(SourceStamp::Absent)) {
            evidence.absent_roots = evidence.absent_roots.saturating_add(1);
            evidence.completed_roots = evidence.completed_roots.saturating_add(1);
            continue;
        }
        let result = stamp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("noncacheable logs"))
            .and_then(|before| read(&path, before, previous, since));
        match result {
            Ok((turns, cursor, reused, delta)) => {
                let complete = cursor.complete;
                map.priority_turns.extend(turns);
                map.incomplete |= !complete;
                evidence.reused_roots = evidence.reused_roots.saturating_add(u32::from(reused));
                evidence.reloaded_roots =
                    evidence.reloaded_roots.saturating_add(u32::from(!reused));
                evidence.delta_rows = evidence.delta_rows.saturating_add(delta);
                if complete {
                    evidence.completed_roots = evidence.completed_roots.saturating_add(1);
                } else {
                    evidence.failed_roots = evidence.failed_roots.saturating_add(1);
                }
                facts.logs.insert(path, cursor);
            }
            Err(_) => {
                // A capture or incremental failure cannot downgrade a fresh
                // read that today's loader can still complete.
                let (complete, rows) =
                    load_codex_logs2_priority_turns_counted(&path, since, &mut map.priority_turns);
                evidence.delta_rows = evidence.delta_rows.saturating_add(rows);
                map.incomplete |= !complete;
                evidence.reloaded_roots = evidence.reloaded_roots.saturating_add(1);
                if complete {
                    evidence.completed_roots = evidence.completed_roots.saturating_add(1);
                } else {
                    evidence.failed_roots = evidence.failed_roots.saturating_add(1);
                }
            }
        }
    }
    facts.charge_heap();
    (map, evidence)
}

fn same_object(a: &SourceStamp, b: &SourceStamp) -> bool {
    matches!((a, b), (SourceStamp::Sqlite { target: a, main: am, .. }, SourceStamp::Sqlite { target: b, main: bm, .. }) if a == b && am.same_object(bm))
}

type ReadResult = (BTreeSet<String>, LogCursor, bool, u64);
fn read(
    path: &Path,
    before: &SourceStamp,
    previous: Option<LogCursor>,
    since: i64,
) -> Result<ReadResult> {
    let read = codex_sqlite_read::CodexSqliteRead::open_stamped(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY,
        std::time::Duration::from_millis(CODEX_LOGS2_BUSY_TIMEOUT_MS),
        Some(before),
    )?;
    let (rows, watermark, complete, reused, delta) = read.read(|db| {
        let tx = db.unchecked_transaction()?;
        let watermark: i64 = tx.query_row("SELECT coalesce(max(id), 0) FROM logs", [], |row| {
            row.get(0)
        })?;
        let previous = previous.filter(|old| {
            old.complete
                && same_object(before, &old.stamp)
                && watermark >= old.watermark
                && since >= old.since
        });
        let reused = previous.is_some();
        let old_watermark = previous.as_ref().map_or(0, |old| old.watermark);
        let mut kept = previous.map_or_else(BTreeMap::new, |old| old.rows);
        kept.retain(|_, (ts, _)| *ts >= since);
        // Every kept id is checked in the same snapshot as max/delta. Chunking
        // only respects SQLite's bound-parameter limit; it drops no ids/facts.
        let ids = kept.keys().copied().collect::<Vec<_>>();
        for chunk in ids.chunks(900) {
            let sql = format!(
                "SELECT id FROM logs WHERE id IN ({})",
                vec!["?"; chunk.len()].join(",")
            );
            let mut statement = tx.prepare(&sql)?;
            let surviving = statement
                .query_map(rusqlite::params_from_iter(chunk), |row| {
                    row.get::<_, i64>(0)
                })?
                .collect::<rusqlite::Result<BTreeSet<_>>>()?;
            for id in chunk {
                if !surviving.contains(id) {
                    kept.remove(id);
                }
            }
        }
        let (mut complete, delta) = read_codex_logs2_priority_turns(
            &tx,
            since,
            Some(old_watermark),
            ", id, ts",
            |row, turn| {
                kept.insert(row.get(1)?, (row.get(2)?, turn));
                Ok(kept.len() < CODEX_LOGS2_MAX_ROWS as usize)
            },
        )?;
        if !complete {
            anyhow::bail!("incomplete logs delta");
        }
        if kept.len() >= CODEX_LOGS2_MAX_ROWS as usize {
            // This is today's ts-DESC LIMIT loader, not a retained-row quota:
            // use exactly its result/incomplete flag and restart from that
            // fresh result. There is no additional cap or discarded fact.
            kept.clear();
            (complete, _) =
                read_codex_logs2_priority_turns(&tx, since, None, ", id, ts", |row, turn| {
                    kept.insert(row.get(1)?, (row.get(2)?, turn));
                    Ok(true)
                })?;
        }
        tx.commit()?;
        Ok((kept, watermark, complete, reused, delta))
    })?;
    let stamp = read
        .after_stamp()
        .ok_or_else(|| anyhow::anyhow!("unstable logs acquisition"))?;
    let turns = rows.values().filter_map(|(_, turn)| turn.clone()).collect();
    Ok((
        turns,
        LogCursor {
            stamp,
            watermark,
            since,
            complete,
            rows,
        },
        reused,
        delta,
    ))
}
