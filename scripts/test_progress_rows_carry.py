#!/usr/bin/env python3
"""Linux CI-only carry check for upload progress rows (writer capability 6).

1. This branch writes a published route whose store holds progress rows.
2. The v0.1.234 source, with only the probe below appended, opens that route:
   it must refuse the store as newer (Hold::NewerSchema) before any pass, so it
   uploads nothing, and every row of every store table stays as it was (page
   and WAL file churn from opening the store is reported, not asserted).
3. This branch opens the route again and reads exactly the rows it wrote.

The signed v0.1.234 release is macOS-only; this builds the same tag's source.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

OLD_TAG = "v0.1.234"
PROBE = r'''
#[cfg(test)]
mod progress_rows_carry_probe {
    use super::*;
    use sha2::Digest;
    use std::collections::{BTreeMap, BTreeSet};

    /// Every row of every table of the store, as values: page and WAL churn
    /// is not a write, a changed row is.
    fn rows(path: &Path) -> BTreeMap<String, BTreeSet<String>> {
        let db = PathBuf::from(format!("{}.v2.sqlite", path.display()));
        let conn = rusqlite::Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .map(|name| name.unwrap())
            .collect();
        let mut out = BTreeMap::new();
        for table in tables {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let columns = stmt.column_count();
            let rows = stmt
                .query_map([], |row| {
                    let mut text = String::new();
                    for n in 0..columns {
                        let value: rusqlite::types::Value = row.get(n)?;
                        text.push_str(&format!("{value:?}|"));
                    }
                    Ok(text)
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            out.insert(table, rows);
        }
        out
    }

    /// Every store file but the shared-memory index and the lock, by content.
    fn files(path: &Path) -> Vec<(String, String)> {
        let mut files = Vec::new();
        for entry in fs::read_dir(path.parent().unwrap()).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            if entry.path().is_dir() || name.ends_with("-shm") || name.ends_with(".lock") {
                continue;
            }
            let bytes = fs::read(entry.path()).unwrap();
            files.push((name, crate::hex::encode(&sha2::Sha256::digest(&bytes))));
        }
        files.sort();
        files
    }

    #[test]
    fn newer_writer_is_refused() {
        let root = PathBuf::from(std::env::var_os("OTTTO_PROGRESS_CARRY_DIR").unwrap());
        let path = PathBuf::from(fs::read_to_string(root.join("index-path.txt")).unwrap());
        let before = files(&path);
        assert!(before.iter().any(|(name, _)| name.ends_with(".v2.sqlite")));
        let rows_before = rows(&path);
        let opened = {
            let _lock = crate::snapshots::CheckpointLock::acquire(&path).unwrap();
            load_locked(&path, false, published(&path).unwrap())
        };
        let error = match opened {
            Ok(_) => panic!("an older writer opened a capability-6 store"),
            Err(error) => error,
        };
        assert!(
            error.chain().any(|e| e.downcast_ref::<Hold>() == Some(&Hold::NewerSchema))
                || format!("{error:#}").contains("state_v2_newer_schema_refused"),
            "{error:#}"
        );
        let rows_after = rows(&path);
        let mut changed = Vec::new();
        for table in rows_before.keys().chain(rows_after.keys()).collect::<BTreeSet<_>>() {
            let (old, new) = (rows_before.get(table), rows_after.get(table));
            let empty = BTreeSet::new();
            let (old, new) = (old.unwrap_or(&empty), new.unwrap_or(&empty));
            for row in old.symmetric_difference(new) {
                let side = if old.contains(row) { "-" } else { "+" };
                changed.push(format!("{table} {side} {}", &row[..row.len().min(240)]));
            }
        }
        println!("PROGRESS_CARRY_FILES before={before:?} after={:?}", files(&path));
        assert!(changed.is_empty(), "the refused open changed rows:\n{}", changed.join("\n"));
        println!("PROGRESS_CARRY_REFUSED");
    }
}
'''


def run(args, **kwargs):
    result = subprocess.run(args, check=False, text=True, **kwargs)
    if result.returncode and result.stdout is not None:
        print(result.stdout, flush=True)
    result.check_returncode()
    return result


def one_test(tree, name, env, marker, ignored):
    args = ["cargo", "test", "-p", "ottto-service", "--lib", "--locked", name,
            "--", "--nocapture", "--test-threads=1"]
    if ignored:
        args.append("--ignored")
    result = run(args, cwd=tree, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, flush=True)
    if not re.search(r"test result: ok\. 1 passed; 0 failed;", result.stdout):
        raise RuntimeError(f"{name} did not execute exactly once")
    if marker not in result.stdout:
        raise RuntimeError(f"{name}: marker {marker} missing")


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise SystemExit("CI Linux only; do not execute on a developer machine")
    repo = Path(__file__).resolve().parents[1]
    temp = os.environ.get("TMPDIR") or os.environ["RUNNER_TEMP"]
    with tempfile.TemporaryDirectory(prefix="progress-rows-carry-", dir=temp) as tmp:
        root = Path(tmp).resolve()
        fixtures = root / "fixtures"
        fixtures.mkdir(mode=0o700)
        env = dict(os.environ, OTTTO_PROGRESS_CARRY_DIR=str(fixtures))
        one_test(repo, "write_progress_rows_carry_fixture", env,
                 "PROGRESS_CARRY_FIXTURE_WRITTEN", True)

        run(["git", "fetch", "--no-tags", "--depth=1", "origin",
             f"refs/tags/{OLD_TAG}:refs/tags/{OLD_TAG}"], cwd=repo)
        old = root / "old"
        old.mkdir()
        archive = root / "old.tar"
        run(["git", "archive", "--format=tar", "--output=" + str(archive), OLD_TAG], cwd=repo)
        run(["tar", "-xf", str(archive), "-C", str(old)])
        migrations = old / "crates/ottto-service/src/snapshots/state_v2/sqlite/migrations.rs"
        if re.search(r"\(\s*6,", migrations.read_text()):
            raise RuntimeError(f"{OLD_TAG} already knows capability 6")
        runtime = old / "crates/ottto-service/src/snapshots/state_v2/runtime.rs"
        runtime.write_text(runtime.read_text() + PROBE)
        old_env = dict(env, CARGO_TARGET_DIR=str(root / "old-target"))
        one_test(old, "progress_rows_carry_probe::newer_writer_is_refused", old_env,
                 "PROGRESS_CARRY_REFUSED", False)

        one_test(repo, "verify_progress_rows_carry_reupgrade", env,
                 "PROGRESS_CARRY_REUPGRADE_VERIFIED", True)
        print(json.dumps({"status": "VERIFIED", "old": OLD_TAG,
                          "checks": ["newer_writer_refused", "zero_uploads_before_any_pass",
                                     "store_rows_unchanged", "reupgrade_equals_no_downgrade"]}))


if __name__ == "__main__":
    main()
