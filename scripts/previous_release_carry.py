#!/usr/bin/env python3
"""Linux CI-only carry check against the previous release's source.

The checked-out tree (the target) writes two synthetic stores:
  1. a published route whose store holds upload progress rows, and
  2. a telemetry-only route with its accepted custody.
The previous release is then built from its own source, with only the two
probes below appended. It must refuse each store as newer (a writer capability
or representation it does not know) and leave every row of every store table
as it was. Finally the target opens both stores again and reads exactly what
it wrote: re-upgrade equals no downgrade.

The previous release is a commit of this repository, given by full SHA; its
signed build is macOS-only, so this builds the same commit's source.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

PROGRESS_PROBE = r'''
#[cfg(test)]
mod previous_release_carry_probe_progress {
    use super::*;
    use sha2::Digest;
    use std::collections::{BTreeMap, BTreeSet};
    use std::fs;
    use std::path::{Path, PathBuf};

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
            Ok(_) => panic!("the previous release opened a newer writer's store"),
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
            let empty = BTreeSet::new();
            let old = rows_before.get(table).unwrap_or(&empty);
            let new = rows_after.get(table).unwrap_or(&empty);
            for row in old.symmetric_difference(new) {
                let side = if old.contains(row) { "-" } else { "+" };
                changed.push(format!("{table} {side} {}", &row[..row.len().min(240)]));
            }
        }
        println!("PROGRESS_CARRY_FILES before={before:?} after={:?}", files(&path));
        assert!(changed.is_empty(), "the refused open changed rows:\n{}", changed.join("\n"));
        println!("PREVIOUS_RELEASE_PROGRESS_REFUSED");
    }
}
'''

TELEMETRY_PROBE = r'''
#[cfg(test)]
mod previous_release_carry_probe_telemetry {
    use crate::snapshots::ScanIndex;
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Path, PathBuf};

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

    #[test]
    fn newer_store_is_refused() {
        let path = PathBuf::from(std::env::var_os("OTTTO_OTEL_CARRY_INDEX").unwrap());
        let before = rows(&path);
        let error = match ScanIndex::load(&path) {
            Ok(_) => panic!("the previous release opened a newer telemetry-only store"),
            Err(error) => error,
        };
        assert!(
            error.chain().any(|cause| matches!(
                cause.to_string().as_str(),
                "state_v2_newer_schema_refused" | "scan_index_representation_refused"
            )),
            "{error:#}"
        );
        assert_eq!(before, rows(&path), "the refused open changed stored rows");
        println!("PREVIOUS_RELEASE_TELEMETRY_REFUSED");
    }
}
'''

CAPABILITY = re.compile(r"\(\s*(\d+),")
LAYOUT = re.compile(r"\(\s*(\d+|[A-Z_]+_LAYOUT),")


def run(args, **kwargs):
    result = subprocess.run(args, check=False, text=True, **kwargs)
    if result.returncode and result.stdout is not None:
        print(result.stdout, flush=True)
    result.check_returncode()
    return result


def cargo_test(tree, name, env, markers, count=1, ignored=False):
    args = ["cargo", "test", "-p", "ottto-service", "--lib", "--locked", name,
            "--", "--nocapture", "--test-threads=1"]
    if ignored:
        args.append("--ignored")
    result = run(args, cwd=tree, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, flush=True)
    if not re.search(rf"test result: ok\. {count} passed; 0 failed;", result.stdout):
        raise RuntimeError(f"{name}: expected exactly {count} test(s) to run and pass")
    for marker in markers:
        if marker not in result.stdout:
            raise RuntimeError(f"{name}: marker {marker} missing")


def history_max(text, start, pattern):
    """Highest entry of a `(n, "...")` history array that begins at `start`."""
    body = text.split(start, 1)[1].split("\n];", 1)[0]
    return max(int(n) for n in pattern.findall(body) if n.isdigit())


def barriers(tree):
    state = tree / "crates/ottto-service/src/snapshots/state_v2"
    capability = history_max((state / "sqlite/migrations.rs").read_text(),
                             "WRITER_CAPABILITIES_HISTORY: &[", CAPABILITY)
    catalogue = (state / "catalogue.rs").read_text()
    named = dict(re.findall(r"const ([A-Z_]+_LAYOUT): u32 = (\d+);", catalogue))
    body = catalogue.split("LAYOUTS_HISTORY: &[", 1)[1].split("\n];", 1)[0]
    layouts = [int(named.get(n, n)) for n in LAYOUT.findall(body)
               if n.isdigit() or n in named]
    return capability, max(layouts)


def channel(tree):
    found = re.search(r'^channel = "(.*)"$', (tree / "rust-toolchain.toml").read_text(), re.M)
    if not found:
        raise RuntimeError("no channel in rust-toolchain.toml")
    return found.group(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--previous", required=True,
                        help="full SHA of the previous release's source commit")
    parser.add_argument("--tree", default=".", help="the target tree (default: cwd)")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise SystemExit("CI Linux only; do not execute on a developer machine")
    if not re.fullmatch(r"[0-9a-f]{40}", args.previous):
        raise SystemExit("--previous must be a full commit SHA")
    repo = Path(args.tree).resolve()
    temp = os.environ.get("TMPDIR") or os.environ["RUNNER_TEMP"]
    with tempfile.TemporaryDirectory(prefix="previous-release-carry-", dir=temp) as tmp:
        root = Path(tmp).resolve()
        progress = root / "progress"
        telemetry = root / "telemetry"
        progress.mkdir(mode=0o700)
        telemetry.mkdir(mode=0o700)
        env = dict(os.environ, OTTTO_PROGRESS_CARRY_DIR=str(progress),
                   OTTTO_OTEL_CARRY_ROOT=str(telemetry))

        # The previous release's source, with only the probes appended.
        if subprocess.run(["git", "cat-file", "-e", args.previous + "^{commit}"],
                          cwd=repo).returncode:
            run(["git", "fetch", "--no-tags", "origin", args.previous], cwd=repo)
        old = root / "old"
        old.mkdir()
        archive = root / "old.tar"
        run(["git", "archive", "--format=tar", "--output=" + str(archive), args.previous],
            cwd=repo)
        run(["tar", "-xf", str(archive), "-C", str(old)])
        archive.unlink()
        new_barriers, old_barriers = barriers(repo), barriers(old)
        print(f"writer capability, catalogue layout: previous={old_barriers} "
              f"target={new_barriers}", flush=True)
        if new_barriers[0] <= old_barriers[0]:
            raise RuntimeError("the target raises no writer capability over the previous "
                               "release; this check would not exercise a refusal")

        # 1. The target writes both stores.
        cargo_test(repo, "write_progress_rows_carry_fixture", env,
                   ["PROGRESS_CARRY_FIXTURE_WRITTEN"], ignored=True)
        child = "telemetry_only_oracle_tests::telemetry_only_carry_child"
        for stage in ("write", "checkpoint"):
            cargo_test(repo, child, dict(env, OTTTO_OTEL_CARRY_STAGE=stage), [])
        index_path, _, _ = json.loads((telemetry / "manifest.json").read_text())

        # 2. The previous release refuses both, changing no row.
        runtime = old / "crates/ottto-service/src/snapshots/state_v2/runtime.rs"
        runtime.write_text(runtime.read_text() + PROGRESS_PROBE)
        sync = old / "crates/ottto-service/src/snapshot_sync.rs"
        sync.write_text(sync.read_text() + TELEMETRY_PROBE)
        old_channel = channel(old)
        if old_channel != channel(repo):
            run(["rustup", "toolchain", "install", old_channel, "--profile", "minimal"])
        old_target = root / "old-target"
        old_env = dict(env, OTTTO_OTEL_CARRY_INDEX=index_path,
                       CARGO_TARGET_DIR=str(old_target), RUSTUP_TOOLCHAIN=old_channel)
        cargo_test(old, "previous_release_carry_probe_", old_env,
                   ["PREVIOUS_RELEASE_PROGRESS_REFUSED", "PREVIOUS_RELEASE_TELEMETRY_REFUSED"],
                   count=2)
        shutil.rmtree(old_target)

        # 3. The target reads back exactly what it wrote.
        cargo_test(repo, "verify_progress_rows_carry_reupgrade", env,
                   ["PROGRESS_CARRY_REUPGRADE_VERIFIED"], ignored=True)
        cargo_test(repo, child, dict(env, OTTTO_OTEL_CARRY_STAGE="verify"), [])
        print(json.dumps({
            "status": "VERIFIED",
            "previous": args.previous,
            "barriers": {"previous": old_barriers, "target": new_barriers},
            "checks": ["progress_store_refused_as_newer", "telemetry_store_refused_as_newer",
                       "refused_opens_changed_no_row", "reupgrade_equals_no_downgrade"],
        }))


if __name__ == "__main__":
    main()
