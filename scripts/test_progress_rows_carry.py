#!/usr/bin/env python3
"""Linux CI-only carry check for upload progress rows (writer capability 6).

1. This branch writes a published route whose store holds progress rows.
2. The v0.1.234 source, with only the probe below appended, opens that route:
   it must refuse the store as newer (Hold::NewerSchema) before any pass, so it
   uploads nothing, and every store file except the SQLite shared-memory index
   stays byte-identical.
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
        let opened = {
            let _lock = super::super::CheckpointLock::acquire(&path).unwrap();
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
        assert_eq!(files(&path), before, "the refused open wrote nothing");
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
                                     "store_files_unchanged", "reupgrade_equals_no_downgrade"]}))


if __name__ == "__main__":
    main()
