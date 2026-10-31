#!/usr/bin/env python3
"""Linux CI-only synthetic branch writer -> pinned old loaders -> branch reader.

Run after ordinary Linux contracts, before merge. No workflow is dispatched here.
Old decoders are compiled from their actual source, with only this test appended.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


STABLE = "7997fe740064273ffc145d2168c299f5d8b9ee3d"
PROBE = r'''
#[cfg(test)]
mod codex_zst_downgrade_probe {
    use super::*;
    #[test]
    fn loads_branch_written_index() {
        let root = PathBuf::from(std::env::var_os("OTTTO_ZST_DOWNGRADE_FIXTURE_DIR").unwrap());
        let path = root.join("branch.json");
        let original = fs::read(&path).unwrap();
        let (decoded, origin) = ScanIndex::load_inner(&path, None).unwrap();
        assert!(matches!(origin, LoadOrigin::Loaded(_)), "no reset/quarantine");
        assert_eq!(decoded.files.len(), 2);
        let mut decoded = ScanIndex::load(&path).unwrap();
        let control = ScanIndex::load(&root.join("as-today.json")).unwrap();
        assert_eq!(serde_json::to_value(&decoded.files).unwrap(), serde_json::to_value(&control.files).unwrap());
        assert_eq!(decoded.file_snapshot_fingerprints, control.file_snapshot_fingerprints);
        assert!(!decoded.file_snapshot_fingerprints.is_empty());
        assert_eq!(decoded.accepted_snapshot_fingerprints, control.accepted_snapshot_fingerprints);
        for entry in decoded.files.values() {
            assert_eq!(entry.scan_identity_version.as_deref(), Some(LOCAL_SCAN_INDEX_IDENTITY_VERSION));
        }
        assert_eq!(fs::read(&path).unwrap(), original);
        let label = std::env::var("OTTTO_ZST_OLD_DECODER").unwrap();
        let saved_path = root.join(format!("{label}.json"));
        // The old writer's CAS requires an existing same-generation checkpoint.
        fs::write(&saved_path, &original).unwrap();
        decoded.save(&saved_path).unwrap();
        println!("ZST_OLD_DECODER_VERIFIED {label}");
        let activation = ScanIndex::load(&root.join("activation.json")).unwrap();
        let key = fs::read_to_string(root.join("activation-key.txt")).unwrap();
        assert_eq!(activation.files.len(), 1);
        assert!(!activation.files[&key].codex_history_is_protected());
        let mut scan = OwnedSourceScan::new(SnapshotSource::Codex,
            &[root.join("activation/sessions")], activation,
            "2026-10-06T23:00:00Z", 7, 10, false, None, &[], false, false);
        let mut saved = false;
        for _ in 0..10000 {
            match scan.step(None) {
                OwnedSourceScanStep::Pending(next) => scan = next,
                OwnedSourceScanStep::Complete { mut index, scan: result, .. } => {
                    assert!(result.census_complete);
                    assert!(!index.files.contains_key(&key), "old census retires unprotected archive");
                    assert!(!index.file_snapshot_fingerprints.contains_key(&key));
                    assert!(!index.accepted_snapshot_fingerprints.is_empty());
                    let saved_path = root.join(format!("{label}-census.json"));
                    fs::copy(root.join("activation.json"), &saved_path).unwrap();
                    index.save(&saved_path).unwrap();
                    saved = true;
                    break;
                }
            }
        }
        assert!(saved, "historical census/save completed");
    }
}
'''


def run(args, **kwargs):
    result = subprocess.run(args, check=False, text=True, **kwargs)
    if result.returncode and result.stdout is not None:
        print(result.stdout, flush=True)
    result.check_returncode()
    return result


def fixture_test(tree, name, env, marker=None):
    result = run(["cargo", "test", "-p", "ottto-service", "--lib", "--locked",
                  name, "--", "--nocapture", "--test-threads=1"], cwd=tree, env=env,
                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout, flush=True)
    if not re.search(r"test result: ok\. 1 passed; 0 failed; 0 ignored;", result.stdout):
        raise RuntimeError("fixture did not execute exactly once")
    if marker and marker not in result.stdout:
        raise RuntimeError("old-loader verification marker missing")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--r1", required=True, help="exact current R1/main commit (before #866)")
    args = parser.parse_args()
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise SystemExit("CI Linux only; do not execute on a developer machine")
    if not re.fullmatch(r"[0-9a-f]{40}", args.r1):
        raise SystemExit("--r1 must be a full commit SHA")
    repo = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="zst-downgrade-", dir=os.environ["RUNNER_TEMP"]) as tmp:
        root = Path(tmp)
        env = dict(os.environ, OTTTO_ZST_DOWNGRADE_FIXTURE_DIR=str(root / "fixtures"))
        fixture_test(repo, "codex_compressed_hold_tests::write_codex_zst_downgrade_fixture", env)
        for label, sha in [("stable", STABLE), ("r1", args.r1)]:
            if subprocess.run(["git", "cat-file", "-e", sha + "^{commit}"], cwd=repo).returncode:
                run(["git", "fetch", "--no-tags", "origin", sha], cwd=repo)
            tree = root / label
            tree.mkdir()
            archive = root / (label + ".tar")
            run(["git", "archive", "--format=tar", "--output=" + str(archive), sha], cwd=repo)
            run(["tar", "-xf", str(archive), "-C", str(tree)])
            source = tree / "crates/ottto-service/src/snapshots.rs"
            text = source.read_text()
            # Fail if the chosen R1 already knows these fields: that requires a
            # new label/membership contract, not silently weaker comparisons.
            entry = text.split("pub struct ScanIndexEntry {", 1)[1].split("\n}", 1)[0]
            if "codex_compressed_hold" in entry or "archive:" in entry:
                raise RuntimeError("old decoder now knows custody/archive; requalify labels")
            source.write_text(text + PROBE)
            old_env = dict(env, OTTTO_ZST_OLD_DECODER=label,
                           CARGO_TARGET_DIR=str(root / (label + "-target")))
            fixture_test(tree, "codex_zst_downgrade_probe::loads_branch_written_index", old_env,
                         "ZST_OLD_DECODER_VERIFIED " + label)
        fixture_test(repo, "codex_compressed_hold_tests::verify_codex_zst_downgrade_roundtrip", env)
        fixture_test(repo, "codex_compressed_hold_tests::historical_census_saved_singleton_schedules_a1_on_reupgrade", env)
        print(json.dumps({"status": "VERIFIED", "stable": STABLE, "r1": args.r1}))


if __name__ == "__main__":
    main()
