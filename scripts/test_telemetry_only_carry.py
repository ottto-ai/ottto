#!/usr/bin/env python3
"""Run the pinned prior source's real progress owner on a synthetic CI store."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PINS = {
    "v0.1.239": "4157e768d0a45046a0225e2d61f2ac8cf65c50be",
    "v0.1.244": "b10c4e9d2acd649dbd09e901000e1f44f891a641",
}
PROBE = r'''
#[cfg(test)]
mod telemetry_only_previous_release_probe {
    use super::*;
    #[test]
    fn hydrate_save_drop() {
        let path = PathBuf::from(std::env::var_os("OTTTO_OTEL_CARRY_INDEX").unwrap());
        let index = ScanIndex::load(&path).unwrap();
        let progress_path = snapshot_upload_progress_path(&path);
        let namespace = format!("{:064x}",99);
        let witness = snapshot_quarantine_witness(SnapshotSource::ClaudeCode);
        let mut progress = SnapshotUploadProgress::load_for_index(&index,&path,&progress_path,&namespace,witness.clone()).unwrap();
        progress.accepted_identity_buckets.bind_test_key(Some([0x42;32]));
        progress.load_identity(["1338a80a-f36e-4cbc-a5bb-50fc66430ba5"]).unwrap();
        assert!(!progress.accepted_fingerprints.is_empty());
        assert!(!progress.accepted_cache_states.is_empty());
        assert!(!progress.accepted_cache_heads.is_empty());
        assert!(progress.accepted_identity_buckets.get("1338a80a-f36e-4cbc-a5bb-50fc66430ba5").is_some());
        let before = (progress.accepted_body_witnesses.clone(),progress.accepted_cache_states.clone(),
            progress.accepted_cache_heads.clone(),serde_json::to_value(&progress.accepted_identity_buckets).unwrap());
        progress.save(&progress_path).unwrap();
        drop(progress);
        let mut progress = SnapshotUploadProgress::load_for_index(&index,&path,&progress_path,&namespace,witness).unwrap();
        progress.accepted_identity_buckets.bind_test_key(Some([0x42;32]));
        progress.load_identity(["1338a80a-f36e-4cbc-a5bb-50fc66430ba5"]).unwrap();
        assert_eq!(before,(progress.accepted_body_witnesses.clone(),progress.accepted_cache_states.clone(),
            progress.accepted_cache_heads.clone(),serde_json::to_value(&progress.accepted_identity_buckets).unwrap()));
        let owner = SnapshotProgressLock::acquire(&progress_path).unwrap().for_v2(&progress_path);
        let (ledger,generation) = crate::snapshots::read_progress_ledger(&path,&owner).unwrap();
        assert!(generation>0);
        assert!(ledger.unwrap().get("telemetry_only").is_none());
        std::fs::write(path.with_extension("old-verified"),b"TELEMETRY_ONLY_OLD_SAVE_VERIFIED").unwrap();
        println!("TELEMETRY_ONLY_OLD_SAVE_VERIFIED");
    }
}
'''


def main():
    if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_OS") != "Linux":
        raise SystemExit("CI Linux only")
    tag, index = sys.argv[1:]
    pin = PINS[tag]
    repo = Path(__file__).resolve().parents[1]
    def run(args, **kwargs):
        return subprocess.run(args, cwd=repo, check=True, **kwargs)
    run(["git", "fetch", "--no-tags", "--depth=1", "origin", f"refs/tags/{tag}:refs/tags/{tag}"])
    observed = subprocess.check_output(["git", "rev-parse", f"{tag}^{{commit}}"], cwd=repo, text=True).strip()
    assert observed == pin, (tag, observed)
    with tempfile.TemporaryDirectory(prefix="otel-old-source-", dir=os.environ.get("RUNNER_TEMP")) as temp:
        tree = Path(temp)
        archive = tree / "source.tar"
        run(["git", "archive", "--format=tar", f"--output={archive}", pin])
        run(["tar", "-xf", str(archive), "-C", str(tree)])
        with (tree / "crates/ottto-service/src/snapshot_sync.rs").open("a") as stream:
            stream.write(PROBE)
        env = dict(os.environ, OTTTO_OTEL_CARRY_INDEX=index, CARGO_TARGET_DIR=str(tree / "old-target"))
        marker = Path(index).with_suffix(".old-verified")
        marker.unlink(missing_ok=True)
        result = subprocess.run(["cargo", "test", "--locked", "-p", "ottto-service", "--lib", "-j", "2",
            "telemetry_only_previous_release_probe::hydrate_save_drop", "--", "--nocapture", "--test-threads=1"],
            cwd=tree, env=env, timeout=1200, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        log = Path(index).with_suffix(f".{tag}.log")
        log.write_text(result.stdout)
        if result.returncode:
            print(f"old source failed: {log}", flush=True)
            for line in result.stdout.splitlines()[-60:]: print("old-source: " + line, flush=True)
        result.check_returncode()
        assert marker.read_bytes() == b"TELEMETRY_ONLY_OLD_SAVE_VERIFIED"
        print(f"{tag} {pin}: TELEMETRY_ONLY_OLD_SAVE_VERIFIED", flush=True)


if __name__ == "__main__":
    main()
