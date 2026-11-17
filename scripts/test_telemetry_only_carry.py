#!/usr/bin/env python3
"""Verify pinned prior sources refuse the current layout without changing custody."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile

PINS = {
    "v0.1.239": "4157e768d0a45046a0225e2d61f2ac8cf65c50be",
    "v0.1.244": "b10c4e9d2acd649dbd09e901000e1f44f891a641",
    "v0.1.256": "be32ecee30407cd66cacf193248446fd29d5a1be",
}
PROBE = r'''
#[cfg(test)]
mod telemetry_only_previous_release_probe {
    use super::*;
    fn rows(path: &Path) -> BTreeMap<String, BTreeSet<String>> {
        let db = PathBuf::from(format!("{}.v2.sqlite", path.display()));
        let conn = rusqlite::Connection::open_with_flags(
            &db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        ).unwrap();
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
            .unwrap().query_map([], |row| row.get(0)).unwrap()
            .map(|name| name.unwrap()).collect();
        let mut out = BTreeMap::new();
        for table in tables {
            let mut stmt = conn.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let columns = stmt.column_count();
            let rows = stmt.query_map([], |row| {
                let mut text = String::new();
                for n in 0..columns {
                    let value: rusqlite::types::Value = row.get(n)?;
                    text.push_str(&format!("{value:?}|"));
                }
                Ok(text)
            }).unwrap().map(|row| row.unwrap()).collect();
            out.insert(table, rows);
        }
        out
    }
    #[test]
    fn refuse_new_layout() {
        let path = PathBuf::from(std::env::var_os("OTTTO_OTEL_CARRY_INDEX").unwrap());
        let before = rows(&path);
        let error = match ScanIndex::load(&path) {
            Ok(_) => panic!("older reader opened a newer catalogue layout"),
            Err(error) => error,
        };
        assert!(format!("{error:#}").contains("scan_index_representation_refused"), "{error:#}");
        assert_eq!(before, rows(&path), "refused open changed stored rows");
        std::fs::write(path.with_extension("old-verified"),b"TELEMETRY_ONLY_OLD_LAYOUT_REFUSED").unwrap();
        println!("TELEMETRY_ONLY_OLD_LAYOUT_REFUSED");
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
            "telemetry_only_previous_release_probe::refuse_new_layout", "--", "--nocapture", "--test-threads=1"],
            cwd=tree, env=env, timeout=1200, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        log = Path(index).with_suffix(f".{tag}.log")
        log.write_text(result.stdout)
        if result.returncode:
            print(f"old source failed: {log}", flush=True)
            for line in result.stdout.splitlines()[-60:]: print("old-source: " + line, flush=True)
        result.check_returncode()
        assert marker.read_bytes() == b"TELEMETRY_ONLY_OLD_LAYOUT_REFUSED"
        print(f"{tag} {pin}: TELEMETRY_ONLY_OLD_LAYOUT_REFUSED", flush=True)


if __name__ == "__main__":
    main()
