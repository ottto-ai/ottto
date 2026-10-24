#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_manifest.sh"
# shellcheck source=scripts/public_repo_temp_cleanup.sh
source "$ROOT/scripts/public_repo_temp_cleanup.sh"

umask 022
tmp_dir="$(mktemp -d)"
script_completed=0
cleanup_tmp_dir() {
  local status=$?
  # Bash 3.2 can report status 0 here after a nounset abort.
  if [[ "$status" -eq 0 && "${script_completed:-0}" -ne 1 ]]; then
    echo "test_public_repo_manifest: exited before completion" >&2
    status=1
  fi
  public_repo_remove_temp_dir "test_public_repo_manifest" "$tmp_dir" || true
  exit "$status"
}
trap cleanup_tmp_dir EXIT

configure_repo() {
  local repo="$1"
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Test"
  # Disposable fixture: keep background gc/maintenance out of .git while the
  # EXIT trap removes it.
  git -C "$repo" config gc.auto 0
  git -C "$repo" config gc.autoDetach false
  git -C "$repo" config maintenance.auto false
  git -C "$repo" config core.fsmonitor false
}

clone_repo() {
  git clone -q "$1" "$2"
  configure_repo "$2"
}

# Writes the manifest public_repo_export_bundle.sh would write for these files:
# the file-system view, with modes from stat().
write_fs_manifest() {
  python3 - "$1" "$2" <<'PY'
import hashlib
import json
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()
records = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root)
    if relative.parts[0] == ".git" or not path.is_file():
        continue
    rel = relative.as_posix()
    if rel == "PUBLIC_EXPORT_MANIFEST.json":
        continue
    mode = stat.S_IMODE(path.stat().st_mode)
    records.append(
        {
            "path": rel,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "size_bytes": path.stat().st_size,
            "mode": f"{mode:04o}",
            "executable": bool(mode & 0o111),
        }
    )
manifest = {
    "schema_version": 1,
    "generated_by": "public_repo_export_bundle.sh",
    "generated_at": "2026-10-24T00:00:00+00:00",
    "source_commit": "0123456789abcdef0123456789abcdef01234567",
    "candidate_file_count": len(records),
    "output_file_count": len(records) + 1,
    "public_roots": [],
    "rewrites_applied": {},
    "files": records,
    "content_sha256": hashlib.sha256(
        json.dumps(records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest(),
}
Path(sys.argv[2]).write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

json_field() {
  python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}

# expect_status <status> <output-file> <command...>
expect_status() {
  local expected="$1"
  local output="$2"
  shift 2
  local status=0
  "$@" >"$output" 2>&1 || status=$?
  if [[ "$status" -ne "$expected" ]]; then
    echo "Expected exit $expected, got $status: $*" >&2
    cat "$output" >&2
    exit 1
  fi
}

# Fixture: a 0644 file, a 0755 file, a nested file named like the root
# manifest (not excluded), and export roots with a comment.
fixture="$tmp_dir/fixture"
mkdir -p "$fixture/scripts" "$fixture/docs" "$fixture/public-export"
git -C "$fixture" init -q
configure_repo "$fixture"
printf '# Public Manifest Fixture\n' > "$fixture/README.md"
printf '#!/usr/bin/env bash\necho ok\n' > "$fixture/scripts/tool.sh"
chmod 0755 "$fixture/scripts/tool.sh"
printf '{"nested": true}\n' > "$fixture/docs/PUBLIC_EXPORT_MANIFEST.json"
printf '# Tracked public repository export roots.\nscripts/\nREADME.md\ndocs/\npublic-export/\n' \
  > "$fixture/public-export/roots.txt"
git -C "$fixture" add .
git -C "$fixture" commit -qm init
first_commit="$(git -C "$fixture" rev-parse HEAD)"
oracle="$tmp_dir/oracle.json"
write_fs_manifest "$fixture" "$oracle"
expected_digest="$(json_field "$oracle" content_sha256)"

digest="$("$SCRIPT" --repo "$fixture" --digest)"
if [[ "$digest" != "$expected_digest" ]]; then
  echo "Expected derived digest $expected_digest, got $digest" >&2
  exit 1
fi
"$SCRIPT" --repo "$fixture" --facts >"$tmp_dir/facts.json"
python3 - "$tmp_dir/facts.json" "$oracle" "$first_commit" <<'PY'
import json
import sys

facts = json.load(open(sys.argv[1], encoding="utf-8"))
oracle = json.load(open(sys.argv[2], encoding="utf-8"))
modes = {record["path"]: (record["mode"], record["executable"]) for record in oracle["files"]}
assert modes["README.md"] == ("0644", False), modes
assert modes["scripts/tool.sh"] == ("0755", True), modes
assert "docs/PUBLIC_EXPORT_MANIFEST.json" in modes, modes
assert facts["schema_version"] == 1
assert facts["derived_from"] == "git_tree"
assert facts["manifest_path"] == "PUBLIC_EXPORT_MANIFEST.json"
assert facts["source_commit"] == sys.argv[3]
assert facts["content_sha256"] == oracle["content_sha256"]
assert facts["file_record_count"] == 4
assert facts["candidate_file_count"] == 4
assert facts["output_file_count"] == 5
assert facts["public_roots"] == ["README.md", "docs/", "public-export/", "scripts/"]
assert facts["tracked_manifest"] == "absent"
PY
"$SCRIPT" --repo "$fixture" --compare "$oracle" >"$tmp_dir/compare.out"
grep -q "derived == $oracle at ${first_commit:0:12}: content_sha256=$expected_digest file_records=4 output_file_count=5" \
  "$tmp_dir/compare.out"
"$SCRIPT" --repo "$fixture" --guard >"$tmp_dir/guard-pass.out"
grep -q "PUBLIC_EXPORT_MANIFEST.json is derived, not tracked" "$tmp_dir/guard-pass.out"

# The executable bit is part of the record: dropping it changes the digest.
git -C "$fixture" update-index --chmod=-x scripts/tool.sh
git -C "$fixture" commit -qm "drop executable bit"
if [[ "$("$SCRIPT" --repo "$fixture" --digest)" == "$expected_digest" ]]; then
  echo "Expected the digest to change when scripts/tool.sh loses its executable bit" >&2
  exit 1
fi
expect_status 1 "$tmp_dir/compare-mode.out" "$SCRIPT" --repo "$fixture" --compare "$oracle"
grep -q "mode differs for scripts/tool.sh" "$tmp_dir/compare-mode.out"
if [[ "$("$SCRIPT" --repo "$fixture" --commit "$first_commit" --digest)" != "$expected_digest" ]]; then
  echo "Expected --commit to derive the manifest of an older commit" >&2
  exit 1
fi
expect_status 2 "$tmp_dir/missing-commit.out" "$SCRIPT" --repo "$fixture" --commit no-such-ref --digest
grep -q "commit not found: no-such-ref" "$tmp_dir/missing-commit.out"

# umask 002 checks files out as 0664/0775; the derived manifest stays 0644/0755
# while the file-system view drifts.
clone_umask="$tmp_dir/clone-umask-002"
(umask 002 && git clone -q "$fixture" "$clone_umask" && git -C "$clone_umask" checkout -q "$first_commit")
python3 - "$clone_umask" <<'PY'
import stat
import sys
from pathlib import Path

root = Path(sys.argv[1])
assert stat.S_IMODE((root / "README.md").stat().st_mode) == 0o664
assert stat.S_IMODE((root / "scripts/tool.sh").stat().st_mode) == 0o775
PY
if [[ "$("$SCRIPT" --repo "$clone_umask" --digest)" != "$expected_digest" ]]; then
  echo "Expected the derived digest not to depend on umask" >&2
  exit 1
fi
write_fs_manifest "$clone_umask" "$tmp_dir/umask-fs.json"
if [[ "$(json_field "$tmp_dir/umask-fs.json" content_sha256)" == "$expected_digest" ]]; then
  echo "Expected the umask 002 file-system manifest to differ from the derived one" >&2
  exit 1
fi

# A root PUBLIC_EXPORT_MANIFEST.json is excluded. Older commits that still
# track it must match the tree; the guard refuses it.
legacy="$tmp_dir/legacy"
clone_repo "$fixture" "$legacy"
git -C "$legacy" reset -q --hard "$first_commit"
cp "$oracle" "$legacy/PUBLIC_EXPORT_MANIFEST.json"
git -C "$legacy" add PUBLIC_EXPORT_MANIFEST.json
git -C "$legacy" commit -qm "legacy committed manifest"
legacy_commit="$(git -C "$legacy" rev-parse HEAD)"
if [[ "$("$SCRIPT" --repo "$legacy" --digest)" != "$expected_digest" ]]; then
  echo "Expected the root manifest to be excluded from the derived digest" >&2
  exit 1
fi
"$SCRIPT" --repo "$legacy" --facts >"$tmp_dir/legacy-facts.json"
if [[ "$(json_field "$tmp_dir/legacy-facts.json" tracked_manifest)" != "matches" ]]; then
  echo "Expected a matching legacy manifest to be reported as matches" >&2
  exit 1
fi
expect_status 1 "$tmp_dir/legacy-guard.out" "$SCRIPT" --repo "$legacy" --guard
grep -q "commit ${legacy_commit:0:12} tracks PUBLIC_EXPORT_MANIFEST.json" "$tmp_dir/legacy-guard.out"
grep -q "git rm PUBLIC_EXPORT_MANIFEST.json" "$tmp_dir/legacy-guard.out"

printf 'changed after the manifest\n' >> "$legacy/README.md"
git -C "$legacy" commit -qam "stale legacy manifest"
expect_status 1 "$tmp_dir/legacy-stale.out" "$SCRIPT" --repo "$legacy" --digest
grep -q "tracked PUBLIC_EXPORT_MANIFEST.json at .* does not match the commit tree" "$tmp_dir/legacy-stale.out"
expect_status 1 "$tmp_dir/legacy-stale-facts.out" "$SCRIPT" --repo "$legacy" --facts
grep -q "does not match the commit tree" "$tmp_dir/legacy-stale-facts.out"
if [[ "$("$SCRIPT" --repo "$legacy" --commit "$legacy_commit" --digest)" != "$expected_digest" ]]; then
  echo "Expected the matching legacy commit to stay verifiable" >&2
  exit 1
fi

git -C "$legacy" rm -q PUBLIC_EXPORT_MANIFEST.json
git -C "$legacy" commit -qm "derive the manifest"
"$SCRIPT" --repo "$legacy" --guard >/dev/null
cp "$oracle" "$legacy/PUBLIC_EXPORT_MANIFEST.json"
git -C "$legacy" add PUBLIC_EXPORT_MANIFEST.json
expect_status 1 "$tmp_dir/index-guard.out" "$SCRIPT" --repo "$legacy" --guard
grep -q "the git index tracks PUBLIC_EXPORT_MANIFEST.json" "$tmp_dir/index-guard.out"
git -C "$legacy" rm -q --cached PUBLIC_EXPORT_MANIFEST.json
"$SCRIPT" --repo "$legacy" --guard >/dev/null

bad_digest="$tmp_dir/bad-digest.json"
python3 - "$oracle" "$bad_digest" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
manifest["content_sha256"] = "0" * 64
json.dump(manifest, open(sys.argv[2], "w", encoding="utf-8"))
PY
expect_status 1 "$tmp_dir/compare-digest.out" \
  "$SCRIPT" --repo "$fixture" --commit "$first_commit" --compare "$bad_digest"
grep -q "content_sha256 0000000000000000000000000000000000000000000000000000000000000000 != derived" \
  "$tmp_dir/compare-digest.out"

# Symlinks and submodules are refused, as the export bundle refuses them.
symlinked="$tmp_dir/symlinked"
clone_repo "$fixture" "$symlinked"
ln -s README.md "$symlinked/link.md"
git -C "$symlinked" add link.md
git -C "$symlinked" commit -qm symlink
expect_status 2 "$tmp_dir/symlink.out" "$SCRIPT" --repo "$symlinked" --digest
grep -q "public manifest does not support symlinked files: link.md" "$tmp_dir/symlink.out"

submodule="$tmp_dir/submodule"
clone_repo "$fixture" "$submodule"
git -C "$submodule" update-index --add --cacheinfo "160000,$first_commit,vendor/sub"
git -C "$submodule" commit -qm gitlink
expect_status 2 "$tmp_dir/submodule.out" "$SCRIPT" --repo "$submodule" --digest
grep -q "public manifest does not support commit entries (mode 160000): vendor/sub" "$tmp_dir/submodule.out"

# --repo must be a checkout's top level, not a directory inside one (such as
# dist/public-export/ottto inside the repository).
mkdir -p "$fixture/dist/public-export/ottto"
expect_status 2 "$tmp_dir/nested.out" "$SCRIPT" --repo "$fixture/dist/public-export/ottto" --digest
grep -q "\-\-repo must be the top level of a git checkout" "$tmp_dir/nested.out"
expect_status 2 "$tmp_dir/no-action.out" "$SCRIPT" --repo "$fixture"
expect_status 2 "$tmp_dir/two-actions.out" "$SCRIPT" --repo "$fixture" --digest --facts

# The real repository: a bundle exported from a clean checkout of HEAD equals
# the manifest derived from HEAD, even when checkout and export run under
# umask 002 (the bundle writes 0644/0755 like the derivation).
real_clone="$tmp_dir/real-clone"
(umask 002 && git clone -q "$ROOT" "$real_clone")
configure_repo "$real_clone"
real_bundle="$tmp_dir/real-bundle"
(umask 002 && "$real_clone/scripts/public_repo_export_bundle.sh" --output-dir "$real_bundle" --force) \
  >"$tmp_dir/real-bundle.out"
"$SCRIPT" --repo "$real_clone" --compare "$real_bundle/PUBLIC_EXPORT_MANIFEST.json" \
  >"$tmp_dir/real-compare.out"
grep -q "derived == $real_bundle/PUBLIC_EXPORT_MANIFEST.json" "$tmp_dir/real-compare.out"

echo "public_repo_manifest tests passed"
script_completed=1
