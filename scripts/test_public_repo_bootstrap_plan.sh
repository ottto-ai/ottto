#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_bootstrap_plan.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

target="$tmp_dir/ottto-target"
bundle="$tmp_dir/bundle"
dry_report="$tmp_dir/dry-run-report.json"
apply_report="$tmp_dir/apply-report.json"
mkdir -p "$target"
git -C "$target" init -q
git -C "$target" config user.email "test@example.com"
git -C "$target" config user.name "Test"
git -C "$target" remote add origin git@github.com:ottto-ai/ottto.git

"$SCRIPT" --target-dir "$target" --bundle-dir "$bundle" --report "$dry_report" > "$tmp_dir/dry-run.out"
grep -q "dry-run only" "$tmp_dir/dry-run.out"
grep -Eq "added=[1-9][0-9]* changed=0 deleted=0" "$tmp_dir/dry-run.out"
test -f "$bundle/README.md"
test -f "$bundle/PUBLIC_EXPORT_MANIFEST.json"
test -f "$dry_report"
if [[ -e "$target/README.md" ]]; then
  echo "Expected dry-run mode to leave target unchanged" >&2
  exit 1
fi
python3 - "$dry_report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["schema_version"] == 1
assert report["mode"] == "dry_run"
assert report["apply_requested"] is False
assert report["applied"] is False
assert report["source"]["head"]
assert report["bundle"]["source_commit"]
assert report["bundle"]["content_sha256"]
assert report["bundle"]["file_record_count"] + 1 == report["bundle"]["output_file_count"]
assert report["bundle_checks"]["manifest"] == "passed"
assert report["bundle_checks"]["skeleton"] == "passed"
assert report["bundle_checks"]["secret_scan"] == "passed"
assert report["bundle_checks"]["contract"] == "passed"
assert report["target"]["remote"] == {
    "name": "origin",
    "repository": "ottto-ai/ottto",
    "url_kind": "ssh",
}
assert report["target_safety_checks"]["clean_checkout"] == "passed"
assert report["target_safety_checks"]["origin_remote"] == "passed"
assert report["post_apply_public_checks"] == "not_run"
assert report["changes"]["added_count"] > 0
assert report["changes"]["changed_count"] == 0
assert report["changes"]["deleted_count"] == 0
for encoded in json.dumps(report).split('"'):
    assert "/private/" not in encoded
    assert "/Users/" not in encoded
    assert "/var/folders/" not in encoded
PY

"$SCRIPT" --target-dir "$target" --bundle-dir "$bundle" --use-existing-bundle --apply --report "$apply_report" > "$tmp_dir/apply.out"
grep -q "post-apply public checks passed" "$tmp_dir/apply.out"
test -f "$target/README.md"
test -f "$target/PUBLIC_EXPORT_MANIFEST.json"
test -x "$target/scripts/public_repo_bootstrap_plan.sh"
test -f "$apply_report"
python3 - "$apply_report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
assert report["mode"] == "apply"
assert report["apply_requested"] is True
assert report["applied"] is True
assert report["target"]["remote"]["repository"] == "ottto-ai/ottto"
assert report["target"]["status_after"]
assert report["post_apply_public_checks"] == {
    "manifest": "passed",
    "skeleton": "passed",
    "secret_scan": "passed",
    "contract": "passed",
}
assert report["changes"]["added_count"] > 0
assert report["changes"]["changed_count"] == 0
assert report["changes"]["deleted_count"] == 0
PY
PUBLIC_SKELETON_REPO_ROOT="$target" "$target/scripts/public_repo_skeleton_check.sh" > "$tmp_dir/target-skeleton.out"

git -C "$target" add .
git -C "$target" commit -qm "bootstrap public repo"
"$SCRIPT" --target-dir "$target" --bundle-dir "$bundle" --use-existing-bundle > "$tmp_dir/noop.out"
grep -q "added=0 changed=0 deleted=0" "$tmp_dir/noop.out"

printf '\n# dirty target\n' >> "$target/README.md"
if "$SCRIPT" --target-dir "$target" --bundle-dir "$bundle" --use-existing-bundle > "$tmp_dir/dirty.out" 2>&1; then
  echo "Expected dirty target checkout to be rejected" >&2
  exit 1
fi
grep -q "target git checkout is not clean" "$tmp_dir/dirty.out"

missing_remote_target="$tmp_dir/missing-remote-target"
mkdir -p "$missing_remote_target"
git -C "$missing_remote_target" init -q
git -C "$missing_remote_target" config user.email "test@example.com"
git -C "$missing_remote_target" config user.name "Test"
if "$SCRIPT" --target-dir "$missing_remote_target" --bundle-dir "$bundle" --use-existing-bundle \
  > "$tmp_dir/missing-remote.out" 2>&1; then
  echo "Expected missing target origin remote to be rejected" >&2
  exit 1
fi
grep -q "target origin remote is missing" "$tmp_dir/missing-remote.out"

wrong_remote_target="$tmp_dir/wrong-remote-target"
mkdir -p "$wrong_remote_target"
git -C "$wrong_remote_target" init -q
git -C "$wrong_remote_target" config user.email "test@example.com"
git -C "$wrong_remote_target" config user.name "Test"
git -C "$wrong_remote_target" remote add origin git@github.com:ottto-ai/not-ottto.git
if "$SCRIPT" --target-dir "$wrong_remote_target" --bundle-dir "$bundle" --use-existing-bundle \
  > "$tmp_dir/wrong-remote.out" 2>&1; then
  echo "Expected wrong target origin remote to be rejected" >&2
  exit 1
fi
grep -q "target origin remote must be ottto-ai/ottto" "$tmp_dir/wrong-remote.out"

source_repo="$(git -C "$ROOT" rev-parse --show-toplevel)"
if "$SCRIPT" --target-dir "$source_repo" --bundle-dir "$bundle" --use-existing-bundle > "$tmp_dir/private-target.out" 2>&1; then
  echo "Expected private source repository target to be rejected" >&2
  exit 1
fi
grep -q "refusing target that overlaps source repository" "$tmp_dir/private-target.out"

echo "public_repo_bootstrap_plan tests passed"
