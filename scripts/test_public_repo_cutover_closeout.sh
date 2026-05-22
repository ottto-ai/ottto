#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BOOTSTRAP_SCRIPT="$ROOT/scripts/public_repo_bootstrap_plan.sh"
CLOSEOUT_SCRIPT="$ROOT/scripts/public_repo_cutover_closeout.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

target="$tmp_dir/ottto-target"
bundle="$tmp_dir/bundle"
apply_report="$tmp_dir/apply-report.json"
closeout_report="$tmp_dir/closeout-report.json"
source_root="$(git -C "$ROOT" rev-parse --show-toplevel)"
expected_private_contracts=false
expected_contract_scope="public_only"
if [[ -d "$source_root/backend" && -d "$source_root/frontend" ]]; then
  expected_private_contracts=true
  expected_contract_scope="public_private"
fi
mkdir -p "$target"
git -C "$target" init -q
git -C "$target" config user.email "test@example.com"
git -C "$target" config user.name "Test"
git -C "$target" remote add origin git@github.com:ottto-ai/ottto.git

"$BOOTSTRAP_SCRIPT" \
  --target-dir "$target" \
  --bundle-dir "$bundle" \
  --apply \
  --report "$apply_report" \
  >/tmp/public-cutover-bootstrap.out

"$target/scripts/public_repo_cutover_closeout.sh" \
  --target-dir "$target" \
  --source-repo-root "$source_root" \
  --bootstrap-report "$apply_report" \
  --report "$closeout_report" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout.out

grep -q "ready_to_commit=true" /tmp/public-cutover-closeout.out
test -f "$closeout_report"
python3 - "$closeout_report" "$expected_private_contracts" "$expected_contract_scope" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
expected_private_contracts = sys.argv[2] == "true"
expected_contract_scope = sys.argv[3]
assert report["schema_version"] == 1
assert report["generated_by"] == "public_repo_cutover_closeout.sh"
assert report["mode"] == "target_closeout"
assert report["ready_to_commit"] is True
assert report["manifest"]["content_sha256"]
assert report["manifest"]["file_record_count"] + 1 == report["manifest"]["output_file_count"]
assert report["target"]["remote"] == {
    "name": "origin",
    "repository": "ottto-ai/ottto",
    "url_kind": "ssh",
}
assert report["bootstrap_report"]["provided"] is True
assert report["bootstrap_report"]["applied"] is True
assert report["bootstrap_report"]["target_branch"] == report["target"]["branch"]
assert report["bootstrap_report"]["target_head_before"] == report["target"]["head"]
assert report["bootstrap_report"]["target_remote"] == report["target"]["remote"]
assert report["bootstrap_report"]["content_sha256"] == report["manifest"]["content_sha256"]
assert report["checks"] == {
    "manifest": "passed",
    "skeleton": "passed",
    "secret_scan": "passed",
    "contract": "passed",
    "surface_ci": "skipped",
}
assert report["source"]["provided"] is True
assert report["source"]["head"]
assert report["source"]["private_consumer_contracts"] is expected_private_contracts
assert report["source"]["secret_scan_scope"] == "target_and_source_history"
assert report["source"]["contract_scope"] == expected_contract_scope
assert report["target"]["status_count"] > 0
for encoded in json.dumps(report).split('"'):
    assert "/private/" not in encoded
    assert "/Users/" not in encoded
    assert "/var/folders/" not in encoded
PY

bad_report="$tmp_dir/bad-bootstrap-report.json"
python3 - "$apply_report" "$bad_report" <<'PY'
import json
import sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
report["bundle"]["content_sha256"] = "0" * 64
json.dump(report, open(sys.argv[2], "w", encoding="utf-8"))
PY
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --bootstrap-report "$bad_report" \
  --report "$tmp_dir/bad-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-bad-report.out 2>&1; then
  echo "Expected bootstrap digest mismatch to fail closeout" >&2
  exit 1
fi
grep -q "bootstrap report bundle digest does not match target manifest" /tmp/public-cutover-closeout-bad-report.out

python3 - "$apply_report" "$tmp_dir/bad-bootstrap-remote.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
report["target"]["remote"]["repository"] = "ottto-ai/not-ottto"
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(report, handle)
PY
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --bootstrap-report "$tmp_dir/bad-bootstrap-remote.json" \
  --report "$tmp_dir/bad-bootstrap-remote-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-bad-bootstrap-remote.out 2>&1; then
  echo "Expected mismatched bootstrap target remote to fail closeout" >&2
  exit 1
fi
grep -q "bootstrap report target remote does not match current target origin" \
  /tmp/public-cutover-closeout-bad-bootstrap-remote.out

python3 - "$apply_report" "$tmp_dir/bad-bootstrap-branch.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
report["target"]["branch"] = "feature/bootstrap"
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(report, handle)
PY
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --bootstrap-report "$tmp_dir/bad-bootstrap-branch.json" \
  --report "$tmp_dir/bad-bootstrap-branch-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-bad-bootstrap-branch.out 2>&1; then
  echo "Expected mismatched bootstrap target branch to fail closeout" >&2
  exit 1
fi
grep -q "bootstrap report target branch does not match current target branch" \
  /tmp/public-cutover-closeout-bad-bootstrap-branch.out

python3 - "$apply_report" "$tmp_dir/bad-bootstrap-head.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    report = json.load(handle)
report["target"]["head_before"] = "abcdef1234567890abcdef1234567890abcdef12"
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump(report, handle)
PY
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --bootstrap-report "$tmp_dir/bad-bootstrap-head.json" \
  --report "$tmp_dir/bad-bootstrap-head-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-bad-bootstrap-head.out 2>&1; then
  echo "Expected mismatched bootstrap target head to fail closeout" >&2
  exit 1
fi
grep -q "bootstrap report target head_before does not match current target head" \
  /tmp/public-cutover-closeout-bad-bootstrap-head.out

git -C "$target" remote set-url origin git@github.com:ottto-ai/not-ottto.git
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --bootstrap-report "$apply_report" \
  --report "$tmp_dir/bad-remote-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-bad-remote.out 2>&1; then
  echo "Expected wrong target remote to fail closeout" >&2
  exit 1
fi
grep -q "target origin remote must be ottto-ai/ottto" /tmp/public-cutover-closeout-bad-remote.out
git -C "$target" remote set-url origin git@github.com:ottto-ai/ottto.git

git -C "$target" remote remove origin
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --bootstrap-report "$apply_report" \
  --report "$tmp_dir/missing-remote-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-missing-remote.out 2>&1; then
  echo "Expected missing target remote to fail closeout" >&2
  exit 1
fi
grep -q "target origin remote is missing" /tmp/public-cutover-closeout-missing-remote.out
git -C "$target" remote add origin git@github.com:ottto-ai/ottto.git

rm "$target/PUBLIC_EXPORT_MANIFEST.json"
if "$CLOSEOUT_SCRIPT" \
  --target-dir "$target" \
  --report "$tmp_dir/missing-manifest-closeout.json" \
  --skip-surface-ci \
  >/tmp/public-cutover-closeout-missing-manifest.out 2>&1; then
  echo "Expected missing target manifest to fail closeout" >&2
  exit 1
fi
grep -q "target is missing required public file: PUBLIC_EXPORT_MANIFEST.json" \
  /tmp/public-cutover-closeout-missing-manifest.out

echo "public_repo_cutover_closeout tests passed"
