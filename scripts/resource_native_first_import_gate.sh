#!/usr/bin/env bash
# Run once by a release operator on an approved native Mac at the PR head.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Native macOS required' >&2; exit 1; }
[[ "${GITHUB_EVENT_NAME:-pull_request}" == pull_request ]] || { echo 'PR-only check' >&2; exit 1; }
pr="${1:?usage: resource_native_first_import_gate.sh PR_NUMBER}"
[[ "$pr" =~ ^[1-9][0-9]*$ && "$#" == 1 ]] || exit 1
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
expected="$(gh pr view "$pr" --repo ottto-ai/ottto --json headRefOid --jq .headRefOid)"
[[ "$expected" =~ ^[0-9a-f]{40}$ && "$(git rev-parse HEAD)" == "$expected" ]] || { echo 'PR head mismatch' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'Clean PR checkout required' >&2; exit 1; }
battery="$(pmset -g batt)"
power="$(pmset -g)"
[[ "$battery" == *"'AC Power'"* ]] || { echo 'AC Power required' >&2; exit 1; }
grep -Eq '^[[:space:]]*lowpowermode[[:space:]]+0([[:space:]]|$)' <<< "$power" || { echo 'Low Power Mode must be known off' >&2; exit 1; }
if grep -Eq '^[[:space:]]*lowpowermode[[:space:]]+1([[:space:]]|$)' <<< "$power"; then
  echo 'Low Power Mode refused' >&2; exit 1
fi
# Same bounded sizing as the Rust fixture: 64..256 files of 16 MiB.
phase_seconds="${OTTTO_RESOURCE_GATE_PHASE_SECONDS:-120}"
[[ "$phase_seconds" =~ ^[1-9][0-9]{0,2}$ ]] || { echo 'Phase seconds must be 1..120' >&2; exit 1; }
phase_seconds=$((10#$phase_seconds))
(( phase_seconds <= 120 )) || { echo 'Phase seconds must be 1..120' >&2; exit 1; }
corpus_files=$(( (phase_seconds * 256 + 119) / 120 ))
(( corpus_files >= 64 )) || corpus_files=64
corpus_kib=$((corpus_files * 16 * 1024))
corpus_gib="$(LC_ALL=C awk -v kib="$corpus_kib" 'BEGIN { printf "%.3f", kib / 1048576 }')"
# Pin the probe to the exact volume checked, including when TMPDIR was unset.
TMPDIR="$(cd "${TMPDIR:-/tmp}" && pwd -P)"
export TMPDIR
available_kib="$(LC_ALL=C df -Pk "$TMPDIR" | awk 'NR == 2 {print $4}')"
[[ "$available_kib" =~ ^[0-9]{1,15}$ ]] || { echo 'Cannot determine temp-volume free space' >&2; exit 1; }
(( 10#$available_kib >= 3 * corpus_kib )) || { echo "Insufficient temp space: need 3x ${corpus_gib} GiB corpus" >&2; exit 1; }
printf 'Native gate corpus_gib=%s required_free_kib=%s available_kib=%s\n' "$corpus_gib" "$((3 * corpus_kib))" "$available_kib"
receipt="$(mktemp -t ottto-first-import-gate.XXXXXX)"
printf 'Native gate receipt: %s\n' "$receipt"
bash "$repo_root/scripts/resource_native_qos_pr.sh" "$pr" 2>&1 | tee "$receipt"
OTTTO_RESOURCE_QOS_PR="$pr" OTTTO_RESOURCE_QOS_HEAD="$expected" cargo test -p ottto-service --locked --lib snapshots::resource_fixture::native_qos::foreground_gate::resource_native_first_import_foreground_gate -- --exact --ignored --nocapture --test-threads=1 2>&1 | tee -a "$receipt"
[[ "$(grep -c '^test result: ok\. 1 passed;' "$receipt")" == 2 ]] || { echo 'Both exact tests must run once' >&2; exit 1; }
[[ "$(grep -Ec "^resource_native_first_import_gate pr=$pr head=$expected corpus_gib=${corpus_gib/./\\.} .* verdict=pass$" "$receipt")" == 1 ]] || { echo 'Missing unique passing head-bound gate receipt' >&2; exit 1; }
printf 'Native gate summary (%s):\n' "$receipt"
grep -E '^resource_native_first_import_(setup|phase|metrics|gate) ' "$receipt"
[[ "${OTTTO_RESOURCE_GATE_PHASE_SECONDS:-120}" == 120 ]] || { echo 'Smoke only: not release gate evidence' >&2; exit 1; }
# Refuse evidence if the checkout or remote PR moved during the run.
[[ "$(git rev-parse HEAD)" == "$expected" && -z "$(git status --porcelain)" ]] || exit 1
[[ "$(gh pr view "$pr" --repo ottto-ai/ottto --json headRefOid --jq .headRefOid)" == "$expected" ]] || { echo 'PR head moved during probe' >&2; exit 1; }
