#!/usr/bin/env bash
# Native Mac PR runner only. No hosted Mac workflow or merge-group selection.
set -euo pipefail
[[ "$(uname -s)" == Darwin ]] || { echo 'Native macOS required' >&2; exit 1; }
[[ "${GITHUB_EVENT_NAME:-pull_request}" == pull_request ]] || { echo 'PR-only check' >&2; exit 1; }
pr="${1:?usage: resource_native_qos_pr.sh PR_NUMBER}"
[[ "$pr" =~ ^[1-9][0-9]*$ ]] || exit 1
expected="$(gh pr view "$pr" --repo ottto-ai/ottto --json headRefOid --jq .headRefOid)"
[[ "$(git rev-parse HEAD)" == "$expected" ]] || { echo 'PR head mismatch' >&2; exit 1; }
OTTTO_RESOURCE_QOS_PR="$pr" cargo test -p ottto-service --locked --lib snapshots::resource_fixture::native_qos::resource_native_ordinary_stage_qos -- --exact --ignored --nocapture --test-threads=1
