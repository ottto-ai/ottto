#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/pr_merge_when_mac_green.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

command -v jq >/dev/null 2>&1 || {
  echo "Required command not found: jq" >&2
  exit 2
}

SHA="1111111111111111111111111111111111111111"
NEW_SHA="2222222222222222222222222222222222222222"
FAKE_BIN="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN"

# Fake gh: replays canned responses. <kind>.<n> answers the n-th call of that
# kind; <kind> answers every other call. A missing file makes the call fail.
cat > "$FAKE_BIN/gh" <<'SH'
#!/usr/bin/env sh
d="${MERGE_GUARD_TEST_DIR:?}"
# The enqueue mutation logs as "gh enqueue pr_id=.. head=..", so graphql counts
# stay queue polls; it exits with merge_exit like "gh pr merge".
case "$*" in
  *enqueuePullRequest*)
    args=""
    for a in "$@"; do
      case "$a" in pr_id=*|head=*) args="$args $a" ;; esac
    done
    printf 'gh enqueue%s\n' "$args" >> "$d/log"
    exit "$(cat "$d/merge_exit" 2>/dev/null || echo 0)" ;;
esac
printf 'gh %s\n' "$*" >> "$d/log"
reply() {
  n=$(( $(cat "$d/count.$1" 2>/dev/null || echo 0) + 1 ))
  echo "$n" > "$d/count.$1"
  if [ -f "$d/$1.$n" ]; then cat "$d/$1.$n"; else cat "$d/$1"; fi
}
case "$1 $2" in
  "pr view") reply pr ;;
  "pr ready") exit 0 ;;
  "pr merge") exit "$(cat "$d/merge_exit" 2>/dev/null || echo 0)" ;;
  api\ *rules/branches*)
    if [ -f "$d/rules" ]; then cat "$d/rules"; else printf '[]\n'; fi ;;
  "api graphql") reply queue ;;
  api\ *check-runs*) reply checks ;;
  api\ *actions/runs*event=merge_group*) reply queue_runs ;;
  api\ *actions/runs*) reply runs ;;
  *) echo "unexpected gh call: $*" >&2; exit 1 ;;
esac
SH
chmod +x "$FAKE_BIN/gh"

cat > "$FAKE_BIN/sleep" <<'SH'
#!/usr/bin/env sh
printf 'sleep %s\n' "$*" >> "${MERGE_GUARD_TEST_DIR:?}/log"
SH
chmod +x "$FAKE_BIN/sleep"

failures=0
case_dir=""

fail() {
  echo "FAIL [$case_name]: $*" >&2
  failures=$((failures + 1))
}

new_case() {
  case_name="$1"
  case_dir="$TMP_DIR/case-$1"
  mkdir -p "$case_dir"
  : > "$case_dir/log"
}

# pr_json <file> <state> <isDraft> <sha> <mergeable> [<fork-owner>]
pr_json() {
  jq -n --arg s "$2" --argjson d "$3" --arg h "$4" --arg m "$5" --arg fork "${6:-}" \
    '{id: "PR_node7", state: $s, isDraft: $d, headRefOid: $h, mergeable: $m,
      baseRefName: "main", headRefName: "feature",
      isCrossRepository: ($fork != ""),
      headRepository: {name: "repo"},
      headRepositoryOwner: {login: (if $fork == "" then "example" else $fork end)}}' \
    > "$case_dir/$1"
}

# check_runs <file> [<id>|<name>|<status>|<conclusion>|<suite>]...
check_runs() {
  local file="$1" spec id name status conclusion suite
  shift
  printf '[]' > "$case_dir/$file.tmp"
  for spec in "$@"; do
    IFS='|' read -r id name status conclusion suite <<EOF_SPEC
$spec
EOF_SPEC
    jq --argjson id "$id" --arg n "$name" --arg s "$status" --arg c "$conclusion" \
      --arg h "$SHA" --argjson suite "$suite" \
      '. + [{id: $id, name: $n, head_sha: $h, status: $s,
             conclusion: (if $c == "" then null else $c end),
             check_suite: {id: $suite}}]' \
      "$case_dir/$file.tmp" > "$case_dir/$file.next"
    mv "$case_dir/$file.next" "$case_dir/$file.tmp"
  done
  jq '{total_count: length, check_runs: .}' "$case_dir/$file.tmp" > "$case_dir/$file"
  rm -f "$case_dir/$file.tmp"
}

# pr_checks <file> <suite> [<spec>]...: check_runs with <spec>s plus a success
# for each required Linux check ("Public surface checks", "Rust advisory
# audit", "Dependency review") in <suite>, so a case only spells out the checks
# it is about.
pr_checks() {
  local file="$1" suite="$2"
  shift 2
  check_runs "$file" "$@" \
    "91|Public surface checks|completed|success|$suite" \
    "92|Rust advisory audit|completed|success|$suite" \
    "93|Dependency review|completed|success|$suite"
}

# workflow_runs [<suite>|<event>[|<pr>|<base>|<head-owner>[|<path>]]]...
# <pr> defaults to 7 and <base> to main; an empty <pr> leaves pull_requests
# empty, as GitHub does for fork PR runs. <head-owner> defaults to example,
# <path> to .github/workflows/ci.yml.
workflow_runs() {
  local spec suite event prnum base owner path
  printf '[]' > "$case_dir/runs.tmp"
  for spec in "$@"; do
    IFS='|' read -r suite event prnum base owner path <<EOF_SPEC
$spec
EOF_SPEC
    case "$spec" in
      *'|'*'|'*) ;;
      *) prnum=7 ;;
    esac
    jq --argjson s "$suite" --arg e "$event" --arg h "$SHA" \
      --arg pr "$prnum" --arg base "${base:-main}" --arg owner "${owner:-example}" \
      --arg path "${path:-.github/workflows/ci.yml}" \
      '. + [{check_suite_id: $s, event: $e, head_sha: $h, path: $path,
             head_branch: "feature",
             head_repository: {full_name: "\($owner)/repo"},
             pull_requests: (if $pr == "" then []
               else [{number: ($pr | tonumber), base: {ref: $base}}] end)}]' \
      "$case_dir/runs.tmp" > "$case_dir/runs.next"
    mv "$case_dir/runs.next" "$case_dir/runs.tmp"
  done
  jq '{total_count: length, workflow_runs: .}' "$case_dir/runs.tmp" > "$case_dir/runs"
  rm -f "$case_dir/runs.tmp"
}

run_guard() {
  local expected="$1" status=0
  shift
  MERGE_GUARD_TEST_DIR="$case_dir" PATH="$FAKE_BIN:$PATH" \
    bash "$GUARD" "$@" > "$case_dir/out" 2>&1 || status=$?
  if [ "$status" -ne "$expected" ]; then
    fail "exit $status, expected $expected; output:"
    sed 's/^/  /' "$case_dir/out" >&2
  fi
}

expect_log() {
  grep -F -q -- "$1" "$case_dir/log" || fail "log lacks: $1"
}

expect_no_log() {
  if grep -F -q -- "$1" "$case_dir/log"; then
    fail "log unexpectedly has: $1"
  fi
}

expect_output() {
  grep -F -q -- "$1" "$case_dir/out" || fail "output lacks: $1"
}

expect_count() {
  local got
  got="$(grep -c -F -- "$1" "$case_dir/log" || true)"
  [ "$got" -eq "$2" ] || fail "expected $2 x '$1', got $got"
}

MERGE_CALL="gh pr merge 7 --squash --match-head-commit $SHA"

new_case draft-pending-then-green
pr_json pr OPEN true "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks.1 500 "10|Rust contracts|in_progress||500"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 0 7
expect_log "gh pr ready 7"
expect_count "sleep 60" 1
expect_log "$MERGE_CALL"

new_case ready-pr-does-not-call-ready
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 0 --repo example/repo 7
expect_no_log "gh pr ready"
expect_no_log "sleep"
expect_log "$MERGE_CALL"

new_case conflicting-refused
pr_json pr OPEN true "$SHA" CONFLICTING
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 3 7
expect_no_log "gh pr ready"
expect_no_log "gh pr merge"

new_case conflict-appears-while-waiting
pr_json pr.1 OPEN false "$SHA" MERGEABLE
pr_json pr OPEN false "$SHA" CONFLICTING
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|queued||500"
run_guard 3 7
expect_no_log "gh pr merge"

new_case closed-refused
pr_json pr MERGED false "$SHA" UNKNOWN
workflow_runs
check_runs checks
run_guard 3 7
expect_no_log "gh pr merge"

new_case skipped-is-not-ready
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|skipped|500"
run_guard 6 --timeout 120 7
expect_count "sleep 60" 2
expect_no_log "gh pr merge"

new_case neutral-is-not-ready
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|neutral|500"
run_guard 6 --timeout 0 7
expect_no_log "sleep"
expect_no_log "gh pr merge"

new_case missing-is-not-ready
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
check_runs checks "11|Public surface checks|completed|success|500" \
  "12|Rust contracts (Mac deferred: draft)|completed|success|500" \
  "13|Rust tests (Linux)|completed|success|500" \
  "15|Rust advisory audit|completed|success|500" \
  "16|Dependency review|completed|success|500"
run_guard 6 --timeout 60 7
expect_count "sleep 60" 1
expect_no_log "gh pr merge"

new_case dispatch-green-is-not-evidence
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "600|workflow_dispatch" "700|push"
pr_checks checks 700 "20|Rust contracts|completed|success|600" \
  "21|Rust contracts|completed|success|700"
run_guard 6 --timeout 60 7
expect_no_log "gh pr merge"

new_case failure-is-red
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|failure|500"
run_guard 4 7
expect_no_log "sleep"
expect_no_log "gh pr merge"

new_case rerun-success-after-failure
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|failure|500" \
  "14|Rust contracts|completed|success|500"
run_guard 0 7
expect_log "$MERGE_CALL"

new_case rerun-in-progress-after-success
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500" \
  "14|Rust contracts|in_progress||500"
run_guard 6 --timeout 60 7
expect_no_log "gh pr merge"

new_case unknown-mergeable-waits
pr_json pr.1 OPEN false "$SHA" UNKNOWN
pr_json pr.2 OPEN false "$SHA" UNKNOWN
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 0 7
expect_count "sleep 60" 1
expect_log "$MERGE_CALL"

new_case head-moved
pr_json pr.1 OPEN false "$SHA" MERGEABLE
pr_json pr OPEN false "$NEW_SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 5 7
expect_no_log "gh pr merge"

new_case api-error-is-not-ready
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
run_guard 6 --timeout 60 7
expect_count "sleep 60" 1
expect_no_log "gh pr merge"

new_case merge-failure
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
echo 1 > "$case_dir/merge_exit"
run_guard 7 7
expect_log "$MERGE_CALL"

new_case custom-interval
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|queued||500"
run_guard 6 --interval 90 --timeout 180 7
expect_count "sleep 90" 2

new_case other-pr-run-is-not-evidence
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request|8|main"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 6 --timeout 0 7
expect_no_log "gh pr merge"

new_case other-base-run-is-not-evidence
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request|7|release"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 6 --timeout 0 7
expect_no_log "gh pr merge"

new_case fork-pr-run-without-links
pr_json pr OPEN false "$SHA" MERGEABLE contributor
workflow_runs "500|pull_request||main|contributor"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 0 7
expect_log "$MERGE_CALL"

new_case fork-run-from-other-repo-is-not-evidence
pr_json pr OPEN false "$SHA" MERGEABLE contributor
workflow_runs "500|pull_request||main|someone-else"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 6 --timeout 0 7
expect_no_log "gh pr merge"

new_case same-repo-run-without-links-is-not-evidence
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request||main|example"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
run_guard 6 --timeout 0 7
expect_no_log "gh pr merge"

new_case linux-surface-red
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
check_runs checks "10|Rust contracts|completed|success|500" \
  "11|Public surface checks|completed|failure|500" \
  "12|Rust advisory audit|completed|success|500" \
  "13|Dependency review|completed|success|500"
run_guard 4 7
expect_output '"Public surface checks" concluded failure'
expect_no_log "sleep"
expect_no_log "gh pr merge"

new_case red-does-not-wait-for-pending-mac
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
check_runs checks "10|Rust contracts|in_progress||500" \
  "11|Public surface checks|completed|success|500" \
  "12|Rust advisory audit|completed|cancelled|500" \
  "13|Dependency review|completed|success|500"
run_guard 4 7
expect_output '"Rust advisory audit" concluded cancelled'
expect_no_log "sleep"
expect_no_log "gh pr merge"

new_case advisory-pending-with-mac-green-waits
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
check_runs checks "10|Rust contracts|completed|success|500" \
  "11|Public surface checks|completed|success|500" \
  "12|Rust advisory audit|queued||500" \
  "13|Dependency review|completed|success|500"
run_guard 6 --timeout 60 7
expect_count "sleep 60" 1
expect_output '"Rust advisory audit" pending'
expect_no_log "gh pr merge"

new_case missing-dependency-review-waits
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
check_runs checks "10|Rust contracts|completed|success|500" \
  "11|Public surface checks|completed|success|500" \
  "12|Rust advisory audit|completed|success|500"
run_guard 6 --timeout 0 7
expect_output '"Dependency review" missing'
expect_no_log "gh pr merge"

new_case informational-check-failure-does-not-block
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500" \
  "14|Rust tests (Linux)|completed|failure|500"
run_guard 0 7
expect_log "$MERGE_CALL"

new_case other-workflow-green-does-not-cover-red-ci
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request" "600|pull_request|7|main|example|.github/workflows/other.yml"
check_runs checks "10|Rust contracts|completed|success|500" \
  "11|Public surface checks|completed|failure|500" \
  "12|Rust advisory audit|completed|success|500" \
  "13|Dependency review|completed|success|500" \
  "20|Public surface checks|completed|success|600"
run_guard 4 7
expect_output '"Public surface checks" concluded failure'
expect_no_log "gh pr merge"

new_case other-workflow-pending-does-not-block-green-ci
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request" "600|pull_request|7|main|example|.github/workflows/other.yml"
pr_checks checks 500 "10|Rust contracts|completed|success|500" \
  "120|Public surface checks|in_progress||600"
run_guard 0 7
expect_log "$MERGE_CALL"
expect_no_log "sleep"

new_case more-than-one-page-is-not-judged
pr_json pr OPEN false "$SHA" MERGEABLE
workflow_runs "500|pull_request"
pr_checks checks 500 "10|Rust contracts|completed|success|500"
jq '.total_count = 150' "$case_dir/checks" > "$case_dir/checks.next"
mv "$case_dir/checks.next" "$case_dir/checks"
run_guard 6 --timeout 0 7
expect_output "more than one page"
expect_no_log "gh pr merge"

# Queue fixtures remain opt-in so all pre-queue cases exercise the unchanged
# direct squash-merge path. Queue API replies follow the same numbered scheme.
queue_case() {
  new_case "$1"
  printf '[{"type":"merge_queue"}]' > "$case_dir/rules"
  pr_json pr OPEN false "$SHA" MERGEABLE
  workflow_runs "500|pull_request"
  pr_checks checks 500 "10|Rust contracts|completed|success|500"
}

# queue_json <file> <state> <sha> <entry-state-or-empty>
queue_json() {
  jq -n --arg state "$2" --arg sha "$3" --arg entry "$4" --arg merge "$NEW_SHA" '
    {data: {repository: {pullRequest: {
      state: $state, headRefOid: $sha,
      mergeCommit: (if $state == "MERGED" then {oid: $merge} else null end),
      mergeQueueEntry: (if $entry == "" then null else {state: $entry, position: 1} end)
    }}}}' > "$case_dir/$1"
}

ENQUEUE_CALL="gh enqueue pr_id=PR_node7 head=$SHA"

queue_case queue-happy-path
pr_json pr OPEN true "$SHA" MERGEABLE
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_log 'gh pr ready 7'
expect_count "$ENQUEUE_CALL" 1
expect_no_log --admin
expect_no_log --auto
expect_no_log --squash
expect_no_log 'gh pr merge'
expect_count 'rules/branches/main' 1
expect_count 'gh api graphql' 2
expect_count 'sleep 60' 1
expect_output "merged PR #7 at merge SHA $NEW_SHA"

queue_case queue-skipped-mac-enqueues
pr_checks checks 500 "10|Rust contracts|completed|skipped|500"
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_log "$ENQUEUE_CALL"

queue_case queue-red-mac-refuses
pr_checks checks 500 "10|Rust contracts|completed|failure|500"
run_guard 4 7
expect_output '"Rust contracts" concluded failure'
expect_no_log 'gh pr merge'

queue_case queue-skipped-linux-waits
check_runs checks "10|Rust contracts|completed|skipped|500" \
  "11|Public surface checks|completed|success|500" \
  "12|Rust advisory audit|completed|success|500" \
  "13|Dependency review|completed|skipped|500"
run_guard 6 --timeout 0 7
expect_output '"Dependency review" notready:skipped'
expect_no_log 'gh pr merge'

queue_case queue-neutral-mac-waits
pr_checks checks 500 "10|Rust contracts|completed|neutral|500"
run_guard 6 --timeout 0 7
expect_no_log 'gh pr merge'

queue_case queue-removed-with-failure
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue OPEN "$SHA" ""
printf '%s' '{"workflow_runs":[{"id":800,"event":"merge_group","path":".github/workflows/ci.yml","head_branch":"gh-readonly-queue/main/pr-7-abc","head_sha":"queue-sha","conclusion":"failure","html_url":"https://example.invalid/actions/runs/800"}]}' > "$case_dir/queue_runs"
run_guard 4 7
expect_log "$ENQUEUE_CALL"
expect_output 'removed from merge queue'
expect_output 'merge_group run 800: failure https://example.invalid/actions/runs/800 (head queue-sha)'

# Ejected while the queue run's macOS job is still running.
queue_case queue-removed-run-in-progress
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue OPEN "$SHA" ""
printf '%s' '{"workflow_runs":[{"id":801,"event":"merge_group","path":".github/workflows/ci.yml","head_branch":"gh-readonly-queue/main/pr-7-abc","head_sha":"queue-sha","status":"in_progress","conclusion":null,"html_url":"https://example.invalid/actions/runs/801"}]}' > "$case_dir/queue_runs"
run_guard 4 7
expect_output 'merge_group run 801: in_progress https://example.invalid/actions/runs/801 (head queue-sha)'

queue_case queue-removed-diagnostics-unavailable
queue_json queue OPEN "$SHA" ""
run_guard 4 7
expect_output 'removed from merge queue'
expect_output 'could not read merge_group runs'

queue_case queue-left-then-merged
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue.2 OPEN "$SHA" ""
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_output 'rechecking before reporting removal'
expect_output "merged PR #7 at merge SHA $NEW_SHA"
expect_no_log 'merge_group&per_page'

queue_case queue-head-moved
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue OPEN "$NEW_SHA" ""
run_guard 5 7
expect_count "$ENQUEUE_CALL" 1
expect_output "head moved from $SHA to $NEW_SHA"

queue_case queue-timeout
queue_json queue OPEN "$SHA" QUEUED
run_guard 6 --timeout 120 7
expect_count 'sleep 60' 2
expect_count 'gh api graphql' 3
expect_count "$ENQUEUE_CALL" 1

queue_case queue-api-error-retried
printf '%s' '{"data":{"repository":{"pullRequest":null}},"errors":[{"message":"unavailable"}]}' > "$case_dir/queue.1"
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_output 'GitHub queue API read failed'
expect_count 'sleep 60' 1
expect_count "$ENQUEUE_CALL" 1

queue_case queue-awaits-initial-admission
queue_json queue.1 OPEN "$SHA" ""
jq '.data.repository.pullRequest.autoMergeRequest = {enabledAt: "2026-01-01T00:00:00Z"}' \
  "$case_dir/queue.1" > "$case_dir/queue.next"
mv "$case_dir/queue.next" "$case_dir/queue.1"
queue_json queue.2 OPEN "$SHA" QUEUED
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_output 'awaiting merge queue admission'
expect_count 'sleep 60' 2
expect_count "$ENQUEUE_CALL" 1
expect_no_log --auto

queue_case queue-removed-even-with-auto-merge
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue OPEN "$SHA" ""
jq '.data.repository.pullRequest.autoMergeRequest = {enabledAt: "2026-01-01T00:00:00Z"}' \
  "$case_dir/queue" > "$case_dir/queue.next"
mv "$case_dir/queue.next" "$case_dir/queue"
run_guard 4 7
expect_output 'removed from merge queue'

queue_case queue-enqueue-error
printf '1' > "$case_dir/merge_exit"
run_guard 7 7
expect_log "$ENQUEUE_CALL"
expect_count 'gh api graphql' 1

# A rerun after a timeout: gh refuses to enqueue a PR that is already queued.
queue_case queue-rerun-already-queued
printf '1' > "$case_dir/merge_exit"
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_count "$ENQUEUE_CALL" 1
expect_output 'already in the merge queue or merged; resuming the wait'
expect_output "merged PR #7 at merge SHA $NEW_SHA"

queue_case queue-rerun-already-merged
printf '1' > "$case_dir/merge_exit"
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_output "merged PR #7 at merge SHA $NEW_SHA"

# A queue entry for another head is not this head's admission.
queue_case queue-enqueue-error-other-head-queued
printf '1' > "$case_dir/merge_exit"
queue_json queue OPEN "$NEW_SHA" QUEUED
run_guard 7 7
expect_output "enqueueing PR #7 at $SHA failed"
expect_count 'gh api graphql' 1

new_case invalid-rules-refused
pr_json pr OPEN false "$SHA" MERGEABLE
# A malformed successful API response must not silently select direct merging.
printf 'null' > "$case_dir/rules"
run_guard 7 7
expect_no_log 'gh pr merge'

new_case short-interval-rejected
run_guard 2 --interval 30 7
expect_no_log "gh "

new_case usage-errors
run_guard 2
run_guard 2 abc
run_guard 2 --timeout -1 7
run_guard 2 7 8
expect_no_log "gh "

if [ "$failures" -ne 0 ]; then
  echo "pr-merge-guard tests: $failures failure(s)" >&2
  exit 1
fi
echo "pr-merge-guard tests passed"
