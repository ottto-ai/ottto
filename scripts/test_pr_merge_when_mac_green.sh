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
# stay queue polls; it exits with enqueue_exit (default 0).
case "$*" in
  *enqueuePullRequest*)
    args=""
    for a in "$@"; do
      case "$a" in pr_id=*|head=*) args="$args $a" ;; esac
    done
    printf 'gh enqueue%s\n' "$args" >> "$d/log"
    exit "$(cat "$d/enqueue_exit" 2>/dev/null || echo 0)" ;;
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
  api\ *rules/branches*)
    if [ -f "$d/rules" ]; then cat "$d/rules"; else printf '[{"type":"merge_queue"}]\n'; fi ;;
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

# queue_json <file> <state> <sha> <entry-state-or-empty>
queue_json() {
  jq -n --arg state "$2" --arg sha "$3" --arg entry "$4" --arg merge "$NEW_SHA" '
    {data: {repository: {pullRequest: {
      state: $state, headRefOid: $sha,
      mergeCommit: (if $state == "MERGED" then {oid: $merge} else null end),
      mergeQueueEntry: (if $entry == "" then null else {state: $entry, position: 1} end)
    }}}}' > "$case_dir/$1"
}

# green_case <name>: an open, mergeable PR whose pull_request run passed (the
# macOS "Rust contracts" job skipped, as on every PR) on a base with a queue.
green_case() {
  new_case "$1"
  pr_json pr OPEN false "$SHA" MERGEABLE
  workflow_runs "500|pull_request"
  pr_checks checks 500 "10|Rust contracts|completed|skipped|500"
}

ENQUEUE_CALL="gh enqueue pr_id=PR_node7 head=$SHA"

green_case pending-then-merged
pr_json pr OPEN true "$SHA" MERGEABLE
check_runs checks.1 "10|Rust contracts|completed|skipped|500" \
  "11|Public surface checks|in_progress||500" \
  "12|Rust advisory audit|completed|success|500" \
  "13|Dependency review|completed|success|500"
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_log 'gh pr ready 7'
expect_output '"Public surface checks" pending'
expect_count "$ENQUEUE_CALL" 1
expect_no_log 'gh pr merge'
expect_count 'sleep 60' 2
expect_output "merged PR #7 at merge SHA $NEW_SHA"

green_case red-check-refused
check_runs checks "10|Rust contracts|completed|skipped|500" \
  "11|Public surface checks|completed|failure|500" \
  "12|Rust advisory audit|completed|success|500" \
  "13|Dependency review|completed|success|500"
run_guard 4 7
expect_output '"Public surface checks" concluded failure'
expect_no_log 'sleep'
expect_no_log 'gh enqueue'

green_case head-moved
pr_json pr.1 OPEN false "$SHA" MERGEABLE
pr_json pr OPEN false "$NEW_SHA" MERGEABLE
run_guard 5 7
expect_output "head moved from $SHA to $NEW_SHA"
expect_no_log 'gh enqueue'

# Neither another PR's run, a fork run from another repository, nor a
# workflow_dispatch run on the same commit is evidence for this PR.
green_case other-runs-are-not-evidence
pr_json pr OPEN false "$SHA" MERGEABLE contributor
workflow_runs "500|pull_request|8|main" "600|pull_request||main|someone-else" "700|workflow_dispatch"
check_runs checks "10|Rust contracts|completed|skipped|500" \
  "11|Public surface checks|completed|success|500" \
  "12|Rust advisory audit|completed|success|600" \
  "13|Dependency review|completed|success|700"
run_guard 6 --timeout 0 7
expect_output '"Public surface checks" missing'
expect_no_log 'gh enqueue'

green_case more-than-one-page-is-not-judged
jq '.total_count = 150' "$case_dir/checks" > "$case_dir/checks.next"
mv "$case_dir/checks.next" "$case_dir/checks"
run_guard 6 --timeout 0 7
expect_output "more than one page"
expect_no_log 'gh enqueue'

green_case removed-from-queue
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue OPEN "$SHA" ""
printf '%s' '{"workflow_runs":[{"id":800,"event":"merge_group","path":".github/workflows/ci.yml","head_branch":"gh-readonly-queue/main/pr-7-abc","head_sha":"queue-sha","conclusion":"failure","html_url":"https://example.invalid/actions/runs/800"}]}' > "$case_dir/queue_runs"
run_guard 4 7
expect_count "$ENQUEUE_CALL" 1
expect_output 'rechecking before reporting removal'
expect_output 'removed from merge queue'
expect_output 'merge_group run 800: failure https://example.invalid/actions/runs/800 (head queue-sha)'

# A rerun after a timeout: GitHub refuses to enqueue a PR that is already queued.
green_case rerun-resumes-queued-wait
printf '1' > "$case_dir/enqueue_exit"
queue_json queue.1 OPEN "$SHA" QUEUED
queue_json queue MERGED "$SHA" ""
run_guard 0 7
expect_count "$ENQUEUE_CALL" 1
expect_output 'already in the merge queue or merged; resuming the wait'
expect_output "merged PR #7 at merge SHA $NEW_SHA"

green_case no-queue-fails-fast
pr_json pr OPEN true "$SHA" MERGEABLE
printf '[]' > "$case_dir/rules"
run_guard 3 7
expect_output 'no merge queue on main'
expect_no_log 'gh pr ready'
expect_no_log 'check-runs'

new_case usage-errors
run_guard 2
run_guard 2 abc
run_guard 2 --interval 30 7
run_guard 2 7 8
expect_no_log "gh "

if [ "$failures" -ne 0 ]; then
  echo "pr-merge-guard tests: $failures failure(s)" >&2
  exit 1
fi
echo "pr-merge-guard tests passed"
