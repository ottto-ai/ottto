#!/usr/bin/env bash
set -euo pipefail

# Enqueue a pull request only after the Public CI (ci.yml) pull-request checks
# passed on the pull-request run for the PR's current head commit, then wait
# for the merge queue to merge it. The base branch must have a merge queue:
# "Rust contracts" (macOS) is skipped on pull requests and runs only there.

# Required job name -> its workflow; every other check is informational. Only
# check runs of the named workflow count, so a same-named job elsewhere cannot
# stand in for (or block) a required job. Drafts run neither workflow; marking
# the PR ready starts both, so the Linux tests always run before the merge.
CI_WORKFLOW=".github/workflows/ci.yml"
LINUX_WORKFLOW=".github/workflows/linux-tests.yml"
REQUIRED_CHECKS="{\"Rust contracts\":\"$CI_WORKFLOW\",\"Public surface checks\":\"$CI_WORKFLOW\",\"Rust advisory audit\":\"$CI_WORKFLOW\",\"Dependency review\":\"$CI_WORKFLOW\",\"Rust tests (Linux)\":\"$LINUX_WORKFLOW\",\"Rust format (Linux)\":\"$LINUX_WORKFLOW\"}"
DEFAULT_INTERVAL=60
MIN_INTERVAL=60
# Two hours: a queued PR waits for its PR checks and then a full queue round
# (Mac slot wait plus the Mac job) inside one shared budget.
DEFAULT_TIMEOUT=7200
PR_FIELDS="id,state,isDraft,headRefOid,mergeable,baseRefName,headRefName,isCrossRepository,headRepository,headRepositoryOwner"

EXIT_USAGE=2
EXIT_REFUSED=3
EXIT_RED=4
EXIT_HEAD_MOVED=5
EXIT_TIMEOUT=6
EXIT_GH=7

usage() {
  cat <<'USAGE'
Usage: pr_merge_when_mac_green.sh [--repo <owner/name>] [--interval <seconds>]
                                  [--timeout <seconds>] <pr-number>

Refuses at once unless the base branch has a merge queue. Marks the PR ready
for review if it is a draft, then waits until each pull-request check
  "Rust contracts"          (ci.yml, macOS; skipped on pull requests counts as passed)
  "Public surface checks"   (ci.yml, Linux)
  "Rust advisory audit"     (ci.yml, Linux)
  "Dependency review"       (ci.yml, Linux)
  "Rust tests (Linux)"      (linux-tests.yml)
  "Rust format (Linux)"     (linux-tests.yml)
completed with conclusion success. For each name only the newest check run of
that exact name counts, and only on a pull_request run of its workflow for this
PR and its current base branch on the PR's head commit. Other checks are
ignored. Once all six passed and the PR is
MERGEABLE it enqueues exactly <head-sha> with GitHub's enqueuePullRequest
mutation (expectedHeadOid; independent of the repository's auto-merge setting)
and waits until merged, removed from the queue, the head changes, or timeout.
The queue's configured merge method applies; no administrator bypass is used.
Rerunning the guard for a PR that is already queued resumes the wait.

Not ready (keeps waiting): a required check run missing, still queued or in
progress, skipped or neutral; mergeability UNKNOWN. A workflow_dispatch or push
run on the same commit is not evidence: it tests the branch head, not the merge
with the base branch. `gh pr checks` exit 0 is not evidence either, and no
Linux job stands in for the macOS "Rust contracts" job.

Options:
  --repo      owner/name; default: the repository gh resolves (or GH_REPO)
  --interval  seconds between polls (default 60, minimum 60)
  --timeout   total seconds to wait before giving up (default 7200)

Exit codes:
  0  merged
  2  usage error or missing tool
  3  refused: PR is not open, has merge conflicts (CONFLICTING), or the base
     branch has no merge queue
  4  a required check finished without success, or PR removed from merge queue
  5  the PR head changed while waiting; rerun for the new head
  6  timed out waiting for required checks or the merge queue
  7  a gh command failed (view, rules, ready, or enqueue)
USAGE
}

log() {
  printf 'pr-merge-guard: %s\n' "$*" >&2
}

die() {
  local code="$1"
  shift
  log "$*"
  exit "$code"
}

is_uint() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
    *) return 0 ;;
  esac
}

pr=""
interval="$DEFAULT_INTERVAL"
timeout="$DEFAULT_TIMEOUT"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      [ "$#" -ge 2 ] || die "$EXIT_USAGE" "--repo requires a value"
      export GH_REPO="$2"
      shift 2
      ;;
    --interval)
      [ "$#" -ge 2 ] || die "$EXIT_USAGE" "--interval requires a value"
      interval="$2"
      shift 2
      ;;
    --timeout)
      [ "$#" -ge 2 ] || die "$EXIT_USAGE" "--timeout requires a value"
      timeout="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      usage >&2
      die "$EXIT_USAGE" "unknown option: $1"
      ;;
    *)
      [ -z "$pr" ] || die "$EXIT_USAGE" "only one PR number is accepted"
      pr="$1"
      shift
      ;;
  esac
done

[ -n "$pr" ] || { usage >&2; die "$EXIT_USAGE" "missing PR number"; }
is_uint "$pr" || die "$EXIT_USAGE" "PR must be a number: $pr"
pr=$((10#$pr))
is_uint "$interval" || die "$EXIT_USAGE" "--interval must be whole seconds: $interval"
is_uint "$timeout" || die "$EXIT_USAGE" "--timeout must be whole seconds: $timeout"
[ "$interval" -ge "$MIN_INTERVAL" ] \
  || die "$EXIT_USAGE" "--interval must be at least $MIN_INTERVAL seconds"

for tool in gh jq; do
  command -v "$tool" >/dev/null 2>&1 || die "$EXIT_USAGE" "required command not found: $tool"
done

pr_json=""
read_pr() {
  pr_json="$(gh pr view "$pr" --json "$PR_FIELDS")" \
    || die "$EXIT_GH" "gh pr view $pr failed"
}

pr_field() {
  printf '%s' "$pr_json" | jq -r ".$1 // empty"
}

refuse_unmergeable() {
  local state mergeable
  state="$(pr_field state)"
  mergeable="$(pr_field mergeable)"
  [ "$state" = OPEN ] || die "$EXIT_REFUSED" "PR #$pr is $state, not OPEN"
  if [ "$mergeable" = CONFLICTING ]; then
    die "$EXIT_REFUSED" "PR #$pr has merge conflicts (CONFLICTING); GitHub starts no pull-request run for it. Rebase onto the base branch, regenerate generated files, push, and rerun."
  fi
}

# Prints "<verdict>|<detail>" for the required checks on $1, judging for each
# name the newest check run that belongs to a pull_request workflow run for
# this PR and base in that check's workflow. <verdict> is success (all passed), red (at least one
# finished without success; <detail> names them) or wait (<detail> lists the
# others as missing, pending or notready:<skipped|neutral>). A check-runs reply
# that does not hold every run of the commit is "wait", never a verdict.
# Returns non-zero on API errors. GitHub leaves pull_requests empty on runs for
# fork PRs, so for a cross-repository PR a run with no PR links counts when its
# head repository and branch match the PR's.
checks_status() {
  local sha="$1" checks runs
  checks="$(gh api "repos/{owner}/{repo}/commits/$sha/check-runs?filter=all&per_page=100")" \
    || return 1
  runs="$(gh api "repos/{owner}/{repo}/actions/runs?head_sha=$sha&event=pull_request&per_page=100")" \
    || return 1
  jq -nr \
    --argjson required "$REQUIRED_CHECKS" \
    --arg sha "$sha" \
    --argjson pr "$pr" \
    --argjson pr_view "$pr_json" \
    --argjson checks "$checks" \
    --argjson runs "$runs" '
      $pr_view.baseRefName as $base
      | "\($pr_view.headRepositoryOwner.login)/\($pr_view.headRepository.name)" as $head_repo
      | [ $runs.workflow_runs[]?
        | select(.event == "pull_request" and .head_sha == $sha)
        | select(.path as $path | any($required[]; . == $path))
        | select(
            any(.pull_requests[]?; .number == $pr and .base.ref == $base)
            or ($pr_view.isCrossRepository == true
                and ((.pull_requests // []) | length) == 0
                and .head_branch == $pr_view.headRefName
                and .head_repository.full_name == $head_repo))
        | {id: .check_suite_id, path} ] as $suites
      | [ $checks.check_runs[]?
          | select(.head_sha == $sha)
          | .check_suite.id as $id
          | . + {path: ([ $suites[] | select(.id == $id) | .path ] | first)}
          | select(.path != null) ] as $pr_checks
      | [ $required | to_entries[] | .key as $name | .value as $path
          | ([ $pr_checks[] | select(.name == $name and .path == $path) ] | sort_by(.id) | last)
          | { name: $name,
              state: (if . == null then "missing"
                elif .status != "completed" then "pending"
                elif .conclusion == "success" then "success"
                elif $name == "Rust contracts" and .conclusion == "skipped"
                  then "success"
                elif .conclusion == "skipped" or .conclusion == "neutral"
                  then "notready:\(.conclusion)"
                else "red:\(.conclusion)"
                end) } ] as $states
      | [ $states[] | select(.state | startswith("red:")) ] as $red
      | if ($checks.total_count // 0) > ($checks.check_runs // [] | length) then
          "wait|commit has \($checks.total_count) check runs, more than one page; not judged"
        elif ($red | length) > 0 then
          "red|" + ([ $red[] | "\"\(.name)\" concluded \(.state | ltrimstr("red:"))" ]
                    | join(", "))
        elif all($states[]; .state == "success") then "success|"
        else
          "wait|" + ([ $states[] | select(.state != "success")
                       | "\"\(.name)\" \(.state)" ] | join(", "))
        end'
}

# Best-effort diagnostics: queue heads differ from the PR head, so identify the
# latest Public CI queue run by GitHub's queue branch prefix, not the PR SHA.
report_queue_failure() {
  local runs detail
  if runs="$(gh api "repos/{owner}/{repo}/actions/runs?event=merge_group&per_page=100")"; then
    detail="$(printf '%s' "$runs" | jq -r \
      --arg prefix "gh-readonly-queue/$base/pr-$pr-" --arg workflow "$CI_WORKFLOW" '
        [.workflow_runs[]?
         | select(.event == "merge_group" and .path == $workflow)
         | select((.head_branch // "") | startswith($prefix))]
        | sort_by(.id) | last
        | select(. != null)
        # A failed required job ejects the PR while the run is still going
        # (the macOS job runs on), so an unfinished run is reported too.
        | select(.conclusion != "success"
                 and .conclusion != "skipped" and .conclusion != "neutral")
        | "merge_group run \(.id): \(.conclusion // .status) \(.html_url) (head \(.head_sha))"')" || detail=""
    if [ -n "$detail" ]; then log "$detail"; fi
  else
    log "could not read merge_group runs for queue failure diagnostics"
  fi
}

# gh pr merge enqueues through enablePullRequestAutoMerge, which depends on the
# repository allowing auto-merge; the direct mutation does not.
enqueue() {
  local pr_id
  pr_id="$(pr_field id)"
  [ -n "$pr_id" ] || return 1
  # GraphQL variables must reach GitHub literally.
  # shellcheck disable=SC2016
  gh api graphql -f pr_id="$pr_id" -f head="$head_sha" \
    -f query='mutation($pr_id: ID!, $head: GitObjectID!) { enqueuePullRequest(input: {pullRequestId: $pr_id, expectedHeadOid: $head}) { mergeQueueEntry { state position } } }' \
    >/dev/null
}

# The budget is spent by sleeping or by wall-clock time, whichever runs out
# first: slow API calls and gh retries count too.
elapsed() {
  local wall=$((SECONDS - started_at))
  if [ "$wall" -gt "$waited" ]; then echo "$wall"; else echo "$waited"; fi
}

out_of_time() {
  [ "$(elapsed)" -ge "$timeout" ]
}

queue_query() {
  # GraphQL variables must reach GitHub literally.
  # shellcheck disable=SC2016
  gh api graphql -F owner='{owner}' -F name='{repo}' -F number="$pr" \
    -f query='query($owner: String!, $name: String!, $number: Int!) {
      repository(owner: $owner, name: $name) {
        pullRequest(number: $number) {
          state headRefOid mergeCommit { oid } mergeQueueEntry { state position }
          autoMergeRequest { enabledAt }
        }
      }
    }'
}

# True when the PR's current head is queued or already merged. Any read error
# or head mismatch is false, so the caller reports the enqueue failure.
already_queued() {
  local response
  response="$(queue_query)" || return 1
  printf '%s' "$response" | jq -e --arg sha "$head_sha" '
    select((.errors // [] | length) == 0)
    | .data.repository.pullRequest
    | select(.headRefOid == $sha)
    | select(.state == "MERGED" or .mergeQueueEntry != null)' >/dev/null
}

# A single small GraphQL read per queue poll supplies membership, PR state,
# head-movement protection, and the resulting merge SHA. API errors are retried
# within the original invocation's timeout, never treated as queue removal.
wait_for_queue() {
  local response queued_pr state current_sha entry seen_queue=false absent=0
  while :; do
    if response="$(queue_query)" && queued_pr="$(printf '%s' "$response" | jq -ce '
        select((.errors // [] | length) == 0)
        | .data.repository.pullRequest
        | select(.state != null and .headRefOid != null)')"; then
      current_sha="$(printf '%s' "$queued_pr" | jq -r '.headRefOid')"
      if [ "$current_sha" != "$head_sha" ]; then
        die "$EXIT_HEAD_MOVED" "PR #$pr head moved from $head_sha to $current_sha; rerun to wait for the new head"
      fi
      state="$(printf '%s' "$queued_pr" | jq -r '.state')"
      if [ "$state" = MERGED ]; then
        log "merged PR #$pr at merge SHA $(printf '%s' "$queued_pr" | jq -r '.mergeCommit.oid // "unknown"')"
        exit 0
      fi
      entry="$(printf '%s' "$queued_pr" | jq -r '.mergeQueueEntry // empty | "\(.state) (position \(.position))"')"
      if [ -n "$entry" ]; then
        seen_queue=true
        absent=0
        log "PR #$pr in merge queue: $entry"
      elif [ "$seen_queue" = false ] && [ "$state" = OPEN ] \
        && [ "$(printf '%s' "$queued_pr" | jq -r '.autoMergeRequest != null')" = true ]; then
        # gh may enable auto-merge instead of enqueueing when another branch
        # requirement is pending. Do not report removal before admission.
        log "PR #$pr awaiting merge queue admission (auto-merge pending)"
      else
        # GitHub can drop the queue entry a moment before the PR reads as
        # MERGED; only a second consecutive open-and-unqueued read is removal.
        absent=$((absent + 1))
        if [ "$absent" -lt 2 ]; then
          log "PR #$pr not visible in the merge queue; rechecking before reporting removal"
        else
          report_queue_failure
          die "$EXIT_RED" "PR #$pr removed from merge queue; not merged"
        fi
      fi
    else
      log "GitHub queue API read failed; continuing to wait"
    fi
    if out_of_time; then
      die "$EXIT_TIMEOUT" "timed out after $(elapsed)s waiting for PR #$pr in the merge queue"
    fi
    sleep "$interval"
    waited=$((waited + interval))
  done
}

read_pr
refuse_unmergeable
base="$(pr_field baseRefName)"
base_path="$(printf '%s' "$base" | jq -sRr @uri)"
rules="$(gh api "repos/{owner}/{repo}/rules/branches/$base_path")" \
  || die "$EXIT_GH" "could not read rules for base branch $base"
has_queue="$(printf '%s' "$rules" | jq -r 'if type == "array" then any(.[]; .type == "merge_queue") else error("expected rules array") end')" \
  || die "$EXIT_GH" "invalid rules response for base branch $base"
[ "$has_queue" = true ] \
  || die "$EXIT_REFUSED" "no merge queue on $base: \"Rust contracts\" runs only in the merge queue, so this guard cannot merge"
head_sha="$(pr_field headRefOid)"
[ -n "$head_sha" ] || die "$EXIT_GH" "gh pr view $pr returned no headRefOid"

if [ "$(pr_field isDraft)" = true ]; then
  log "PR #$pr is a draft; marking it ready for review"
  gh pr ready "$pr" >/dev/null || die "$EXIT_GH" "gh pr ready $pr failed"
fi

log "PR #$pr head $head_sha: waiting for the required checks $REQUIRED_CHECKS (interval ${interval}s, timeout ${timeout}s)"
waited=0
started_at=$SECONDS
while :; do
  read_pr
  refuse_unmergeable
  current_sha="$(pr_field headRefOid)"
  if [ "$current_sha" != "$head_sha" ]; then
    die "$EXIT_HEAD_MOVED" "PR #$pr head moved from $head_sha to $current_sha; rerun to wait for the new head"
  fi

  if status="$(checks_status "$head_sha")"; then
    detail="${status#*|}"
    case "$status" in
      success\|*)
        mergeable="$(pr_field mergeable)"
        if [ "$mergeable" = MERGEABLE ]; then
          log "all required PR checks passed on $head_sha; enqueuing PR #$pr"
          if ! enqueue; then
            # A rerun after a timeout finds the PR already queued (or just
            # merged); resume waiting instead of reporting a gh failure.
            if already_queued; then
              log "PR #$pr is already in the merge queue or merged; resuming the wait"
            else
              die "$EXIT_GH" "enqueueing PR #$pr at $head_sha failed"
            fi
          fi
          wait_for_queue # exits
        fi
        log "all required checks passed; mergeability is ${mergeable:-unknown}, waiting"
        ;;
      red\|*)
        die "$EXIT_RED" "$detail on $head_sha; not merging"
        ;;
      *)
        log "required checks on $head_sha not ready: $detail"
        ;;
    esac
  else
    log "GitHub API read failed; treating as not ready"
  fi

  if out_of_time; then
    die "$EXIT_TIMEOUT" "timed out after $(elapsed)s waiting for the required checks on $head_sha; not merging"
  fi
  sleep "$interval"
  waited=$((waited + interval))
done
