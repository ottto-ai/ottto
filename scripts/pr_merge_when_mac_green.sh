#!/usr/bin/env bash
set -euo pipefail

# Merge a pull request only after the Public CI (ci.yml) pull-request checks
# passed on the pull-request run for the PR's current head commit: the macOS
# "Rust contracts" job and the Linux "Public surface checks", "Rust advisory
# audit" and "Dependency review" jobs.

# Job names from .github/workflows/ci.yml; every other check is informational.
# Only check runs of that workflow count, so a same-named job elsewhere cannot
# stand in for (or block) a ci.yml job.
CI_WORKFLOW=".github/workflows/ci.yml"
REQUIRED_CHECKS='["Rust contracts","Public surface checks","Rust advisory audit","Dependency review"]'
DEFAULT_INTERVAL=60
MIN_INTERVAL=60
DEFAULT_TIMEOUT=3600
PR_FIELDS="state,isDraft,headRefOid,mergeable,baseRefName,headRefName,isCrossRepository,headRepository,headRepositoryOwner"

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

Marks the PR ready for review if it is a draft, then waits until each of the
Public CI pull-request checks
  "Rust contracts"          (macOS)
  "Public surface checks"   (Linux)
  "Rust advisory audit"     (Linux)
  "Dependency review"       (Linux)
completed with conclusion success. For each name only the newest check run of
that exact name counts, and only on a pull_request workflow run of this PR and
its current base branch for the PR's head commit. Other checks (for example
"Rust tests (Linux)") are ignored. Once all four passed and the PR is
MERGEABLE it runs:
  gh pr merge <pr> --squash --match-head-commit <head-sha>

Not ready (keeps waiting): a required check run missing, still queued or in
progress, skipped or neutral; mergeability UNKNOWN. A workflow_dispatch or push
run on the same commit is not evidence: it tests the branch head, not the merge
with the base branch. `gh pr checks` exit 0 is not evidence either, and no
Linux job stands in for the macOS "Rust contracts" job.

Options:
  --repo      owner/name; default: the repository gh resolves (or GH_REPO)
  --interval  seconds between polls (default 60, minimum 60)
  --timeout   total seconds to wait before giving up (default 3600)

Exit codes:
  0  merged
  2  usage error or missing tool
  3  refused: PR is not open, or has merge conflicts (CONFLICTING)
  4  a required check finished without success (failure, cancelled, ...)
  5  the PR head changed while waiting; rerun for the new head
  6  timed out before all required checks passed
  7  a gh command failed (view, ready, or merge)
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
# this PR and base in ci.yml. <verdict> is success (all four passed), red (at least one
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
    --arg workflow "$CI_WORKFLOW" \
    --arg sha "$sha" \
    --argjson pr "$pr" \
    --argjson pr_view "$pr_json" \
    --argjson checks "$checks" \
    --argjson runs "$runs" '
      $pr_view.baseRefName as $base
      | "\($pr_view.headRepositoryOwner.login)/\($pr_view.headRepository.name)" as $head_repo
      | [ $runs.workflow_runs[]?
        | select(.event == "pull_request" and .head_sha == $sha)
        | select(.path == $workflow)
        | select(
            any(.pull_requests[]?; .number == $pr and .base.ref == $base)
            or ($pr_view.isCrossRepository == true
                and ((.pull_requests // []) | length) == 0
                and .head_branch == $pr_view.headRefName
                and .head_repository.full_name == $head_repo))
        | .check_suite_id ] as $suites
      | [ $checks.check_runs[]?
          | select(.head_sha == $sha)
          | select(.check_suite.id as $id | any($suites[]; . == $id)) ] as $pr_checks
      | [ $required[] as $name
          | ([ $pr_checks[] | select(.name == $name) ] | sort_by(.id) | last)
          | { name: $name,
              state: (if . == null then "missing"
                elif .status != "completed" then "pending"
                elif .conclusion == "success" then "success"
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

read_pr
refuse_unmergeable
head_sha="$(pr_field headRefOid)"
[ -n "$head_sha" ] || die "$EXIT_GH" "gh pr view $pr returned no headRefOid"

if [ "$(pr_field isDraft)" = true ]; then
  log "PR #$pr is a draft; marking it ready for review"
  gh pr ready "$pr" >/dev/null || die "$EXIT_GH" "gh pr ready $pr failed"
fi

log "PR #$pr head $head_sha: waiting for the required checks $REQUIRED_CHECKS (interval ${interval}s, timeout ${timeout}s)"
waited=0
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
          log "all required checks passed on $head_sha; merging PR #$pr"
          gh pr merge "$pr" --squash --match-head-commit "$head_sha" \
            || die "$EXIT_GH" "gh pr merge $pr failed"
          log "merged PR #$pr at head $head_sha"
          exit 0
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

  if [ "$waited" -ge "$timeout" ]; then
    die "$EXIT_TIMEOUT" "timed out after ${waited}s waiting for the required checks on $head_sha; not merging"
  fi
  sleep "$interval"
  waited=$((waited + interval))
done
