#!/usr/bin/env bash
set -euo pipefail

# Usage: linux_check_state.sh <sha>
# Prints the state of the linux-tests.yml checks ("Rust tests (Linux)" and
# "Rust format (Linux)") on <sha>: success (both passed in some run), pending
# (one is still queued or running), red, or none (no run). Skipped and
# cancelled runs (drafts, superseded pushes) and the calling workflow run
# ($GITHUB_RUN_ID) are ignored. Needs gh with checks: read.

sha="${1:?usage: linux_check_state.sh <sha>}"
gh api "repos/$GITHUB_REPOSITORY/commits/$sha/check-runs?filter=all&per_page=100" | jq -r \
  --arg own "/actions/runs/${GITHUB_RUN_ID:-none}/" '
    [ .check_runs[]
      | select(.name == "Rust tests (Linux)" or .name == "Rust format (Linux)")
      | select((.details_url // "") | contains($own) | not)
      | select(.conclusion != "skipped" and .conclusion != "cancelled") ] as $runs
    | def state($name):
        [ $runs[] | select(.name == $name) ]
        | if length == 0 then "none"
          elif any(.conclusion == "success") then "success"
          elif any(.status != "completed") then "pending"
          else "red" end;
    [ state("Rust tests (Linux)"), state("Rust format (Linux)") ]
    | if all(. == "success") then "success"
      elif any(. == "pending") then "pending"
      elif any(. == "red") then "red"
      else "none" end'
