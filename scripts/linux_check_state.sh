#!/usr/bin/env bash
set -euo pipefail

# Usage: linux_check_state.sh <sha>
# Prints the state of the linux-tests.yml checks ("Rust tests (Linux)" and
# "Rust format (Linux)") on <sha>: success (both passed in some run), pending
# (one is still queued or running), red, or none (no run). Skipped and
# cancelled runs (drafts, superseded pushes) and the calling workflow run
# ($GITHUB_RUN_ID) are ignored. A running shard ("Rust tests (Linux) shard
# 2/3") counts as pending; only the summary check counts as success.
# Needs gh with checks: read.

sha="${1:?usage: linux_check_state.sh <sha>}"
gh api "repos/$GITHUB_REPOSITORY/commits/$sha/check-runs?filter=all&per_page=100" | jq -r \
  --arg own "/actions/runs/${GITHUB_RUN_ID:-none}/" '
    [ .check_runs[]
      | select(.name | startswith("Rust tests (Linux)") or . == "Rust format (Linux)")
      | select((.details_url // "") | contains($own) | not)
      | select(.conclusion != "skipped" and .conclusion != "cancelled") ] as $runs
    | def state($name):
        [ $runs[] | select(.name == $name) ] as $exact
        | if any($exact[]; .conclusion == "success") then "success"
          elif any($runs[]; (.name | startswith($name)) and .status != "completed") then "pending"
          # Finished shards whose summary check is not created yet.
          elif ($exact | length) == 0 and any($runs[]; .name | startswith($name)) then "pending"
          elif ($exact | length) == 0 then "none"
          else "red" end;
    [ state("Rust tests (Linux)"), state("Rust format (Linux)") ]
    | if all(. == "success") then "success"
      elif any(. == "pending") then "pending"
      elif any(. == "red") then "red"
      else "none" end'
