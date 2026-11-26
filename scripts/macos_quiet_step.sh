#!/usr/bin/env bash
# Usage: macos_quiet_step.sh <label> <command> [args...]
#
# Runs one release command for the macOS stable release workflow with its
# standard output and error discarded, and prints one fixed status line:
# "<label>: ok" or "<label>: failed (exit N)". Release tools can print host
# paths, names and selector values; none of that reaches the public job log
# and no raw log is kept (docs/release-verification.md, "Release Privacy
# Gate"). A command may print fixed, typed status lines to the file
# descriptor named by OTTTO_STATUS_FD; that descriptor is the step's output.
set -uo pipefail

label="${1:-}"
label_pattern='^[a-z][a-z0-9-]*( [a-z0-9-]+)*$'
if [[ ! "$label" =~ $label_pattern || "${#label}" -gt 48 || $# -lt 2 ]]; then
  echo "macos_quiet_step.sh: usage: <label> <command> [args...]" >&2
  exit 2
fi
shift

OTTTO_STATUS_FD=9 "$@" 9>&1 >/dev/null 2>&1
rc=$?
if [[ "$rc" -eq 0 ]]; then
  echo "$label: ok"
else
  echo "$label: failed (exit $rc)" >&2
fi
exit "$rc"
