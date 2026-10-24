#!/usr/bin/env bash

# Bounded removal of a script-owned mktemp directory, for use from EXIT traps.
#
# A plain `rm -rf "$tmp_dir"` as the last command of an EXIT trap replaces the
# script's exit status, so one "Directory not empty" race turns a passing run
# into a failure. Callers capture `$?` first, call this helper, then
# `exit "$status"` to preserve failures. They also check a completion marker
# because bash 3.2 can report status 0 in an EXIT trap after a nounset abort.
#
# Retries up to 5 times with fixed short sleeps (0.2+0.4+0.8+1.6 = 3.0 s of
# sleep at most). Returns 0 when the directory is gone and 1 when it refused an
# unsafe path or every attempt left the directory behind; in the latter case it
# prints a ::warning:: diagnostic naming the path and the last rm error.
public_repo_remove_temp_dir() {
  local label="$1"
  local dir="$2"
  local delays=(0.2 0.4 0.8 1.6)
  local attempts=$((${#delays[@]} + 1))
  local attempt=1
  local output=""
  local line

  case "$dir" in
    /?*) ;;
    *)
      echo "::warning::$label: refusing to remove unsafe temp path '$dir'" >&2
      return 1
      ;;
  esac
  if [[ "$dir" =~ ^/+$ ]]; then
    echo "::warning::$label: refusing to remove unsafe temp path '$dir'" >&2
    return 1
  fi

  while true; do
    if output="$(rm -rf "$dir" 2>&1)" && [[ ! -e "$dir" && ! -L "$dir" ]]; then
      if [[ "$attempt" -gt 1 ]]; then
        echo "$label: removed temp dir $dir after $attempt attempts" >&2
      fi
      return 0
    fi
    if [[ "$attempt" -ge "$attempts" ]]; then
      break
    fi
    sleep "${delays[$((attempt - 1))]}"
    attempt=$((attempt + 1))
  done

  echo "::warning::$label: temp dir cleanup incomplete after $attempts attempts; left $dir in place (script exit status unchanged)" >&2
  if [[ -n "$output" ]]; then
    while IFS= read -r line; do
      echo "$label: last rm error: $line" >&2
    done <<<"$output"
  fi
  return 1
}
