#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/scripts/public_repo_temp_cleanup.sh"
SURFACE_SCRIPT="$ROOT/scripts/public_repo_surface_ci.sh"
# shellcheck source=scripts/public_repo_temp_cleanup.sh
source "$HELPER"

tmp_dir="$(mktemp -d)"
cleanup_tmp_dir() {
  local status=$?
  public_repo_remove_temp_dir "test_public_repo_temp_cleanup" "$tmp_dir" || true
  exit "$status"
}
trap cleanup_tmp_dir EXIT

stub_bin="$tmp_dir/bin"
mkdir -p "$stub_bin"
REAL_RM="$(command -v rm)"
export REAL_RM

# Busy-directory stand-in: for the first STUB_RM_FAILURES calls, really remove
# the target, then recreate a late file under it (as a background git writer
# would) and fail the way BSD rm does. Later calls behave like rm.
cat > "$stub_bin/rm" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
target="${!#}"
calls=0
if [[ -f "$STUB_RM_COUNT" ]]; then
  calls="$(cat "$STUB_RM_COUNT")"
fi
calls=$((calls + 1))
echo "$calls" > "$STUB_RM_COUNT"
echo "$target" >> "$STUB_RM_COUNT.targets"
if [[ "$calls" -le "$STUB_RM_FAILURES" ]]; then
  "$REAL_RM" -rf "$target"
  mkdir -p "$target/public-git/.git/objects"
  touch "$target/public-git/.git/objects/late-write"
  echo "rm: $target/public-git/.git/objects: Directory not empty" >&2
  exit 1
fi
exec "$REAL_RM" "$@"
SH
cat > "$stub_bin/sleep" <<'SH'
#!/usr/bin/env bash
echo "$1" >> "$STUB_SLEEP_LOG"
SH
chmod +x "$stub_bin/rm" "$stub_bin/sleep"

# Same trap shape as the scripts that own mktemp dirs.
harness="$tmp_dir/trap-harness.sh"
cat > "$harness" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
source "$1"
target="$2"
mode="$3"
cleanup_tmp_dir() {
  local status=$?
  public_repo_remove_temp_dir "harness" "$target" || true
  exit "$status"
}
trap cleanup_tmp_dir EXIT
case "$mode" in
  pass) echo "harness checks passed" ;;
  fail) exit 7 ;;
esac
SH

case_index=0
run_case() {
  local failures="$1"
  shift
  case_index=$((case_index + 1))
  case_dir="$tmp_dir/case-$case_index"
  mkdir -p "$case_dir"
  STUB_RM_COUNT="$case_dir/rm-count"
  STUB_SLEEP_LOG="$case_dir/sleep.log"
  case_out="$case_dir/out"
  : > "$STUB_SLEEP_LOG"
  if PATH="$stub_bin:$PATH" \
    STUB_RM_FAILURES="$failures" \
    STUB_RM_COUNT="$STUB_RM_COUNT" \
    STUB_SLEEP_LOG="$STUB_SLEEP_LOG" \
    "$@" >"$case_out" 2>&1; then
    case_status=0
  else
    case_status=$?
  fi
}

new_target() {
  local target="$tmp_dir/target-$case_index-$1"
  mkdir -p "$target/public-git/.git/objects"
  touch "$target/public-git/.git/objects/packed"
  echo "$target"
}

expect_status() {
  if [[ "$case_status" -ne "$1" ]]; then
    echo "Expected exit status $1, got $case_status ($2)" >&2
    cat "$case_out" >&2
    exit 1
  fi
}

expect_rm_calls() {
  local calls
  calls="$(cat "$STUB_RM_COUNT" 2>/dev/null || echo 0)"
  if [[ "$calls" -ne "$1" ]]; then
    echo "Expected $1 rm call(s), got $calls ($2)" >&2
    exit 1
  fi
}

expect_sleeps() {
  local sleeps
  sleeps="$(tr '\n' ' ' < "$STUB_SLEEP_LOG")"
  if [[ "$sleeps" != "$1" ]]; then
    echo "Expected sleeps '$1', got '$sleeps' ($2)" >&2
    exit 1
  fi
}

# Passing run whose first cleanup attempts race a writer: retry wins, exit 0.
target="$(new_target transient)"
run_case 2 bash "$harness" "$HELPER" "$target" pass
expect_status 0 "transient cleanup failure after passing run"
expect_rm_calls 3 "transient cleanup failure"
expect_sleeps "0.2 0.4 " "transient cleanup failure"
[[ ! -e "$target" ]] || { echo "Expected transient target to be removed" >&2; exit 1; }
grep -Fq "harness: removed temp dir $target after 3 attempts" "$case_out"
if grep -Fq "::warning::" "$case_out"; then
  echo "Expected no warning when a retry removed the temp dir" >&2
  exit 1
fi

# Clean first attempt: no retries, no sleeps, no diagnostics.
target="$(new_target clean)"
run_case 0 bash "$harness" "$HELPER" "$target" pass
expect_status 0 "clean cleanup after passing run"
expect_rm_calls 1 "clean cleanup"
expect_sleeps "" "clean cleanup"
[[ ! -e "$target" ]] || { echo "Expected clean target to be removed" >&2; exit 1; }
if grep -Fq "harness:" "$case_out"; then
  echo "Expected no cleanup output when the first attempt succeeds" >&2
  exit 1
fi

# A real failure keeps its exact status even when cleanup never succeeds.
target="$(new_target failing)"
run_case 99 bash "$harness" "$HELPER" "$target" fail
expect_status 7 "failing run with exhausted cleanup"
expect_rm_calls 5 "failing run with exhausted cleanup"
grep -Fq "::warning::harness: temp dir cleanup incomplete after 5 attempts; left $target in place" "$case_out"

# Exhausted retries after a passing run: status stays 0, diagnostic names the
# path and the last rm error, and nothing claims the dir was removed.
target="$(new_target exhausted)"
run_case 99 bash "$harness" "$HELPER" "$target" pass
expect_status 0 "passing run with exhausted cleanup"
expect_rm_calls 5 "passing run with exhausted cleanup"
expect_sleeps "0.2 0.4 0.8 1.6 " "passing run with exhausted cleanup"
[[ -e "$target" ]] || { echo "Expected exhausted target to remain" >&2; exit 1; }
grep -Fq "::warning::harness: temp dir cleanup incomplete after 5 attempts; left $target in place (script exit status unchanged)" "$case_out"
grep -Fq "harness: last rm error: rm: $target/public-git/.git/objects: Directory not empty" "$case_out"
if grep -Fq "removed temp dir" "$case_out"; then
  echo "Expected exhausted cleanup not to report success" >&2
  exit 1
fi

# Unsafe paths are refused without invoking rm.
for unsafe in "" "/" "//" "relative/dir"; do
  # shellcheck disable=SC2016
  run_case 0 bash -c 'source "$1"; public_repo_remove_temp_dir harness "$2"' _ "$HELPER" "$unsafe"
  expect_status 1 "unsafe path '$unsafe'"
  expect_rm_calls 0 "unsafe path '$unsafe'"
  grep -Fq "::warning::harness: refusing to remove unsafe temp path '$unsafe'" "$case_out"
done

# The real surface CI trap preserves its own failure status (2 from a missing
# staged output) while cleanup of its mktemp checkout is exhausted.
run_case 99 bash "$SURFACE_SCRIPT" --staged-output "$tmp_dir/missing-staged-output"
surface_target="$(head -n 1 "$STUB_RM_COUNT.targets")"
public_repo_remove_temp_dir "test_public_repo_temp_cleanup" "$surface_target"
expect_status 2 "surface CI failure with exhausted cleanup"
expect_rm_calls 5 "surface CI failure with exhausted cleanup"
grep -Fq "public-surface-ci: staged output is not a directory" "$case_out"
grep -Fq "::warning::public-surface-ci: temp dir cleanup incomplete after 5 attempts; left $surface_target in place (script exit status unchanged)" "$case_out"

run_case 0 bash "$SURFACE_SCRIPT" --staged-output "$tmp_dir/missing-staged-output"
surface_target="$(head -n 1 "$STUB_RM_COUNT.targets")"
expect_status 2 "surface CI failure with clean cleanup"
expect_rm_calls 1 "surface CI failure with clean cleanup"
[[ ! -e "$surface_target" ]] || { echo "Expected surface CI to remove $surface_target" >&2; exit 1; }

echo "public_repo_temp_cleanup tests passed"
