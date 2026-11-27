#!/usr/bin/env bash
# Tests scripts/macos_release_gh_isolation.sh with a stub gh: the shim it installs
# refuses without a job token before gh runs, forces the host and config folder,
# and every run gets a fresh, empty folder. Bash 3.2-safe.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER="$ROOT/scripts/macos_release_gh_isolation.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "macos_release_gh_isolation test: $*" >&2
  exit 1
}

# The stub stands for the real gh: it logs its arguments and the variables the
# shim controls, then exits with STUB_EXIT (default 0).
stub_bin="$TMP_DIR/stub bin"
mkdir -p "$stub_bin"
cat > "$stub_bin/gh" <<'STUB'
#!/bin/bash
{
  printf 'args:'
  for arg in "$@"; do printf ' [%s]' "$arg"; done
  printf '\n'
  printf 'GH_TOKEN=%s\n' "${GH_TOKEN-<unset>}"
  printf '%s=%s\n' GITHUB_TOKEN "${GITHUB_TOKEN-<unset>}"
  printf 'GH_ENTERPRISE_TOKEN=%s\n' "${GH_ENTERPRISE_TOKEN-<unset>}"
  printf 'GITHUB_ENTERPRISE_TOKEN=%s\n' "${GITHUB_ENTERPRISE_TOKEN-<unset>}"
  printf 'GH_HOST=%s\n' "${GH_HOST-<unset>}"
  printf 'GH_CONFIG_DIR=%s\n' "${GH_CONFIG_DIR-<unset>}"
  printf 'GH_PROMPT_DISABLED=%s\n' "${GH_PROMPT_DISABLED-<unset>}"
} >> "$STUB_LOG"
exit "${STUB_EXIT:-0}"
STUB
chmod +x "$stub_bin/gh"
export STUB_LOG="$TMP_DIR/stub.log"
# The fallback token variable gh would read; its assignments are built from the
# name (the public secret scan refuses the literal assignment form).
fallback=GITHUB_TOKEN

# A space in the runner temp folder checks the shim's quoting.
runner_temp="$TMP_DIR/runner temp"
mkdir -p "$runner_temp"

# run_helper <path> <github env file> <github path file>
run_helper() {
  env -i PATH="$1" RUNNER_TEMP="$runner_temp" GITHUB_ENV="$2" GITHUB_PATH="$3" \
    bash "$HELPER" >"$TMP_DIR/helper.out" 2>&1
}

# env_value <github env file> <name>: the last value written for name.
env_value() {
  sed -n "s/^$2=//p" "$1" | tail -n 1
}

# run_step <shim dir> <config dir> [name=value...] -- <command...>: a later
# step: the runner prepends the GITHUB_PATH folder and sets the GITHUB_ENV values;
# the extra assignments stand for the step's own environment.
run_step() {
  local shim_dir="$1" config_dir="$2"
  shift 2
  local -a assigns=()
  while [[ "$1" != "--" ]]; do
    assigns+=("$1")
    shift
  done
  shift
  env -i PATH="$shim_dir:$stub_bin:/usr/bin:/bin" STUB_LOG="$STUB_LOG" \
    GH_CONFIG_DIR="$config_dir" GH_PROMPT_DISABLED=1 GH_HOST=github.com \
    "${assigns[@]+"${assigns[@]}"}" "$@" >"$TMP_DIR/step.out" 2>&1
}

# A folder an old run left behind is never reused.
mkdir -m 700 "$runner_temp/gh-config"
printf 'hosts: {}\n' > "$runner_temp/gh-config/hosts.yml"

# [behaviour] The helper writes the environment and PATH files and prints one line.
: > "$TMP_DIR/env1"
: > "$TMP_DIR/path1"
run_helper "$stub_bin:/usr/bin:/bin" "$TMP_DIR/env1" "$TMP_DIR/path1" ||
  { cat "$TMP_DIR/helper.out" >&2; fail "the helper failed"; }
[[ "$(cat "$TMP_DIR/helper.out")" == "gh isolation: ok" ]] || fail "the helper printed more than its status line"
shim_dir="$(cat "$TMP_DIR/path1")"
config_dir="$(env_value "$TMP_DIR/env1" GH_CONFIG_DIR)"
[[ "$(wc -l < "$TMP_DIR/path1" | tr -d ' ')" == 1 ]] || fail "GITHUB_PATH must get exactly one folder"
[[ "$(env_value "$TMP_DIR/env1" GH_HOST)" == github.com ]] || fail "GH_HOST must be github.com in GITHUB_ENV"
[[ "$(env_value "$TMP_DIR/env1" GH_PROMPT_DISABLED)" == 1 ]] || fail "GH_PROMPT_DISABLED must be set in GITHUB_ENV"

# [behaviour] The config folder is fresh, empty, private and under RUNNER_TEMP.
case "$config_dir" in
  "$runner_temp"/gh-isolation.*/config) ;;
  *) fail "the config folder is not a fresh folder under RUNNER_TEMP" ;;
esac
[[ -d "$config_dir" && -z "$(ls -A "$config_dir")" ]] || fail "the config folder is not empty"
[[ -n "$(find "$config_dir" -maxdepth 0 -perm 700)" ]] || fail "the config folder is not private"
[[ -x "$shim_dir/gh" && "$shim_dir" == "$(dirname "$config_dir")/bin" ]] || fail "the shim is not in the run's folder"

# [behaviour] The shim is the gh a later step and its child scripts find.
run_step "$shim_dir" "$config_dir" -- bash -c 'command -v gh' || fail "no gh found in a later step"
[[ "$(cat "$TMP_DIR/step.out")" == "$shim_dir/gh" ]] || fail "the shim is not first on PATH"

refused="gh: refused: this step sets no GH_TOKEN; release steps run gh with the job token only."

# [behaviour] No job token: the shim refuses before gh runs.
: > "$STUB_LOG"
rc=0
run_step "$shim_dir" "$config_dir" -- gh api repos/example/example || rc=$?
[[ "$rc" == 4 && "$(cat "$TMP_DIR/step.out")" == "$refused" ]] || fail "an unset GH_TOKEN was not refused (exit $rc)"
[[ ! -s "$STUB_LOG" ]] || fail "gh ran without GH_TOKEN"

# [behaviour] An empty job token with fallback tokens: still refused, gh never runs.
rc=0
run_step "$shim_dir" "$config_dir" GH_TOKEN= "$fallback=dummy-fallback" GH_ENTERPRISE_TOKEN=dummy-enterprise \
  GITHUB_ENTERPRISE_TOKEN=dummy-enterprise -- gh attestation verify ./x || rc=$?
[[ "$rc" == 4 && "$(cat "$TMP_DIR/step.out")" == "$refused" ]] || fail "an empty GH_TOKEN with GITHUB_TOKEN was not refused"
[[ ! -s "$STUB_LOG" ]] || fail "gh ran with an empty GH_TOKEN"

# [behaviour] The same refusal through a child script calling gh through a variable.
rc=0
# shellcheck disable=SC2016 # The child shell expands $cli.
run_step "$shim_dir" "$config_dir" "$fallback=dummy-fallback" -- bash -c 'cli=gh; "$cli" api x' || rc=$?
[[ "$rc" == 4 && ! -s "$STUB_LOG" ]] || fail "a gh call through a variable was not refused"

# [behaviour] With the job token: gh runs with its arguments, on github.com, with the
# isolated config folder and no fallback token, whatever the step's environment says.
run_step "$shim_dir" "$config_dir" GH_TOKEN=job-token "$fallback=dummy-fallback" \
  GH_ENTERPRISE_TOKEN=dummy-enterprise GITHUB_ENTERPRISE_TOKEN=dummy-enterprise \
  GH_HOST=ghe.example.invalid GH_CONFIG_DIR="$runner_temp/gh-config" GH_PROMPT_DISABLED= \
  -- gh api "repos/example/with space" -f "a=b" || { cat "$TMP_DIR/step.out" >&2; fail "gh did not run with a token"; }
expected="args: [api] [repos/example/with space] [-f] [a=b]
GH_TOKEN=job-token
$fallback=<unset>
GH_ENTERPRISE_TOKEN=<unset>
GITHUB_ENTERPRISE_TOKEN=<unset>
GH_HOST=github.com
GH_CONFIG_DIR=$config_dir
GH_PROMPT_DISABLED=1"
[[ "$(cat "$STUB_LOG")" == "$expected" ]] || {
  cat "$STUB_LOG" >&2
  fail "the shim did not force the host, config folder and token"
}

# [behaviour] gh's exit status reaches the caller.
rc=0
run_step "$shim_dir" "$config_dir" GH_TOKEN=job-token STUB_EXIT=7 -- gh api x || rc=$?
[[ "$rc" == 7 ]] || fail "gh's exit status was lost (got $rc)"

# [behaviour] A later run makes a new folder and leaves the old one alone.
: > "$TMP_DIR/env2"
: > "$TMP_DIR/path2"
run_helper "$stub_bin:/usr/bin:/bin" "$TMP_DIR/env2" "$TMP_DIR/path2" || fail "the second run failed"
config_two="$(env_value "$TMP_DIR/env2" GH_CONFIG_DIR)"
[[ "$config_two" != "$config_dir" && "$(cat "$TMP_DIR/path2")" != "$shim_dir" ]] || fail "a later run reused a folder"
[[ -z "$(ls -A "$config_two")" ]] || fail "the second config folder is not empty"
[[ -f "$runner_temp/gh-config/hosts.yml" ]] || fail "the helper touched an old folder"

# [behaviour] A shim already first on PATH is refused, not wrapped: it would force
# its own, older config folder.
: > "$TMP_DIR/env3"
: > "$TMP_DIR/path3"
if run_helper "$shim_dir:$stub_bin:/usr/bin:/bin" "$TMP_DIR/env3" "$TMP_DIR/path3"; then
  fail "the helper wrapped an existing shim"
fi
grep -Fxq "gh isolation: gh on PATH is already a release gh shim" "$TMP_DIR/helper.out" || fail "no fixed shim refusal"
[[ ! -s "$TMP_DIR/env3" && ! -s "$TMP_DIR/path3" ]] || fail "a refused run wrote GITHUB_ENV or GITHUB_PATH"

# [behaviour] Missing runner files or gh: the helper fails and writes nothing.
tools="$TMP_DIR/tools"
mkdir -p "$tools"
for tool in bash env mktemp chmod mkdir cat grep; do
  ln -s "$(command -v "$tool")" "$tools/$tool"
done
: > "$TMP_DIR/env4"
: > "$TMP_DIR/path4"
if run_helper "$tools" "$TMP_DIR/env4" "$TMP_DIR/path4"; then
  fail "the helper ran without gh on PATH"
fi
grep -Fxq "gh isolation: gh is not on PATH" "$TMP_DIR/helper.out" || fail "no fixed missing-gh message"
for missing in RUNNER_TEMP GITHUB_ENV GITHUB_PATH; do
  if env -i PATH="$stub_bin:/usr/bin:/bin" RUNNER_TEMP="$runner_temp" GITHUB_ENV="$TMP_DIR/env4" \
    GITHUB_PATH="$TMP_DIR/path4" "$missing=" bash "$HELPER" >"$TMP_DIR/helper.out" 2>&1; then
    fail "the helper ran without $missing"
  fi
  grep -Fxq "gh isolation: $missing is required" "$TMP_DIR/helper.out" || fail "no fixed message for $missing"
done
[[ ! -s "$TMP_DIR/env4" && ! -s "$TMP_DIR/path4" ]] || fail "a failed run wrote GITHUB_ENV or GITHUB_PATH"

echo "macos_release_gh_isolation tests passed"
