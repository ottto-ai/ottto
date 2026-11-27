#!/usr/bin/env bash
# Usage: macos_release_gh_isolation.sh
#
# Makes every later gh call of the macOS stable release job use only the job
# token (docs/release-verification.md, "Release host runner"). The workflow runs
# it once, as an unconditional step right after checkout. It:
# - makes a fresh folder under RUNNER_TEMP (mktemp -d) holding an empty gh
#   config folder and a bin folder;
# - resolves the real gh once and writes a gh shim into the bin folder;
# - prepends the bin folder to PATH for later steps (GITHUB_PATH) and sets
#   GH_CONFIG_DIR, GH_PROMPT_DISABLED=1 and GH_HOST=github.com (GITHUB_ENV).
#
# The shim refuses (exit 4, one fixed line, gh never runs) unless GH_TOKEN is
# non-empty. Otherwise it drops GITHUB_TOKEN, GH_ENTERPRISE_TOKEN and
# GITHUB_ENTERPRISE_TOKEN, forces GH_HOST, GH_CONFIG_DIR and GH_PROMPT_DISABLED, and
# runs the real gh with the same arguments. A gh call by name, from a step or any
# script it runs, reaches the shim; only an absolute path to gh would not, and
# scripts/test_workflow_gh_token.py rejects one. Output is fixed lines only.
set -euo pipefail

SHIM_MARKER="# macos_release_gh_isolation.sh shim"

fail() {
  echo "gh isolation: $*" >&2
  exit 1
}

for name in RUNNER_TEMP GITHUB_ENV GITHUB_PATH; do
  [[ -n "${!name:-}" ]] || fail "$name is required"
done
[[ "$RUNNER_TEMP" == /* && -d "$RUNNER_TEMP" ]] || fail "RUNNER_TEMP must be an absolute folder"

real_gh="$(type -P gh)" || fail "gh is not on PATH"
[[ "$real_gh" == /* ]] || fail "gh must resolve to an absolute path"
# A shim from another run would force its own, older config folder.
if LC_ALL=C grep -Fq "$SHIM_MARKER" "$real_gh" 2>/dev/null; then
  fail "gh on PATH is already a release gh shim"
fi

root="$(mktemp -d "$RUNNER_TEMP/gh-isolation.XXXXXXXX" 2>/dev/null)" ||
  fail "could not make a folder under RUNNER_TEMP"
case "$root" in
  *$'\n'*) fail "the folder name has a line break" ;;
esac
config="$root/config"
bin="$root/bin"
{ chmod 700 "$root" && mkdir -m 700 "$config" "$bin"; } 2>/dev/null ||
  fail "could not make the gh folders"

cat > "$bin/gh" <<SHIM
#!/bin/bash
$SHIM_MARKER
if [ -z "\${GH_TOKEN:-}" ]; then
  echo "gh: refused: this step sets no GH_TOKEN; release steps run gh with the job token only." >&2
  exit 4
fi
unset GITHUB_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN
export GH_HOST=github.com GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1
export GH_CONFIG_DIR=$(printf '%q' "$config")
exec $(printf '%q' "$real_gh") "\$@"
SHIM
chmod 500 "$bin/gh"

printf 'GH_CONFIG_DIR=%s\nGH_PROMPT_DISABLED=1\nGH_HOST=github.com\n' "$config" >> "$GITHUB_ENV"
printf '%s\n' "$bin" >> "$GITHUB_PATH"
echo "gh isolation: ok"
