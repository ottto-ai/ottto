#!/usr/bin/env bash
set -euo pipefail

APP_TARGET="$HOME/Applications/Ottto.app"
CLI_TARGET="$HOME/.ottto/bin/ottto"
DAEMON_TARGET="$HOME/.ottto/bin/ottto-service"
LAUNCH_AGENT_LABEL="net.ottto.service"
CLAIM_CODE="${OTTTO_DEV_E2E_CLAIM_CODE:-}"
API_BASE_URL="${OTTTO_API_BASE_URL:-}"
SKIP_APP_LAUNCH="false"

usage() {
  cat <<'USAGE'
Usage: dev_e2e_smoke.sh [options]

Runs the installed macOS dev/preview Ottto local-platform smoke after a dev
install. It validates the app bundle, Rust CLI, per-user daemon LaunchAgent,
real setup-run claim handoff when a claim is provided, source verification, and
diagnostics redaction.

Options:
  --app <path>             Installed Ottto.app path. Default: ~/Applications/Ottto.app
  --cli <path>             Installed ottto CLI path. Default: ~/.ottto/bin/ottto
  --daemon <path>          Installed ottto-service path. Default: ~/.ottto/bin/ottto-service
  --label <launchd-label>  LaunchAgent label. Default: net.ottto.service
  --claim-code <code>      Real setup claim code to attach. Default: OTTTO_DEV_E2E_CLAIM_CODE or skipped.
  --api-base-url <url>     Backend API base for claim attach. Default: OTTTO_API_BASE_URL or CLI default.
  --skip-app-launch        Validate the app bundle without opening it.
  -h, --help               Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)
      APP_TARGET="${2:?--app requires a value}"
      shift 2
      ;;
    --cli)
      CLI_TARGET="${2:?--cli requires a value}"
      shift 2
      ;;
    --daemon)
      DAEMON_TARGET="${2:?--daemon requires a value}"
      shift 2
      ;;
    --label)
      LAUNCH_AGENT_LABEL="${2:?--label requires a value}"
      shift 2
      ;;
    --claim-code)
      CLAIM_CODE="${2:?--claim-code requires a value}"
      shift 2
      ;;
    --api-base-url)
      API_BASE_URL="${2:?--api-base-url requires a value}"
      shift 2
      ;;
    --skip-app-launch)
      SKIP_APP_LAUNCH="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

pass() {
  echo "ok - $1"
}

fail() {
  echo "not ok - $1" >&2
  exit 1
}

json_assert() {
  local file="$1"
  local expression="$2"
  local description="$3"
  local failure_dump="${4:-full}"

  if jq -e "$expression" "$file" >/dev/null; then
    pass "$description"
  else
    echo "JSON assertion failed: $description" >&2
    if [[ "$failure_dump" == "full" ]]; then
      jq . "$file" >&2
    else
      echo "JSON output omitted because it may contain machine identifiers or local diagnostics." >&2
    fi
    exit 1
  fi
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "macOS is required for the local-platform dev E2E smoke"
fi

require_command jq
require_command launchctl
require_command open
require_command pgrep
require_command sw_vers

if [[ ! -x /usr/libexec/PlistBuddy ]]; then
  fail "PlistBuddy is required at /usr/libexec/PlistBuddy"
fi

[[ -d "$APP_TARGET" ]] || fail "app bundle exists at $APP_TARGET"
[[ -x "$CLI_TARGET" ]] || fail "CLI is executable at $CLI_TARGET"
[[ -x "$DAEMON_TARGET" ]] || fail "daemon is executable at $DAEMON_TARGET"

pass "installed artifacts exist"

app_executable="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP_TARGET/Contents/Info.plist")"
[[ -n "$app_executable" ]] || fail "app bundle declares CFBundleExecutable"
[[ -x "$APP_TARGET/Contents/MacOS/$app_executable" ]] || fail "app executable exists in bundle"
pass "app bundle executable is $app_executable"

uid="$(id -u)"
launch_domain="gui/$uid/$LAUNCH_AGENT_LABEL"
launchctl print "$launch_domain" >/dev/null || fail "LaunchAgent $launch_domain is loaded"
pass "LaunchAgent $launch_domain is loaded"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

status_json="$tmp_dir/status.json"
"$CLI_TARGET" doctor --json > "$status_json"
json_assert "$status_json" \
  '.daemon == "running" and (.protocol_version | type == "number" and . >= 5) and .machine.os == "macos" and (.machine.arch | type == "string" and length > 0)' \
  "CLI doctor reaches ottto-service and returns current macOS machine status"
json_assert "$status_json" \
  '.update.channel == "dev" or .update.channel == "preview" or .update.channel == "stable-candidate"' \
  "installed build is a dev/preview/stable-candidate channel, not stable"

if [[ -n "$CLAIM_CODE" ]]; then
  setup_json="$tmp_dir/setup.json"
  setup_args=(setup --claim-code "$CLAIM_CODE" --json)
  if [[ -n "$API_BASE_URL" ]]; then
    setup_args+=(--api-base-url "$API_BASE_URL")
  fi
  "$CLI_TARGET" "${setup_args[@]}" > "$setup_json"
  json_assert "$setup_json" \
    '.claim_code_provided == true and (.setup_run_id | type == "string" and length > 0) and (.detected_sources | type == "array") and (.actions | type == "array") and (.status == "waiting_for_user" or .status == "waiting_for_companion" or .status == "running_action" or .status == "completed")' \
    "setup claim handoff attaches, scans, and returns the real setup-run contract"
  if grep -F "$CLAIM_CODE" "$setup_json" >/dev/null; then
    fail "setup output leaked the raw claim code"
  fi
  pass "setup output does not leak the raw claim code"
else
  pass "setup claim handoff skipped; pass --claim-code to exercise real setup-run attach"
fi

verify_json="$tmp_dir/verify-codex.json"
"$CLI_TARGET" verify --source codex --json > "$verify_json"
json_assert "$verify_json" \
  '.source == "codex" and (.status == "account_not_connected" or .status == "reconnect_required" or .status == "verified" or .status == "no_fresh_telemetry" or .status == "failed") and (.message.text | type == "string" and length > 0)' \
  "Codex verification command returns an actionable stable agent JSON contract"

diagnostics_json="$tmp_dir/diagnostics.json"
"$CLI_TARGET" diagnostics collect --json > "$diagnostics_json"
json_assert "$diagnostics_json" \
  '(
    (.auth_header == "[REDACTED]" and .daemon_state == "Running")
    or
    (
      ([.sections[]? | select(.name == "security") | .items.auth_header] | first) == "[REDACTED]"
      and
      ([.sections[]? | select(.name == "runtime") | .items.daemon_state] | first) == "Running"
    )
  )' \
  "diagnostics output redacts auth material" \
  redacted
python3 - "$diagnostics_json" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))

patterns = [
    r"bearer\s+[A-Za-z0-9._~+/=-]{12,}",
    r"password\s*[:=]\s*['\"]?[^,'\"\s}]{6,}",
    r"claim_[A-Za-z0-9_-]{8,}",
    r"[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
]


def string_values(value):
    if isinstance(value, dict):
        for child in value.values():
            yield from string_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from string_values(child)
    elif isinstance(value, str):
        yield value


for string in string_values(payload):
    for pattern in patterns:
        if re.search(pattern, string, flags=re.IGNORECASE):
            print("diagnostics output contains unredacted sensitive-looking material", file=sys.stderr)
            sys.exit(1)
PY
if [[ -n "$CLAIM_CODE" ]] && grep -F "$CLAIM_CODE" "$diagnostics_json" >/dev/null; then
  fail "diagnostics output contains the raw claim code"
fi
pass "diagnostics output has no obvious sensitive material"

if [[ "$SKIP_APP_LAUNCH" != "true" ]]; then
  open -gj "$APP_TARGET"
  for _ in $(seq 1 20); do
    if pgrep -x "$app_executable" >/dev/null; then
      pass "Ottto app process is running"
      break
    fi
    sleep 0.5
  done
  pgrep -x "$app_executable" >/dev/null || fail "Ottto app process started"
else
  pass "app launch skipped by request"
fi

echo "Ottto local platform dev E2E smoke passed on macOS $(sw_vers -productVersion)."
