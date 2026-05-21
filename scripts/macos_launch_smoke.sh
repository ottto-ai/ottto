#!/usr/bin/env bash
set -euo pipefail

APP=""
OUTPUT=""
WAIT_SECONDS="${OTTTO_MACOS_LAUNCH_SMOKE_WAIT_SECONDS:-10}"

usage() {
  cat <<'USAGE'
Usage: macos_launch_smoke.sh --app <Ottto.app> --output <evidence.json> [options]

Launches a packaged macOS app, verifies it survives a short startup window,
records redacted JSON evidence, then terminates the process.

Options:
  --app <path>            Packaged .app bundle to launch.
  --output <path>         JSON evidence output path.
  --wait-seconds <n>      Startup survival window. Default: 10.
  -h, --help             Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --app)
      APP="${2:?--app requires a value}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?--output requires a value}"
      shift 2
      ;;
    --wait-seconds)
      WAIT_SECONDS="${2:?--wait-seconds requires a value}"
      shift 2
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

require_command jq
require_command plutil

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS launch smoke can only run on Darwin." >&2
  exit 2
fi
if [[ -z "$APP" || -z "$OUTPUT" ]]; then
  usage >&2
  exit 2
fi
if ! [[ "$WAIT_SECONDS" =~ ^[0-9]+$ ]] || [[ "$WAIT_SECONDS" -lt 1 ]]; then
  echo "--wait-seconds must be a positive integer" >&2
  exit 2
fi
if [[ ! -d "$APP" ]]; then
  echo "App bundle does not exist: $APP" >&2
  exit 1
fi

INFO_PLIST="$APP/Contents/Info.plist"
if [[ ! -f "$INFO_PLIST" ]]; then
  echo "App bundle is missing Info.plist: $APP" >&2
  exit 1
fi

plist_value() {
  local key="$1"
  plutil -extract "$key" raw -o - "$INFO_PLIST" 2>/dev/null || true
}

EXECUTABLE_NAME="$(plist_value CFBundleExecutable)"
BUNDLE_ID="$(plist_value CFBundleIdentifier)"
BUNDLE_VERSION="$(plist_value CFBundleVersion)"
BUNDLE_SHORT_VERSION="$(plist_value CFBundleShortVersionString)"

if [[ -z "$EXECUTABLE_NAME" ]]; then
  echo "Info.plist is missing CFBundleExecutable: $INFO_PLIST" >&2
  exit 1
fi

EXECUTABLE="$APP/Contents/MacOS/$EXECUTABLE_NAME"
if [[ ! -x "$EXECUTABLE" ]]; then
  echo "App executable is missing or not executable: $EXECUTABLE" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUTPUT")"
TMP_DIR="$(mktemp -d)"
MARKER="$TMP_DIR/launch-start.marker"
REPORTS_FILE="$TMP_DIR/crash-reports.txt"
STDOUT_LOG="$TMP_DIR/stdout.log"
STDERR_LOG="$TMP_DIR/stderr.log"
touch "$MARKER"

PID=""
cleanup() {
  if [[ -n "$PID" ]] && kill -0 "$PID" >/dev/null 2>&1; then
    disown "$PID" 2>/dev/null || true
    kill "$PID" >/dev/null 2>&1 || true
    for ((attempt = 0; attempt < 20; attempt += 1)); do
      if ! kill -0 "$PID" >/dev/null 2>&1; then
        break
      fi
      sleep 0.1
    done
    kill -9 "$PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

CHECKED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
OTTTO_SKIP_BUNDLED_AGENT_REGISTRATION=1 "$EXECUTABLE" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
PID="$!"

PROCESS_SURVIVED="false"
EXIT_CODE_JSON="null"
deadline=$((SECONDS + WAIT_SECONDS))
while (( SECONDS < deadline )); do
  if ! kill -0 "$PID" >/dev/null 2>&1; then
    set +e
    wait "$PID"
    exit_code="$?"
    set -e
    EXIT_CODE_JSON="$exit_code"
    break
  fi
  sleep 0.2
done

if kill -0 "$PID" >/dev/null 2>&1; then
  PROCESS_SURVIVED="true"
fi

# CrashReporter can lag process exit slightly; give it a short window before
# deciding that no new diagnostic report was created for this launch attempt.
sleep 0.75
: > "$REPORTS_FILE"
DIAGNOSTIC_DIR="$HOME/Library/Logs/DiagnosticReports"
if [[ -d "$DIAGNOSTIC_DIR" ]]; then
  find "$DIAGNOSTIC_DIR" -type f \
    \( -name "${EXECUTABLE_NAME}_*.crash" -o -name "${EXECUTABLE_NAME}_*.ips" \) \
    -newer "$MARKER" -print 2>/dev/null \
    | sort \
    | while IFS= read -r report; do basename "$report"; done \
    | head -5 > "$REPORTS_FILE"
fi

CRASH_REPORTS_JSON="$(jq -R -s 'split("\n") | map(select(length > 0))' "$REPORTS_FILE")"
CRASH_REPORT_COUNT="$(jq 'length' <<<"$CRASH_REPORTS_JSON")"
STATUS="passed"
if [[ "$PROCESS_SURVIVED" != "true" || "$CRASH_REPORT_COUNT" != "0" ]]; then
  STATUS="failed"
fi

jq -n \
  --arg gate "packaged_app_launch" \
  --arg status "$STATUS" \
  --arg checked_at "$CHECKED_AT" \
  --arg app_path "$APP" \
  --arg bundle_id "$BUNDLE_ID" \
  --arg bundle_version "$BUNDLE_VERSION" \
  --arg bundle_short_version "$BUNDLE_SHORT_VERSION" \
  --arg executable_name "$EXECUTABLE_NAME" \
  --argjson wait_seconds "$WAIT_SECONDS" \
  --argjson process_survived_wait "$PROCESS_SURVIVED" \
  --argjson exit_code "$EXIT_CODE_JSON" \
  --argjson crash_reports "$CRASH_REPORTS_JSON" \
  '{
    schema_version: 1,
    gate: $gate,
    status: $status,
    checked_at: $checked_at,
    app_path: $app_path,
    bundle_id: $bundle_id,
    bundle_version: $bundle_version,
    bundle_short_version: $bundle_short_version,
    executable_name: $executable_name,
    wait_seconds: $wait_seconds,
    process_survived_wait: $process_survived_wait,
    exit_code: $exit_code,
    crash_reports: $crash_reports
  }' > "$OUTPUT"

if [[ "$STATUS" != "passed" ]]; then
  echo "Packaged app launch smoke failed for $APP; evidence: $OUTPUT" >&2
  exit 1
fi

echo "Packaged app launch smoke passed for $APP; evidence: $OUTPUT"
