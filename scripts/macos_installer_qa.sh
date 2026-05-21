#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_DIR="$ROOT/dist/macos"
PORT="${OTTTO_INSTALLER_QA_PORT:-8765}"
WAIT_SECONDS="${OTTTO_MACOS_LAUNCH_SMOKE_WAIT_SECONDS:-10}"

usage() {
  cat <<'USAGE'
Usage: macos_installer_qa.sh [options]

Serves a prebuilt macOS release directory over localhost, runs the generated
installer dry-run, installs into temporary directories, and launch-smokes the
installed Ottto.app.

Options:
  --release-dir <path>     Release directory. Default: dist/macos
  --port <port>            Local HTTP port. Default: 8765
  --wait-seconds <n>       Installed-app launch smoke window. Default: 10
  -h, --help               Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-dir)
      RELEASE_DIR="${2:?--release-dir requires a value}"
      shift 2
      ;;
    --port)
      PORT="${2:?--port requires a value}"
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

require_command curl
require_command jq
require_command python3

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "macOS installer QA can only run on Darwin." >&2
  exit 2
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 || "$PORT" -gt 65535 ]]; then
  echo "--port must be a TCP port" >&2
  exit 2
fi

RELEASE_DIR="$(cd "$RELEASE_DIR" && pwd)"
INSTALLER="$RELEASE_DIR/install-macos-dev.sh"
MANIFEST="$RELEASE_DIR/release-manifest.json"
if [[ ! -x "$INSTALLER" ]]; then
  echo "Generated installer is missing or not executable: $INSTALLER" >&2
  exit 1
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Release manifest is missing: $MANIFEST" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
SERVER_DIR="$TMP_DIR/release"
SERVER_PID=""
cleanup() {
  if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" >/dev/null 2>&1; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BASE_URL="http://127.0.0.1:$PORT"
mkdir -p "$SERVER_DIR"
find "$RELEASE_DIR" -maxdepth 1 -type f -exec cp {} "$SERVER_DIR/" \;
jq --arg base "$BASE_URL" '
  .artifacts |= map(
    .url = ($base + "/" + ((.path // .url) | split("/")[-1]))
  )
' "$MANIFEST" > "$SERVER_DIR/release-manifest.json"

python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$SERVER_DIR" \
  >"$TMP_DIR/http.log" 2>&1 &
SERVER_PID="$!"
sleep 0.2
if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
  cat "$TMP_DIR/http.log" >&2
  exit 1
fi

for _ in $(seq 1 50); do
  if curl -fsS "$BASE_URL/release-manifest.json" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl -fsS "$BASE_URL/release-manifest.json" >/dev/null

APP_DIR="$TMP_DIR/Applications"
BIN_DIR="$TMP_DIR/bin"
mkdir -p "$APP_DIR" "$BIN_DIR"

OTTTO_LOCAL_PLATFORM_RELEASE_URL="$BASE_URL" \
  "$INSTALLER" \
  --app-dir "$APP_DIR" \
  --bin-dir "$BIN_DIR" \
  --no-bootstrap \
  --no-open \
  --dry-run >/dev/null

OTTTO_LOCAL_PLATFORM_RELEASE_URL="$BASE_URL" \
  "$INSTALLER" \
  --app-dir "$APP_DIR" \
  --bin-dir "$BIN_DIR" \
  --no-bootstrap \
  --no-open >/dev/null

"$ROOT/scripts/macos_launch_smoke.sh" \
  --app "$APP_DIR/Ottto.app" \
  --wait-seconds "$WAIT_SECONDS" \
  --output "$TMP_DIR/installed-app-launch-smoke.json" >/dev/null

echo "macOS installer QA passed for $RELEASE_DIR"
