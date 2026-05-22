#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NOTARIZE="$ROOT/scripts/macos_notarize.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

require_command jq
require_command shasum

FAKE_BIN="$TMP_DIR/bin"
mkdir -p "$FAKE_BIN"

cat > "$FAKE_BIN/xcrun" <<'SH'
#!/usr/bin/env sh
printf 'xcrun %s\n' "$*" >> "$OTTTO_NOTARIZE_TEST_LOG"
exit 0
SH
chmod +x "$FAKE_BIN/xcrun"

cat > "$FAKE_BIN/codesign" <<'SH'
#!/usr/bin/env sh
printf 'codesign %s\n' "$*" >> "$OTTTO_NOTARIZE_TEST_LOG"
exit 0
SH
chmod +x "$FAKE_BIN/codesign"

cat > "$FAKE_BIN/spctl" <<'SH'
#!/usr/bin/env sh
printf 'spctl %s\n' "$*" >> "$OTTTO_NOTARIZE_TEST_LOG"
exit 0
SH
chmod +x "$FAKE_BIN/spctl"

make_artifact() {
  local path="$1"
  printf 'artifact:%s\n' "$(basename "$path")" > "$path"
}

APP_DMG="$TMP_DIR/Ottto-macos-arm64.dmg"
APP_BUNDLE="$TMP_DIR/Ottto.app"
CLI_ZIP="$TMP_DIR/ottto-macos-arm64.zip"
CLI_BIN="$TMP_DIR/ottto"
DAEMON_ZIP="$TMP_DIR/ottto-service-macos-arm64.zip"
DAEMON_BIN="$TMP_DIR/ottto-service"
mkdir -p "$APP_BUNDLE"
make_artifact "$APP_DMG"
make_artifact "$APP_BUNDLE/Ottto"
make_artifact "$CLI_ZIP"
make_artifact "$CLI_BIN"
make_artifact "$DAEMON_ZIP"
make_artifact "$DAEMON_BIN"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

write_manifest() {
  local manifest="$1"
  jq -n \
    --arg app_dmg "$APP_DMG" \
    --arg app_bundle "$APP_BUNDLE" \
    --arg app_sha "$(sha256_file "$APP_DMG")" \
    --arg cli_zip "$CLI_ZIP" \
    --arg cli_bin "$CLI_BIN" \
    --arg cli_sha "$(sha256_file "$CLI_ZIP")" \
    --arg daemon_zip "$DAEMON_ZIP" \
    --arg daemon_bin "$DAEMON_BIN" \
    --arg daemon_sha "$(sha256_file "$DAEMON_ZIP")" \
    '{
      schema_version: 1,
      product: "ottto-local-platform",
      version: "0.1.0",
      channel: "stable",
      commit: "abcdef123456",
      generated_at: "2026-05-20T00:00:00Z",
      artifacts: [
        {
          name: "Ottto.app",
          kind: "macos_app",
          platform: "macos",
          arch: "arm64",
          path: $app_dmg,
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/Ottto-macos-arm64.dmg",
          verification_path: $app_bundle,
          sha256: $app_sha,
          signed: true,
          notarized: false,
          gatekeeper_assessed: false
        },
        {
          name: "ottto",
          kind: "cli",
          platform: "macos",
          arch: "arm64",
          path: $cli_zip,
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-macos-arm64.zip",
          verification_path: $cli_bin,
          sha256: $cli_sha,
          signed: true,
          notarized: false,
          gatekeeper_assessed: false
        },
        {
          name: "ottto-service",
          kind: "daemon",
          platform: "macos",
          arch: "arm64",
          path: $daemon_zip,
          url: "https://install.ottto.net/ottto-local-platform/releases/stable/0.1.0/ottto-service-macos-arm64.zip",
          verification_path: $daemon_bin,
          sha256: $daemon_sha,
          signed: true,
          notarized: false,
          gatekeeper_assessed: false
        }
      ]
    }' > "$manifest"
}

MANIFEST="$TMP_DIR/release-manifest.json"
LOG="$TMP_DIR/commands.log"
write_manifest "$MANIFEST"

OTTTO_NOTARIZE_TEST_LOG="$LOG" \
  PATH="$FAKE_BIN:$PATH" \
  "$NOTARIZE" \
    --manifest "$MANIFEST" \
    --keychain-profile TEST_PROFILE \
    --artifact-kind cli \
    --artifact-name ottto-service >/dev/null

if [[ "$(jq -r '.artifacts[0].notarized' "$MANIFEST")" != "false" ]]; then
  echo "Expected unselected app artifact to remain not notarized" >&2
  exit 1
fi
if [[ "$(jq -r '.artifacts[1].notarized' "$MANIFEST")" != "true" ]]; then
  echo "Expected CLI artifact to be marked notarized" >&2
  exit 1
fi
if [[ "$(jq -r '.artifacts[2].gatekeeper_assessed' "$MANIFEST")" != "true" ]]; then
  echo "Expected daemon artifact to be marked Gatekeeper assessed" >&2
  exit 1
fi
if grep -q "Ottto-macos-arm64.dmg" "$LOG"; then
  echo "Expected artifact filter to avoid resubmitting app DMG" >&2
  exit 1
fi
if ! grep -q "ottto-macos-arm64.zip" "$LOG"; then
  echo "Expected artifact filter to submit CLI ZIP" >&2
  exit 1
fi
if ! grep -q "ottto-service-macos-arm64.zip" "$LOG"; then
  echo "Expected artifact filter to submit daemon ZIP" >&2
  exit 1
fi
if ! grep -q "spctl --assess --type install .*ottto$" "$LOG"; then
  echo "Expected CLI Gatekeeper assessment to use install policy" >&2
  exit 1
fi
if ! grep -q "spctl --assess --type install .*ottto-service$" "$LOG"; then
  echo "Expected daemon Gatekeeper assessment to use install policy" >&2
  exit 1
fi

NO_MATCH_MANIFEST="$TMP_DIR/no-match-manifest.json"
write_manifest "$NO_MATCH_MANIFEST"
if OTTTO_NOTARIZE_TEST_LOG="$TMP_DIR/no-match.log" \
  PATH="$FAKE_BIN:$PATH" \
  "$NOTARIZE" \
    --manifest "$NO_MATCH_MANIFEST" \
    --keychain-profile TEST_PROFILE \
    --artifact-name missing >/dev/null 2>&1; then
  echo "Expected missing artifact filter to fail" >&2
  exit 1
fi

VALIDATE_ONLY_MANIFEST="$TMP_DIR/validate-only-manifest.json"
VALIDATE_ONLY_LOG="$TMP_DIR/validate-only.log"
write_manifest "$VALIDATE_ONLY_MANIFEST"
OTTTO_NOTARIZE_TEST_LOG="$VALIDATE_ONLY_LOG" \
  PATH="$FAKE_BIN:$PATH" \
  "$NOTARIZE" \
    --manifest "$VALIDATE_ONLY_MANIFEST" \
    --artifact-name Ottto.app \
    --validate-only >/dev/null

if grep -q "notarytool submit" "$VALIDATE_ONLY_LOG"; then
  echo "Expected validate-only mode not to submit to notarytool" >&2
  exit 1
fi
if ! grep -q "stapler staple .*Ottto-macos-arm64.dmg" "$VALIDATE_ONLY_LOG"; then
  echo "Expected validate-only mode to staple the selected app DMG" >&2
  exit 1
fi
if ! grep -q "spctl --assess --type execute .*Ottto.app$" "$VALIDATE_ONLY_LOG"; then
  echo "Expected app Gatekeeper assessment to use execute policy" >&2
  exit 1
fi
if [[ "$(jq -r '.artifacts[0].notarized' "$VALIDATE_ONLY_MANIFEST")" != "true" ]]; then
  echo "Expected validate-only app artifact to be marked notarized" >&2
  exit 1
fi
if [[ "$(jq -r '.artifacts[1].notarized' "$VALIDATE_ONLY_MANIFEST")" != "false" ]]; then
  echo "Expected unselected CLI artifact to remain not notarized" >&2
  exit 1
fi

echo "macos_notarize artifact filter tests passed"
