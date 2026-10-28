#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_SCRIPT="$ROOT/scripts/macos_package.sh"
# shellcheck source=scripts/macos_companion_entitlements.sh
source "$ROOT/scripts/macos_companion_entitlements.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "$*" >&2
  exit 1
}

write_plist() {
  local path="$1"
  local body="$2"
  cat >"$path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
$body
</dict>
</plist>
PLIST
}

valid="$TMP_DIR/valid.plist"
write_plist "$valid" "  <key>com.apple.security.automation.apple-events</key>
  <true/>"
ottto_macos_check_companion_entitlements "$valid" || fail "the Apple Events entitlement alone must be accepted"

reject() {
  local name="$1"
  local path="$2"
  if ottto_macos_check_companion_entitlements "$path" 2>/dev/null; then
    fail "Companion entitlements must reject $name"
  fi
}
write_plist "$TMP_DIR/sandbox.plist" "  <key>com.apple.security.automation.apple-events</key>
  <true/>
  <key>com.apple.security.app-sandbox</key>
  <true/>"
reject "an extra App Sandbox key" "$TMP_DIR/sandbox.plist"
write_plist "$TMP_DIR/false.plist" "  <key>com.apple.security.automation.apple-events</key>
  <false/>"
reject "a false value" "$TMP_DIR/false.plist"
write_plist "$TMP_DIR/other.plist" "  <key>com.apple.security.cs.disable-library-validation</key>
  <true/>"
reject "another entitlement" "$TMP_DIR/other.plist"
write_plist "$TMP_DIR/empty.plist" ""
reject "an empty plist" "$TMP_DIR/empty.plist"
printf 'not a plist' >"$TMP_DIR/garbage.plist"
reject "a malformed file" "$TMP_DIR/garbage.plist"
reject "a missing file" "$TMP_DIR/missing.plist"
ln -s "$valid" "$TMP_DIR/link.plist"
reject "a symlink" "$TMP_DIR/link.plist"

# Signing: the entitlement lands only where it is passed.
cp /usr/bin/true "$TMP_DIR/companion"
cp /usr/bin/true "$TMP_DIR/helper"
codesign --force --entitlements "$valid" --sign - "$TMP_DIR/companion" >/dev/null 2>&1
codesign --force --sign - "$TMP_DIR/helper" >/dev/null 2>&1
[[ "$(ottto_macos_signed_entitlement_keys "$TMP_DIR/companion")" == "[\"$OTTTO_MACOS_COMPANION_ENTITLEMENT_KEY\"]" ]] ||
  fail "signed Companion entitlements were not read back"
[[ "$(ottto_macos_signed_entitlement_keys "$TMP_DIR/helper")" == "[]" ]] ||
  fail "a helper signed without entitlements must report none"
printf 'not code' >"$TMP_DIR/unsigned"
if ottto_macos_signed_entitlement_keys "$TMP_DIR/unsigned" >/dev/null 2>&1; then
  fail "an unreadable signature must fail, not report no entitlements"
fi

# The packager consumes the shared plist for the Companion only.
# shellcheck disable=SC2016
{
  grep -Fq 'source "$SCRIPT_DIR/macos_companion_entitlements.sh"' "$PACKAGE_SCRIPT" ||
    fail "macOS packaging must source the Companion entitlement policy"
  grep -Fq 'COMPANION_ENTITLEMENTS="$MAC_APP_ROOT/Companion.entitlements.plist"' "$PACKAGE_SCRIPT" ||
    fail "macOS packaging must read the shared Companion entitlements from the app subtree"
  grep -Fq 'ls-files --error-unmatch -- "$MAC_APP_SOURCE_PATH/Companion.entitlements.plist"' "$PACKAGE_SCRIPT" ||
    fail "macOS packaging must require the Companion entitlements to be tracked at the source commit"
  grep -Fq 'ottto_macos_check_companion_entitlements "$COMPANION_ENTITLEMENTS"' "$PACKAGE_SCRIPT" ||
    fail "macOS packaging must validate the Companion entitlements before building"
  [[ "$(grep -c -- '--entitlements "$COMPANION_ENTITLEMENTS"' "$PACKAGE_SCRIPT")" -eq 2 ]] ||
    fail "only sign_companion (signed and ad-hoc) may pass the Companion entitlements"
  [[ "$(grep -c -- '--entitlements' "$PACKAGE_SCRIPT")" -eq 2 ]] ||
    fail "no other signing call may pass an entitlements plist"
  for target in '"$APP_MACOS/Ottto"' '"$APP_BUNDLE"'; do
    grep -Fxq "sign_companion $target" "$PACKAGE_SCRIPT" || fail "Companion target must use sign_companion: $target"
  done
  for target in '"$APP_HELPERS/ottto"' '"$APP_HELPERS/ottto-service"' '"$OUTPUT_DIR/ottto"' '"$OUTPUT_DIR/ottto-service"'; do
    grep -Fxq "sign_code $target" "$PACKAGE_SCRIPT" || fail "helper must stay on sign_code: $target"
  done
  grep -Fq 'ottto_macos_signed_entitlement_keys "$APP_BUNDLE"' "$PACKAGE_SCRIPT" ||
    fail "macOS packaging must verify the signed app entitlements"
  if ! grep -Fq '<key>NSAppleEventsUsageDescription</key>' "$PACKAGE_SCRIPT" ||
    ! grep -Fq '<string>${OTTTO_MACOS_APPLE_EVENTS_USAGE}</string>' "$PACKAGE_SCRIPT"; then
    fail "the packaged Info.plist must explain Apple Events use"
  fi
}
[[ "$OTTTO_MACOS_APPLE_EVENTS_USAGE" == "Ottto reads the folder in your selected terminal tab when you choose Terminal folder, and opens Terminal when you sign in to Claude Code." ]] ||
  fail "Apple Events usage text changed; update the private dev build to match"

echo "macOS Companion entitlement policy tests passed"
