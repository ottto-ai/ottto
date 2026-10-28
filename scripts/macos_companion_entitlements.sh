#!/usr/bin/env bash

# The Companion app executable is the only code signed with an entitlement
# plist. The plist lives in the private app subtree (tools/ottto-macos-app),
# so the dev build and this release packager sign the same permission
# surface. It may grant exactly one thing: sending Apple Events, which the
# "Terminal folder" action uses to read the front terminal tab's folder, and
# Claude Code sign-in uses to open Terminal, after the person allows
# Automation. No App Sandbox, no Accessibility, and never on
# the bundled ottto CLI, ottto-service or Sparkle helpers.
OTTTO_MACOS_COMPANION_ENTITLEMENT_KEY="com.apple.security.automation.apple-events"
# shellcheck disable=SC2034 # read by the sourcing packager and its tests
OTTTO_MACOS_APPLE_EVENTS_USAGE="Ottto reads the folder in your selected terminal tab when you choose Terminal folder, and opens Terminal when you sign in to Claude Code."

ottto_macos_check_companion_entitlements() {
  local plist="${1:-}"
  local json
  if [[ -z "$plist" || ! -f "$plist" || -L "$plist" ]]; then
    echo "Companion entitlements plist is missing: $plist" >&2
    return 1
  fi
  if ! plutil -lint -s "$plist" >/dev/null 2>&1; then
    echo "Companion entitlements plist is not a valid property list: $plist" >&2
    return 1
  fi
  if ! json="$(plutil -convert json -o - -- "$plist" 2>/dev/null)"; then
    echo "Companion entitlements plist could not be read: $plist" >&2
    return 1
  fi
  if ! jq -e --arg key "$OTTTO_MACOS_COMPANION_ENTITLEMENT_KEY" \
    'type == "object" and keys == [$key] and .[$key] == true' <<<"$json" >/dev/null; then
    echo "Companion entitlements must grant only $OTTTO_MACOS_COMPANION_ENTITLEMENT_KEY = true" >&2
    return 1
  fi
}

# Prints the signed entitlement keys of a code path as a sorted JSON array.
ottto_macos_signed_entitlement_keys() {
  local code="${1:-}"
  local xml
  # A codesign failure is an error, never "no entitlements".
  if ! xml="$(codesign -d --entitlements - --xml "$code" 2>/dev/null)"; then
    echo "Could not read the code signature of $code" >&2
    return 1
  fi
  if [[ -z "$xml" ]]; then
    printf '[]\n'
    return 0
  fi
  plutil -convert json -o - - <<<"$xml" | jq -c 'keys'
}
