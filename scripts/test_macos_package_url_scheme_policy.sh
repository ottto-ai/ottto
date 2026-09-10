#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACKAGE_SCRIPT="$ROOT/scripts/macos_package.sh"
# shellcheck source=scripts/macos_bundle_url_scheme.sh
source "$ROOT/scripts/macos_bundle_url_scheme.sh"

if ! grep -Fq "source \"\$SCRIPT_DIR/macos_bundle_url_scheme.sh\"" "$PACKAGE_SCRIPT" || \
  ! grep -Fq "OTTTO_URL_TYPES_PLIST=\"\$(ottto_macos_url_types_plist \"\$CHANNEL\")\"" "$PACKAGE_SCRIPT"; then
  echo "macOS packaging must render the channel-gated URL scheme policy" >&2
  exit 1
fi

stable_plist="$(ottto_macos_url_types_plist stable)"
if [[ "$(grep -Fc '<key>CFBundleURLTypes</key>' <<<"$stable_plist")" -ne 1 ]]; then
  echo "stable macOS packages must declare URL types exactly once" >&2
  exit 1
fi
if [[ "$(grep -Fc '<string>ottto</string>' <<<"$stable_plist")" -ne 1 ]]; then
  echo "stable macOS packages must declare the production URL scheme exactly once" >&2
  exit 1
fi
for channel in dev preview stable-candidate; do
  if [[ -n "$(ottto_macos_url_types_plist "$channel")" ]]; then
    echo "$channel macOS packages must not register a URL scheme" >&2
    exit 1
  fi
done
if ottto_macos_url_types_plist unsupported >/dev/null 2>&1; then
  echo "unknown macOS package channels must be rejected" >&2
  exit 1
fi

echo "macOS package URL scheme policy tests passed"
