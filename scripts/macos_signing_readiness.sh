#!/usr/bin/env bash
set -euo pipefail

SIGN_IDENTITY="${OTTTO_MACOS_CODESIGN_IDENTITY:-}"
KEYCHAIN_PROFILE="${OTTTO_NOTARY_PROFILE:-}"
TEAM_ID="${OTTTO_COMPANION_TEAM_ID:-}"
HOST_ONLY="false"

usage() {
  cat <<'USAGE'
Usage: macos_signing_readiness.sh [options]

Checks whether this Mac is ready to build, notarize, staple, and Gatekeeper-test
stable Ottto macOS artifacts. The script reports missing local Apple signing
prerequisites without printing secrets.

Options:
  --sign-identity <identity>    Developer ID Application signing identity.
  --keychain-profile <profile>  notarytool keychain profile.
  --team-id <team-id>           Apple Developer Team ID expected in the identity.
  --host-only                   Check macOS signing tools without requiring credentials.
  -h, --help                    Show help.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sign-identity)
      SIGN_IDENTITY="${2:?--sign-identity requires a value}"
      shift 2
      ;;
    --keychain-profile)
      KEYCHAIN_PROFILE="${2:?--keychain-profile requires a value}"
      shift 2
      ;;
    --team-id)
      TEAM_ID="${2:?--team-id requires a value}"
      shift 2
      ;;
    --host-only)
      HOST_ONLY="true"
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

failures=0

pass() {
  printf 'ok: %s\n' "$1"
}

fail() {
  printf 'missing: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_command() {
  if command -v "$1" >/dev/null 2>&1; then
    pass "found $1"
  else
    fail "required command not found: $1"
  fi
}

if [[ "$(uname -s)" != "Darwin" ]]; then
  fail "stable macOS signing must run on macOS"
fi

require_command codesign
require_command security
require_command spctl
require_command xcrun

if xcrun --find notarytool >/dev/null 2>&1; then
  pass "notarytool is available"
else
  fail "xcrun notarytool is unavailable"
fi

if xcrun --find stapler >/dev/null 2>&1; then
  pass "stapler is available"
else
  fail "xcrun stapler is unavailable"
fi

if [[ "$HOST_ONLY" == "true" ]]; then
  if [[ "$failures" -gt 0 ]]; then
    echo "macOS signing host preflight failed with $failures issue(s)." >&2
    exit 1
  fi

  cat <<'NEXT'
macOS signing host preflight passed.

No Apple signing identity or notarytool profile was required for this check.
Run the full readiness check on the trusted signing Mac after creating and
installing the Developer ID Application certificate and storing notarization
credentials.
NEXT
  exit 0
fi

if [[ -z "$SIGN_IDENTITY" ]]; then
  fail "Developer ID identity is required; set OTTTO_MACOS_CODESIGN_IDENTITY or pass --sign-identity"
else
  identity_line="$(security find-identity -v -p codesigning 2>/dev/null | grep -F "$SIGN_IDENTITY" || true)"
  if [[ -z "$identity_line" ]]; then
    fail "Developer ID identity not found in the local keychain: $SIGN_IDENTITY"
  elif ! grep -q "Developer ID Application" <<<"$identity_line"; then
    fail "identity is not a Developer ID Application identity: $SIGN_IDENTITY"
  else
    pass "Developer ID Application identity is installed"
    if [[ -n "$TEAM_ID" ]]; then
      if grep -q "($TEAM_ID)" <<<"$identity_line"; then
        pass "Developer ID identity matches team $TEAM_ID"
      else
        fail "Developer ID identity does not include expected team id: $TEAM_ID"
      fi
    fi
  fi
fi

if [[ -z "$KEYCHAIN_PROFILE" ]]; then
  fail "notarytool keychain profile is required; set OTTTO_NOTARY_PROFILE or pass --keychain-profile"
elif ! xcrun --find notarytool >/dev/null 2>&1; then
  fail "xcrun notarytool is unavailable"
elif xcrun notarytool history --keychain-profile "$KEYCHAIN_PROFILE" >/dev/null 2>&1; then
  pass "notarytool keychain profile works"
else
  fail "notarytool keychain profile could not be used: $KEYCHAIN_PROFILE"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "macOS signing readiness failed with $failures issue(s)." >&2
  exit 1
fi

cat <<'NEXT'
macOS signing readiness passed.

Next stable release commands:
  ./scripts/macos_package.sh --version <version> --channel stable
  ./scripts/macos_notarize.sh --manifest dist/macos/release-manifest.json --keychain-profile "$OTTTO_NOTARY_PROFILE"
  ./scripts/macos_stable_preflight.sh --manifest dist/macos/release-manifest.json --sign-identity "$OTTTO_MACOS_CODESIGN_IDENTITY" --keychain-profile "$OTTTO_NOTARY_PROFILE"
NEXT
