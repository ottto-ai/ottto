#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECK="$ROOT/scripts/macos_signing_readiness.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

stub_bin="$TMP_DIR/bin"
mkdir -p "$stub_bin"

cat > "$stub_bin/uname" <<'SH'
#!/usr/bin/env sh
if [ "$1" = "-s" ]; then
  echo Darwin
else
  echo arm64
fi
SH

cat > "$stub_bin/security" <<'SH'
#!/usr/bin/env sh
if [ "$1" = "find-identity" ]; then
  printf '  1) ABCDEF "Developer ID Application: Ottto Inc (TEAM123)"\n'
  printf '  2) 123456 "Apple Development: Ottto Inc (TEAM123)"\n'
  exit 0
fi
exit 1
SH

cat > "$stub_bin/xcrun" <<'SH'
#!/usr/bin/env sh
if [ "$1" = "--find" ] && { [ "$2" = "notarytool" ] || [ "$2" = "stapler" ]; }; then
  exit 0
fi
if [ "$1" = "notarytool" ] && [ "$2" = "history" ]; then
  shift 2
  if [ "$1" = "--keychain-profile" ] && [ "$2" = "GOOD_PROFILE" ]; then
    exit 0
  fi
  exit 1
fi
exit 1
SH

cat > "$stub_bin/codesign" <<'SH'
#!/usr/bin/env sh
exit 0
SH

cat > "$stub_bin/spctl" <<'SH'
#!/usr/bin/env sh
exit 0
SH

chmod +x "$stub_bin"/*

PATH="$stub_bin:$PATH" "$CHECK" --host-only >/dev/null

PATH="$stub_bin:$PATH" "$CHECK" \
  --sign-identity "Developer ID Application: Ottto Inc (TEAM123)" \
  --keychain-profile GOOD_PROFILE \
  --team-id TEAM123 >/dev/null

if PATH="$stub_bin:$PATH" "$CHECK" \
  --sign-identity "Developer ID Application: Ottto Inc (TEAM123)" \
  --keychain-profile GOOD_PROFILE \
  --team-id OTHERTEAM >/dev/null 2>&1; then
  echo "Expected team-id mismatch to fail" >&2
  exit 1
fi

if PATH="$stub_bin:$PATH" "$CHECK" \
  --sign-identity "Developer ID Application: Missing Inc (TEAM123)" \
  --keychain-profile GOOD_PROFILE \
  --team-id TEAM123 >/dev/null 2>&1; then
  echo "Expected missing identity to fail" >&2
  exit 1
fi

if PATH="$stub_bin:$PATH" "$CHECK" \
  --sign-identity "Developer ID Application: Ottto Inc (TEAM123)" \
  --keychain-profile BAD_PROFILE \
  --team-id TEAM123 >/dev/null 2>&1; then
  echo "Expected unusable notary profile to fail" >&2
  exit 1
fi

echo "macos_signing_readiness tests passed"
