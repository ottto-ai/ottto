#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: OTTTO_MACOS_APP_ROOT=<app package root> check_macos_resource_bundle_guard.sh

Checks that the Companion app target builds no SwiftPM resource bundle:
  - the OtttoCompanion executable target in Package.swift declares no
    resources: and excludes "Resources";
  - no Swift source under Sources/ uses Bundle.module outside a comment.
SwiftPM's generated Bundle.module accessor stores the absolute build folder
as a string in the shipped binary, and no compiler flag maps it. Release
packaging copies the app's Resources into Ottto.app itself.

OTTTO_MACOS_APP_ROOT is required: the Swift package root of the app.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi
if [[ $# -gt 0 ]]; then
  usage >&2
  exit 2
fi
MAC_APP_ROOT="${OTTTO_MACOS_APP_ROOT:-}"
if [[ -z "$MAC_APP_ROOT" ]]; then
  echo "OTTTO_MACOS_APP_ROOT is required: the app's Swift package root" >&2
  exit 2
fi
SOURCES_DIR="$MAC_APP_ROOT/Sources"
PACKAGE_SWIFT="$MAC_APP_ROOT/Package.swift"
if [[ ! -d "$SOURCES_DIR" ]]; then
  echo "The app root has no Sources folder" >&2
  exit 1
fi
if [[ ! -f "$PACKAGE_SWIFT" ]]; then
  echo "The app root has no Package.swift" >&2
  exit 1
fi

# The executable target's declaration: from `.executableTarget(` up to the
# next target declaration or the end of the targets list.
app_target="$(
  awk '
    /\.executableTarget\(/ { inside = 1 }
    inside && /\.(testTarget|target|binaryTarget|macro|plugin|systemLibrary)\(/ && !/\.executableTarget\(/ { exit }
    inside { print }
  ' "$PACKAGE_SWIFT"
)"
app_target_code="$(awk '{ sub("//.*$", ""); print }' <<<"$app_target")"
if [[ -z "$app_target_code" ]]; then
  echo "Package.swift declares no executable target" >&2
  exit 1
fi
if grep -Eq 'resources[[:space:]]*:' <<<"$app_target_code"; then
  echo "The app target must not declare SwiftPM resources: its Bundle.module accessor stores the build folder in the binary" >&2
  exit 1
fi
# One line, so an exclude array split across lines still matches.
app_target_line="$(tr '\n' ' ' <<<"$app_target_code")"
if ! grep -Eq 'exclude[[:space:]]*:[[:space:]]*\[[^]]*"Resources"' <<<"$app_target_line"; then
  echo 'The app target must exclude its Resources folder (exclude: ["Resources"])' >&2
  exit 1
fi

find_bundle_module_matches() {
  if [[ "${OTTTO_MACOS_RESOURCE_GUARD_FORCE_GREP:-}" != "1" ]] && command -v rg >/dev/null 2>&1; then
    rg -n 'Bundle\.module' "$SOURCES_DIR" --glob '*.swift' || true
    return 0
  fi

  local swift_files swift_file
  swift_files="$(find "$SOURCES_DIR" -type f -name '*.swift')"
  while IFS= read -r swift_file; do
    [[ -n "$swift_file" ]] || continue
    grep -nH 'Bundle\.module' "$swift_file" || true
  done <<<"$swift_files"
}

matches="$(find_bundle_module_matches)"
violations="$(
  awk '
    length($0) {
      content = $0
      sub("^[^:]*:[0-9]+:", "", content)
      if (content !~ /^[[:space:]]*\/\//) {
        sub("^.*/Sources/", "Sources/", $0)
        print
      }
    }
  ' <<<"$matches"
)"

if [[ -n "$violations" ]]; then
  echo "Bundle.module must not be used; the app target has no SwiftPM resource bundle:" >&2
  echo "$violations" >&2
  exit 1
fi

echo "macOS resource bundle guard passed"
