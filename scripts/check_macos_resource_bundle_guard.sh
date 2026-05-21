#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
MAC_APP_ROOT="${OTTTO_MACOS_APP_ROOT:-$REPO_ROOT/tools/ottto-macos-app}"
SOURCES_DIR="$MAC_APP_ROOT/Sources"
ALLOWED_FILE="$SOURCES_DIR/OtttoCompanion/Theme/ResourceBundles.swift"

usage() {
  cat <<'USAGE'
Usage: check_macos_resource_bundle_guard.sh

Fails if Swift runtime code touches Bundle.module outside the shared
OtttoResourceBundles helper. Direct Bundle.module access can assert inside a
packaged .app when SwiftPM's generated resource-bundle accessor cannot resolve
the module bundle beside Bundle.main.bundleURL.

Set OTTTO_MACOS_APP_ROOT to validate a fixture app root.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ ! -d "$SOURCES_DIR" ]]; then
  echo "macOS app Sources directory does not exist: $SOURCES_DIR" >&2
  exit 1
fi

find_bundle_module_matches() {
  if [[ "${OTTTO_MACOS_RESOURCE_GUARD_FORCE_GREP:-}" != "1" ]] && command -v rg >/dev/null 2>&1; then
    rg -n 'Bundle\.module' "$SOURCES_DIR" --glob '*.swift' || true
    return 0
  fi

  while IFS= read -r -d '' swift_file; do
    grep -nH 'Bundle\.module' "$swift_file" || true
  done < <(find "$SOURCES_DIR" -type f -name '*.swift' -print0)
}

matches="$(find_bundle_module_matches)"
violations="$(
  awk -F: -v allowed="$ALLOWED_FILE" '
    length($0) && $1 != allowed {
      content = $0
      sub("^[^:]*:[0-9]+:", "", content)
      if (content !~ /^[[:space:]]*\/\//) {
        print
      }
    }
  ' <<<"$matches"
)"

if [[ -n "$violations" ]]; then
  echo "Bundle.module may only be used by OtttoResourceBundles:" >&2
  echo "$violations" >&2
  exit 1
fi

echo "macOS resource bundle guard passed"
