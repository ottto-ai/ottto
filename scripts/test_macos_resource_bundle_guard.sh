#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check_macos_resource_bundle_guard.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fixture_root="$TMP_DIR/ottto-macos-app"
mkdir -p "$fixture_root/Sources/OtttoCompanion/Theme" "$fixture_root/Sources/OtttoCompanion/Views"

cat > "$fixture_root/Sources/OtttoCompanion/Theme/ResourceBundles.swift" <<'SWIFT'
import Foundation

enum OtttoResourceBundles {
    static var candidates: [Bundle] {
        [Bundle.main, Bundle.module]
    }
}
SWIFT

cat > "$fixture_root/Sources/OtttoCompanion/Views/ContentView.swift" <<'SWIFT'
import SwiftUI

struct ContentView: View {
    var body: some View {
        Text("ok")
    }
}
SWIFT

OTTTO_MACOS_APP_ROOT="$fixture_root" "$GUARD" >/dev/null
OTTTO_MACOS_RESOURCE_GUARD_FORCE_GREP=1 OTTTO_MACOS_APP_ROOT="$fixture_root" "$GUARD" >/dev/null

cat > "$fixture_root/Sources/OtttoCompanion/Views/BrandView.swift" <<'SWIFT'
import Foundation

let unsafeBundle = Bundle.module
SWIFT

if OTTTO_MACOS_APP_ROOT="$fixture_root" "$GUARD" >/dev/null 2>&1; then
  echo "Expected direct Bundle.module use outside ResourceBundles.swift to fail" >&2
  exit 1
fi

if OTTTO_MACOS_RESOURCE_GUARD_FORCE_GREP=1 OTTTO_MACOS_APP_ROOT="$fixture_root" "$GUARD" >/dev/null 2>&1; then
  echo "Expected grep fallback to catch direct Bundle.module use outside ResourceBundles.swift" >&2
  exit 1
fi

echo "macOS resource bundle guard tests passed"
