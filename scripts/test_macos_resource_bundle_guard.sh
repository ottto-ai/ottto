#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check_macos_resource_bundle_guard.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fixture_root="$TMP_DIR/app"
mkdir -p "$fixture_root/Sources/OtttoCompanion/Theme" "$fixture_root/Sources/OtttoCompanion/Views"

# write_package <app target lines> [test target extra line]
write_package() {
  cat > "$fixture_root/Package.swift" <<SWIFT
// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "OtttoCompanion",
    targets: [
        .executableTarget(
            name: "OtttoCompanion",
            // Declaring Resources as resources: [.copy("Resources")] would
            // generate a Bundle.module accessor.
            $1
        ),
        .testTarget(
            name: "OtttoCompanionTests",
            dependencies: ["OtttoCompanion"],${2:-}
            resources: [
                .copy("Fixtures")
            ]
        )
    ]
)
SWIFT
}

# The layout the guard accepts: Resources excluded, a test target that keeps
# its own Fixtures resources, Bundle.main lookups and a comment that names
# Bundle.module.
write_package 'exclude: ["Resources"]'
cat > "$fixture_root/Sources/OtttoCompanion/Theme/ResourceBundles.swift" <<'SWIFT'
import Foundation

enum OtttoResourceBundles {
    // No Bundle.module: the app target has no SwiftPM resources.
    static var candidates: [Bundle] { [Bundle.main] }
}
SWIFT

expect_pass() {  # $1 = label
  local mode
  for mode in rg grep; do
    if [[ "$mode" == rg ]] && ! command -v rg >/dev/null 2>&1; then
      continue
    fi
    if ! OTTTO_MACOS_RESOURCE_GUARD_FORCE_GREP="$([[ "$mode" == grep ]] && echo 1 || echo 0)" \
      OTTTO_MACOS_APP_ROOT="$fixture_root" bash "$GUARD" >"$TMP_DIR/out" 2>&1; then
      echo "Expected the guard to pass ($mode): $1" >&2
      cat "$TMP_DIR/out" >&2
      exit 1
    fi
  done
}

expect_fail() {  # $1 = label, $2 = expected message
  local mode
  for mode in rg grep; do
    if [[ "$mode" == rg ]] && ! command -v rg >/dev/null 2>&1; then
      continue
    fi
    if OTTTO_MACOS_RESOURCE_GUARD_FORCE_GREP="$([[ "$mode" == grep ]] && echo 1 || echo 0)" \
      OTTTO_MACOS_APP_ROOT="$fixture_root" bash "$GUARD" >"$TMP_DIR/out" 2>&1; then
      echo "Expected the guard to fail ($mode): $1" >&2
      exit 1
    fi
    if ! grep -Fq -- "$2" "$TMP_DIR/out"; then
      echo "Guard failure ($mode) for $1 did not report: $2" >&2
      cat "$TMP_DIR/out" >&2
      exit 1
    fi
    if grep -Fq "$TMP_DIR" "$TMP_DIR/out"; then
      echo "Guard output ($mode) for $1 names the absolute app folder" >&2
      exit 1
    fi
  done
}

# [behaviour] The new layout passes, on the rg path and the grep fallback.
expect_pass "Resources excluded, no Bundle.module"

# [behaviour] The app root is required; there is no default location.
if bash "$GUARD" >"$TMP_DIR/out" 2>&1; then
  echo "Expected the guard to require OTTTO_MACOS_APP_ROOT" >&2
  exit 1
fi
if ! grep -Fq "OTTTO_MACOS_APP_ROOT is required" "$TMP_DIR/out"; then
  echo "Guard without an app root did not name OTTTO_MACOS_APP_ROOT" >&2
  exit 1
fi

# [behaviour] Any Bundle.module use fails, the old shared helper included.
cat > "$fixture_root/Sources/OtttoCompanion/Theme/ResourceBundles.swift" <<'SWIFT'
import Foundation

enum OtttoResourceBundles {
    static var candidates: [Bundle] { [Bundle.main, Bundle.module] }
}
SWIFT
expect_fail "Bundle.module in ResourceBundles.swift" "Sources/OtttoCompanion/Theme/ResourceBundles.swift:4:"
rm "$fixture_root/Sources/OtttoCompanion/Theme/ResourceBundles.swift"
printf 'import Foundation\nlet unsafeBundle = Bundle.module\n' > "$fixture_root/Sources/OtttoCompanion/Views/BrandView.swift"
expect_fail "Bundle.module in a view" "Bundle.module must not be used"
rm "$fixture_root/Sources/OtttoCompanion/Views/BrandView.swift"
expect_pass "no Swift source uses Bundle.module"

# [behaviour] The app target must not declare resources, in any form.
write_package 'exclude: ["Resources"], resources: [.copy("Resources")]'
expect_fail ".copy(\"Resources\") in the app target" "must not declare SwiftPM resources"
write_package 'exclude: ["Resources"],
            resources: [.process("Assets")]'
expect_fail "resources from another folder" "must not declare SwiftPM resources"

# [behaviour] The app target must exclude Resources; the test target's own
# exclude does not count.
write_package 'path: "Sources/OtttoCompanion"' ' exclude: ["Resources"],'
expect_fail "Resources not excluded from the app target" 'must exclude its Resources folder'
write_package 'exclude: [
                "Resources"
            ]'
expect_pass "Resources excluded in a multiline array"
write_package 'exclude: ["Resources"]'
expect_pass "restored layout"

echo "macOS resource bundle guard tests passed"
