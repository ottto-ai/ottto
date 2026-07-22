#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_sparkle_bundle_version.sh
source "$ROOT/scripts/macos_sparkle_bundle_version.sh"

assert_bundle_version() {
  local display_version="$1"
  local expected_bundle_version="$2"
  local actual_bundle_version
  actual_bundle_version="$(ottto_sparkle_bundle_version "$display_version")"
  if [[ "$actual_bundle_version" != "$expected_bundle_version" ]]; then
    echo "Expected $display_version to map to $expected_bundle_version, got $actual_bundle_version" >&2
    exit 1
  fi
}

# These exact forms exercise the three release-train boundaries proven against
# Sparkle's SUStandardVersionComparator: rc1 < rc2 < stable < next release rc1.
assert_bundle_version "0.1.92-rc1" "0.1.92fc1"
assert_bundle_version "0.1.92-rc2" "0.1.92fc2"
assert_bundle_version "0.1.92" "0.1.92"
assert_bundle_version "0.1.93-rc1" "0.1.93fc1"

# Unrelated development/preview suffixes retain their existing bundle version.
assert_bundle_version "0.1.92-dev" "0.1.92-dev"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

repo="$TMP_DIR/public-ottto"
app_root="$TMP_DIR/ottto-macos-app"
mock_bin="$TMP_DIR/bin"
output_dir="$TMP_DIR/output"
mkdir -p \
  "$repo/scripts" \
  "$repo/crates/ottto-protocol/src" \
  "$repo/target/release" \
  "$app_root/.build/release/OtttoCompanion_OtttoCompanion.bundle/Resources" \
  "$app_root/.build/release/Sparkle.framework/Versions/B/XPCServices/Installer.xpc" \
  "$app_root/.build/release/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc" \
  "$app_root/.build/release/Sparkle.framework/Versions/B/Updater.app" \
  "$app_root/Sources/OtttoCompanion/Resources" \
  "$mock_bin"

cp "$ROOT/scripts/macos_package.sh" "$repo/scripts/macos_package.sh"
cp "$ROOT/scripts/macos_sparkle_bundle_version.sh" "$repo/scripts/macos_sparkle_bundle_version.sh"
cat > "$repo/crates/ottto-protocol/src/lib.rs" <<'RS'
pub const PROTOCOL_VERSION: u16 = 15;
RS
cat > "$app_root/Package.swift" <<'SWIFT'
// test fixture
SWIFT
printf '#!/usr/bin/env bash\nexit 0\n' > "$app_root/.build/release/Ottto"
printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/target/release/ottto"
printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/target/release/ottto-service"
printf 'fixture\n' > "$app_root/.build/release/OtttoCompanion_OtttoCompanion.bundle/Resources/fixture.txt"
printf 'fixture\n' > "$app_root/Sources/OtttoCompanion/Resources/OtttoCompanionIcon.icns"
touch \
  "$app_root/.build/release/Sparkle.framework/Versions/B/Autoupdate" \
  "$app_root/.build/release/Sparkle.framework/Versions/B/Updater.app/fixture"
chmod +x \
  "$app_root/.build/release/Ottto" \
  "$repo/target/release/ottto" \
  "$repo/target/release/ottto-service"

cat > "$repo/scripts/macos_launch_smoke.sh" <<'SMOKE'
#!/usr/bin/env bash
set -euo pipefail
app=""
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) app="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --wait-seconds) shift 2 ;;
    *) exit 2 ;;
  esac
done
info_plist="$app/Contents/Info.plist"
jq -n \
  --arg bundle_version "$(plutil -extract CFBundleVersion raw -o - "$info_plist")" \
  --arg bundle_short_version "$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")" \
  '{
    status: "passed",
    checked_at: "2026-07-23T00:00:00Z",
    wait_seconds: 1,
    bundle_id: "net.ottto.Companion",
    bundle_version: $bundle_version,
    bundle_short_version: $bundle_short_version,
    executable_name: "Ottto",
    process_survived_wait: true,
    crash_reports: []
  }' > "$output"
SMOKE
chmod +x "$repo/scripts/macos_launch_smoke.sh"

cat > "$repo/scripts/cyclonedx_sbom.sh" <<'SBOM'
#!/usr/bin/env bash
set -euo pipefail
output=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --version) shift 2 ;;
    *) exit 2 ;;
  esac
done
printf '{}\n' > "$output"
SBOM
chmod +x "$repo/scripts/cyclonedx_sbom.sh"

cat > "$mock_bin/ditto" <<'DITTO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-c" && "${2:-}" == "-k" ]]; then
  cp "$3" "$4"
else
  cp -R "$1" "$2"
fi
DITTO
cat > "$mock_bin/hdiutil" <<'HDIUTIL'
#!/usr/bin/env bash
set -euo pipefail
output=""
for arg in "$@"; do
  output="$arg"
done
printf 'test dmg\n' > "$output"
HDIUTIL
cat > "$mock_bin/otool" <<'OTOOL'
#!/usr/bin/env bash
printf 'path @executable_path/../Frameworks\n'
OTOOL
for command_name in cargo codesign install_name_tool swift; do
  cat > "$mock_bin/$command_name" <<'NOOP'
#!/usr/bin/env bash
exit 0
NOOP
done
chmod +x "$mock_bin"/*

git -C "$repo" init -q
git -C "$repo" config user.email "sparkle-version-test@example.invalid"
git -C "$repo" config user.name "Sparkle Version Test"
git -C "$repo" add .
git -C "$repo" commit -qm "fixture"

PATH="$mock_bin:$PATH" \
OTTTO_MACOS_APP_ROOT="$app_root" \
bash "$repo/scripts/macos_package.sh" \
  --version "0.1.92-rc2" \
  --channel stable-candidate \
  --release-notes "Sparkle version fixture" \
  --output-dir "$output_dir" \
  --skip-build >/dev/null

info_plist="$output_dir/Ottto.app/Contents/Info.plist"
bundle_short_version="$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")"
bundle_version="$(plutil -extract CFBundleVersion raw -o - "$info_plist")"
if [[ "$bundle_short_version" != "0.1.92-rc2" ]]; then
  echo "Packaged display version changed: $bundle_short_version" >&2
  exit 1
fi
if [[ "$bundle_version" != "0.1.92fc2" ]]; then
  echo "Packaged Sparkle bundle version is not monotonic: $bundle_version" >&2
  exit 1
fi
if ! jq -e '
  .quality_gates.packaged_app_launch.bundle_short_version == "0.1.92-rc2"
  and .quality_gates.packaged_app_launch.bundle_version == "0.1.92fc2"
' "$output_dir/release-manifest.json" >/dev/null; then
  echo "Release manifest launch evidence did not preserve both bundle versions" >&2
  exit 1
fi

echo "macOS Sparkle bundle version test passed"
