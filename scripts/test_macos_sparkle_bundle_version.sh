#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_sparkle_bundle_version.sh
source "$ROOT/scripts/macos_sparkle_bundle_version.sh"
# shellcheck source=scripts/macos_app_binary.sh
source "$ROOT/scripts/macos_app_binary.sh"

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
TMP_DIR="$(cd "$TMP_DIR" && pwd -P)"

repo="$TMP_DIR/public-ottto"
app_root="$TMP_DIR/SampleApp"
mock_bin="$TMP_DIR/bin"
apple_tools="$TMP_DIR/apple-tools"
output_dir="$TMP_DIR/output"
# Private folders the release runner provides, outside every checkout.
dsym_dir="$TMP_DIR/release-host/dsym"
runner_temp="$TMP_DIR/runner/_work/_temp"
export ORDER_LOG="$TMP_DIR/order.log" SCRATCH_RECORD="$TMP_DIR/scratch.record" CARGO_RECORD="$TMP_DIR/cargo.record"
mkdir -p \
  "$repo/scripts" \
  "$repo/crates/ottto-protocol/src" \
  "$repo/target/release" \
  "$repo/licenses" \
  "$app_root/Sources/OtttoCompanion/Resources/Fonts" \
  "$runner_temp" \
  "$apple_tools" \
  "$mock_bin"

cp "$ROOT/scripts/macos_package.sh" "$repo/scripts/macos_package.sh"
cp "$ROOT/scripts/macos_bundle_url_scheme.sh" "$repo/scripts/macos_bundle_url_scheme.sh"
cp "$ROOT/scripts/macos_companion_entitlements.sh" "$repo/scripts/macos_companion_entitlements.sh"
cp "$ROOT/scripts/macos_sparkle_bundle_version.sh" "$repo/scripts/macos_sparkle_bundle_version.sh"
cp "$ROOT/scripts/macos_app_binary.sh" "$repo/scripts/macos_app_binary.sh"
cp "$ROOT/scripts/macos_license_notices.sh" "$repo/scripts/macos_license_notices.sh"
cp "$ROOT/scripts/macos_release_archive.sh" "$repo/scripts/macos_release_archive.sh"
# shellcheck source=scripts/macos_license_notices.sh
source "$ROOT/scripts/macos_license_notices.sh"
sparkle_license="licenses/Sparkle-$OTTTO_SPARKLE_LICENSE_VERSION-LICENSE"
cp "$ROOT/$sparkle_license" "$repo/$sparkle_license"
printf 'Fixture license\n' > "$repo/LICENSE"
printf 'Fixture notice\n' > "$repo/NOTICE"
printf '<!doctype html>\n<title>Fixture notices</title>\n' > "$repo/LICENSE-THIRD-PARTY.html"
cat > "$repo/crates/ottto-protocol/src/lib.rs" <<'RS'
pub const PROTOCOL_VERSION: u16 = 15;
RS
cat > "$app_root/Package.swift" <<'SWIFT'
// test fixture
SWIFT
# The vendored license pin; the app's pin and embedded framework must match it.
sparkle_revision="$OTTTO_SPARKLE_LICENSE_REVISION"
# write_sparkle_pin <revision>: the app lockfile's Sparkle pin.
write_sparkle_pin() {
  jq -n --arg version "$OTTTO_SPARKLE_LICENSE_VERSION" --arg revision "$1" '{
    originHash: "fixture",
    pins: [{
      identity: "sparkle",
      kind: "remoteSourceControl",
      location: "https://github.com/sparkle-project/Sparkle",
      state: {revision: $revision, version: $version}
    }],
    version: 3
  }' > "$app_root/Package.resolved"
}
write_sparkle_pin "$sparkle_revision"
cat > "$app_root/Companion.entitlements.plist" <<'ENTITLEMENTS'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.security.automation.apple-events</key>
  <true/>
</dict>
</plist>
ENTITLEMENTS
printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/target/release/ottto"
printf '#!/usr/bin/env bash\nexit 0\n' > "$repo/target/release/ottto-service"
# Every listed Companion resource, plus the source README that never ships.
while IFS= read -r resource_name; do
  printf 'fixture %s\n' "$resource_name" > "$app_root/Sources/OtttoCompanion/Resources/$resource_name"
done < <(ottto_macos_companion_resource_names)
printf 'private source notes\n' > "$app_root/Sources/OtttoCompanion/Resources/README.md"
chmod +x \
  "$repo/target/release/ottto" \
  "$repo/target/release/ottto-service"

cat > "$repo/scripts/macos_launch_smoke.sh" <<'SMOKE'
#!/usr/bin/env bash
set -euo pipefail
app=""
output=""
manifest_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --app) app="$2"; shift 2 ;;
    --output) output="$2"; shift 2 ;;
    --manifest-dir) manifest_dir="$2"; shift 2 ;;
    --wait-seconds) shift 2 ;;
    *) exit 2 ;;
  esac
done
# Packaged evidence must be written for the release folder.
[[ -n "$manifest_dir" && "$(dirname "$app")" == "$manifest_dir" && "$(dirname "$output")" == "$manifest_dir" ]] || exit 3
info_plist="$app/Contents/Info.plist"
jq -n \
  --arg app_path "$(basename "$app")" \
  --arg bundle_version "$(plutil -extract CFBundleVersion raw -o - "$info_plist")" \
  --arg bundle_short_version "$(plutil -extract CFBundleShortVersionString raw -o - "$info_plist")" \
  '{
    status: "passed",
    app_path: $app_path,
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

# Records the SBOM inputs the packager passes.
cat > "$repo/scripts/cyclonedx_sbom.sh" <<'SBOM'
#!/usr/bin/env bash
set -euo pipefail
output=""
version=""
sparkle_version=""
sparkle_revision=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --version) version="$2"; shift 2 ;;
    --sparkle-version) sparkle_version="$2"; shift 2 ;;
    --sparkle-revision) sparkle_revision="$2"; shift 2 ;;
    *) exit 2 ;;
  esac
done
jq -n --arg version "$version" --arg sparkle_version "$sparkle_version" \
  --arg sparkle_revision "$sparkle_revision" \
  '{version: $version, sparkle_version: $sparkle_version, sparkle_revision: $sparkle_revision}' > "$output"
SBOM
chmod +x "$repo/scripts/cyclonedx_sbom.sh"

# Archive calls are logged with their time zone; the last two arguments are
# always the input and the output.
export fixture_ditto_archive_log="$TMP_DIR/ditto-archive.log"
cat > "$mock_bin/ditto" <<'DITTO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "-c" && "${2:-}" == "-k" ]]; then
  printf 'TZ=%s %s\n' "${TZ:-}" "$*" >> "$fixture_ditto_archive_log"
  src=""
  dst=""
  for arg in "$@"; do
    src="$dst"
    dst="$arg"
  done
  if [[ -d "$src" ]]; then
    if [[ "${fixture_fail_daemon_zip:-}" == "true" && "$src" == */daemon ]]; then
      echo "Fixture daemon zip creation failed" >&2
      exit 1
    fi
    # A folder "zip" lists its entries with their hashes.
    (cd "$src" && find . -mindepth 1 | LC_ALL=C sort | while IFS= read -r entry; do
      printf '%s %s\n' "$(shasum -a 256 "$entry" | awk '{print $1}')" "${entry#./}"
    done) > "$dst"
  else
    cp "$src" "$dst"
  fi
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
# Logs every signing call and records the entitlements plist each target is
# signed with; -d prints it, so the packager's post-sign entitlement check sees
# what it asked for. The app must already hold its license notices.
cat > "$mock_bin/codesign" <<'CODESIGN'
#!/usr/bin/env bash
set -euo pipefail
entitlements=""
display="false"
target=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) display="true"; shift ;;
    --entitlements)
      if [[ "$display" != "true" ]]; then entitlements="$2"; fi
      shift 2
      ;;
    --sign|--options) shift 2 ;;
    *) target="$1"; shift ;;
  esac
done
record="$target.fixture-entitlements"
if [[ "$display" == "true" ]]; then
  if [[ -f "$record" ]]; then cat "$record"; fi
  exit 0
fi
printf 'codesign %s\n' "$target" >> "${ORDER_LOG:-/dev/null}"
if [[ "$target" == */Ottto.app ]]; then
  for notice in LICENSE NOTICE LICENSE-THIRD-PARTY.html LICENSE-Sparkle.txt; do
    if [[ ! -s "$target/Contents/Resources/$notice" ]]; then
      echo "App is missing $notice at signing time" >&2
      exit 1
    fi
  done
fi
if [[ -n "$entitlements" ]]; then cp "$entitlements" "$record"; else rm -f "$record"; fi
CODESIGN
cat > "$mock_bin/install_name_tool" <<'NOOP'
#!/usr/bin/env bash
exit 0
NOOP
# Records the Rust remap flags the packager hands Cargo.
cat > "$mock_bin/cargo" <<'CARGO'
#!/usr/bin/env bash
printf '%s\n' "${CARGO_ENCODED_RUSTFLAGS:-}" > "${CARGO_RECORD:-/dev/null}"
CARGO
# A fresh SwiftPM build: the scratch folder must be new and empty. An app that
# still declares .copy("Resources") also gets the legacy resource bundle.
cat > "$mock_bin/swift" <<'SWIFT'
#!/usr/bin/env bash
set -euo pipefail
printf 'swift %s\n' "$*" >> "${ORDER_LOG:-/dev/null}"
scratch=""
package=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --scratch-path) scratch="$2"; shift 2 ;;
    --package-path) package="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ "${SWIFT_MODE:-ok}" == "fail" ]]; then
  echo "error: /synthetic/build/home/private-checkout/Sources/App.swift:1: build failed" >&2
  exit 1
fi
if [[ ! -d "$scratch" || -n "$(ls -A "$scratch")" ]]; then
  echo "mock swift: the scratch folder is not new and empty" >&2
  exit 1
fi
printf '%s\n' "$scratch" > "${SCRATCH_RECORD:-/dev/null}"
release="$scratch/release"
sparkle="$release/Sparkle.framework/Versions/B"
mkdir -p "$sparkle/XPCServices/Installer.xpc" "$sparkle/XPCServices/Downloader.xpc" "$sparkle/Updater.app"
touch "$sparkle/Autoupdate" "$sparkle/Updater.app/fixture"
mkdir -p "$sparkle/Resources"
cat > "$sparkle/Resources/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>org.sparkle-project.Sparkle</string>
  <key>CFBundleShortVersionString</key>
  <string>${SPARKLE_FRAMEWORK_VERSION:-2.9.2}</string>
</dict>
</plist>
PLIST
printf '#!/usr/bin/env bash\nexit 0\n' > "$release/Ottto"
chmod +x "$release/Ottto"
if grep -Fq '.copy("Resources")' "$package/Package.swift"; then
  mkdir -p "$release/OtttoCompanion_OtttoCompanion.bundle/Resources"
  cp -R "$package/Sources/OtttoCompanion/Resources/." "$release/OtttoCompanion_OtttoCompanion.bundle/Resources/"
  printf 'bundle only\n' > "$release/OtttoCompanion_OtttoCompanion.bundle/Resources/fixture.txt"
fi
SWIFT
chmod +x "$mock_bin"/*

# Apple developer tools (OTTTO_MACOS_APPLE_TOOL_DIR). The build output has a
# debug map; the executable inside Ottto.app has none after strip.
cat > "$apple_tools/strip" <<'STRIP'
#!/usr/bin/env bash
printf 'strip %s\n' "$*" >> "${ORDER_LOG:-/dev/null}"
STRIP
cat > "$apple_tools/nm" <<'NM'
#!/usr/bin/env bash
target="${*: -1}"
if [[ "$1" == "-ap" && "$target" != */Ottto.app/* ]]; then
  printf '0000000000000000 - 00 0001    OSO arm64-apple-macosx/release/OtttoCompanion.build/App.swift.o\n'
fi
printf '0000000100003f20 t _$s14OtttoCompanion3AppVACycfC\n0000000100004000 T _main\n'
NM
cat > "$apple_tools/dsymutil" <<'DSYMUTIL'
#!/usr/bin/env bash
printf 'dsymutil %s\n' "$*" >> "${ORDER_LOG:-/dev/null}"
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
mkdir -p "$out/Contents/Resources/DWARF"
printf 'dwarf\n' > "$out/Contents/Resources/DWARF/Ottto"
DSYMUTIL
cat > "$apple_tools/dwarfdump" <<'DWARFDUMP'
#!/usr/bin/env bash
case "$1" in
  --uuid) printf 'UUID: 0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9 (arm64) %s\n' "$2" ;;
  --debug-info) printf '0x0000000b: DW_TAG_compile_unit\n' ;;
esac
DWARFDUMP
cat > "$apple_tools/atos" <<'ATOS'
#!/usr/bin/env bash
printf 'main (in Ottto) (OtttoCompanionApp.swift:0)\n'
ATOS
chmod +x "$apple_tools"/*
# release_env <command...>: the signing runner's environment for a stable build.
release_env() {
  env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u HOST_CFLAGS -u TARGET_CFLAGS \
    PATH="$mock_bin:$PATH" \
    OTTTO_MACOS_APPLE_TOOL_DIR="$apple_tools" \
    OTTTO_MACOS_DSYM_DIR="$dsym_dir" \
    RUNNER_TEMP="$runner_temp" \
    RUNNER_WORKSPACE="$TMP_DIR/runner/_work" \
    GITHUB_WORKSPACE="$TMP_DIR/runner/_work/ottto" \
    "$@"
}

git -C "$repo" init -q
git -C "$repo" config user.email "sparkle-version-test@example.invalid"
git -C "$repo" config user.name "Sparkle Version Test"
git -C "$repo" add .
git -C "$repo" commit -qm "fixture"
# The app package is any tracked subdirectory of its checkout; the packager
# records only its commit and tree.
private_repo="$TMP_DIR/app-checkout"
mkdir -p "$private_repo/inputs"
mv "$app_root" "$private_repo/inputs/SampleApp"
app_root="$private_repo/inputs/SampleApp"
git -C "$private_repo" init -q
git -C "$private_repo" config user.email "sparkle-version-test@example.invalid"
git -C "$private_repo" config user.name "Sparkle Version Test"
# No origin remote is needed: the record names no repository.
git -C "$private_repo" add .
git -C "$private_repo" commit -qm "app fixture"
private_commit="$(git -C "$private_repo" rev-parse HEAD)"
private_tree="$(git -C "$private_repo" rev-parse HEAD:inputs/SampleApp)"
# The packager must never call gh: any call is logged and fails.
gh_calls="$TMP_DIR/gh.calls"
cat > "$mock_bin/gh" <<GH
#!/usr/bin/env bash
printf '%s\\n' "\$*" >> "$gh_calls"
exit 2
GH
chmod +x "$mock_bin/gh"

# package_expect_failure <label> <expected message> <packager args...>
package_expect_failure() {
  local label="$1"
  local expected="$2"
  shift 2
  if PATH="$mock_bin:$PATH" bash "$repo/scripts/macos_package.sh" \
    --version "0.1.92-rc3" \
    --channel stable-candidate \
    --release-notes "Pin fixture" \
    --output-dir "$TMP_DIR/$label-output" \
    --skip-build "$@" >"$TMP_DIR/$label.out" 2>&1; then
    echo "Expected packaging to fail: $label" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$TMP_DIR/$label.out"; then
    echo "Packaging failure for $label did not report: $expected" >&2
    cat "$TMP_DIR/$label.out" >&2
    exit 1
  fi
}

# [behaviour] The app root is a required flag.
package_expect_failure missing-app-root "--app-root is required" \
  --app-source-commit "$private_commit"
# [behaviour] Stable channels require the app source commit, and the checkout must be at it.
package_expect_failure missing-pin "--app-source-commit is required for stable-candidate and stable" \
  --app-root "$app_root"
package_expect_failure invalid-pin "--app-source-commit must be a 40-hex" \
  --app-root "$app_root" --app-source-commit "${private_commit:0:12}"
package_expect_failure pin-mismatch "not --app-source-commit" \
  --app-root "$app_root" --app-source-commit "$(printf '0%.0s' {1..40})"

# [behaviour] Stable channels refuse reused build outputs and a missing
# private dSYM folder before anything is built.
OTTTO_MACOS_DSYM_DIR="$dsym_dir" \
  package_expect_failure stable-skip-build "Stable channels build from source" \
    --app-root "$app_root" --app-source-commit "$private_commit"
if PATH="$mock_bin:$PATH" bash "$repo/scripts/macos_package.sh" \
  --app-root "$app_root" --app-source-commit "$private_commit" \
  --version "0.1.92-rc3" --channel stable-candidate --release-notes "No dSYM folder" \
  --output-dir "$TMP_DIR/no-dsym-output" >"$TMP_DIR/no-dsym.out" 2>&1; then
  echo "Expected a stable build without OTTTO_MACOS_DSYM_DIR to fail" >&2
  exit 1
fi
grep -Fq "OTTTO_MACOS_DSYM_DIR is required for stable channels" "$TMP_DIR/no-dsym.out"
if [[ -e "$ORDER_LOG" ]] && grep -q '^swift ' "$ORDER_LOG"; then
  echo "A refused stable build must not compile" >&2
  exit 1
fi

# [behaviour] A failing tool keeps its path-bearing output in the private log.
if SWIFT_MODE=fail release_env bash "$repo/scripts/macos_package.sh" \
  --app-root "$app_root" --app-source-commit "$private_commit" \
  --version "0.1.92-rc3" --channel stable-candidate --release-notes "Failing build" \
  --output-dir "$TMP_DIR/failing-output" >"$TMP_DIR/failing.out" 2>&1; then
  echo "Expected the failing Swift build to fail packaging" >&2
  exit 1
fi
if ! grep -Fq "Swift release build failed" "$TMP_DIR/failing.out" || \
  grep -Fq "/synthetic/build/home" "$TMP_DIR/failing.out"; then
  echo "A failing Swift build must print its fixed label and never its output" >&2
  cat "$TMP_DIR/failing.out" >&2
  exit 1
fi
grep -Fq "/synthetic/build/home" "$dsym_dir/logs/Swift release build.log"
: > "$ORDER_LOG"

release_env bash "$repo/scripts/macos_package.sh" \
  --app-root "$app_root" \
  --app-source-commit "$private_commit" \
  --version "0.1.92-rc2" \
  --channel stable-candidate \
  --release-notes "Sparkle version fixture" \
  --output-dir "$output_dir" >"$TMP_DIR/package.out" 2>&1 || {
    cat "$TMP_DIR/package.out" >&2
    echo "Stable-candidate packaging fixture failed" >&2
    exit 1
  }
if [[ -e "$gh_calls" ]]; then
  echo "Packaging must not call gh:" >&2
  cat "$gh_calls" >&2
  exit 1
fi

# [behaviour] Both published zips are written in UTC without resource forks or
# extended attributes.
for zip_name in "ottto-macos-" "ottto-service-macos-"; do
  if ! grep -Eq "^TZ=UTC -c -k --norsrc --noextattr .* $output_dir/${zip_name}[a-z0-9_]+\.zip\$" "$fixture_ditto_archive_log"; then
    echo "Published zip ${zip_name}* must be archived with TZ=UTC --norsrc --noextattr" >&2
    cat "$fixture_ditto_archive_log" >&2
    exit 1
  fi
done

# [behaviour] The signed app carries the four license notices, and each binary
# zip holds exactly its executable plus three notices at its root.
sha256_of() {
  shasum -a 256 "$1" | awk '{print $1}'
}
resources="$output_dir/Ottto.app/Contents/Resources"
while IFS= read -r name; do
  case "$name" in
    LICENSE-Sparkle.txt) source_file="$repo/$sparkle_license" ;;
    *) source_file="$repo/$name" ;;
  esac
  if ! cmp -s "$source_file" "$resources/$name"; then
    echo "Packaged app is missing license notice $name" >&2
    exit 1
  fi
done < <(ottto_app_license_resource_names)
for zip_binary in ottto-macos:ottto ottto-service-macos:ottto-service; do
  binary_name="${zip_binary#*:}"
  zip_listing="$(find "$output_dir" -maxdepth 1 -name "${zip_binary%%:*}-*.zip" -print -quit)"
  expected_listing="$(
    for name in LICENSE LICENSE-THIRD-PARTY.html NOTICE; do
      printf '%s %s\n' "$(sha256_of "$repo/$name")" "$name"
    done
    printf '%s %s\n' "$(sha256_of "$output_dir/$binary_name")" "$binary_name"
  )"
  if [[ -z "$zip_listing" ]] ||
    [[ "$(LC_ALL=C sort -k2 "$zip_listing")" != "$(LC_ALL=C sort -k2 <<<"$expected_listing")" ]]; then
    echo "The $binary_name zip must hold $binary_name and the license notices at its root" >&2
    exit 1
  fi
done
if find "$output_dir" -maxdepth 1 -name '*stag*' | grep -q .; then
  echo "Zip staging folders must not be left in the release output folder" >&2
  exit 1
fi

# [behaviour] Only the daemon LaunchAgent carries the allocator setting.
service_plist="$output_dir/Ottto.app/Contents/Library/LaunchAgents/net.ottto.service.plist"
if [[ "$(plutil -extract EnvironmentVariables.MallocLargeCache raw -o - "$service_plist")" != "0" ]]; then
  echo "Packaged daemon must disable libmalloc large-cache retention" >&2
  exit 1
fi
if [[ "$(plutil -extract EnvironmentVariables.MallocSpaceEfficient raw -o - "$service_plist")" != "1" ]]; then
  echo "Packaged daemon must enable libmalloc space-efficient mode" >&2
  exit 1
fi
info_plist="$output_dir/Ottto.app/Contents/Info.plist"
for allocator_key in MallocLargeCache MallocSpaceEfficient; do
  if plutil -extract "LSEnvironment.$allocator_key" raw -o - "$info_plist" >/dev/null 2>&1; then
    echo "Companion app must not carry the daemon allocator setting $allocator_key" >&2
    exit 1
  fi
done
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
# Launch Services applies LSMultipleInstancesProhibited across user sessions,
# which blocks a second macOS user from opening the app. One process per user
# is the app's own responsibility.
if plutil -extract LSMultipleInstancesProhibited raw -o - "$info_plist" >/dev/null 2>&1; then
  echo "Packaged Info.plist must not prohibit Ottto in other macOS user sessions" >&2
  exit 1
fi
if [[ "$(plutil -extract CFBundleIdentifier raw -o - "$info_plist")" != "net.ottto.Companion" ]]; then
  echo "Packaged bundle identifier changed" >&2
  exit 1
fi
if [[ "$(plutil -extract NSAppleEventsUsageDescription raw -o - "$info_plist")" != \
  "Ottto reads the folder in your selected terminal tab when you choose Terminal folder, and opens Terminal when you sign in to Claude Code." ]]; then
  echo "Packaged Info.plist must explain the Terminal folder Apple Events use" >&2
  exit 1
fi
if [[ ! -f "$output_dir/Ottto.app.fixture-entitlements" ]] || \
  [[ -e "$output_dir/Ottto.app/Contents/Helpers/ottto.fixture-entitlements" ]] || \
  [[ -e "$output_dir/Ottto.app/Contents/Helpers/ottto-service.fixture-entitlements" ]]; then
  echo "Only the Companion app may be signed with the shared entitlements" >&2
  exit 1
fi
if ! jq -e '
  .quality_gates.packaged_app_launch.bundle_short_version == "0.1.92-rc2"
  and .quality_gates.packaged_app_launch.bundle_version == "0.1.92fc2"
  and (.supply_chain.materials | length) == 2
' "$output_dir/release-manifest.json" >/dev/null; then
  echo "Release manifest launch evidence did not preserve both bundle versions" >&2
  exit 1
fi
if ! jq -e \
  --arg public_commit "$(git -C "$repo" rev-parse HEAD)" \
  --arg private_commit "$private_commit" \
  --arg private_tree "$private_tree" \
  '
    .supply_chain.materials[0] == {
      kind: "git_repository",
      repository: "ottto-ai/ottto",
      commit: $public_commit
    }
    and .supply_chain.materials[1] == {
      kind: "private_source",
      name: "ottto-macos-app",
      visibility: "private",
      commit: $private_commit,
      tree: $private_tree,
      clean: true
    }
  ' "$output_dir/release-manifest.json" >/dev/null; then
  echo "Release manifest did not bind the exact public and private app Git materials" >&2
  exit 1
fi
# [behaviour] Every local file reference is a filename beside the manifest and
# no string carries a build-host path.
if ! jq -e --arg tmp "$TMP_DIR" '
  ([.artifacts[] | .verification_path] == ["Ottto.app", "ottto", "ottto-service"])
  and ([.artifacts[] | .path] | all(test("^[A-Za-z0-9_][A-Za-z0-9_.+-]*$")))
  and .supply_chain.sbom.path == "ottto-local-platform-sbom.cdx.json"
  and .quality_gates.packaged_app_launch.evidence_path == "packaged-app-launch-smoke.json"
  and (.supply_chain.slsa_build.verification_command | startswith("gh attestation verify ./Ottto-macos-"))
  and (.supply_chain.sbom.verification_command | startswith("gh attestation verify ./Ottto-macos-"))
  and ([.. | strings | select(contains($tmp) or startswith("/"))] | length == 0)
' "$output_dir/release-manifest.json" >/dev/null; then
  echo "Release manifest must name local files by filename, never by build-host path" >&2
  jq '[.. | strings | select(startswith("/"))]' "$output_dir/release-manifest.json" >&2
  exit 1
fi
if [[ "$(jq -r '.app_path' "$output_dir/packaged-app-launch-smoke.json")" != "Ottto.app" ]]; then
  echo "Packaged launch evidence must name the app by its release filename" >&2
  exit 1
fi
# [behaviour] Swift compiled in a new folder outside the app checkout, which
# packaging removed afterwards; Cargo got the path remaps.
scratch_path="$(cat "$SCRATCH_RECORD")"
case "$scratch_path/" in
  "$runner_temp/ottto-swift."*) ;;
  *) echo "Swift must compile in a fresh folder under RUNNER_TEMP" >&2; exit 1 ;;
esac
if [[ -e "$scratch_path" ]]; then
  echo "Packaging must remove the fresh Swift build folder" >&2
  exit 1
fi
if ! tr '\037' '\n' < "$CARGO_RECORD" | grep -Eq '^--remap-path-prefix=.*/public-ottto=\.$'; then
  echo "Cargo must get the public checkout remap through CARGO_ENCODED_RUSTFLAGS" >&2
  exit 1
fi
# [behaviour] Public output never names the private folders.
for private_path in "$dsym_dir" "$scratch_path" "$app_root"; do
  if grep -Fq "$private_path" "$TMP_DIR/package.out"; then
    echo "Packaging output names a private build folder" >&2
    exit 1
  fi
done
if grep -Fq "still declares SwiftPM resources" "$TMP_DIR/package.out"; then
  echo "An app without SwiftPM resources must not get the legacy-layout warning" >&2
  exit 1
fi
# [behaviour] Resources come from the app source: exactly the listed files
# plus the license files, byte-equal, never the README.
app_resources="$output_dir/Ottto.app/Contents/Resources"
ottto_macos_check_app_resources "$app_resources"
for resource_name in OtttoCompanionIcon.icns Fonts/Fraunces-VF.ttf ottto-mark.png; do
  cmp -s "$app_resources/$resource_name" "$app_root/Sources/OtttoCompanion/Resources/$resource_name" || {
    echo "Packaged $resource_name must match the app source" >&2
    exit 1
  }
done
if [[ -e "$app_resources/README.md" ]]; then
  echo "The app's README.md must never ship" >&2
  exit 1
fi
# [behaviour] Strip runs on the bundle copy before any signing; the dSYM is
# kept privately under its UUID, never in the release output.
first_strip="$(grep -n "^strip -S -x $output_dir/Ottto.app/Contents/MacOS/Ottto$" "$ORDER_LOG" | head -n 1 | cut -d: -f1)"
first_sign="$(grep -n '^codesign ' "$ORDER_LOG" | head -n 1 | cut -d: -f1)"
if [[ -z "$first_strip" || -z "$first_sign" || "$first_strip" -ge "$first_sign" ]]; then
  echo "strip -S -x must run on Ottto.app's executable before signing" >&2
  cat "$ORDER_LOG" >&2
  exit 1
fi
if [[ ! -d "$dsym_dir/Ottto-0.1.92-rc2-0A1B2C3D-4E5F-6071-8293-A4B5C6D7E8F9.dSYM" ]] || \
  [[ -n "$(find "$dsym_dir" -maxdepth 1 -name '.incoming.*')" ]] || \
  [[ -n "$(find "$output_dir" -name '*.dSYM')" ]]; then
  echo "The Companion dSYM must be kept only in the private folder, under its UUID" >&2
  exit 1
fi

# [behaviour] The SBOM gets the release version and the app commit's Sparkle pin.
if ! jq -e --arg version "$OTTTO_SPARKLE_LICENSE_VERSION" --arg revision "$sparkle_revision" '
  . == {version: "0.1.92-rc2", sparkle_version: $version, sparkle_revision: $revision}
' "$output_dir/ottto-local-platform-sbom.cdx.json" >/dev/null; then
  echo "Packaged SBOM did not receive the release version and Sparkle pin" >&2
  cat "$output_dir/ottto-local-platform-sbom.cdx.json" >&2
  exit 1
fi

# commit_app_fixture <message>: commit the app fixture and print the commit.
commit_app_fixture() {
  git -C "$private_repo" add .
  git -C "$private_repo" commit -qm "$1"
  git -C "$private_repo" rev-parse HEAD
}
# package_build_expect_failure <label> <expected message> <packager args...>:
# a fresh mocked stable-candidate build that must fail with <expected message>.
package_build_expect_failure() {
  local label="$1"
  local expected="$2"
  shift 2
  if release_env bash "$repo/scripts/macos_package.sh" \
    --version "0.1.92-rc3" \
    --channel stable-candidate \
    --release-notes "Pin fixture" \
    --output-dir "$TMP_DIR/$label-output" "$@" >"$TMP_DIR/$label.out" 2>&1; then
    echo "Expected packaging to fail: $label" >&2
    exit 1
  fi
  if ! grep -Fq -- "$expected" "$TMP_DIR/$label.out"; then
    echo "Packaging failure for $label did not report: $expected" >&2
    cat "$TMP_DIR/$label.out" >&2
    exit 1
  fi
}

# [behaviour] A failed archive leaves no copied binaries or notices in the temp directory.
zip_tmp="$TMP_DIR/zip-tmp"
mkdir "$zip_tmp"
TMPDIR="$zip_tmp" fixture_fail_daemon_zip=true \
  package_build_expect_failure daemon-zip "Fixture daemon zip creation failed" \
    --app-root "$app_root" --app-source-commit "$private_commit"
if [[ -n "$(find "$zip_tmp" -name 'ottto-zip-stage.*' -print -quit)" ]]; then
  echo "Binary zip creation failure left a staging directory behind" >&2
  exit 1
fi

# expect_sparkle_rejection <label> <expected message> <packager args...>: a
# fresh build refused before any code is signed.
expect_sparkle_rejection() {
  : > "$ORDER_LOG"
  package_build_expect_failure "$@"
  if grep -q '^codesign ' "$ORDER_LOG" || \
    [[ -n "$(find "$TMP_DIR/$1-output" -name '*.fixture-entitlements' -print -quit 2>/dev/null)" ]]; then
    echo "Packaging signed code before rejecting $1" >&2
    cat "$ORDER_LOG" >&2
    exit 1
  fi
}
# [behaviour] Packaging refuses an embedded Sparkle that differs from the pin.
SPARKLE_FRAMEWORK_VERSION=2.9.3 expect_sparkle_rejection sparkle-mismatch \
  "Embedded Sparkle framework version must match the app source pin (2.9.2)" \
  --app-root "$app_root" --app-source-commit "$private_commit"
# [behaviour] A lockfile without exactly one upstream Sparkle pin is refused.
jq '.pins = []' "$app_root/Package.resolved" > "$app_root/Package.resolved.next"
mv "$app_root/Package.resolved.next" "$app_root/Package.resolved"
no_pin_commit="$(commit_app_fixture "drop the Sparkle pin")"
expect_sparkle_rejection sparkle-no-pin "Expected one upstream Sparkle pin in Package.resolved" \
  --app-root "$app_root" --app-source-commit "$no_pin_commit"
# [behaviour] A Sparkle pin without a revision is refused with a reason.
write_sparkle_pin "$sparkle_revision"
jq 'del(.pins[0].state.revision)' "$app_root/Package.resolved" > "$app_root/Package.resolved.next"
mv "$app_root/Package.resolved.next" "$app_root/Package.resolved"
no_revision_commit="$(commit_app_fixture "drop the Sparkle revision")"
expect_sparkle_rejection sparkle-no-revision "The Sparkle pin in Package.resolved needs a version and a revision" \
  --app-root "$app_root" --app-source-commit "$no_revision_commit"
# [behaviour] A different revision of the same Sparkle version is refused.
write_sparkle_pin "1111111111111111111111111111111111111111"
other_pin_commit="$(commit_app_fixture "change the Sparkle revision")"
expect_sparkle_rejection other-sparkle-pin "the vendored Sparkle license is for" \
  --app-root "$app_root" --app-source-commit "$other_pin_commit"
git -C "$private_repo" reset -q --hard "$private_commit"

# [behaviour] Migration: an app that still declares .copy("Resources") packages
# from its source folder too, with a warning; the SwiftPM bundle never ships.
printf '.executableTarget(name: "OtttoCompanion", resources: [.copy("Resources")])\n' > "$app_root/Package.swift"
git -C "$private_repo" commit -qam "legacy app fixture"
legacy_commit="$(git -C "$private_repo" rev-parse HEAD)"
release_env bash "$repo/scripts/macos_package.sh" \
  --app-root "$app_root" \
  --app-source-commit "$legacy_commit" \
  --version "0.1.92-rc3" \
  --channel stable-candidate \
  --release-notes "Legacy layout fixture" \
  --output-dir "$TMP_DIR/legacy-output" >"$TMP_DIR/legacy.out" 2>&1 || {
    cat "$TMP_DIR/legacy.out" >&2
    echo "Legacy app layout packaging failed" >&2
    exit 1
  }
grep -Fq "::warning::The app source still declares SwiftPM resources" "$TMP_DIR/legacy.out"
ottto_macos_check_app_resources "$TMP_DIR/legacy-output/Ottto.app/Contents/Resources"
if [[ -e "$TMP_DIR/legacy-output/Ottto.app/Contents/Resources/fixture.txt" ]]; then
  echo "The SwiftPM resource bundle must never ship" >&2
  exit 1
fi

printf '// dirty fixture\n' >> "$app_root/Package.swift"
if PATH="$mock_bin:$PATH" \
  bash "$repo/scripts/macos_package.sh" \
    --app-root "$app_root" \
    --app-source-commit "$legacy_commit" \
    --version "0.1.92-rc3" \
    --channel stable-candidate \
    --release-notes "Dirty provenance fixture" \
    --output-dir "$TMP_DIR/dirty-output" \
    --skip-build >"$TMP_DIR/dirty.out" 2>&1; then
  echo "Expected packaging to reject a dirty private app source" >&2
  exit 1
fi
if ! grep -Fq "macOS app source subtree has tracked changes" "$TMP_DIR/dirty.out"; then
  echo "Dirty private app rejection did not report the expected provenance failure" >&2
  exit 1
fi

echo "macOS Sparkle bundle version test passed"
