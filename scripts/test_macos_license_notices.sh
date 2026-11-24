#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_license_notices.sh
source "$ROOT/scripts/macos_license_notices.sh"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "macOS license notices test: $*" >&2
  exit 1
}

# expect_failure <label> <expected message> <command...>
expect_failure() {
  local label="$1"
  local expected="$2"
  shift 2
  if "$@" >"$TMP_DIR/$label.out" 2>&1; then
    fail "expected failure: $label"
  fi
  if ! grep -Fq -- "$expected" "$TMP_DIR/$label.out"; then
    cat "$TMP_DIR/$label.out" >&2
    fail "$label did not report: $expected"
  fi
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

# A synthetic public tree with the real vendored Sparkle license.
repo="$TMP_DIR/public"
mkdir -p "$repo/licenses"
printf 'Fixture license\n' > "$repo/LICENSE"
printf 'Fixture notice\n' > "$repo/NOTICE"
printf '<!doctype html>\n<title>Fixture notices</title>\n' > "$repo/LICENSE-THIRD-PARTY.html"
sparkle_license="licenses/Sparkle-$OTTTO_SPARKLE_LICENSE_VERSION-LICENSE"
cp "$ROOT/$sparkle_license" "$repo/$sparkle_license"

# [behaviour] B and F check Resources against exactly these names.
if [[ "$(ottto_app_license_resource_names | tr '\n' ' ')" != "LICENSE NOTICE LICENSE-THIRD-PARTY.html LICENSE-Sparkle.txt " ]]; then
  fail "unexpected app license resource names"
fi

# [behaviour] The committed Sparkle license matches the recorded upstream hash.
if [[ "$(shasum -a 256 "$ROOT/$sparkle_license" | awk '{print $1}')" != "$OTTTO_SPARKLE_LICENSE_SHA256" ]]; then
  fail "vendored Sparkle license does not match OTTTO_SPARKLE_LICENSE_SHA256"
fi

# [behaviour] The app gets all four notices, byte for byte, mode 0644.
resources="$TMP_DIR/Resources"
mkdir -p "$resources"
ottto_copy_app_license_notices "$repo" "$resources"
while IFS= read -r name; do
  case "$name" in
    LICENSE-Sparkle.txt) source_file="$repo/$sparkle_license" ;;
    *) source_file="$repo/$name" ;;
  esac
  cmp -s "$source_file" "$resources/$name" || fail "Resources/$name differs from its source"
  [[ "$(file_mode "$resources/$name")" == "644" ]] || fail "Resources/$name is not mode 0644"
done < <(ottto_app_license_resource_names)
if [[ "$(find "$resources" -mindepth 1 | wc -l | tr -d ' ')" != "4" ]]; then
  fail "the app copy added files beyond the four notices"
fi

# [behaviour] Missing, empty or altered notices fail the copy.
missing="$TMP_DIR/missing"
cp -R "$repo" "$missing"
rm "$missing/NOTICE"
mkdir -p "$TMP_DIR/out-missing"
expect_failure missing-notice "License notice is missing or empty: NOTICE" \
  ottto_copy_app_license_notices "$missing" "$TMP_DIR/out-missing"
empty="$TMP_DIR/empty"
cp -R "$repo" "$empty"
: > "$empty/LICENSE-THIRD-PARTY.html"
mkdir -p "$TMP_DIR/out-empty"
expect_failure empty-notice "License notice is missing or empty: LICENSE-THIRD-PARTY.html" \
  ottto_copy_app_license_notices "$empty" "$TMP_DIR/out-empty"
altered="$TMP_DIR/altered"
cp -R "$repo" "$altered"
printf 'changed\n' >> "$altered/$sparkle_license"
mkdir -p "$TMP_DIR/out-altered"
expect_failure altered-sparkle "Vendored Sparkle license does not match its recorded SHA-256" \
  ottto_copy_app_license_notices "$altered" "$TMP_DIR/out-altered"
[[ ! -e "$TMP_DIR/out-altered/LICENSE-Sparkle.txt" ]] || fail "an altered Sparkle license was copied"

# [behaviour] The Sparkle pin is read from the committed Package.resolved.
app_repo="$TMP_DIR/app"
mkdir -p "$app_repo/tools/ottto-macos-app"
write_resolved() {
  local revision="$1"
  local location="${2:-https://github.com/sparkle-project/Sparkle}"
  jq -n --arg revision "$revision" --arg location "$location" '{
    pins: [{
      identity: "sparkle",
      kind: "remoteSourceControl",
      location: $location,
      state: {revision: $revision, version: "2.9.2"}
    }],
    version: 3
  }' > "$app_repo/tools/ottto-macos-app/Package.resolved"
}
commit_app() {
  git -C "$app_repo" add .
  git -C "$app_repo" commit -qm "$1"
  git -C "$app_repo" rev-parse HEAD
}
git -C "$app_repo" init -q
git -C "$app_repo" config user.email "license-notices-test@example.invalid"
git -C "$app_repo" config user.name "License Notices Test"
write_resolved "$OTTTO_SPARKLE_LICENSE_REVISION"
pinned_commit="$(commit_app "pinned")"
# A rewritten working copy must not change what the commit pins.
write_resolved "0000000000000000000000000000000000000000"
pin="$(ottto_macos_sparkle_pin "$app_repo" "$pinned_commit" tools/ottto-macos-app)"
if [[ "$(jq -r '.version + " " + .revision' <<<"$pin")" != "2.9.2 $OTTTO_SPARKLE_LICENSE_REVISION" ]]; then
  fail "the Sparkle pin was not read from the committed Package.resolved: $pin"
fi
write_resolved "$OTTTO_SPARKLE_LICENSE_REVISION" "https://example.invalid/fork/Sparkle"
fork_commit="$(commit_app "fork")"
expect_failure fork-pin "Expected one upstream Sparkle pin" \
  ottto_macos_sparkle_pin "$app_repo" "$fork_commit" tools/ottto-macos-app
expect_failure no-resolved "The app source commit has no Package.resolved" \
  ottto_macos_sparkle_pin "$app_repo" "$fork_commit" tools/missing

# [behaviour] The pin and the embedded framework must be the vendored release.
mock_bin="$TMP_DIR/bin"
mkdir -p "$mock_bin"
cat > "$mock_bin/plutil" <<'PLUTIL'
#!/usr/bin/env bash
# Stand-in for plutil -extract: the fixture plist holds only the version.
for last; do :; done
cat "$last"
PLUTIL
chmod +x "$mock_bin/plutil"
framework="$TMP_DIR/Sparkle.framework"
mkdir -p "$framework/Versions/B/Resources"
printf '2.9.2' > "$framework/Versions/B/Resources/Info.plist"
PATH="$mock_bin:$PATH" ottto_check_sparkle_license_pin 2.9.2 "$OTTTO_SPARKLE_LICENSE_REVISION" "$framework"
expect_failure other-revision "update licenses/ first" \
  ottto_check_sparkle_license_pin 2.9.2 "1111111111111111111111111111111111111111" "$framework"
expect_failure other-version "update licenses/ first" \
  ottto_check_sparkle_license_pin 2.10.0 "$OTTTO_SPARKLE_LICENSE_REVISION" "$framework"
printf '2.9.1' > "$framework/Versions/B/Resources/Info.plist"
PATH="$mock_bin:$PATH" expect_failure framework-version "Embedded Sparkle framework version must match" \
  ottto_check_sparkle_license_pin 2.9.2 "$OTTTO_SPARKLE_LICENSE_REVISION" "$framework"

# [behaviour] A zip stage holds the unchanged executable plus three notices.
binary="$TMP_DIR/ottto"
printf '#!/bin/sh\nexit 0\n' > "$binary"
chmod 0755 "$binary"
stage="$TMP_DIR/stage-cli"
ottto_stage_license_archive "$repo" "$binary" "$stage"
cmp -s "$binary" "$stage/ottto" || fail "staged executable bytes changed"
[[ "$(file_mode "$stage/ottto")" == "755" ]] || fail "staged executable lost its mode"
for name in LICENSE NOTICE LICENSE-THIRD-PARTY.html; do
  cmp -s "$repo/$name" "$stage/$name" || fail "staged $name differs from its source"
  [[ "$(file_mode "$stage/$name")" == "644" ]] || fail "staged $name is not mode 0644"
done
if [[ "$(find "$stage" -mindepth 1 | wc -l | tr -d ' ')" != "4" ]]; then
  fail "the zip stage holds files beyond the executable and three notices"
fi
expect_failure reused-stage "Archive staging directory already exists" \
  ottto_stage_license_archive "$repo" "$binary" "$stage"

# [behaviour] With real ditto, the files sit at the zip root with no wrapper
# folder (AppleDouble entries are the archive step's concern).
if command -v ditto >/dev/null 2>&1; then
  ditto -c -k "$stage" "$TMP_DIR/cli.zip"
  python3 -I - "$TMP_DIR/cli.zip" "$stage" <<'PY'
import os
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as archive:
    names = [n for n in archive.namelist() if not os.path.basename(n.rstrip("/")).startswith("._") and not n.startswith("__MACOSX/")]
    expected = {"ottto", "LICENSE", "NOTICE", "LICENSE-THIRD-PARTY.html"}
    if set(names) != expected or len(names) != len(expected):
        sys.exit(f"unexpected zip entries: {sorted(names)}")
    for name in expected:
        with open(os.path.join(sys.argv[2], name), "rb") as source:
            if archive.read(name) != source.read():
                sys.exit(f"zip entry {name} differs from the staged file")
PY
fi

echo "macOS license notices test passed"
