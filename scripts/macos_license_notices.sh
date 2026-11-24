#!/usr/bin/env bash
# License notices shipped with the macOS release, sourced by macos_package.sh.
#
# Ottto.app/Contents/Resources gets LICENSE, NOTICE, LICENSE-THIRD-PARTY.html
# and Sparkle's license before the app is signed. Each binary zip gets the
# executable plus LICENSE, NOTICE and LICENSE-THIRD-PARTY.html at its root,
# where Homebrew installs them into the formula prefix.
#
# Functions return nonzero on any missing or mismatched input; callers run
# under set -e and must not mask the status.

# The vendored Sparkle license is the file at this upstream release and
# commit. The app's Sparkle pin must match it, so a Sparkle bump also needs a
# reviewed update of all three values and licenses/Sparkle-<version>-LICENSE.
OTTTO_SPARKLE_LICENSE_VERSION="2.9.2"
OTTTO_SPARKLE_LICENSE_REVISION="6276ba2b404829d139c45ff98427cf90e2efc59b"
OTTTO_SPARKLE_LICENSE_SHA256="389a4e4e9a32f059775b13a06e25a591445ba229d2838d26dd3e7c0c45127cfe"

# The exact license file names in Ottto.app/Contents/Resources, one per line.
ottto_app_license_resource_names() {
  printf '%s\n' LICENSE NOTICE LICENSE-THIRD-PARTY.html LICENSE-Sparkle.txt
}

# ottto_macos_sparkle_pin <git-root> <commit> <app-source-path>
# Prints the Sparkle pin state ({"revision", "version"}) from Package.resolved
# as committed at <commit>, not from a working copy that could differ.
ottto_macos_sparkle_pin() {
  local git_root="$1"
  local commit="$2"
  local source_path="$3"
  local resolved
  if ! resolved="$(git -C "$git_root" show "$commit:$source_path/Package.resolved" 2>/dev/null)"; then
    echo "The app source commit has no Package.resolved" >&2
    return 1
  fi
  jq -ce '
    [.pins[] | select(.identity == "sparkle"
      and .kind == "remoteSourceControl"
      and .location == "https://github.com/sparkle-project/Sparkle")]
    | if length == 1 then .[0].state else error("Expected one upstream Sparkle pin") end
    | select((.version | type) == "string" and (.revision | type) == "string")
  ' <<<"$resolved"
}

# ottto_check_sparkle_license_pin <version> <revision> <Sparkle.framework>
# The pin and the embedded framework must both be the Sparkle release whose
# license is vendored.
ottto_check_sparkle_license_pin() {
  local version="$1"
  local revision="$2"
  local framework="$3"
  local embedded_version
  if [[ "$version" != "$OTTTO_SPARKLE_LICENSE_VERSION" || "$revision" != "$OTTTO_SPARKLE_LICENSE_REVISION" ]]; then
    echo "The app pins Sparkle $version ($revision), but the vendored Sparkle license is for $OTTTO_SPARKLE_LICENSE_VERSION ($OTTTO_SPARKLE_LICENSE_REVISION); update licenses/ first" >&2
    return 1
  fi
  if ! embedded_version="$(plutil -extract CFBundleShortVersionString raw -o - "$framework/Versions/B/Resources/Info.plist" 2>/dev/null)" ||
    [[ "$embedded_version" != "$version" ]]; then
    echo "Embedded Sparkle framework version must match the app source pin $version" >&2
    return 1
  fi
}

# ottto_license_copy <source> <destination>: a regular, non-empty file, 0644.
ottto_license_copy() {
  local source="$1"
  local destination="$2"
  if [[ -L "$source" || ! -f "$source" || ! -s "$source" ]]; then
    echo "License notice is missing or empty: $(basename "$source")" >&2
    return 1
  fi
  cp -f "$source" "$destination" && chmod 0644 "$destination"
}

# ottto_copy_rust_license_notices <repo-root> <destination-directory>
ottto_copy_rust_license_notices() {
  local root="$1"
  local destination="$2"
  local name
  for name in LICENSE NOTICE LICENSE-THIRD-PARTY.html; do
    ottto_license_copy "$root/$name" "$destination/$name" || return 1
  done
}

# ottto_copy_app_license_notices <repo-root> <app-resources-directory>
# Run before the app is signed; the pin check must have passed.
ottto_copy_app_license_notices() {
  local root="$1"
  local resources="$2"
  local sparkle_license="$root/licenses/Sparkle-$OTTTO_SPARKLE_LICENSE_VERSION-LICENSE"
  local actual_sha256
  ottto_copy_rust_license_notices "$root" "$resources" || return 1
  if [[ ! -f "$sparkle_license" ]] ||
    ! actual_sha256="$(shasum -a 256 "$sparkle_license" | awk '{print $1}')" ||
    [[ "$actual_sha256" != "$OTTTO_SPARKLE_LICENSE_SHA256" ]]; then
    echo "Vendored Sparkle license does not match its recorded SHA-256" >&2
    return 1
  fi
  ottto_license_copy "$sparkle_license" "$resources/LICENSE-Sparkle.txt"
}

# ottto_stage_license_archive <repo-root> <executable> <new-stage-directory>
# Fills a new directory with the executable (bytes and mode kept) and the
# notices; zip its contents, not the directory, so they sit at the zip root.
ottto_stage_license_archive() {
  local root="$1"
  local executable="$2"
  local stage="$3"
  if [[ -e "$stage" || -L "$stage" ]]; then
    echo "Archive staging directory already exists: $(basename "$stage")" >&2
    return 1
  fi
  if [[ ! -f "$executable" || ! -x "$executable" ]]; then
    echo "Archive executable is missing: $(basename "$executable")" >&2
    return 1
  fi
  mkdir "$stage" &&
    cp -p "$executable" "$stage/$(basename "$executable")" &&
    ottto_copy_rust_license_notices "$root" "$stage"
}
