#!/usr/bin/env bash
# Release records name their local files as plain filenames that sit beside
# release-manifest.json. Readers resolve them against the manifest's own
# directory, never against the working directory, so a release folder can be
# moved or downloaded and still verify.

# A release filename starts with a letter, digit or underscore, so it cannot be
# empty, hidden, a traversal or an option, and it never contains a slash.
macos_release_filename() {
  [[ "$1" =~ ^[A-Za-z0-9_][A-Za-z0-9_.+-]*$ ]]
}

# Physical directory of a manifest path.
macos_release_manifest_dir() {
  (cd "$(dirname "$1")" >/dev/null && pwd -P)
}

# Print <manifest dir>/<name> for a valid release filename that is not a
# symlink. Callers check the type and existence of the result themselves.
macos_release_path() {
  local manifest_dir="$1" name="$2"
  if ! macos_release_filename "$name" || [[ -L "$manifest_dir/$name" ]]; then
    return 1
  fi
  printf '%s/%s\n' "$manifest_dir" "$name"
}
