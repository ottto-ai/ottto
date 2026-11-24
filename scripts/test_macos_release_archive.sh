#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_release_archive.sh
source "$ROOT/scripts/macos_release_archive.sh"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Skipping macOS release archive test on non-Darwin host."
  exit 0
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

fail() {
  echo "$*" >&2
  exit 1
}

# A synthetic executable with a harmless extended attribute, last modified at
# a known UTC instant.
tool="$TMP_DIR/tool"
printf '#!/bin/sh\necho fixture\n' > "$tool"
chmod 0755 "$tool"
xattr -w net.ottto.release-archive-test fixture "$tool"
TZ=UTC touch -t 202601010000 "$tool"

# Archive from a parent whose local time zone is 14 hours ahead of UTC.
TZ=Pacific/Kiritimati bash -c '
  source "$1"
  ottto_release_zip "$2" "$3"
' archive "$ROOT/scripts/macos_release_archive.sh" "$tool" "$TMP_DIR/tool.zip"

# Read the raw ZIP central directory, not an extracted copy: extraction can add
# local metadata of its own.
python3 - "$TMP_DIR/tool.zip" "$tool" <<'PY' || fail "release zip must hold only the original file"
import sys
import zipfile
from pathlib import Path

archive, original = sys.argv[1], Path(sys.argv[2])
with zipfile.ZipFile(archive) as zf:
    entries = zf.infolist()
    names = [entry.filename for entry in entries]
    if names != ["tool"]:
        sys.exit(f"unexpected zip members (AppleDouble or extra entries): {names}")
    entry = entries[0]
    if zf.read(entry) != original.read_bytes():
        sys.exit("zip member bytes differ from the original file")
    mode = (entry.external_attr >> 16) & 0o7777
    if mode != 0o755:
        sys.exit(f"zip member lost its executable mode: {oct(mode)}")
    # DOS timestamps are local time; the archive must record the UTC instant.
    if entry.date_time != (2026, 1, 1, 0, 0, 0):
        sys.exit(f"zip member time is not UTC: {entry.date_time}")
PY

# The original file keeps its attribute: archiving never edits the input.
[[ "$(xattr -p net.ottto.release-archive-test "$tool")" == "fixture" ]] \
  || fail "archiving must not change the input file"

echo "macOS release archive tests passed"
