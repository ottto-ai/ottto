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

# A staged folder like the packager's: a synthetic executable plus synthetic
# notices, each with a harmless extended attribute, last modified at a known
# UTC instant.
stage="$TMP_DIR/stage"
mkdir "$stage"
tool="$stage/tool"
printf '#!/bin/sh\necho fixture\n' > "$tool"
chmod 0755 "$tool"
printf 'Fixture license\n' > "$stage/LICENSE"
printf 'Fixture notice\n' > "$stage/NOTICE"
chmod 0644 "$stage/LICENSE" "$stage/NOTICE"
for file in "$tool" "$stage/LICENSE" "$stage/NOTICE"; do
  xattr -w net.ottto.release-archive-test fixture "$file"
  TZ=UTC touch -t 202601010000 "$file"
done

# Archive from a parent whose local time zone is 14 hours ahead of UTC.
TZ=Pacific/Kiritimati bash -c '
  source "$1"
  ottto_release_zip "$2" "$3"
' archive "$ROOT/scripts/macos_release_archive.sh" "$stage" "$TMP_DIR/tool.zip"

# Read the raw ZIP central directory, not an extracted copy: extraction can add
# local metadata of its own.
python3 - "$TMP_DIR/tool.zip" "$stage" <<'PY' || fail "release zip must hold only the staged files"
import sys
import zipfile
from pathlib import Path

archive, stage = sys.argv[1], Path(sys.argv[2])
want_modes = {"LICENSE": 0o644, "NOTICE": 0o644, "tool": 0o755}
with zipfile.ZipFile(archive) as zf:
    entries = zf.infolist()
    names = sorted(entry.filename for entry in entries)
    if names != sorted(want_modes):
        sys.exit(f"unexpected zip members (AppleDouble, folder or extra entries): {names}")
    for entry in entries:
        if zf.read(entry) != (stage / entry.filename).read_bytes():
            sys.exit(f"zip member bytes differ from the staged file: {entry.filename}")
        mode = (entry.external_attr >> 16) & 0o7777
        if mode != want_modes[entry.filename]:
            sys.exit(f"zip member {entry.filename} has mode {oct(mode)}")
        # DOS timestamps are local time; the archive must record the UTC instant.
        if entry.date_time != (2026, 1, 1, 0, 0, 0):
            sys.exit(f"zip member {entry.filename} time is not UTC: {entry.date_time}")
PY

# The original file keeps its attribute: archiving never edits the input.
[[ "$(xattr -p net.ottto.release-archive-test "$tool")" == "fixture" ]] \
  || fail "archiving must not change the input file"

echo "macOS release archive tests passed"
