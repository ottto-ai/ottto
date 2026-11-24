#!/usr/bin/env bash
# Published ZIP archives carry file bytes and permissions only.

# ottto_release_zip <input> <output.zip>
#
# --norsrc --noextattr keep resource forks and extended attributes (such as
# com.apple.provenance, which ties a file to the Mac that built it) out of the
# archive, so it holds no AppleDouble "._" members. TZ=UTC makes the local-time
# DOS timestamps in the ZIP the same on every build host.
ottto_release_zip() {
  TZ=UTC ditto -c -k --norsrc --noextattr "$1" "$2"
}
