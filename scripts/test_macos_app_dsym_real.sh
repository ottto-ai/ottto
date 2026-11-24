#!/usr/bin/env bash
# Runs the Companion dSYM and strip helpers of scripts/macos_app_binary.sh on
# a real optimized Swift Mach-O with the Xcode toolchain: dsymutil, dwarfdump,
# atos, nm and strip are the real Apple tools, not mocks. macOS only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ "$(uname -s)" != Darwin ]]; then
  echo "test_macos_app_dsym_real: needs macOS and Xcode" >&2
  exit 1
fi
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
# Physical path, as the packager uses for the object prefix.
TMP_DIR="$(cd "$TMP_DIR" && pwd -P)"
# shellcheck source=scripts/macos_app_binary.sh
source "$ROOT/scripts/macos_app_binary.sh"

fail() {
  echo "test_macos_app_dsym_real: $*" >&2
  exit 1
}

expect_status() {  # <want> <label> <command...>: runs in a subshell, keeps output.
  local want="$1" label="$2" got=0
  shift 2
  ( "$@" ) >"$TMP_DIR/out" 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    cat "$TMP_DIR/out" >&2
    fail "$label: exit $got, want $want"
  fi
}

expect_output() {  # <fixed text> <label>
  grep -Fq -- "$1" "$TMP_DIR/out" || { cat "$TMP_DIR/out" >&2; fail "$2: output lacks: $1"; }
}

expect_no_output() {  # <text> <label>
  if grep -Fq -- "$1" "$TMP_DIR/out"; then
    cat "$TMP_DIR/out" >&2
    fail "$2: output must not contain: $1"
  fi
}

# A two-file module named like the Companion: @main in the entry file and a
# function the optimizer keeps in a second object.
scratch="$TMP_DIR/scratch"
src="$TMP_DIR/src"
mkdir -p "$scratch/obj" "$scratch/release" "$src"
cat > "$src/$OTTTO_MACOS_COMPANION_ENTRY_SOURCE" <<'SWIFT'
@main
struct FixtureApp {
    static func main() {
        print(Helper.compute(CommandLine.arguments.count))
    }
}
SWIFT
cat > "$src/Helper.swift" <<'SWIFT'
enum Helper {
    @inline(never)
    static func compute(_ x: Int) -> Int { x * 3 + Int.random(in: 0...1) }
}
SWIFT
(
  cd "$scratch/obj"
  xcrun swiftc -O -g -c "$src/$OTTTO_MACOS_COMPANION_ENTRY_SOURCE" "$src/Helper.swift" \
    -module-name OtttoCompanion -parse-as-library
)
exe="$scratch/release/Ottto"
xcrun swiftc "$scratch/obj/"*.o -o "$exe" -Xlinker -oso_prefix -Xlinker "$scratch/"
[[ "$(ottto_macos_count_stabs "$exe" OSO)" == "2" ]] || fail "the fixture executable must have a two-object debug map"

OTTTO_MACOS_APPLE_TOOL_DIR=/usr/bin
dsym_dir="$TMP_DIR/private-dsym"
mkdir -p "$dsym_dir/logs"
make_dsym() {
  OTTTO_MACOS_DSYM_DIR="$dsym_dir"
  OTTTO_MACOS_PRIVATE_LOG_DIR="$dsym_dir/logs"
  ottto_macos_make_dsym "$exe" "$scratch" || return 1
  # The checked dSYM stays in the incoming folder for the keep step.
  printf '%s\n' "$OTTTO_MACOS_DSYM_INCOMING" > "$TMP_DIR/incoming"
  printf '%s\n' "$OTTTO_MACOS_DSYM_UUID" > "$TMP_DIR/uuid"
}
expect_status 0 "dSYM of a real optimized Swift executable" make_dsym
expect_output "Companion dSYM made: 2 debug-map objects read, main resolves to $OTTTO_MACOS_COMPANION_ENTRY_SOURCE" "real dSYM"
expect_no_output "$TMP_DIR" "real dSYM"
incoming="$(cat "$TMP_DIR/incoming")"
uuid="$(cat "$TMP_DIR/uuid")"
dwarf="$incoming/Ottto.app.dSYM/Contents/Resources/DWARF/Ottto"
symbols="$(/usr/bin/nm -n "$exe")"
helper_address="$(awk '$3 ~ /^_\$s14OtttoCompanion6HelperO7compute/ && !found {print "0x" $1; found = 1}' <<<"$symbols")"
[[ -n "$helper_address" ]] || fail "the fixture keeps Helper.compute"
helper_frame="$(/usr/bin/atos -o "$dwarf" "$helper_address")"
[[ "$helper_frame" =~ \(Helper\.swift:[1-9][0-9]*\) ]] \
  || fail "the dSYM must resolve the second object's function to a source line, got: $helper_frame"

# Strip the bundle copy, sign it ad hoc, then keep the dSYM under the signed
# executable's UUID.
app_exe="$TMP_DIR/Ottto.app/Contents/MacOS/Ottto"
mkdir -p "$(dirname "$app_exe")"
cp "$exe" "$app_exe"
[[ "$(ottto_macos_count_stabs "$app_exe")" != "0" ]] || fail "the unstripped copy has debug-map entries"
expect_status 0 "strip" ottto_macos_strip_companion "$app_exe"
codesign --force --sign - "$app_exe" >/dev/null 2>&1 || fail "ad hoc signing failed"
expect_status 0 "no debug map after strip" ottto_macos_check_no_stabs "$app_exe"
keep_dsym() {
  OTTTO_MACOS_DSYM_DIR="$dsym_dir"
  OTTTO_MACOS_DSYM_INCOMING="$incoming"
  OTTTO_MACOS_DSYM_UUID="$uuid"
  ottto_macos_keep_dsym "$app_exe" 0.1.92-rc2
}
expect_status 0 "keep the dSYM under the signed UUID" keep_dsym
kept="$dsym_dir/Ottto-0.1.92-rc2-$uuid.dSYM"
[[ -d "$kept" ]] || fail "the dSYM is kept under its version and UUID"
[[ "$(ottto_macos_dsym_uuid "$app_exe")" == "$(ottto_macos_dsym_uuid "$kept")" ]] \
  || fail "the kept dSYM's UUID is the signed executable's"

# A debug-map object deleted before dsymutil runs: dsymutil only warns and
# exits 0; the helper fails without naming the object in its output.
rm "$scratch/obj/Helper.o"
expect_status 1 "a missing debug-map object" make_dsym
expect_output "dsymutil could not read every object" "a missing debug-map object"
expect_no_output "$TMP_DIR" "a missing debug-map object"
grep -Fq "unable to open object file" "$dsym_dir/logs/Make the Companion dSYM.log" \
  || fail "dsymutil's missing-object warning is in the private log"

echo "macOS app dSYM tests on a real Swift executable passed"
