#!/usr/bin/env bash
# Tests for scripts/macos_app_binary.sh with fixture git repositories and
# mocked Apple tools. Portable: plain bash, git, find and awk.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
TMP_DIR="$(cd "$TMP_DIR" && pwd -P)"
# shellcheck source=scripts/macos_app_binary.sh
source "$ROOT/scripts/macos_app_binary.sh"
# shellcheck source=scripts/macos_license_notices.sh
source "$ROOT/scripts/macos_license_notices.sh"

fail() {
  echo "test_macos_app_binary: $*" >&2
  exit 1
}

# expect_status <want> <label> <command...>: runs in a subshell, keeps output.
expect_status() {
  local want="$1" label="$2" got=0
  shift 2
  ( "$@" ) >"$TMP_DIR/out" 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    cat "$TMP_DIR/out" >&2
    fail "$label: exit $got, want $want"
  fi
}

# with_env NAME=value <command...>: exports into the expect_status subshell only.
with_env() {
  export "${1?}"
  shift
  "$@"
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

# --- Rust/C path remapping ----------------------------------------------------
build_env_case() {
  HOME=/tmp/fixture-home CARGO_HOME=/tmp/fixture-home/.cargo CFLAGS="${1:-}"
  unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS HOST_CFLAGS TARGET_CFLAGS
  ottto_macos_release_build_env /tmp/fixture-home/work/public
  printf '%s\n' "$CARGO_ENCODED_RUSTFLAGS" | tr '\037' '\n' > "$TMP_DIR/rustflags"
  printf '%s\n' "$CFLAGS" > "$TMP_DIR/cflags"
}
expect_status 0 "clean build env" build_env_case "-O2"
printf '%s\n' \
  "--remap-path-prefix=/tmp/fixture-home=~" \
  "--remap-path-prefix=/tmp/fixture-home/.cargo=/cargo" \
  "--remap-path-prefix=/tmp/fixture-home/work/public=." > "$TMP_DIR/want-rustflags"
cmp -s "$TMP_DIR/rustflags" "$TMP_DIR/want-rustflags" || fail "CARGO_ENCODED_RUSTFLAGS must be the three remaps, most specific last"
[[ "$(cat "$TMP_DIR/cflags")" == "-O2 -ffile-prefix-map=/tmp/fixture-home=~ -ffile-prefix-map=/tmp/fixture-home/.cargo=/cargo -ffile-prefix-map=/tmp/fixture-home/work/public=." ]] \
  || fail "CFLAGS must keep a preset value and append the three maps"
expect_status 2 "preset RUSTFLAGS" env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS=-Cdebuginfo=2 bash -c "source '$ROOT/scripts/macos_app_binary.sh'; ottto_macos_release_build_env /tmp/x"
expect_output "unset RUSTFLAGS" "preset RUSTFLAGS"
expect_status 2 "preset CARGO_ENCODED_RUSTFLAGS" env -u RUSTFLAGS CARGO_ENCODED_RUSTFLAGS=-g bash -c "source '$ROOT/scripts/macos_app_binary.sh'; ottto_macos_release_build_env /tmp/x"
for c_var in TARGET_CFLAGS HOST_CFLAGS CFLAGS_aarch64_apple_darwin CFLAGS_aarch64-apple-darwin; do
  expect_status 2 "preset $c_var" env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u HOST_CFLAGS -u TARGET_CFLAGS "$c_var=-ffile-prefix-map=/x=/y" bash -c "source '$ROOT/scripts/macos_app_binary.sh'; ottto_macos_release_build_env /tmp/x"
  expect_output "unset HOST_CFLAGS, TARGET_CFLAGS and CFLAGS_<target>" "preset $c_var"
done
expect_status 2 "root with a space" env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u HOST_CFLAGS -u TARGET_CFLAGS HOME=/tmp/fixture-home bash -c "source '$ROOT/scripts/macos_app_binary.sh'; ottto_macos_release_build_env '/tmp/fixture home/public'"
expect_output "must not contain whitespace" "root with a space"

# --- Swift scratch folder -----------------------------------------------------
mkdir -p "$TMP_DIR/runner-temp"
first="$(RUNNER_TEMP="$TMP_DIR/runner-temp" ottto_macos_swift_scratch stable /fixture/app)"
second="$(RUNNER_TEMP="$TMP_DIR/runner-temp" ottto_macos_swift_scratch stable-candidate /fixture/app)"
[[ -d "$first" && -d "$second" && "$first" != "$second" ]] || fail "stable channels must get a new folder per build"
[[ "$first" == "$TMP_DIR/runner-temp/ottto-swift."* ]] || fail "the stable scratch folder belongs under RUNNER_TEMP"
[[ -z "$(ls -A "$first")" ]] || fail "the stable scratch folder must start empty"
[[ "$(ottto_macos_swift_scratch dev /fixture/app)" == "/fixture/app/.build" ]] || fail "dev keeps the incremental .build"
[[ "$(ottto_macos_swift_scratch preview /fixture/app)" == "/fixture/app/.build" ]] || fail "preview keeps the incremental .build"

# --- binary policy: fresh builds and the private dSYM folder -------------------
policy_root="$TMP_DIR/policy"
mkdir -p "$policy_root/public" "$policy_root/app-checkout" "$policy_root/runner/_work/_temp" "$policy_root/private"
policy() {  # <channel> <skip-build> [dSYM folder]
  RUNNER_TEMP="$policy_root/runner/_work/_temp" RUNNER_WORKSPACE="$policy_root/runner/_work" \
    OTTTO_MACOS_DSYM_DIR="${3:-}" \
    ottto_macos_check_binary_policy "$1" "$2" "$policy_root/public" "$policy_root/out" "$policy_root/app-checkout"
}
for channel in stable stable-candidate; do
  expect_status 2 "$channel --skip-build" policy "$channel" true "$policy_root/private/dsym"
  expect_output "Stable channels build from source" "$channel --skip-build"
  expect_status 2 "$channel without a dSYM folder" policy "$channel" false
  expect_output "OTTTO_MACOS_DSYM_DIR is required for stable channels" "$channel without a dSYM folder"
done
expect_status 0 "dev without a dSYM folder" policy dev false
expect_output "::warning::Companion dSYM not kept" "dev without a dSYM folder"
expect_status 0 "preview reuse without a dSYM folder" policy preview true
expect_status 2 "relative dSYM folder" policy stable false "relative/dsym"
expect_output "must be an absolute folder" "relative dSYM folder"
for inside in public/dsym out/dsym app-checkout/.dsym runner/_work/_temp/dsym runner/_work/dsym; do
  expect_status 2 "dSYM folder in $inside" policy stable false "$policy_root/$inside"
  expect_output "must be outside the public checkout" "dSYM folder in $inside"
  expect_no_output "$policy_root" "dSYM folder in $inside"
done
expect_status 2 "dSYM folder holding the public checkout" policy stable false "$policy_root"
expect_status 0 "private dSYM folder" policy stable false "$policy_root/private/dsym"
expect_no_output "$policy_root" "private dSYM folder"
[[ -d "$policy_root/private/dsym/logs" ]] || fail "the policy creates the private log folder"
[[ -n "$(find "$policy_root/private/dsym" -maxdepth 0 -perm 700)" ]] || fail "the dSYM folder must be private (0700)"

# --- private logs -------------------------------------------------------------
logged_failure() {
  OTTTO_MACOS_PRIVATE_LOG_DIR="$TMP_DIR/private-log"
  mkdir -p "$OTTTO_MACOS_PRIVATE_LOG_DIR"
  ottto_macos_run_logged "Swift release build" bash -c 'echo "/synthetic/build/home/OtttoCompanion.build/x.o: error" >&2; exit 3'
}
expect_status 3 "logged failure" logged_failure
expect_output "Swift release build failed (exit 3)" "logged failure"
expect_no_output "/synthetic/build/home" "logged failure"
grep -Fq "/synthetic/build/home" "$TMP_DIR/private-log/Swift release build.log" || fail "the private log keeps the tool output"
# A log that cannot be opened (its folder is a file) gets a fixed public error;
# the shell's own open diagnostic would name the private path.
printf 'not a folder\n' > "$TMP_DIR/synthetic-private-marker"
blocked_log() {
  OTTTO_MACOS_PRIVATE_LOG_DIR="$TMP_DIR/synthetic-private-marker/logs"
  ottto_macos_run_logged "Rust release build" echo "ran"
}
expect_status 1 "blocked private log" blocked_log
expect_output "Rust release build: the private build log could not be opened" "blocked private log"
expect_no_output "synthetic-private-marker" "blocked private log"
expect_no_output "ran" "blocked private log"

# --- Companion resources from the app commit ---------------------------------
app_git="$TMP_DIR/app-git"
resources="$app_git/tools/app/Sources/OtttoCompanion/Resources"
new_app_repo() {
  rm -rf "$app_git"
  mkdir -p "$resources/Fonts"
  git -C "$TMP_DIR" init -q "$app_git"
  git -C "$app_git" config user.email "app-binary-test@example.invalid"
  git -C "$app_git" config user.name "App Binary Test"
  local name
  while IFS= read -r name; do
    printf 'fixture %s\n' "$name" > "$resources/$name"
  done < <(ottto_macos_companion_resource_names)
  printf 'private notes\n' > "$resources/README.md"
}
commit_app() {
  git -C "$app_git" add -A
  git -C "$app_git" commit -qm fixture
}
copy_log_dir="$TMP_DIR/copy-private-log"
copy_into() {  # <dest> [commit]
  rm -rf "$1" "$copy_log_dir"
  mkdir -p "$1" "$copy_log_dir"
  OTTTO_MACOS_PRIVATE_LOG_DIR="$copy_log_dir"
  ottto_macos_copy_companion_resources "$app_git" "${2:-$(git -C "$app_git" rev-parse HEAD)}" tools/app "$1"
}
copy_log="$copy_log_dir/Copy Companion resources.log"

new_app_repo
commit_app
printf 'untracked\n' > "$resources/stray.png"
expect_status 0 "copy the listed resources" copy_into "$TMP_DIR/res"
while IFS= read -r name; do
  cmp -s "$TMP_DIR/res/$name" <(git -C "$app_git" cat-file blob "HEAD:tools/app/Sources/OtttoCompanion/Resources/$name") \
    || fail "$name must be the committed blob"
done < <(ottto_macos_companion_resource_names)
[[ ! -e "$TMP_DIR/res/README.md" ]] || fail "README.md never ships"
[[ ! -e "$TMP_DIR/res/stray.png" ]] || fail "an untracked file never ships"
expect_status 1 "final inventory without the license files" ottto_macos_check_app_resources "$TMP_DIR/res"
while IFS= read -r name; do
  printf 'x\n' > "$TMP_DIR/res/$name"
done < <(ottto_app_license_resource_names)
expect_status 0 "final inventory of the copied resources" ottto_macos_check_app_resources "$TMP_DIR/res"

# Resources come from the recorded commit even after the checkout moves on.
rm "$resources/stray.png"
recorded="$(git -C "$app_git" rev-parse HEAD)"
printf 'changed after the build\n' > "$resources/ottto-mark.png"
commit_app
expect_status 0 "copy from the recorded commit" copy_into "$TMP_DIR/res" "$recorded"
cmp -s "$TMP_DIR/res/ottto-mark.png" <(git -C "$app_git" cat-file blob "$recorded:tools/app/Sources/OtttoCompanion/Resources/ottto-mark.png") \
  || fail "resources come from the recorded commit, not the moved HEAD"
expect_status 1 "abbreviated commit" copy_into "$TMP_DIR/res" "${recorded:0:12}"
expect_output "the app commit is not a full object id" "abbreviated commit"
expect_status 1 "unknown commit" copy_into "$TMP_DIR/res" 0123456789abcdef0123456789abcdef01234567
expect_output "Could not list the app's tracked Resources; details are in the private build log" "unknown commit"
expect_no_output "$app_git" "unknown commit"
[[ -s "$copy_log" ]] || fail "git's diagnostic goes to the private log"

# A tracked file outside the list fails; its name stays in the private log.
printf 'notes\n' > "$resources/synthetic-private-marker.txt"
commit_app
expect_status 1 "tracked file outside the list" copy_into "$TMP_DIR/res"
expect_output "has a Companion resource that is not on the release list; its name is in the private build log" "tracked file outside the list"
expect_no_output "synthetic-private-marker" "tracked file outside the list"
grep -Fq "not on the release list: synthetic-private-marker.txt" "$copy_log" || fail "the unlisted name goes to the private log"

new_app_repo
mkdir -p "$resources/Fonts/sub"
printf 'x\n' > "$resources/Fonts/sub/Fraunces-VF.ttf"
commit_app
expect_status 1 "nested font" copy_into "$TMP_DIR/res"
expect_output "not on the release list; its name is in the private build log" "nested font"
grep -Fq "not on the release list: Fonts/sub/Fraunces-VF.ttf" "$copy_log" || fail "the nested name goes to the private log"

new_app_repo
rm "$resources/brand-pi.png"
ln -s ottto-mark.png "$resources/brand-pi.png"
commit_app
expect_status 1 "tracked symlink" copy_into "$TMP_DIR/res"
expect_output "not a regular file: brand-pi.png" "tracked symlink"

new_app_repo
rm "$resources/Fonts/JetBrainsMono-SemiBold.ttf"
commit_app
expect_status 1 "missing listed font" copy_into "$TMP_DIR/res"
expect_output "missing from the app commit: Fonts/JetBrainsMono-SemiBold.ttf" "missing listed font"

# --- final Resources inventory ------------------------------------------------
new_app_repo
commit_app
inventory_log="$copy_log_dir/Check Ottto.app Resources.log"
inventory_case() {  # <setup snippet>
  copy_into "$TMP_DIR/inv"
  eval "$1"
  ottto_macos_check_app_resources "$TMP_DIR/inv"
}
# The license helper names the exact license files; nothing else passes.
# shellcheck disable=SC2016 # expanded later by eval
licenses='for n in LICENSE NOTICE LICENSE-THIRD-PARTY.html LICENSE-Sparkle.txt; do printf "x\n" > "$TMP_DIR/inv/$n"; done'
expect_status 0 "listed resources and the four license files" inventory_case "$licenses"
expect_status 1 "a license file missing" inventory_case "$licenses; rm \"\$TMP_DIR/inv/NOTICE\""
expect_output "missing: NOTICE" "a license file missing"
expect_status 1 "an extra license file" inventory_case "$licenses; printf 'x\n' > \"\$TMP_DIR/inv/LICENSE-debug.txt\""
expect_output "Ottto.app Resources holds a file outside the release list; its name is in the private build log" "an extra license file"
expect_no_output "LICENSE-debug" "an extra license file"
grep -Fq "outside the release list: LICENSE-debug.txt" "$inventory_log" || fail "the extra name goes to the private log"
expect_status 1 "an unlisted file" inventory_case "$licenses; printf 'x\n' > \"\$TMP_DIR/inv/synthetic-private-marker.bin\""
expect_no_output "synthetic-private-marker" "an unlisted file"
expect_status 1 "a nested license file" inventory_case "$licenses; mkdir -p \"\$TMP_DIR/inv/LICENSE-foo\"; printf 'x\n' > \"\$TMP_DIR/inv/LICENSE-foo/bar\""
expect_output "Ottto.app Resources holds an unexpected folder" "a nested license file"
expect_no_output "LICENSE-foo" "a nested license file"
expect_status 1 "README shipped" inventory_case "$licenses; printf 'x\n' > \"\$TMP_DIR/inv/README.md\""
expect_status 1 "symlinked resource" inventory_case "$licenses; rm \"\$TMP_DIR/inv/ottto-mark.png\"; ln -s brand-pi.png \"\$TMP_DIR/inv/ottto-mark.png\""
expect_output "Ottto.app Resources holds a symlink" "symlinked resource"
grep -Fq "holds a symlink: ottto-mark.png" "$inventory_log" || fail "the symlink name goes to the private log"
expect_status 1 "a font missing" inventory_case "$licenses; rm \"\$TMP_DIR/inv/Fonts/Fraunces-VF.ttf\""
expect_output "missing: Fonts/Fraunces-VF.ttf" "a font missing"

# --- strip and debug-map count ------------------------------------------------
tools="$TMP_DIR/tools"
mkdir -p "$tools"
cat > "$tools/strip" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_LOG"
MOCK
cat > "$tools/nm" <<'MOCK'
#!/usr/bin/env bash
case "${NM_MODE:-clean}" in
  fail) echo "nm: /synthetic/build/home/Ottto: truncated" >&2; exit 1 ;;
  ast) printf '0000000000000000 - 00 0000    AST /synthetic/build/home/x.swiftmodule\n0000000100003f20 T _main\n' ;;
  stripped) printf '0000000005614542 - 00 0000    OPT radr://5614542\n0000000100003f20 T _main\n' ;;
  opt) printf '0000000005614542 - 00 0000    OPT /synthetic/build/home/x.o\n0000000100003f20 T _main\n' ;;
  oso) printf '0000000000000000 - 00 0001    OSO release/x.o\n0000000000000000 - 01 0000    SO x.swift\n0000000100003f20 T _main\n' ;;
  *) printf '0000000100003f20 T _main\n                 U _objc_msgSend\n' ;;
esac
MOCK
chmod +x "$tools"/*
export MOCK_LOG="$TMP_DIR/mock.log"
OTTTO_MACOS_APPLE_TOOL_DIR="$tools"
OTTTO_MACOS_PRIVATE_LOG_DIR=""
: > "$MOCK_LOG"
expect_status 0 "strip" ottto_macos_strip_companion /fixture/Ottto.app/Contents/MacOS/Ottto
[[ "$(cat "$MOCK_LOG")" == "-S -x /fixture/Ottto.app/Contents/MacOS/Ottto" ]] || fail "strip must run as strip -S -x <executable>"
expect_status 0 "no stabs" with_env NM_MODE=clean ottto_macos_check_no_stabs /x
# Apple strip leaves its own OPT radr://5614542 marker; nothing else passes.
expect_status 0 "strip's own marker" with_env NM_MODE=stripped ottto_macos_check_no_stabs /x
expect_status 1 "another OPT stab" with_env NM_MODE=opt ottto_macos_check_no_stabs /x
expect_output "still has 1 debug-map entries" "another OPT stab"
[[ "$(NM_MODE=stripped ottto_macos_count_stabs /x OPT)" == "1" ]] || fail "a typed count still sees the marker"
expect_status 1 "an unlisted stab type" with_env NM_MODE=ast ottto_macos_check_no_stabs /x
expect_output "still has 1 debug-map entries" "an unlisted stab type"
expect_no_output "/synthetic/build/home" "an unlisted stab type"
expect_status 1 "OSO and SO stabs" with_env NM_MODE=oso ottto_macos_check_no_stabs /x
expect_output "still has 2 debug-map entries" "OSO and SO stabs"
expect_status 1 "nm failure" with_env NM_MODE=fail ottto_macos_check_no_stabs /x
expect_output "nm could not read the Companion executable" "nm failure"
expect_no_output "/synthetic/build/home" "nm failure"
[[ "$(NM_MODE=oso ottto_macos_count_stabs /x OSO)" == "1" ]] || fail "count one stab type"

# --- dSYM: make, validate, keep under its UUID --------------------------------
# dsymutil warns and exits 0 when an object is missing; the helper reads this
# run's part of the private log.
cat > "$tools/dsymutil" <<'MOCK'
#!/usr/bin/env bash
printf 'dsymutil %s\n' "$*" >> "$MOCK_LOG"
case "${DSYMUTIL_MODE:-ok}" in
  fail) echo "error: /synthetic/build/home/release/Ottto: cannot parse the debug map" >&2; exit 1 ;;
  missing) echo "warning: (arm64) /synthetic/build/home/release/x.o unable to open object file: No such file or directory" >&2 ;;
  stale) echo "warning: /synthetic/build/home/release/x.o: timestamp mismatch between object file (2026-01-01 00:00:01) and debug map (2026-01-01 00:00:00)" >&2 ;;
  swiftmodule) echo "warning: /synthetic/build/home/release/X.swiftmodule: timestamp mismatch between swift interface file (2026-01-01 00:00:01) and debug map (2026-01-01 00:00:00)" >&2 ;;
esac
out=""
while [[ $# -gt 0 ]]; do
  case "$1" in -o) out="$2"; shift 2 ;; *) shift ;; esac
done
mkdir -p "$out/Contents/Resources/DWARF"
if [[ "${DSYMUTIL_MODE:-ok}" == empty ]]; then
  : > "$out/Contents/Resources/DWARF/Ottto"
else
  printf 'dwarf\n' > "$out/Contents/Resources/DWARF/Ottto"
fi
MOCK
cat > "$tools/dwarfdump" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  --uuid)
    uuid="${DSYM_UUID:-11111111-2222-3333-4444-555555555555}"
    [[ "$2" == *.dSYM ]] || uuid="${APP_UUID:-11111111-2222-3333-4444-555555555555}"
    printf 'UUID: %s (arm64) %s\n' "$uuid" "$2" ;;
  --debug-info)
    # A counting loop: BSD seq 1 0 counts down and prints two lines.
    i=0
    while [[ "$i" -lt "${UNITS:-3}" ]]; do printf '0x0000000b: DW_TAG_compile_unit\n'; i=$((i + 1)); done ;;
esac
MOCK
# main of a Swift @main type maps to its file at line 0 (compiler-generated).
cat > "$tools/atos" <<'MOCK'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$MOCK_LOG"
case "${ATOS_MODE:-ok}" in
  ok) printf 'main (in Ottto) (OtttoCompanionApp.swift:0)\n' ;;
  other) printf 'main (in Ottto) (Generated.swift:4)\n' ;;
  *) printf 'main (in Ottto) + 0\n' ;;
esac
MOCK
cat > "$tools/nm" <<'MOCK'
#!/usr/bin/env bash
if [[ "$1" == -ap ]]; then
  [[ "${NM_OSO:-2}" == 0 ]] || printf '0000000000000000 - 00 0001    OSO release/a.o\n0000000000000000 - 00 0001    OSO release/b.o\n'
else
  printf '0000000100003f20 t _$s14OtttoCompanion3AppVACycfC\n'
  [[ "${NM_MAIN:-yes}" == no ]] || printf '0000000100004000 T _main\n'
fi
MOCK
chmod +x "$tools"/*
dsym_dir="$TMP_DIR/private-dsym"
dsym_log="$dsym_dir/logs/Make the Companion dSYM.log"
dsym_case() {  # make + keep with the current mock settings
  OTTTO_MACOS_DSYM_DIR="$dsym_dir"
  OTTTO_MACOS_PRIVATE_LOG_DIR="$dsym_dir/logs"
  mkdir -p "$OTTTO_MACOS_PRIVATE_LOG_DIR"
  ottto_macos_make_dsym /synthetic/scratch/release/Ottto /synthetic/scratch &&
    ottto_macos_keep_dsym /fixture/Ottto.app/Contents/MacOS/Ottto 0.1.92-rc2
}
# An earlier run's missing-object warning in the same log does not count.
mkdir -p "$dsym_dir/logs"
printf 'warning: (arm64) /synthetic/old/x.o unable to open object file: No such file or directory\n' > "$dsym_log"
: > "$MOCK_LOG"
expect_status 0 "keep a valid dSYM" dsym_case
[[ -d "$dsym_dir/Ottto-0.1.92-rc2-11111111-2222-3333-4444-555555555555.dSYM" ]] || fail "the dSYM is kept under its version and UUID"
[[ -z "$(find "$dsym_dir" -maxdepth 1 -name '.incoming.*')" ]] || fail "the incoming folder is removed"
grep -Fq -- "dsymutil --oso-prepend-path=/synthetic/scratch /synthetic/scratch/release/Ottto -o $dsym_dir/.incoming." "$MOCK_LOG" \
  || fail "dsymutil reads the unstripped executable with the object prefix"
grep -Eq -- "^-o $dsym_dir/\.incoming\.[^ ]+/Ottto\.app\.dSYM/Contents/Resources/DWARF/Ottto 0x0000000100004000$" "$MOCK_LOG" \
  || fail "atos looks up main's address in the new dSYM"
expect_no_output "$dsym_dir" "keep a valid dSYM"
expect_output "Companion dSYM made: 2 debug-map objects read, main resolves to OtttoCompanionApp.swift" "keep a valid dSYM"
expect_output "Companion dSYM kept privately for UUID 11111111-2222-3333-4444-555555555555" "keep a valid dSYM"

expect_status 1 "dsymutil failure" with_env DSYMUTIL_MODE=fail dsym_case
expect_output "Make the Companion dSYM failed" "dsymutil failure"
expect_no_output "/synthetic/build/home" "dsymutil failure"
for mode in missing stale; do
  expect_status 1 "dsymutil $mode object warning" with_env DSYMUTIL_MODE="$mode" dsym_case
  expect_output "dsymutil could not read every object" "dsymutil $mode object warning"
  expect_no_output "/synthetic/build/home" "dsymutil $mode object warning"
done
grep -Fq "/synthetic/build/home/release/x.o unable to open object file" "$dsym_log" || fail "the dsymutil warning stays in the private log"
expect_status 0 "a Swift module timestamp warning" with_env DSYMUTIL_MODE=swiftmodule dsym_case
expect_status 1 "no debug map" with_env NM_OSO=0 dsym_case
expect_output "has no debug map" "no debug map"
expect_status 1 "empty DWARF" with_env DSYMUTIL_MODE=empty dsym_case
expect_output "has no DWARF compile units" "empty DWARF"
expect_status 1 "no compile units" with_env UNITS=0 dsym_case
expect_output "has no DWARF compile units" "no compile units"
expect_status 1 "main does not resolve" with_env ATOS_MODE=none dsym_case
expect_output "does not resolve main to OtttoCompanionApp.swift" "main does not resolve"
expect_status 1 "main resolves elsewhere" with_env ATOS_MODE=other dsym_case
expect_status 1 "no main symbol" with_env NM_MAIN=no dsym_case
blocked_dsym_log() {
  OTTTO_MACOS_DSYM_DIR="$dsym_dir"
  OTTTO_MACOS_PRIVATE_LOG_DIR="$TMP_DIR/synthetic-private-marker/logs"
  ottto_macos_make_dsym /synthetic/scratch/release/Ottto /synthetic/scratch
}
expect_status 1 "blocked dSYM log" blocked_dsym_log
expect_no_output "synthetic-private-marker" "blocked dSYM log"
expect_status 1 "UUID mismatch" with_env APP_UUID=99999999-2222-3333-4444-555555555555 dsym_case
expect_output "UUID does not match the signed app" "UUID mismatch"
[[ ! -e "$dsym_dir/Ottto-0.1.92-rc2-99999999-2222-3333-4444-555555555555.dSYM" ]] || fail "a mismatched dSYM is never kept"
# A failed retry of the same version leaves the earlier dSYM alone.
[[ -d "$dsym_dir/Ottto-0.1.92-rc2-11111111-2222-3333-4444-555555555555.dSYM" ]] || fail "a failed retry must not erase the kept dSYM"

echo "macOS app binary helper tests passed"
