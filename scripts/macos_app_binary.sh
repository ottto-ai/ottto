#!/usr/bin/env bash
# Companion app binary hygiene for release packaging. Sourced by
# macos_package.sh; defines functions only.
#   - Rust/C: map build folders through CARGO_ENCODED_RUSTFLAGS and CFLAGS.
#   - Swift: stable channels compile in a new, empty scratch folder.
#   - Resources: copy an exact list of the app's tracked Resources.
#   - Strip debug-map (stab) entries and local symbols before signing; keep
#     the dSYM in a private folder.
# Release job logs are public. Tool output that can carry build-Mac paths goes
# to a private log, and failures print fixed labels only.

# Apple developer tools (strip, nm, dsymutil, dwarfdump, atos). Release runs
# keep /usr/bin, so a Homebrew binutils strip or nm earlier on PATH never
# touches a Mach-O; package fixtures point it at mocks.
OTTTO_MACOS_APPLE_TOOL_DIR="${OTTTO_MACOS_APPLE_TOOL_DIR:-/usr/bin}"
# Set by ottto_macos_check_binary_policy: the private log folder (empty means
# tool output goes to the terminal, dev and preview only).
OTTTO_MACOS_PRIVATE_LOG_DIR=""
# A dSYM made but not yet moved into place; removed by the caller's cleanup.
OTTTO_MACOS_DSYM_INCOMING=""
OTTTO_MACOS_DSYM_UUID=""

ottto_macos_is_stable_channel() {
  [[ "$1" == "stable" || "$1" == "stable-candidate" ]]
}

# ottto_macos_physical_path <path>
# Prints the physical form of a folder path that need not exist yet.
ottto_macos_physical_path() {
  local path="$1" tail=""
  while [[ ! -d "$path" ]]; do
    tail="/$(basename "$path")$tail"
    path="$(dirname "$path")"
  done
  path="$(cd "$path" && pwd -P)" || return 1
  printf '%s%s\n' "${path%/}" "$tail"
}

# ottto_macos_path_within <path> <folder>
ottto_macos_path_within() {
  [[ -n "$2" ]] || return 1
  case "$1/" in
    "${2%/}/"*) return 0 ;;
  esac
  return 1
}

# ottto_macos_check_binary_policy <channel> <skip-build> <public-root> <output-dir> <app-git-root>
# Stable channels build fresh and keep the Companion dSYM: --skip-build and a
# missing OTTTO_MACOS_DSYM_DIR are refused before anything is built. Dev and
# preview runs may reuse build outputs and only warn without a dSYM folder.
# The dSYM folder must be absolute and outside the public checkout, the
# release output, the app checkout and the runner's folders; it is never
# printed. Its logs/ subfolder becomes the private log.
ottto_macos_check_binary_policy() {
  local channel="$1" skip_build="$2" root="$3" output_dir="$4" app_git_root="$5"
  local dir="${OTTTO_MACOS_DSYM_DIR:-}" physical folder log_dir
  if ottto_macos_is_stable_channel "$channel" && [[ "$skip_build" == "true" ]]; then
    echo "Stable channels build from source: --skip-build is for dev and preview builds" >&2
    return 2
  fi
  if [[ -z "$dir" ]]; then
    if ottto_macos_is_stable_channel "$channel"; then
      echo "OTTTO_MACOS_DSYM_DIR is required for stable channels: a private folder for the Companion dSYM" >&2
      return 2
    fi
    if [[ "$skip_build" != "true" ]]; then
      echo "::warning::Companion dSYM not kept (OTTTO_MACOS_DSYM_DIR is not set)"
    fi
    return 0
  fi
  if [[ "$dir" != /* ]]; then
    echo "OTTTO_MACOS_DSYM_DIR must be an absolute folder" >&2
    return 2
  fi
  physical="$(ottto_macos_physical_path "$dir")" || {
    echo "OTTTO_MACOS_DSYM_DIR could not be resolved" >&2
    return 2
  }
  for folder in "$root" "$output_dir" "$app_git_root" "${RUNNER_TEMP:-}" "${RUNNER_WORKSPACE:-}" "${GITHUB_WORKSPACE:-}"; do
    [[ -n "$folder" ]] || continue
    folder="$(ottto_macos_physical_path "$folder")" || return 2
    if ottto_macos_path_within "$physical" "$folder" || ottto_macos_path_within "$folder" "$physical"; then
      echo "OTTTO_MACOS_DSYM_DIR must be outside the public checkout, the release output, the app checkout and the runner folders" >&2
      return 2
    fi
  done
  log_dir="$physical/logs"
  if ! (umask 077 && mkdir -p "$log_dir") 2>/dev/null || ! chmod 700 "$physical" "$log_dir" 2>/dev/null; then
    echo "OTTTO_MACOS_DSYM_DIR could not be created as a private folder" >&2
    return 2
  fi
  OTTTO_MACOS_DSYM_DIR="$physical"
  OTTTO_MACOS_PRIVATE_LOG_DIR="$log_dir"
}

# ottto_macos_run_logged <label> <command...>
# Runs a command whose output can name build-Mac paths. With a private log
# folder, its stdout and stderr go to <label>.log there and a failure prints
# only the label. The log is opened under an outer stderr redirect, so a log
# that cannot be opened never puts its path in the public job log.
ottto_macos_run_logged() {
  local label="$1" rc=0 log
  shift
  if [[ -z "$OTTTO_MACOS_PRIVATE_LOG_DIR" ]]; then
    "$@" || rc=$?
  else
    log="$OTTTO_MACOS_PRIVATE_LOG_DIR/$label.log"
    if ! { : >>"$log"; } 2>/dev/null; then
      echo "$label: the private build log could not be opened" >&2
      return 1
    fi
    { "$@" >>"$log" 2>&1; } 2>/dev/null || rc=$?
  fi
  if [[ "$rc" != 0 ]]; then
    echo "$label failed (exit $rc); details are in the private build log" >&2
  fi
  return "$rc"
}

# ottto_macos_private_note <label> <text>
# Adds a line that can name private files (tool diagnostics, file names from
# the app checkout) to <label>.log in the private log folder. Without one (dev
# and preview runs), the line goes to stderr on the build Mac's own terminal.
ottto_macos_private_note() {
  if [[ -z "$OTTTO_MACOS_PRIVATE_LOG_DIR" ]]; then
    printf '%s\n' "$2" >&2
  else
    { printf '%s\n' "$2" >>"$OTTTO_MACOS_PRIVATE_LOG_DIR/$1.log"; } 2>/dev/null || true
  fi
}

# ottto_macos_private_git <label> <git arguments...>
# Runs git with its stdout kept and its stderr (which names files of the app
# checkout) in the label's private log.
ottto_macos_private_git() {
  local label="$1"
  shift
  if [[ -z "$OTTTO_MACOS_PRIVATE_LOG_DIR" ]]; then
    git "$@"
  else
    { git "$@" 2>>"$OTTTO_MACOS_PRIVATE_LOG_DIR/$label.log"; } 2>/dev/null
  fi
}

# ottto_macos_release_build_env <public-root>
# Exports CARGO_ENCODED_RUSTFLAGS and CFLAGS that map this Mac's folders to
# neutral prefixes. Cargo reads CARGO_ENCODED_RUSTFLAGS before RUSTFLAGS and
# every config rustflags, so no Cargo config on the build Mac can drop the
# remap. The cc crate appends HOST_/TARGET_CFLAGS and CFLAGS_<target> after
# CFLAGS, where a later prefix map could win, so those are refused, as is a
# preset RUSTFLAGS or CARGO_ENCODED_RUSTFLAGS. Rust symbols are kept: the
# release profile has no debug info to strip, and its symbols name panic
# backtrace frames.
ottto_macos_release_build_env() {
  local root="$1" home="${HOME:-}" cargo_home remap
  local rust_flags=() c_flags=()
  cargo_home="${CARGO_HOME:-${home:+$home/.cargo}}"
  if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
    echo "Refusing to build: unset RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS; the packager sets the release path remapping itself" >&2
    return 2
  fi
  if env | grep -E '^(HOST_CFLAGS|TARGET_CFLAGS|CFLAGS_[A-Za-z0-9_.-]+)=.' >/dev/null; then
    echo "Refusing to build: unset HOST_CFLAGS, TARGET_CFLAGS and CFLAGS_<target>; they follow the packager's C path remapping" >&2
    return 2
  fi
  # rustc and clang apply the last matching map, so the most specific folder
  # comes last.
  for remap in "$home=~" "$cargo_home=/cargo" "$root=."; do
    [[ "$remap" == /* ]] || continue
    if [[ "$remap" == *[[:space:]]* ]]; then
      echo "Release build folders must not contain whitespace" >&2
      return 2
    fi
    rust_flags+=("--remap-path-prefix=$remap")
    c_flags+=("-ffile-prefix-map=$remap")
  done
  CARGO_ENCODED_RUSTFLAGS="$(IFS=$'\037'; printf '%s' "${rust_flags[*]}")"
  CFLAGS="${CFLAGS:+$CFLAGS }${c_flags[*]}"
  export CARGO_ENCODED_RUSTFLAGS CFLAGS
}

# ottto_macos_swift_scratch <channel> <app-root>
# Prints the SwiftPM scratch folder. Stable channels compile into a new empty
# folder (a reused build folder shipped objects compiled hours before the
# release run); dev and preview keep the app's incremental .build.
ottto_macos_swift_scratch() {
  local channel="$1" app_root="$2" base dir
  if ! ottto_macos_is_stable_channel "$channel"; then
    printf '%s\n' "$app_root/.build"
    return 0
  fi
  base="${RUNNER_TEMP:-${TMPDIR:-/tmp}}"
  dir="$(mktemp -d "${base%/}/ottto-swift.XXXXXX" 2>/dev/null)" || {
    echo "Could not create a fresh Swift build folder" >&2
    return 1
  }
  # Physical path, so -oso_prefix and dsymutil see the string SwiftPM uses.
  (cd "$dir" && pwd -P)
}

# The Companion resources a release ships, relative to the app's
# Sources/OtttoCompanion/Resources. The tracked README.md never ships. A new
# resource joins this list before an app release that uses it: any other
# tracked file makes packaging fail rather than silently drop it.
ottto_macos_companion_resource_names() {
  printf '%s\n' \
    OtttoCompanionIcon.icns \
    OFL-Fraunces.txt \
    OFL-JetBrainsMono.txt \
    Fonts/Fraunces-VF.ttf \
    Fonts/JetBrainsMono-Regular.ttf \
    Fonts/JetBrainsMono-SemiBold.ttf \
    brand-claude-icon.png \
    brand-claude.png \
    brand-cursor.png \
    brand-openai-blossom-black.png \
    brand-openai-blossom-white.png \
    brand-pi.png \
    oto-attention.png \
    oto-error.png \
    oto-happy.png \
    oto-neutral.png \
    oto-sleepy.png \
    oto-wink.png \
    ottto-dock-icon.png \
    ottto-logo-tight.png \
    ottto-mark.png \
    ottto-menubar-icon.png
}

# The license files the license helper (scripts/macos_license_notices.sh,
# sourced by the packager) copies into Contents/Resources, by exact name.
ottto_macos_license_resource_names() {
  ottto_app_license_resource_names
}

# ottto_macos_name_in_list <name> <newline-separated list>
ottto_macos_name_in_list() {
  case $'\n'"$2"$'\n' in
    *$'\n'"$1"$'\n'*) return 0 ;;
  esac
  return 1
}

# ottto_macos_copy_companion_resources <git-root> <commit> <app-subtree> <dest>
# Copies the listed Resources from the recorded app commit (the one the
# release manifest names), so an untracked or ignored file never ships and a
# checkout that moves after the build changes nothing. Fails on a missing
# listed file, a listed entry that is not a regular file, or a tracked file
# not on the list. Git diagnostics and unlisted names go to the private log.
ottto_macos_copy_companion_resources() {
  local git_root="$1" commit="$2" subtree="$3" dest="$4"
  local label="Copy Companion resources" prefix listing names paths line meta path mode rel name
  prefix="$subtree/Sources/OtttoCompanion/Resources"
  names="$(ottto_macos_companion_resource_names)"
  if [[ ! "$commit" =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]; then
    echo "$label: the app commit is not a full object id" >&2
    return 1
  fi
  listing="$(ottto_macos_private_git "$label" -C "$git_root" ls-tree -r "$commit" -- "$prefix/")" || {
    echo "Could not list the app's tracked Resources; details are in the private build log" >&2
    return 1
  }
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    meta="${line%%$'\t'*}"
    path="${line#*$'\t'}"
    mode="${meta%% *}"
    rel="${path#"$prefix"/}"
    [[ "$rel" == "README.md" ]] && continue
    if ! ottto_macos_name_in_list "$rel" "$names"; then
      ottto_macos_private_note "$label" "Companion resource is not on the release list: $rel"
      echo "The app commit has a Companion resource that is not on the release list; its name is in the private build log" >&2
      return 1
    fi
    # Only listed names reach here, so printing one is safe.
    if [[ "$mode" != "100644" && "$mode" != "100755" ]]; then
      echo "Companion resource is not a regular file: $rel" >&2
      return 1
    fi
  done <<<"$listing"
  paths="$(printf '%s\n' "$listing" | cut -f2)"
  while IFS= read -r name; do
    if ! ottto_macos_name_in_list "$prefix/$name" "$paths"; then
      echo "Companion resource is missing from the app commit: $name" >&2
      return 1
    fi
    mkdir -p "$dest/$(dirname "$name")"
    if ! { ottto_macos_private_git "$label" -C "$git_root" cat-file blob "$commit:$prefix/$name" >"$dest/$name"; } 2>/dev/null; then
      echo "Could not copy Companion resource: $name; details are in the private build log" >&2
      return 1
    fi
    chmod 0644 "$dest/$name"
  done <<<"$names"
}

# ottto_macos_check_app_resources <Ottto.app/Contents/Resources>
# The final Resources folder holds exactly the listed Companion resources and
# the license files: no other file, no symlink, no other folder.
ottto_macos_check_app_resources() {
  local dir="$1" expected folders entries entry rel name problem
  expected="$(ottto_macos_companion_resource_names; ottto_macos_license_resource_names)"
  folders="$(printf '%s\n' "$expected" | awk -F/ 'NF > 1 {sub("/[^/]*$", ""); print}' | sort -u)"
  entries="$(cd "$dir" && find . -mindepth 1)" || {
    echo "Could not list Ottto.app Resources" >&2
    return 1
  }
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    rel="${entry#./}"
    if [[ -L "$dir/$rel" ]]; then
      problem="holds a symlink"
    elif [[ -d "$dir/$rel" ]]; then
      ottto_macos_name_in_list "$rel" "$folders" && continue
      problem="holds an unexpected folder"
    elif [[ -f "$dir/$rel" ]]; then
      ottto_macos_name_in_list "$rel" "$expected" && continue
      problem="holds a file outside the release list"
    else
      problem="has an entry that is not a regular file"
    fi
    # The entry need not be a listed name, so its name stays private.
    ottto_macos_private_note "Check Ottto.app Resources" "Ottto.app Resources $problem: $rel"
    echo "Ottto.app Resources $problem; its name is in the private build log" >&2
    return 1
  done <<<"$entries"
  while IFS= read -r name; do
    if [[ ! -f "$dir/$name" || -L "$dir/$name" ]]; then
      echo "Ottto.app Resources is missing: $name" >&2
      return 1
    fi
  done <<<"$expected"
}

# ottto_macos_count_stabs <mach-o> [stab type]
# Prints how many debug-map (stab) records the Mach-O has, of every type, or
# only of the given type. Apple nm -ap prints a stab as
# "<value> - <sect> <desc> <TYPE> <string>", so the type marker is "-".
# Apple strip itself writes one "OPT radr://5614542" record into a stripped
# executable; it names no file, so the all-types count leaves it out.
ottto_macos_count_stabs() {
  local exe="$1" type="${2:-}" listing
  listing="$("$OTTTO_MACOS_APPLE_TOOL_DIR/nm" -ap "$exe" 2>/dev/null)" || {
    echo "nm could not read the Companion executable" >&2
    return 1
  }
  awk -v type="$type" '
    $2 != "-" { next }
    type == "" && $5 == "OPT" && $6 == "radr://5614542" && NF == 6 { next }
    type == "" || $5 == type { n++ }
    END { print n + 0 }
  ' <<<"$listing"
}

# ottto_macos_strip_companion <executable inside Ottto.app>
# Removes debug-map entries and local symbols. Run before install_name_tool
# and signing. Rust helpers are not stripped.
ottto_macos_strip_companion() {
  ottto_macos_run_logged "Strip the Companion executable" \
    "$OTTTO_MACOS_APPLE_TOOL_DIR/strip" -S -x "$1"
}

# ottto_macos_check_no_stabs <signed Companion executable>
ottto_macos_check_no_stabs() {
  local count
  count="$(ottto_macos_count_stabs "$1")" || return 1
  if [[ "$count" != "0" ]]; then
    echo "Companion executable still has $count debug-map entries after strip" >&2
    return 1
  fi
  echo "Companion executable has no debug-map entries"
}

# ottto_macos_dsym_uuid <Mach-O or dSYM>
ottto_macos_dsym_uuid() {
  local out
  out="$("$OTTTO_MACOS_APPLE_TOOL_DIR/dwarfdump" --uuid "$1" 2>/dev/null)" || return 1
  out="$(awk '$1 == "UUID:" {print $2}' <<<"$out")"
  [[ "$out" =~ ^[0-9A-Fa-f-]{36}$ ]] || return 1
  printf '%s\n' "$out"
}

# The Companion's entry file. Every executable keeps main, and the line
# table of a Swift @main type maps it to the file that declares the type.
OTTTO_MACOS_COMPANION_ENTRY_SOURCE="OtttoCompanionApp.swift"

# dsymutil diagnostics that mean the dSYM lacks an object's debug data. It
# warns and still exits 0 when a debug-map object is missing, unreadable or
# rebuilt after the link.
OTTTO_MACOS_DSYM_MISSING_OBJECT_PATTERN='unable to open object file|timestamp mismatch between object file|no debug symbols in'

# ottto_macos_make_dsym <unstripped executable> <object path prefix>
# With OTTTO_MACOS_DSYM_DIR set, writes the dSYM into a private incoming
# folder while the build's object files still exist, and proves it holds the
# debug data: this dsymutil run reported no missing object, the DWARF file
# has compile units, and main resolves to the Companion's entry source file.
# ottto_macos_keep_dsym moves it into place once its UUID matches the signed
# app.
ottto_macos_make_dsym() {
  local exe="$1" oso_prefix="$2" label="Make the Companion dSYM"
  local incoming dsym dwarf log log_start objects units main_address frame
  [[ -n "${OTTTO_MACOS_DSYM_DIR:-}" ]] || return 0
  incoming="$(mktemp -d "$OTTTO_MACOS_DSYM_DIR/.incoming.XXXXXX" 2>/dev/null)" || {
    echo "Could not create the private dSYM folder" >&2
    return 1
  }
  OTTTO_MACOS_DSYM_INCOMING="$incoming"
  dsym="$incoming/Ottto.app.dSYM"
  dwarf="$dsym/Contents/Resources/DWARF/Ottto"
  objects="$(ottto_macos_count_stabs "$exe" OSO)" || return 1
  if [[ "$objects" == "0" ]]; then
    echo "The Companion executable has no debug map to make a dSYM from" >&2
    return 1
  fi
  # Only this run's part of the private log counts.
  log="$OTTTO_MACOS_PRIVATE_LOG_DIR/$label.log"
  log_start="$( { wc -c <"$log"; } 2>/dev/null | tr -d ' ')" || log_start=0
  ottto_macos_run_logged "$label" \
    "$OTTTO_MACOS_APPLE_TOOL_DIR/dsymutil" --oso-prepend-path="$oso_prefix" "$exe" -o "$dsym" || return 1
  if [[ -z "$OTTTO_MACOS_PRIVATE_LOG_DIR" ]] || ! { tail -c "+$((${log_start:-0} + 1))" "$log" >"$incoming/dsymutil.log"; } 2>/dev/null; then
    echo "Could not read this dsymutil run's private log" >&2
    return 1
  fi
  if grep -Eq "$OTTTO_MACOS_DSYM_MISSING_OBJECT_PATTERN" "$incoming/dsymutil.log"; then
    echo "Companion dSYM is incomplete: dsymutil could not read every object (see the private build log)" >&2
    return 1
  fi
  # Readers consume the whole output (grep -c, awk without exit), so the
  # writer never sees a closed pipe under pipefail.
  units=0
  if [[ -s "$dwarf" ]]; then
    units="$("$OTTTO_MACOS_APPLE_TOOL_DIR/dwarfdump" --debug-info -r 0 "$dwarf" 2>/dev/null | grep -c 'DW_TAG_compile_unit')" || units=0
  fi
  if [[ "$units" == "0" ]]; then
    echo "Companion dSYM has no DWARF compile units" >&2
    return 1
  fi
  main_address="$("$OTTTO_MACOS_APPLE_TOOL_DIR/nm" -n "$exe" 2>/dev/null)" || main_address=""
  main_address="$(awk '$3 == "_main" && ($2 == "T" || $2 == "t") && !found {print "0x" $1; found = 1}' <<<"$main_address")"
  frame=""
  if [[ -n "$main_address" ]]; then
    frame="$("$OTTTO_MACOS_APPLE_TOOL_DIR/atos" -o "$dwarf" "$main_address" 2>/dev/null)" || frame=""
  fi
  if [[ "$frame" != *"($OTTTO_MACOS_COMPANION_ENTRY_SOURCE:"[0-9]*")"* ]]; then
    echo "Companion dSYM does not resolve main to $OTTTO_MACOS_COMPANION_ENTRY_SOURCE" >&2
    return 1
  fi
  OTTTO_MACOS_DSYM_UUID="$(ottto_macos_dsym_uuid "$dsym")" || {
    echo "Could not read the Companion dSYM UUID" >&2
    return 1
  }
  echo "Companion dSYM made: $objects debug-map objects read, main resolves to $OTTTO_MACOS_COMPANION_ENTRY_SOURCE"
}

# ottto_macos_keep_dsym <signed Companion executable> <version>
# Moves the checked dSYM to OTTTO_MACOS_DSYM_DIR/Ottto-<version>-<UUID>.dSYM
# when its UUID is the signed app's. An existing dSYM of that UUID is kept.
ottto_macos_keep_dsym() {
  local exe="$1" version="$2" app_uuid target
  [[ -n "${OTTTO_MACOS_DSYM_DIR:-}" && -n "$OTTTO_MACOS_DSYM_INCOMING" ]] || return 0
  app_uuid="$(ottto_macos_dsym_uuid "$exe")" || {
    echo "Could not read the signed Companion executable's UUID" >&2
    return 1
  }
  if [[ "$app_uuid" != "$OTTTO_MACOS_DSYM_UUID" ]]; then
    echo "Companion dSYM UUID does not match the signed app" >&2
    return 1
  fi
  target="$OTTTO_MACOS_DSYM_DIR/Ottto-$version-$app_uuid.dSYM"
  if [[ ! -e "$target" ]]; then
    mv "$OTTTO_MACOS_DSYM_INCOMING/Ottto.app.dSYM" "$target" 2>/dev/null || {
      echo "Could not move the Companion dSYM into the private folder" >&2
      return 1
    }
    chmod -R go-rwx "$target"
  fi
  rm -rf "$OTTTO_MACOS_DSYM_INCOMING"
  OTTTO_MACOS_DSYM_INCOMING=""
  echo "Companion dSYM kept privately for UUID $app_uuid"
}
