#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_release_paths.sh
source "$ROOT/scripts/macos_release_paths.sh"
MANIFEST=""
OUTPUT=""

usage() {
  cat <<'USAGE'
Usage: macos_release_verification_folder.sh --manifest <release-manifest.json> --output <new folder>

Stages a downloaded release folder for the release and RC gates. A download
holds the published archives, not the app bundle and binaries the manifest
names as verification targets, so the gates cannot run on it directly.

The script copies the manifest byte for byte, its signature and the other
release files beside it into a new folder. It then checks each archive against
its manifest SHA-256 and unpacks the verification target under its recorded
name: the app from the DMG (mounted read-only) and each binary from its ZIP.

The output folder must not exist yet and must be outside the downloaded folder.
It is a disposable verification copy: never publish or upload it.
USAGE
}

die() {
  echo "release-verification-folder: $*" >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --output)
      OUTPUT="${2:?--output requires a value}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "$MANIFEST" || -z "$OUTPUT" ]]; then
  usage >&2
  exit 2
fi

for command_name in jq shasum ditto cmp; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "Required command not found: $command_name" >&2
    exit 2
  }
done

if [[ ! -f "$MANIFEST" || -L "$MANIFEST" ]]; then
  die "release manifest is missing or not a regular file"
fi
manifest_name="$(basename "$MANIFEST")"
if ! macos_release_filename "$manifest_name"; then
  die "release manifest name must be a release filename"
fi
source_dir="$(macos_release_manifest_dir "$MANIFEST")"

if [[ -e "$OUTPUT" || -L "$OUTPUT" ]]; then
  die "output folder already exists; choose a new folder"
fi
output_parent="$(dirname "$OUTPUT")"
if [[ ! -d "$output_parent" ]]; then
  die "output folder's parent does not exist"
fi
output_dir="$(cd "$output_parent" >/dev/null && pwd -P)/$(basename "$OUTPUT")"
case "$output_dir/" in
  "$source_dir"/*)
    die "output folder must be outside the downloaded release folder"
    ;;
esac

work_dir="$(mktemp -d)"
mounted=""
created_output="false"
cleanup() {
  local status=$?
  if [[ -n "$mounted" ]]; then
    hdiutil detach "$mounted" >/dev/null 2>&1 || true
  fi
  rm -rf "$work_dir"
  if [[ "$status" -ne 0 && "$created_output" == "true" ]]; then
    rm -rf "$output_dir"
  fi
}
trap cleanup EXIT

mkdir "$output_dir"
created_output="true"

verification_names="$(jq -r '[.artifacts[]? | .verification_path // empty | select(. != "")] | .[]' "$MANIFEST")"

# Copy the downloaded release files. Only top-level regular files with release
# filenames: no folders, no symlinks, and nothing named like a verification
# target, which this script alone puts in the output folder.
while IFS= read -r -d '' file; do
  name="$(basename "$file")"
  if [[ -L "$file" || ! -f "$file" ]] || ! macos_release_filename "$name"; then
    continue
  fi
  if grep -Fxq -- "$name" <<<"$verification_names"; then
    die "downloaded folder already holds a file named like a verification target"
  fi
  cp -p "$file" "$output_dir/$name"
done < <(find "$source_dir" -mindepth 1 -maxdepth 1 -print0)

if ! cmp -s "$MANIFEST" "$output_dir/$manifest_name"; then
  die "staged manifest is not byte-identical to the downloaded manifest"
fi

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

staged=0
while IFS= read -r artifact; do
  name="$(jq -r '.name // ""' <<<"$artifact")"
  path_ref="$(jq -r '.path // ""' <<<"$artifact")"
  verification_ref="$(jq -r '.verification_path // ""' <<<"$artifact")"
  expected_sha="$(jq -r '.sha256 // ""' <<<"$artifact")"
  if [[ -z "$verification_ref" ]]; then
    continue
  fi
  if ! macos_release_filename "$verification_ref"; then
    die "verification_path must be a release filename: $name"
  fi
  if ! archive="$(macos_release_path "$source_dir" "$path_ref")" || [[ ! -f "$archive" ]]; then
    die "archive must be a release file beside the manifest: $name"
  fi
  # Never mount or unpack bytes the signed record does not name.
  if [[ "$(sha256_file "$archive")" != "$expected_sha" ]]; then
    die "archive does not match its manifest SHA-256: $name"
  fi
  target="$output_dir/$verification_ref"
  if [[ -e "$target" || -L "$target" ]]; then
    die "verification target is named twice: $name"
  fi
  case "$path_ref" in
    *.dmg)
      command -v hdiutil >/dev/null 2>&1 || die "hdiutil is required to stage $name"
      mounted="$work_dir/mount-$staged"
      mkdir "$mounted"
      if ! hdiutil attach -nobrowse -readonly -mountpoint "$mounted" "$archive" >/dev/null; then
        rmdir "$mounted" 2>/dev/null || true
        mounted=""
        die "could not mount the disk image read-only: $name"
      fi
      if [[ -L "$mounted/$verification_ref" || ! -d "$mounted/$verification_ref" ]]; then
        die "disk image does not hold the verification target: $name"
      fi
      ditto "$mounted/$verification_ref" "$target"
      hdiutil detach "$mounted" >/dev/null
      mounted=""
      ;;
    *.zip)
      extract_dir="$work_dir/zip-$staged"
      mkdir "$extract_dir"
      ditto -x -k "$archive" "$extract_dir"
      if [[ -L "$extract_dir/$verification_ref" || ! -f "$extract_dir/$verification_ref" ]]; then
        die "ZIP archive does not hold the verification target: $name"
      fi
      ditto "$extract_dir/$verification_ref" "$target"
      ;;
    *)
      die "unsupported archive format for a verification target: $name"
      ;;
  esac
  staged=$((staged + 1))
done < <(jq -c '.artifacts[]?' "$MANIFEST")

echo "Release verification folder staged $staged verification target(s): $output_dir/$manifest_name"
