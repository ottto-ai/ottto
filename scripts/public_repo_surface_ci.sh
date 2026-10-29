#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/public_repo_temp_cleanup.sh
source "$SCRIPT_DIR/public_repo_temp_cleanup.sh"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$DEFAULT_REPO_ROOT"
STAGED_OUTPUT_DIR=""
KEEP_TEMP=0
SCOPE="all"
TMP_DIR=""
script_completed=0
steps_run=0

usage() {
  cat <<'USAGE'
Usage: public_repo_surface_ci.sh [--root <dir>] [--staged-output <dir>] [--keep-temp]
                                [--scope all|portable|macos]

Runs the public repository surface checks that GitHub Actions runs before a
public commit: schema/registry JSON validation, shellcheck, export gate tests,
release/installer dry-run tests, manifest/skeleton/secret/contract checks, and
a self-exported staged bundle verification.

Use --staged-output to copy a generated root-shaped bundle into a temporary git
checkout before running the same checks. This is the local substitute for public
GitHub CI while the separate ottto repository is not reachable.

--scope picks which steps run. Each step is portable (P), needed on both Linux
and macOS (B: the scripts under test run on Macs under /bin/bash 3.2 and BSD
tools), or macOS-only (M: real plutil, codesign, packaging tools, LaunchServices).
  all       every step once (default; macOS only)
  portable  P and B steps (runs on Linux; GitHub CI "Public surface checks")
  macos     M and B steps plus a /bin/bash 3.2 parse of scripts/*.sh
            (GitHub CI "Rust contracts" job)
USAGE
}

fail() {
  echo "public-surface-ci: $*" >&2
  exit 2
}

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    fail "$1 is required"
  fi
}

cleanup() {
  local status=$?
  # Bash 3.2 can report status 0 here after a nounset abort.
  if [[ "$status" -eq 0 && "${script_completed:-0}" -ne 1 ]]; then
    echo "public-surface-ci: exited before completion" >&2
    status=1
  fi
  if [[ -n "$TMP_DIR" && "$KEEP_TEMP" -eq 0 ]]; then
    public_repo_remove_temp_dir "public-surface-ci" "$TMP_DIR" || true
  elif [[ -n "$TMP_DIR" ]]; then
    echo "public-surface-ci: kept temporary checkout at $TMP_DIR"
  fi
  exit "$status"
}
trap cleanup EXIT

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --root)
      [[ "$#" -ge 2 ]] || fail "--root requires a value"
      REPO_ROOT="$2"
      shift 2
      ;;
    --staged-output)
      [[ "$#" -ge 2 ]] || fail "--staged-output requires a value"
      STAGED_OUTPUT_DIR="$2"
      shift 2
      ;;
    --keep-temp)
      KEEP_TEMP=1
      shift
      ;;
    --scope)
      [[ "$#" -ge 2 ]] || fail "--scope requires a value"
      SCOPE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      script_completed=1
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

case "$SCOPE" in
  all|portable|macos) ;;
  *) fail "unknown scope: $SCOPE (use all, portable, or macos)" ;;
esac
echo "public-surface-ci: scope=$SCOPE bash=$BASH_VERSION"

require_command git
require_command jq
require_command python3
require_command cargo

prepare_staged_checkout() {
  local staged_root="$1"
  local checkout_root="$2"
  if [[ ! -d "$staged_root" ]]; then
    fail "staged output is not a directory: $staged_root"
  fi
  mkdir -p "$checkout_root"
  python3 - "$staged_root" "$checkout_root" <<'PY'
from __future__ import annotations

import shutil
import sys
from pathlib import Path

source_root = Path(sys.argv[1]).resolve()
checkout_root = Path(sys.argv[2]).resolve()

if not source_root.is_dir():
    print(f"public-surface-ci: staged output is not a directory: {source_root}", file=sys.stderr)
    sys.exit(2)

checkout_root.mkdir(parents=True, exist_ok=True)
for path in sorted(source_root.rglob("*")):
    relative = path.relative_to(source_root)
    if ".git" in relative.parts:
        continue
    if path.is_symlink():
        print(f"public-surface-ci: refusing symlink in staged output: {relative.as_posix()}", file=sys.stderr)
        sys.exit(2)

for child in sorted(source_root.iterdir(), key=lambda path: path.name):
    if child.name == ".git":
        continue
    target = checkout_root / child.name
    if child.is_dir():
        shutil.copytree(child, target, symlinks=False, ignore=shutil.ignore_patterns(".git"))
    elif child.is_file():
        shutil.copy2(child, target)
PY
  git -C "$checkout_root" init -q
  git -C "$checkout_root" config user.email "public-surface-ci@example.invalid"
  git -C "$checkout_root" config user.name "Public Surface CI"
  git -C "$checkout_root" add .
  git -C "$checkout_root" commit -qm "public surface smoke"
}

if [[ -n "$STAGED_OUTPUT_DIR" ]]; then
  TMP_DIR="$(mktemp -d)"
  REPO_ROOT="$TMP_DIR/public-ottto"
  prepare_staged_checkout "$STAGED_OUTPUT_DIR" "$REPO_ROOT"
fi

REPO_ROOT="$(cd "$REPO_ROOT" && pwd)"
if [[ ! -d "$REPO_ROOT" ]]; then
  fail "repository root is not a directory: $REPO_ROOT"
fi
if ! git -C "$REPO_ROOT" rev-parse --show-toplevel >/dev/null 2>&1; then
  fail "repository root is not a git checkout: $REPO_ROOT"
fi

required_public_files=(
  "connectors/registry.generated.json"
  "public-export/roots.txt"
  "scripts/public_repo_export_bundle.sh"
  "scripts/public_repo_manifest_check.sh"
  "scripts/public_repo_skeleton_check.sh"
  "schemas/source-manifest.schema.json"
)
for path in "${required_public_files[@]}"; do
  if [[ ! -f "$REPO_ROOT/$path" ]]; then
    fail "root is not a root-shaped public ottto checkout; missing $path"
  fi
done

# Checked only after staged-output preparation and root checks, so their
# failures (exit 2 with their own message) stay the same on every OS and on a
# Mac without shellcheck (the macOS scope does not need it).
if [[ "$SCOPE" != portable && "$(uname -s)" != Darwin ]]; then
  fail "scope $SCOPE needs macOS; use --scope portable"
fi
if [[ "$SCOPE" != macos ]]; then
  require_command shellcheck
fi

# run_step <P|B|M> <label> <command...>: see --help for the step classes.
run_step() {
  local class="$1"
  local label="$2"
  shift 2
  case "$class" in
    P) [[ "$SCOPE" != macos ]] || return 0 ;;
    B) ;;
    M) [[ "$SCOPE" != portable ]] || return 0 ;;
    *) fail "unknown step class '$class' for: $label" ;;
  esac
  echo "public-surface-ci: $label"
  (cd "$REPO_ROOT" && "$@")
  steps_run=$((steps_run + 1))
}

# PUBLIC_EXPORT_MANIFEST.json is derived from the commit tree
# (scripts/public_repo_manifest.sh) and must not be committed. A staged bundle
# carries its generated copy at the root; it must still match its files and the
# derived manifest.
check_root_manifest() {
  if [[ -n "$STAGED_OUTPUT_DIR" ]]; then
    if [[ -f PUBLIC_EXPORT_MANIFEST.json ]]; then
      bash scripts/public_repo_manifest_check.sh
      bash scripts/public_repo_manifest.sh --compare PUBLIC_EXPORT_MANIFEST.json
    else
      echo "public-surface-ci: staged output has no root manifest; the self-export check covers it"
    fi
    return
  fi
  bash scripts/public_repo_manifest.sh --guard
}

check_self_export_matches_tree() {
  if ! git diff --quiet HEAD --; then
    fail "tracked files differ from HEAD; commit or stash them before comparing the self-exported manifest"
  fi
  bash scripts/public_repo_manifest.sh --compare dist/public-export/ottto/PUBLIC_EXPORT_MANIFEST.json
}

run_step P "validate public schemas and generated registry" \
  bash -c 'jq empty connectors/registry.generated.json schemas/*.schema.json'
run_step P "shellcheck public scripts" bash -c 'shellcheck scripts/*.sh'
run_step P "test local autoreview helper" env PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_autoreview.py
run_step P "test PR merge guard" bash scripts/test_pr_merge_when_mac_green.sh

run_step P "test public export check" bash scripts/test_public_repo_export_check.sh
run_step P "run public export check" bash scripts/public_repo_export_check.sh
run_step P "test public export bundle" bash scripts/test_public_repo_export_bundle.sh
run_step P "test public bootstrap plan" bash scripts/test_public_repo_bootstrap_plan.sh
run_step P "test public cutover closeout" bash scripts/test_public_repo_cutover_closeout.sh
run_step P "test public manifest check" bash scripts/test_public_repo_manifest_check.sh
run_step P "test public manifest derivation" bash scripts/test_public_repo_manifest.sh
run_step P "check root manifest is derived from the commit tree" check_root_manifest
run_step P "test public skeleton check" bash scripts/test_public_repo_skeleton_check.sh
run_step P "test public secret scan" bash scripts/test_public_repo_secret_scan.sh
run_step B "test public temp cleanup" bash scripts/test_public_repo_temp_cleanup.sh
run_step P "test public contract check" bash scripts/test_public_repo_contract_check.sh
run_step B "test macOS release gate" bash scripts/test_macos_release_gate.sh
run_step P "test macOS installer channel policy" bash scripts/test_macos_installer_channel_policy.sh
run_step B "test macOS package URL scheme policy" bash scripts/test_macos_package_url_scheme_policy.sh
run_step M "test macOS package root resolution" bash scripts/test_macos_package_root_resolution.sh
run_step M "test macOS Companion entitlement policy" bash scripts/test_macos_companion_entitlements.sh
run_step M "test macOS Sparkle bundle version and launch policy" bash scripts/test_macos_sparkle_bundle_version.sh
run_step M "test macOS launch smoke" bash scripts/test_macos_launch_smoke.sh
run_step P "test macOS stable release workflow policy" bash scripts/test_macos_stable_release_workflow.sh
run_step B "test macOS attestation binder" bash scripts/test_macos_attestation_bind.sh
run_step B "test macOS manifest signature helper" bash scripts/test_macos_manifest_signature.sh
run_step B "test stable-candidate RC gate" bash scripts/test_macos_public_rc_gate.sh
run_step B "test stable preflight gate" bash scripts/test_macos_stable_preflight.sh
run_step B "test stable closeout gate" bash scripts/test_macos_stable_closeout_gate.sh
run_step B "test stable QA evidence template" bash scripts/test_macos_stable_qa_evidence_template.sh
run_step B "test Homebrew formula generator" bash scripts/test_homebrew_formula.sh
run_step B "test hosted native installer generator" bash scripts/test_hosted_native_installer.sh
run_step B "test CycloneDX SBOM generator" bash scripts/test_cyclonedx_sbom.sh

# Free macOS /bin/bash 3.2 parse check for the scripts only Linux runs.
# shellcheck disable=SC2016
run_step M "parse public scripts with macOS /bin/bash" \
  /bin/bash -c 'for f in scripts/*.sh; do /bin/bash -n "$f" || exit 1; done'

run_step P "generate self-exported public bundle" bash scripts/public_repo_export_bundle.sh --force
run_step P "verify self-exported manifest" \
  bash scripts/public_repo_manifest_check.sh --staged-output dist/public-export/ottto
run_step P "verify self-exported manifest matches commit tree" check_self_export_matches_tree
run_step P "verify public skeleton" \
  bash -c 'PUBLIC_SKELETON_REPO_ROOT=dist/public-export/ottto scripts/public_repo_skeleton_check.sh'
run_step P "scan self-exported public bundle" \
  bash scripts/public_repo_secret_scan.sh --staged-output dist/public-export/ottto
run_step P "verify self-exported public contracts" \
  bash scripts/public_repo_contract_check.sh --staged-output dist/public-export/ottto

echo "public-surface-ci: ran $steps_run steps (scope=$SCOPE)"
echo "public-surface-ci: completed public surface checks at $REPO_ROOT"
script_completed=1
