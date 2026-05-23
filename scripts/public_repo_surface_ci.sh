#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$DEFAULT_REPO_ROOT"
STAGED_OUTPUT_DIR=""
KEEP_TEMP=0
TMP_DIR=""

usage() {
  cat <<'USAGE'
Usage: public_repo_surface_ci.sh [--root <dir>] [--staged-output <dir>] [--keep-temp]

Runs the public repository surface checks that GitHub Actions runs before a
public commit: schema/registry JSON validation, shellcheck, export gate tests,
release/installer dry-run tests, manifest/skeleton/secret/contract checks, and
a self-exported staged bundle verification.

Use --staged-output to copy a generated root-shaped bundle into a temporary git
checkout before running the same checks. This is the local substitute for public
GitHub CI while the separate ottto repository is not reachable.
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
  if [[ -n "$TMP_DIR" && "$KEEP_TEMP" -eq 0 ]]; then
    rm -rf "$TMP_DIR"
  elif [[ -n "$TMP_DIR" ]]; then
    echo "public-surface-ci: kept temporary checkout at $TMP_DIR"
  fi
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
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

require_command git
require_command jq
require_command shellcheck
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

run_step() {
  local label="$1"
  shift
  echo "public-surface-ci: $label"
  (cd "$REPO_ROOT" && "$@")
}

run_step "validate public schemas and generated registry" \
  bash -c 'jq empty connectors/registry.generated.json schemas/*.schema.json'
run_step "shellcheck public scripts" bash -c 'shellcheck scripts/*.sh'

run_step "test public export check" bash scripts/test_public_repo_export_check.sh
run_step "run public export check" bash scripts/public_repo_export_check.sh
run_step "test public export bundle" bash scripts/test_public_repo_export_bundle.sh
run_step "test public bootstrap plan" bash scripts/test_public_repo_bootstrap_plan.sh
run_step "test public cutover closeout" bash scripts/test_public_repo_cutover_closeout.sh
run_step "test public manifest check" bash scripts/test_public_repo_manifest_check.sh
run_step "run public manifest check" bash scripts/public_repo_manifest_check.sh
run_step "test public skeleton check" bash scripts/test_public_repo_skeleton_check.sh
run_step "test public secret scan" bash scripts/test_public_repo_secret_scan.sh
run_step "test public contract check" bash scripts/test_public_repo_contract_check.sh
run_step "test macOS release gate" bash scripts/test_macos_release_gate.sh
run_step "test macOS installer channel policy" bash scripts/test_macos_installer_channel_policy.sh
run_step "test macOS package root resolution" bash scripts/test_macos_package_root_resolution.sh
run_step "test macOS stable release workflow policy" bash scripts/test_macos_stable_release_workflow.sh
run_step "test macOS attestation binder" bash scripts/test_macos_attestation_bind.sh
run_step "test macOS manifest signature helper" bash scripts/test_macos_manifest_signature.sh
run_step "test stable-candidate RC gate" bash scripts/test_macos_public_rc_gate.sh
run_step "test stable preflight gate" bash scripts/test_macos_stable_preflight.sh
run_step "test stable closeout gate" bash scripts/test_macos_stable_closeout_gate.sh
run_step "test stable QA evidence template" bash scripts/test_macos_stable_qa_evidence_template.sh
run_step "test Homebrew formula generator" bash scripts/test_homebrew_formula.sh
run_step "test hosted native installer generator" bash scripts/test_hosted_native_installer.sh
run_step "test CycloneDX SBOM generator" bash scripts/test_cyclonedx_sbom.sh

run_step "generate self-exported public bundle" bash scripts/public_repo_export_bundle.sh --force
run_step "verify self-exported manifest" \
  bash scripts/public_repo_manifest_check.sh --staged-output dist/public-export/ottto
run_step "verify public skeleton" bash scripts/public_repo_skeleton_check.sh
run_step "scan self-exported public bundle" \
  bash scripts/public_repo_secret_scan.sh --staged-output dist/public-export/ottto
run_step "verify self-exported public contracts" \
  bash scripts/public_repo_contract_check.sh --staged-output dist/public-export/ottto

echo "public-surface-ci: completed public surface checks at $REPO_ROOT"
