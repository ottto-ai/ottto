#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="${PUBLIC_SKELETON_REPO_ROOT:-$DEFAULT_REPO_ROOT}"

usage() {
  cat <<'USAGE'
Usage: public_repo_skeleton_check.sh

Checks that a root-shaped public ottto repository checkout contains the
expected runtime, connector, docs, release, policy, CI, and agent-adapter
skeleton. Override PUBLIC_SKELETON_REPO_ROOT to check a staged export bundle.
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

failures=0

fail() {
  echo "public-skeleton: $*" >&2
  failures=$((failures + 1))
}

require_file() {
  if [[ ! -f "$REPO_ROOT/$1" ]]; then
    fail "required file is missing: $1"
  fi
}

require_dir() {
  if [[ ! -d "$REPO_ROOT/$1" ]]; then
    fail "required directory is missing: $1"
  fi
}

require_executable() {
  if [[ ! -x "$REPO_ROOT/$1" ]]; then
    fail "required executable is missing or not executable: $1"
  fi
}

require_grep() {
  local pattern="$1"
  local path="$2"
  local description="$3"
  if [[ ! -f "$REPO_ROOT/$path" ]]; then
    fail "$description: missing file $path"
    return
  fi
  if ! grep -Eq "$pattern" "$REPO_ROOT/$path"; then
    fail "$description: pattern not found in $path"
  fi
}

deny_path() {
  if [[ -e "$REPO_ROOT/$1" ]]; then
    fail "private or non-root-shaped path must not exist: $1"
  fi
}

if [[ ! -d "$REPO_ROOT" ]]; then
  echo "public-skeleton: repository root is not a directory: $REPO_ROOT" >&2
  exit 2
fi

required_dirs=(
  ".github"
  ".github/workflows"
  "agent-adapters"
  "agent-adapters/codex-skill"
  "agent-adapters/codex-skill/agents"
  "agent-adapters/claude-code-skill"
  "connectors"
  "connectors/sources"
  "crates"
  "crates/ottto-cli"
  "crates/ottto-connector-sdk"
  "crates/ottto-connector-testkit"
  "crates/ottto-core"
  "crates/ottto-protocol"
  "crates/ottto-service"
  "docs"
  "fixtures"
  "homebrew"
  "public-export"
  "release"
  "schemas"
  "scripts"
)

for path in "${required_dirs[@]}"; do
  require_dir "$path"
done

required_files=(
  ".github/dependabot.yml"
  ".github/workflows/ci.yml"
  "CODE_OF_CONDUCT.md"
  "CONTRIBUTING.md"
  "Cargo.lock"
  "Cargo.toml"
  "LICENSE"
  "NOTICE"
  "PUBLIC_EXPORT_MANIFEST.json"
  "README.md"
  "SECURITY.md"
  "SUPPORT.md"
  "TRADEMARKS.md"
  "agent-adapters/codex-skill/SKILL.md"
  "agent-adapters/codex-skill/agents/openai.yaml"
  "agent-adapters/claude-code-skill/SKILL.md"
  "connectors/README.md"
  "connectors/registry.generated.json"
  "connectors/sources/codex/source.toml"
  "crates/Cargo.lock"
  "crates/Cargo.toml"
  "crates/ottto-cli/Cargo.toml"
  "crates/ottto-connector-sdk/Cargo.toml"
  "crates/ottto-connector-testkit/Cargo.toml"
  "crates/ottto-core/Cargo.toml"
  "crates/ottto-protocol/Cargo.toml"
  "crates/ottto-service/Cargo.toml"
  "docs/README.md"
  "docs/agent-adapters.md"
  "docs/support.md"
  "fixtures/cli/help-contract.txt"
  "homebrew/README.md"
  "public-export/path-map.tsv"
  "public-export/rewrite-rules.tsv"
  "public-export/roots.txt"
  "release/README.md"
  "release/manifest.schema.json"
  "schemas/collector-fixture.schema.json"
  "schemas/collector-manifest.schema.json"
  "schemas/connector-registry.schema.json"
  "schemas/source-manifest.schema.json"
)

for path in "${required_files[@]}"; do
  require_file "$path"
done

required_executables=(
  "scripts/homebrew_formula.sh"
  "scripts/hosted_native_installer.sh"
  "scripts/macos_release_gate.sh"
  "scripts/macos_public_rc_evidence_template.sh"
  "scripts/macos_public_rc_gate.sh"
  "scripts/macos_stable_preflight.sh"
  "scripts/macos_stable_qa_evidence_template.sh"
  "scripts/public_repo_bootstrap_plan.sh"
  "scripts/public_repo_cutover_closeout.sh"
  "scripts/public_repo_export_bundle.sh"
  "scripts/public_repo_export_check.sh"
  "scripts/public_repo_contract_check.sh"
  "scripts/public_repo_manifest_check.sh"
  "scripts/public_repo_secret_scan.sh"
  "scripts/public_repo_skeleton_check.sh"
  "scripts/public_repo_surface_ci.sh"
  "scripts/test_public_repo_bootstrap_plan.sh"
  "scripts/test_public_repo_contract_check.sh"
  "scripts/test_public_repo_cutover_closeout.sh"
  "scripts/test_public_repo_export_bundle.sh"
  "scripts/test_public_repo_export_check.sh"
  "scripts/test_public_repo_manifest_check.sh"
  "scripts/test_public_repo_secret_scan.sh"
  "scripts/test_public_repo_skeleton_check.sh"
  "scripts/test_public_repo_surface_ci.sh"
  "scripts/test_macos_public_rc_gate.sh"
  "scripts/test_macos_stable_qa_evidence_template.sh"
)

for path in "${required_executables[@]}"; do
  require_executable "$path"
done

deny_path ".agents"
deny_path ".claude"
deny_path "backend"
deny_path "docs/ai"
deny_path "docs/dev"
deny_path "frontend"
deny_path "infra"
deny_path "tools/ottto-local-platform"

require_grep '^\[workspace\]$' "Cargo.toml" "root Rust workspace"
require_grep '"crates/ottto-cli"' "Cargo.toml" "runtime crate workspace membership"
require_grep '"crates/ottto-service"' "Cargo.toml" "service crate workspace membership"
require_grep '^\[workspace\]$' "crates/Cargo.toml" "connector Rust workspace"
require_grep '"ottto-connector-sdk"' "crates/Cargo.toml" "connector SDK workspace membership"
require_grep '"ottto-connector-testkit"' "crates/Cargo.toml" "connector testkit workspace membership"
require_grep '^# Ottto Local Platform$' "README.md" "root README title"
require_grep '"content_sha256"' "PUBLIC_EXPORT_MANIFEST.json" "manifest integrity digest"
require_grep '"files"' "PUBLIC_EXPORT_MANIFEST.json" "manifest file inventory"
require_grep '^## Public V1 Promise$' "README.md" "public v1 promise"
require_grep '^# Ottto Local Platform Public Docs$' "docs/README.md" "public docs index"
require_grep '^# Agent Adapters$' "docs/agent-adapters.md" "agent adapter docs"
require_grep 'MCP adapter is intentionally deferred' "docs/agent-adapters.md" "MCP adapter deferral"
require_grep '^# Ottto Local Platform Support Runbook$' "docs/support.md" "support runbook title"
require_grep '^## Triage$' "docs/support.md" "support runbook triage"
require_grep '^## Diagnostics$' "docs/support.md" "support runbook diagnostics"
require_grep '^## Escalation$' "docs/support.md" "support runbook escalation"
require_grep '^## Do Not Collect$' "docs/support.md" "support runbook data boundaries"
require_grep 'docs/support\.md' "SUPPORT.md" "root support runbook link"
require_grep '^\.github/workflows/ci\.yml$' "public-export/roots.txt" "public CI export root"
require_grep '^agent-adapters/codex-skill/' "public-export/roots.txt" "Codex adapter export root"
require_grep '^agent-adapters/claude-code-skill/' "public-export/roots.txt" "Claude adapter export root"
require_grep 'github-actions' ".github/dependabot.yml" "GitHub Actions dependency hygiene"
require_grep 'package-ecosystem: cargo' ".github/dependabot.yml" "Cargo dependency hygiene"
require_grep 'cargo clippy' ".github/workflows/ci.yml" "Rust clippy CI"
require_grep 'public_repo_surface_ci\.sh' ".github/workflows/ci.yml" "public surface CI gate"
require_grep 'public_repo_contract_check\.sh' "scripts/public_repo_surface_ci.sh" "public contract CI gate"
require_grep 'public_repo_cutover_closeout\.sh' "scripts/public_repo_surface_ci.sh" "public cutover closeout CI gate"
require_grep 'public_repo_manifest_check\.sh' "scripts/public_repo_surface_ci.sh" "public manifest CI gate"
require_grep 'public_repo_secret_scan\.sh' "scripts/public_repo_surface_ci.sh" "secret scan CI gate"
require_grep 'public_repo_skeleton_check\.sh' "scripts/public_repo_surface_ci.sh" "skeleton CI gate"

if [[ "$failures" -gt 0 ]]; then
  echo "public-skeleton: failed with $failures issue(s) under $REPO_ROOT" >&2
  exit 1
fi

echo "public-skeleton: checked public repository skeleton at $REPO_ROOT"
