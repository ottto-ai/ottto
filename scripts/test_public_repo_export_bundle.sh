#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/public_repo_export_bundle.sh"
CHECK_SCRIPT="$ROOT/scripts/public_repo_export_check.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

write_config() {
  local repo="$1"
  mkdir -p "$repo/config"
  cat > "$repo/config/roots.txt" <<'ROOTS'
private-root/README.md
private-root/scripts/
.agents/skills/ottto/
.claude/skills/ottto/
ROOTS
  cat > "$repo/config/path-map.tsv" <<'PATHMAP'
# source_prefix	destination_prefix	reason
private-root/	.	root mapping
.agents/skills/ottto/	agent-adapters/codex-skill/	Codex adapter
.claude/skills/ottto/	agent-adapters/claude-code-skill/	Claude adapter
PATHMAP
  cat > "$repo/config/rewrite-rules.tsv" <<'REWRITES'
# literal	replacement	reason
ottto-ai/coding-agents-observability	ottto-ai/ottto	test rewrite
coding-agents-observability	ottto	test rewrite
REWRITES
  cat > "$repo/config/deny-patterns.tsv" <<'DENY'
# scope	regex	description
path	(^|/)backend(/|$)	backend path denied
content	/Users/ronshub	local operator path denied
content	docs/dev/	private docs denied
content	Bearer[[:space:]]+[A-Za-z0-9._~+/=-]{16,}	bearer token denied
DENY
}

init_repo() {
  local repo="$1"
  mkdir -p "$repo/private-root/scripts" "$repo/.agents/skills/ottto" "$repo/.claude/skills/ottto"
  git -C "$repo" init -q
  git -C "$repo" config user.email "test@example.com"
  git -C "$repo" config user.name "Test"
  write_config "$repo"
}

run_bundle() {
  local repo="$1"
  local output="$2"
  shift 2
  PUBLIC_EXPORT_REPO_ROOT="$repo" \
    PUBLIC_EXPORT_CONFIG_DIR="$repo/config" \
    PUBLIC_EXPORT_PATH_MAP_FILE="$repo/config/path-map.tsv" \
    PUBLIC_EXPORT_CHECK_SCRIPT="$CHECK_SCRIPT" \
    "$SCRIPT" --output-dir "$output" "$@"
}

pass_repo="$tmp_dir/pass"
init_repo "$pass_repo"
cat > "$pass_repo/private-root/README.md" <<'EOF'
# Public Files

Attestation examples still mention ottto-ai/coding-agents-observability before
the public export rewrite step. The old repository name was
coding-agents-observability.
EOF
cat > "$pass_repo/private-root/scripts/tool.sh" <<'EOF'
#!/usr/bin/env bash
echo "tool"
EOF
chmod +x "$pass_repo/private-root/scripts/tool.sh"
cat > "$pass_repo/.agents/skills/ottto/SKILL.md" <<'EOF'
# Codex Ottto Skill
EOF
cat > "$pass_repo/.claude/skills/ottto/SKILL.md" <<'EOF'
# Claude Ottto Skill
EOF
git -C "$pass_repo" add .
git -C "$pass_repo" commit -qm init

output_dir="$tmp_dir/out"
rewrite_required_output="$tmp_dir/public-export-rewrite-required.out"
if run_bundle "$pass_repo" "$output_dir" >"$rewrite_required_output" 2>&1; then
  echo "Expected rewrite-required bundle input to fail without --allow-rewrites" >&2
  exit 1
fi
grep -q "rewrite-required references are not allowed" "$rewrite_required_output"
run_bundle "$pass_repo" "$output_dir" --allow-rewrites
test -f "$output_dir/README.md"
test -x "$output_dir/scripts/tool.sh"
test -f "$output_dir/agent-adapters/codex-skill/SKILL.md"
test -f "$output_dir/agent-adapters/claude-code-skill/SKILL.md"
test -f "$output_dir/PUBLIC_EXPORT_MANIFEST.json"
grep -q "ottto-ai/ottto" "$output_dir/README.md"
grep -q "^ottto\\.$" "$output_dir/README.md"
if grep -R "coding-agents-observability" "$output_dir"; then
  echo "Expected private repository name to be rewritten" >&2
  exit 1
fi
python3 - "$output_dir/PUBLIC_EXPORT_MANIFEST.json" <<'PY'
import json
import sys

manifest = json.load(open(sys.argv[1], encoding="utf-8"))
assert manifest["schema_version"] == 1
assert manifest["candidate_file_count"] == 4
assert manifest["output_file_count"] == 8
assert manifest["rewrites_applied"]["ottto-ai/ottto"] == 1
assert manifest["rewrites_applied"]["ottto"] == 1
assert len(manifest["content_sha256"]) == 64
files = manifest["files"]
assert len(files) == manifest["output_file_count"] - 1
assert [record["path"] for record in files] == sorted(record["path"] for record in files)
readme = next(record for record in files if record["path"] == "README.md")
assert len(readme["sha256"]) == 64
assert readme["size_bytes"] > 0
assert readme["mode"] == "0644"
assert readme["executable"] is False
tool = next(record for record in files if record["path"] == "scripts/tool.sh")
assert len(tool["sha256"]) == 64
assert tool["mode"] == "0755"
assert tool["executable"] is True
PY
"$ROOT/scripts/public_repo_manifest_check.sh" --staged-output "$output_dir" >/tmp/public-export-toy-manifest.out
test -f "$output_dir/public-export/roots.txt"
test -f "$output_dir/public-export/path-map.tsv"
test -f "$output_dir/public-export/rewrite-rules.tsv"
grep -q "agent-adapters/codex-skill/" "$output_dir/public-export/roots.txt"
grep -q "No private repository rewrite rules" "$output_dir/public-export/rewrite-rules.tsv"

existing_output="$tmp_dir/public-export-existing.out"
if run_bundle "$pass_repo" "$output_dir" --allow-rewrites >"$existing_output" 2>&1; then
  echo "Expected non-empty output directory to require --force" >&2
  exit 1
fi
grep -q "pass --force" "$existing_output"
run_bundle "$pass_repo" "$output_dir" --force --allow-rewrites >/dev/null

real_output="$tmp_dir/real-output"
"$SCRIPT" --output-dir "$real_output" --force >/tmp/public-export-real.out
test -f "$real_output/LICENSE"
test -f "$real_output/NOTICE"
test -f "$real_output/SECURITY.md"
test -f "$real_output/CONTRIBUTING.md"
test -f "$real_output/CODE_OF_CONDUCT.md"
test -f "$real_output/SUPPORT.md"
test -f "$real_output/TRADEMARKS.md"
test -f "$real_output/docs/support.md"
test -f "$real_output/.github/workflows/ci.yml"
test -f "$real_output/.github/dependabot.yml"
grep -q "Apache License" "$real_output/LICENSE"
grep -q "TRADEMARKS.md" "$real_output/NOTICE"
grep -q "## Public V1 Promise" "$real_output/README.md"
grep -q "Homebrew tap" "$real_output/README.md"
grep -q "Live telemetry is source-level" "$real_output/README.md"
test -f "$real_output/docs/agent-adapters.md"
grep -q "MCP adapter is intentionally deferred" "$real_output/docs/agent-adapters.md"
grep -q "Ottto Local Platform Support Runbook" "$real_output/docs/support.md"
grep -q "docs/support.md" "$real_output/SUPPORT.md"
grep -q "cargo audit --deny warnings" "$real_output/.github/workflows/ci.yml"
grep -q "public_repo_surface_ci.sh" "$real_output/.github/workflows/ci.yml"
grep -q "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294" "$real_output/.github/workflows/ci.yml"
grep -q "package-ecosystem: cargo" "$real_output/.github/dependabot.yml"
test -f "$real_output/connectors/registry.generated.json"
test -f "$real_output/connectors/sources/codex/source.toml"
test -f "$real_output/crates/ottto-connector-sdk/Cargo.toml"
test -f "$real_output/crates/ottto-connector-testkit/Cargo.toml"
test -f "$real_output/schemas/source-manifest.schema.json"
grep -q 'license = "Apache-2.0"' "$real_output/Cargo.toml"
grep -q 'license = "Apache-2.0"' "$real_output/crates/ottto-connector-sdk/Cargo.toml"
grep -q 'license = "Apache-2.0"' "$real_output/crates/ottto-connector-testkit/Cargo.toml"
grep -q "^LICENSE$" "$real_output/public-export/roots.txt"
grep -q "^NOTICE$" "$real_output/public-export/roots.txt"
grep -q "^SECURITY.md$" "$real_output/public-export/roots.txt"
grep -q "^.github/workflows/ci.yml$" "$real_output/public-export/roots.txt"
grep -q "^.github/dependabot.yml$" "$real_output/public-export/roots.txt"
grep -q "connectors/" "$real_output/public-export/roots.txt"
grep -q "schemas/" "$real_output/public-export/roots.txt"
grep -Fq $'Cargo.lock\t.\tPublic repository root file is already in export shape.' "$real_output/public-export/path-map.tsv"
grep -Fq $'crates/Cargo.lock\tcrates\tPublic repository root file is already in export shape.' "$real_output/public-export/path-map.tsv"
grep -Fq $'.github/workflows/ci.yml\t.github/workflows\tPublic repository root file is already in export shape.' "$real_output/public-export/path-map.tsv"
test -x "$real_output/scripts/public_repo_surface_ci.sh"
test -x "$real_output/scripts/test_public_repo_surface_ci.sh"
grep -q "test_macos_public_rc_gate.sh" "$real_output/scripts/public_repo_surface_ci.sh"
grep -q "test_macos_stable_preflight.sh" "$real_output/scripts/public_repo_surface_ci.sh"
grep -q "test_homebrew_formula.sh" "$real_output/scripts/public_repo_surface_ci.sh"
grep -q "test_hosted_native_installer.sh" "$real_output/scripts/public_repo_surface_ci.sh"
grep -q "test_cyclonedx_sbom.sh" "$real_output/scripts/public_repo_surface_ci.sh"
test -x "$real_output/scripts/macos_public_rc_evidence_template.sh"
test -x "$real_output/scripts/macos_public_rc_gate.sh"
test -x "$real_output/scripts/test_macos_public_rc_gate.sh"
PUBLIC_SKELETON_REPO_ROOT="$real_output" "$real_output/scripts/public_repo_skeleton_check.sh" >/tmp/public-export-skeleton.out
"$real_output/scripts/public_repo_manifest_check.sh" --staged-output "$real_output" >/tmp/public-export-manifest.out
source_repo="$ROOT/../.."
if git -C "$source_repo" rev-parse --show-toplevel >/dev/null 2>&1 && [[ -d "$source_repo/tools/ottto-local-platform" ]]; then
  PUBLIC_EXPORT_REPO_ROOT="$source_repo" \
    "$real_output/scripts/public_repo_secret_scan.sh" --staged-output "$real_output" >/tmp/public-export-secret-scan.out
else
  current_repo="$(git -C "$ROOT" rev-parse --show-toplevel)"
  PUBLIC_EXPORT_REPO_ROOT="$current_repo" \
    "$real_output/scripts/public_repo_secret_scan.sh" --staged-output "$real_output" >/tmp/public-export-secret-scan.out
fi
if [[ -d "$source_repo/backend" && -d "$source_repo/frontend" ]]; then
  PUBLIC_CONTRACT_PRIVATE_REPO_ROOT="$source_repo" \
    "$real_output/scripts/public_repo_contract_check.sh" --staged-output "$real_output" >/tmp/public-export-contract.out
else
  "$real_output/scripts/public_repo_contract_check.sh" --staged-output "$real_output" >/tmp/public-export-contract.out
fi

secret_repo="$tmp_dir/secret"
init_repo "$secret_repo"
cat > "$secret_repo/private-root/README.md" <<'EOF'
Raw operator output: /Users/ronshub/private
EOF
git -C "$secret_repo" add .
git -C "$secret_repo" commit -qm init
if run_bundle "$secret_repo" "$tmp_dir/secret-out" >/tmp/public-export-secret.out 2>&1; then
  echo "Expected local user path to fail bundle generation" >&2
  exit 1
fi
grep -q "local operator path denied" /tmp/public-export-secret.out

collision_repo="$tmp_dir/collision"
mkdir -p "$collision_repo/one" "$collision_repo/two" "$collision_repo/config"
git -C "$collision_repo" init -q
git -C "$collision_repo" config user.email "test@example.com"
git -C "$collision_repo" config user.name "Test"
printf 'one\n' > "$collision_repo/one/README.md"
printf 'two\n' > "$collision_repo/two/README.md"
cat > "$collision_repo/config/roots.txt" <<'ROOTS'
one/
two/
ROOTS
cat > "$collision_repo/config/path-map.tsv" <<'PATHMAP'
# source_prefix	destination_prefix	reason
one/	.	test collision
two/	.	test collision
PATHMAP
cat > "$collision_repo/config/rewrite-rules.tsv" <<'REWRITES'
# literal	replacement	reason
old	new	test
REWRITES
cat > "$collision_repo/config/deny-patterns.tsv" <<'DENY'
# scope	regex	description
content	/Users/ronshub	local operator path denied
DENY
git -C "$collision_repo" add .
git -C "$collision_repo" commit -qm init
if run_bundle "$collision_repo" "$tmp_dir/collision-out" >/tmp/public-export-collision.out 2>&1; then
  echo "Expected path-map collision to fail bundle generation" >&2
  exit 1
fi
grep -q "path map collision" /tmp/public-export-collision.out

echo "public_repo_export_bundle tests passed"
