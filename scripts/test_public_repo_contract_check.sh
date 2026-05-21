#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_SCRIPT="$ROOT/scripts/public_repo_export_bundle.sh"
CONTRACT_SCRIPT="$ROOT/scripts/public_repo_contract_check.sh"
PRIVATE_ROOT="$(cd "$ROOT/../.." && pwd)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

output_dir="$tmp_dir/public-ottto"
"$BUNDLE_SCRIPT" --output-dir "$output_dir" --force >/tmp/public-contract-bundle.out

write_valid_pin() {
  local manifest_path="$1"
  local pin_path="$2"
  python3 - "$manifest_path" "$pin_path" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
pin_path = Path(sys.argv[2])
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
pin_path.parent.mkdir(parents=True, exist_ok=True)
pin = {
    "schema_version": 1,
    "generated_by": "public_runtime_pin.v1",
    "expected_repository": "ottto-ai/ottto",
    "authority_state": "pre_public_repo_export",
    "public_export_manifest": {
        "content_sha256": manifest["content_sha256"],
        "output_file_count": manifest["output_file_count"],
        "file_record_count": len(manifest["files"]),
    },
}
pin_path.write_text(json.dumps(pin, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_public_commit_pin() {
  local manifest_path="$1"
  local pin_path="$2"
  local commit="$3"
  python3 - "$manifest_path" "$pin_path" "$commit" <<'PY'
import json
import sys
from pathlib import Path

manifest_path = Path(sys.argv[1])
pin_path = Path(sys.argv[2])
commit = sys.argv[3]
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
pin_path.parent.mkdir(parents=True, exist_ok=True)
pin = {
    "schema_version": 1,
    "generated_by": "public_runtime_pin.v1",
    "expected_repository": "ottto-ai/ottto",
    "authority_state": "public_repo_commit",
    "public_repo_commit": {
        "repository": "ottto-ai/ottto",
        "commit": commit,
        "manifest_path": "PUBLIC_EXPORT_MANIFEST.json",
        "manifest_content_sha256": manifest["content_sha256"],
    },
    "public_export_manifest": {
        "content_sha256": manifest["content_sha256"],
        "output_file_count": manifest["output_file_count"],
        "file_record_count": len(manifest["files"]),
    },
}
pin_path.write_text(json.dumps(pin, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_valid_private_consumers() {
  local private_root="$1"
  local manifest_path="$2"
  mkdir -p \
    "$private_root/backend/app/domain/connectors" \
    "$private_root/backend/app/domain/local_platform" \
    "$private_root/backend/app/features/setup_runs" \
    "$private_root/backend/app/schemas" \
    "$private_root/frontend/src/lib/apps"
  write_valid_pin \
    "$manifest_path" \
    "$private_root/backend/app/domain/local_platform/public_runtime_pin.json"
  cat > "$private_root/backend/app/domain/connectors/registry.py" <<'PY'
from typing import Literal

DEFAULT_CONNECTOR_REGISTRY_PATH = REPO_ROOT / "connectors" / "registry.generated.json"
schema_version: Literal["connector_registry.v1"]
PY
  cat > "$private_root/backend/app/schemas/setup_runs.py" <<'PY'
from typing import Literal

product: Literal["ottto-local-platform"] = "ottto-local-platform"
PY
  cat > "$private_root/backend/app/features/setup_runs/service.py" <<'PY'
def load_manifest(manifest):
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported schema")
    if manifest.get("product") != "ottto-local-platform":
        raise ValueError("unsupported product")
    return manifest
PY
  cat > "$private_root/frontend/src/lib/apps/local-telemetry-control.ts" <<'TS'
const LOCAL_CONTROL_PROTOCOL_VERSION = 11;
type LocalControlRequest = {
  command: "telemetry_control";
  targetAddressSpace?: "loopback";
};
TS
}

if [[ -d "$PRIVATE_ROOT/backend" && -d "$PRIVATE_ROOT/frontend" ]]; then
  "$CONTRACT_SCRIPT" \
    --staged-output "$output_dir" \
    --private-repo-root "$PRIVATE_ROOT" \
    >/tmp/public-contract-private-script.out
  "$output_dir/scripts/public_repo_contract_check.sh" \
    --staged-output "$output_dir" \
    --private-repo-root "$PRIVATE_ROOT" \
    >/tmp/public-contract-exported-script.out
else
  "$CONTRACT_SCRIPT" \
    --staged-output "$output_dir" \
    >/tmp/public-contract-private-script.out
  "$output_dir/scripts/public_repo_contract_check.sh" \
    --staged-output "$output_dir" \
    >/tmp/public-contract-exported-script.out
fi

broken_protocol="$tmp_dir/broken-protocol"
cp -R "$output_dir" "$broken_protocol"
python3 - "$broken_protocol/fixtures/control/status-request.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["protocol_version"] = 10
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_protocol" >/tmp/public-contract-broken-protocol.out 2>&1; then
  echo "Expected contract check to fail when control protocol drifts" >&2
  exit 1
fi
grep -q "control status request protocol_version must be 11" /tmp/public-contract-broken-protocol.out

broken_registry="$tmp_dir/broken-registry"
cp -R "$output_dir" "$broken_registry"
python3 - "$broken_registry/connectors/registry.generated.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["sources"] = [
    source for source in payload["sources"] if source.get("source_id") != "codex"
]
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_registry" >/tmp/public-contract-broken-registry.out 2>&1; then
  echo "Expected contract check to fail when a required source is missing" >&2
  exit 1
fi
grep -q "registry is missing required source(s): codex" /tmp/public-contract-broken-registry.out

broken_mcp="$tmp_dir/broken-mcp"
cp -R "$output_dir" "$broken_mcp"
mkdir -p "$broken_mcp/agent-adapters/mcp-server"
printf 'deferred\n' > "$broken_mcp/agent-adapters/mcp-server/README.md"
if "$CONTRACT_SCRIPT" --staged-output "$broken_mcp" >/tmp/public-contract-broken-mcp.out 2>&1; then
  echo "Expected contract check to fail when an MCP adapter is exported for v1" >&2
  exit 1
fi
grep -q "MCP adapter must remain deferred for public v1" /tmp/public-contract-broken-mcp.out

pin_private="$tmp_dir/pin-private"
write_valid_private_consumers "$pin_private" "$output_dir/PUBLIC_EXPORT_MANIFEST.json"
bad_pin="$tmp_dir/bad-pin.json"
python3 - "$pin_private/backend/app/domain/local_platform/public_runtime_pin.json" "$bad_pin" <<'PY'
import json
import sys
from pathlib import Path

pin = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
pin["public_export_manifest"]["content_sha256"] = "0" * 64
Path(sys.argv[2]).write_text(json.dumps(pin, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" \
  --staged-output "$output_dir" \
  --private-repo-root "$pin_private" \
  --private-runtime-pin "$bad_pin" \
  >/tmp/public-contract-bad-pin.out 2>&1; then
  echo "Expected contract check to fail when the private runtime pin drifts" >&2
  exit 1
fi
grep -q "private runtime pin content_sha256 must match public manifest content_sha256" \
  /tmp/public-contract-bad-pin.out

if "$CONTRACT_SCRIPT" \
  --staged-output "$output_dir" \
  --private-repo-root "$pin_private" \
  --require-public-authority \
  >/tmp/public-contract-require-public-authority.out 2>&1; then
  echo "Expected contract check to fail when public authority is required but pin is pre-public" >&2
  exit 1
fi
grep -q "private runtime pin authority_state must be public_repo_commit when public authority is required" \
  /tmp/public-contract-require-public-authority.out

public_git="$tmp_dir/public-git"
cp -R "$output_dir" "$public_git"
git -C "$public_git" init -q
git -C "$public_git" config user.email "public-contract@example.invalid"
git -C "$public_git" config user.name "Public Contract"
git -C "$public_git" add .
git -C "$public_git" commit -qm "public runtime"
public_commit="$(git -C "$public_git" rev-parse HEAD)"
public_authority_private="$tmp_dir/public-authority-private"
write_valid_private_consumers "$public_authority_private" "$public_git/PUBLIC_EXPORT_MANIFEST.json"
write_public_commit_pin \
  "$public_git/PUBLIC_EXPORT_MANIFEST.json" \
  "$public_authority_private/backend/app/domain/local_platform/public_runtime_pin.json" \
  "$public_commit"
"$CONTRACT_SCRIPT" \
  --staged-output "$public_git" \
  --private-repo-root "$public_authority_private" \
  --require-public-authority \
  >/tmp/public-contract-public-authority.out

bad_public_authority_private="$tmp_dir/bad-public-authority-private"
write_valid_private_consumers "$bad_public_authority_private" "$public_git/PUBLIC_EXPORT_MANIFEST.json"
write_public_commit_pin \
  "$public_git/PUBLIC_EXPORT_MANIFEST.json" \
  "$bad_public_authority_private/backend/app/domain/local_platform/public_runtime_pin.json" \
  "0000000000000000000000000000000000000000"
if "$CONTRACT_SCRIPT" \
  --staged-output "$public_git" \
  --private-repo-root "$bad_public_authority_private" \
  --require-public-authority \
  >/tmp/public-contract-bad-public-authority.out 2>&1; then
  echo "Expected contract check to fail when public authority pin commit mismatches public root" >&2
  exit 1
fi
grep -q "private runtime pin public_repo_commit.commit must match public root HEAD" \
  /tmp/public-contract-bad-public-authority.out

if "$CONTRACT_SCRIPT" \
  --staged-output "$output_dir" \
  --private-repo-root "$pin_private" \
  --private-runtime-pin "$tmp_dir/missing-pin.json" \
  >/tmp/public-contract-missing-pin.out 2>&1; then
  echo "Expected contract check to fail when the private runtime pin is missing" >&2
  exit 1
fi
grep -q "private runtime pin is missing" /tmp/public-contract-missing-pin.out

fake_private="$tmp_dir/private"
write_valid_private_consumers "$fake_private" "$output_dir/PUBLIC_EXPORT_MANIFEST.json"
cat > "$fake_private/backend/app/domain/connectors/registry.py" <<'PY'
DEFAULT_CONNECTOR_REGISTRY_PATH = REPO_ROOT / "tools" / "ottto-local-platform" / "connectors" / "registry.generated.json"
PY
cat > "$fake_private/backend/app/schemas/setup_runs.py" <<'PY'
product: str
PY
cat > "$fake_private/backend/app/features/setup_runs/service.py" <<'PY'
def loader(manifest):
    return manifest
PY
cat > "$fake_private/frontend/src/lib/apps/local-telemetry-control.ts" <<'TS'
const LOCAL_CONTROL_PROTOCOL_VERSION = 10;
TS
if "$CONTRACT_SCRIPT" \
  --staged-output "$output_dir" \
  --private-repo-root "$fake_private" \
  >/tmp/public-contract-broken-private.out 2>&1; then
  echo "Expected contract check to fail when private consumers drift" >&2
  exit 1
fi
grep -q "private backend registry loader must read root connectors/registry.generated.json" /tmp/public-contract-broken-private.out
grep -q "private frontend local-control client must send protocol version 11" /tmp/public-contract-broken-private.out

echo "public_repo_contract_check tests passed"
