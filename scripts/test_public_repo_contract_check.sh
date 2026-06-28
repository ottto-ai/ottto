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
const LOCAL_CONTROL_PROTOCOL_VERSIONS = [15, 14, 13, 12] as const;
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
grep -q "control status request protocol_version must be 15" /tmp/public-contract-broken-protocol.out

broken_uninstall="$tmp_dir/broken-uninstall"
cp -R "$output_dir" "$broken_uninstall"
python3 - "$broken_uninstall/fixtures/cli/uninstall-request.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["command"] = "uninstall"
payload["confirm"] = False
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_uninstall" >/tmp/public-contract-broken-uninstall.out 2>&1; then
  echo "Expected contract check to fail when uninstall is not a confirmed execute request" >&2
  exit 1
fi
grep -q "CLI uninstall request command must be uninstall_execute" \
  /tmp/public-contract-broken-uninstall.out
grep -q "CLI uninstall request confirm must be true" \
  /tmp/public-contract-broken-uninstall.out

broken_fix="$tmp_dir/broken-fix"
cp -R "$output_dir" "$broken_fix"
python3 - "$broken_fix/fixtures/cli/fix-codex-request.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["source"] = "claude_code"
payload["dry_run"] = True
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_fix" >/tmp/public-contract-broken-fix.out 2>&1; then
  echo "Expected contract check to fail when fix request source or dry_run drifts" >&2
  exit 1
fi
grep -q "CLI fix Codex request source must be codex" \
  /tmp/public-contract-broken-fix.out
grep -q "CLI fix Codex request dry_run must be false" \
  /tmp/public-contract-broken-fix.out

broken_setup_state="$tmp_dir/broken-setup-state"
cp -R "$output_dir" "$broken_setup_state"
python3 - "$broken_setup_state/fixtures/cli/setup-needs-user-action-output.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["next_action"] = {"type": "browser_claim"}
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_setup_state" >/tmp/public-contract-broken-setup-state.out 2>&1; then
  echo "Expected contract check to fail when setup output has ambiguous next state" >&2
  exit 1
fi
grep -q "needs-user-action output must not set both next_question and next_action" \
  /tmp/public-contract-broken-setup-state.out
grep -q "needs-user-action next_action must be null while waiting for approval" \
  /tmp/public-contract-broken-setup-state.out

broken_setup_agent_action="$tmp_dir/broken-setup-agent-action"
cp -R "$output_dir" "$broken_setup_agent_action"
python3 - \
  "$broken_setup_agent_action/fixtures/cli/setup-browser-claim-output.json" \
  "$broken_setup_agent_action/fixtures/cli/setup-needs-user-action-output.json" \
  "$broken_setup_agent_action/fixtures/cli/setup-timed-out-output.json" <<'PY'
import json
import sys
from pathlib import Path

browser_path = Path(sys.argv[1])
needs_path = Path(sys.argv[2])
timeout_path = Path(sys.argv[3])

browser = json.loads(browser_path.read_text(encoding="utf-8"))
browser["agent_action"]["kind"] = "answer_setup_question"
browser["agent_action"]["description"] = "Read the human setup output."
browser_path.write_text(json.dumps(browser, indent=2) + "\n", encoding="utf-8")

needs = json.loads(needs_path.read_text(encoding="utf-8"))
needs["agent_action"]["requires_user"] = False
needs["agent_action"]["description"] = "Ask the user what to do."
needs_path.write_text(json.dumps(needs, indent=2) + "\n", encoding="utf-8")

timeout = json.loads(timeout_path.read_text(encoding="utf-8"))
timeout["agent_action"]["retryable"] = False
timeout["agent_action"]["description"] = "Give up on setup."
timeout_path.write_text(json.dumps(timeout, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_setup_agent_action" >/tmp/public-contract-broken-setup-agent-action.out 2>&1; then
  echo "Expected contract check to fail when setup agent_action semantics drift" >&2
  exit 1
fi
grep -q "browser claim agent_action.kind must be open_browser_claim" \
  /tmp/public-contract-broken-setup-agent-action.out
grep -q "browser claim agent_action.description must be stable" \
  /tmp/public-contract-broken-setup-agent-action.out
grep -q "needs-user-action agent_action.requires_user must be true" \
  /tmp/public-contract-broken-setup-agent-action.out
grep -q "needs-user-action agent_action.description must be stable" \
  /tmp/public-contract-broken-setup-agent-action.out
grep -q "setup timed-out agent_action.retryable must be true" \
  /tmp/public-contract-broken-setup-agent-action.out
grep -q "setup timed-out agent_action.description must be stable" \
  /tmp/public-contract-broken-setup-agent-action.out

broken_setup_docs="$tmp_dir/broken-setup-docs"
cp -R "$output_dir" "$broken_setup_docs"
python3 - "$broken_setup_docs/docs/setup.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "Default setup opens a browser claim and waits for approval",
    "Default setup can run locally without browser approval",
)
text = text.replace("ottto setup --json", "ottto setup", 1)
text = text.replace(
    "parseable JSON payload with a\nnonzero exit code",
    "human-readable payload with a failure",
)
text = text.replace(
    "ottto setup --json --no-browser --no-wait",
    "ottto setup --no-browser",
)
text = text.replace(
    "Show the returned `claim_url` or `claim_code` to the user",
    "Continue setup without showing claim details",
)
text = text.replace(
    "Exit code `60` means\nbrowser or user action is required",
    "Exit code `60` means retry later",
)
text = text.replace(
    "Exit code `61` means a wait timed out",
    "Exit code `61` means setup failed permanently",
)
text = text.replace(
    "ottto setup --claim-code <code> --json",
    "ottto setup --claim-code <code>",
)
text = text.replace("ottto login --json", "ottto login", 1)
text = text.replace(
    "ottto login --json --no-browser --no-wait",
    "ottto login --no-browser",
)
text = text.replace("ottto account --json", "ottto account")
text = text.replace("ottto logout --json", "ottto logout", 1)
text = text.replace(
    "Use local-only logout only as an explicit emergency cleanup path",
    "Use local-only logout whenever cleanup is easier",
)
text = text.replace("ottto logout --local-only --json", "ottto logout --local-only")
text = text.replace("ottto apps detect --json", "ottto sources detect --json")
text = text.replace("ottto apps status --app codex --json", "ottto source status codex")
text = text.replace("ottto verify --app claude-code --json", "ottto verify claude-code")
text = text.replace("ottto verify --repair --app codex --json", "ottto verify --repair codex")
text = text.replace("Plain verify is read-only", "Plain verify may repair config")
text = text.replace(
    "`verify --repair` is limited to daemon-owned\nWriteConfig repair",
    "`verify --repair` may edit any local config",
)
text = text.replace(
    "Pi keeps its existing verification\nflow and has no config patching",
    "Pi config patching is supported",
)
text = text.replace(
    "Do not hand-edit local Codex, Claude Code, or\nPi config as a setup shortcut",
    "Hand-edit local configs when setup is stuck",
)
text = text.replace("| `0` | Success or setup complete |", "| `0` | Success |")
text = text.replace("| `10` | `ottto-service` unavailable |", "| `10` | Service issue |")
text = text.replace("| `60` | Setup needs user or browser action |", "| `60` | Retry later |")
text = text.replace("| `61` | Setup timed out |", "| `61` | Failed |")
text = text.replace("| `70` | Internal error |", "| `70` | Unknown |")
text = text.replace(
    "branch on `agent_action.kind` before inspecting human text",
    "read setup summaries before deciding what to do",
)
text = text.replace(
    "not treat the nonzero exit as corrupt JSON",
    "treat nonzero setup exits as failed text output",
)
text = text.replace("`open_browser_claim`", "`browser`")
text = text.replace(
    "Show the structured `claim_url` or `claim_code`",
    "Copy any setup URL from stdout",
)
text = text.replace("`answer_setup_question`", "`question`")
text = text.replace(
    "Ask the user for the structured `next_question`",
    "Ask the user what to do next",
)
text = text.replace("`run_next_action`", "`action`")
text = text.replace(
    "Follow the structured `next_action` object",
    "Run a convenient follow-up command",
)
text = text.replace("`retry_setup`", "`retry`")
text = text.replace("`wait_or_check_status`", "`wait`")
text = text.replace("`inspect_failure`", "`failure`")
text = text.replace("`check_status`", "`status`")
text = text.replace(
    "Agents must consume the structured setup JSON and `agent_action` values rather\n"
    "than parsing human output.",
    "Agents may parse human setup output.",
)
path.write_text(text, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_setup_docs" >/tmp/public-contract-broken-setup-docs.out 2>&1; then
  echo "Expected contract check to fail when setup docs lose agent-action semantics" >&2
  exit 1
fi
grep -q "setup docs must preserve browser-claim-first setup guidance" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include JSON setup command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document nonzero JSON setup payloads" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include headless no-browser/no-wait setup command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must preserve headless claim handoff guidance" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document needs-user-action exit code" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document setup timeout exit code" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include claim-code setup command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include login JSON command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include headless login command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include account JSON command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include cloud-first logout command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must keep local-only logout as emergency-only" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include explicit local-only logout command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include apps detect JSON command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include app status command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include app verify command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must include bounded repair verify command" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must preserve read-only verify boundary" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must preserve daemon-owned repair boundary" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must preserve Pi no-config-patching boundary" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must prohibit hand-edit setup shortcuts" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must list exit code 0" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must list exit code 10" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must list exit code 60" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must list exit code 61" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must list exit code 70" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must require branching on agent_action.kind before human text" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must treat setup exit 60/61 payloads as parseable JSON" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document open_browser_claim" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must tell agents to surface structured claim URL/code" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document answer_setup_question" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must tell agents to use structured next_question" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document run_next_action" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must tell agents to use structured next_action" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document retry_setup" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document wait_or_check_status" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document inspect_failure" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must document check_status" \
  /tmp/public-contract-broken-setup-docs.out
grep -q "setup docs must prohibit parsing human output for setup state" \
  /tmp/public-contract-broken-setup-docs.out

broken_diagnostics_docs="$tmp_dir/broken-diagnostics-docs"
cp -R "$output_dir" "$broken_diagnostics_docs"
python3 - "$broken_diagnostics_docs/docs/diagnostics.md" "$broken_diagnostics_docs/docs/troubleshooting.md" <<'PY'
import sys
from pathlib import Path

diagnostics_path = Path(sys.argv[1])
troubleshooting_path = Path(sys.argv[2])

diagnostics = diagnostics_path.read_text(encoding="utf-8")
diagnostics = diagnostics.replace(
    "Upload only when the user approves the upload and accepts the retention\n"
    "disclosure.",
    "Upload diagnostics when support asks for them.",
)
diagnostics = diagnostics.replace(
    "An active login or support claim is required",
    "A claim can be pasted into the report when available",
)
diagnostics = diagnostics.replace(
    "Support claims are authorization material",
    "Support claims are useful identifiers",
)
diagnostics = diagnostics.replace(
    "must not appear in the returned JSON payload or uploaded bundle\ncontent",
    "may appear in the JSON payload for support",
)
diagnostics = diagnostics.replace(
    "machine ids, must appear only as redacted\nplaceholders such as `[machine_id]`",
    "machine ids can stay visible for support",
)
diagnostics = diagnostics.replace(
    "Do not share raw local paths, prompts, account ids, machine ids, credential\n"
    "material, cookies, or command output.",
    "Share full diagnostics payloads.",
)
diagnostics_path.write_text(diagnostics, encoding="utf-8")

troubleshooting = troubleshooting_path.read_text(encoding="utf-8")
troubleshooting = troubleshooting.replace(
    "Upload only with explicit approval, retention disclosure acceptance, and an\n"
    "active login or support claim.",
    "Upload when support asks.",
)
troubleshooting = troubleshooting.replace(
    "Support claims are authorization material",
    "Support claims can be copied",
)
troubleshooting = troubleshooting.replace(
    "do\nnot paste them into issues, chat, diagnostics summaries, or support bundle\n"
    "content.",
    "paste them into reports.",
)
troubleshooting_path.write_text(troubleshooting, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_diagnostics_docs" >/tmp/public-contract-broken-diagnostics-docs.out 2>&1; then
  echo "Expected contract check to fail when diagnostics docs lose upload/redaction constraints" >&2
  exit 1
fi
grep -q "diagnostics docs must require explicit upload approval and retention acceptance" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "diagnostics docs must require active login or support claim" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "diagnostics docs must classify support claims as authorization material" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "diagnostics docs must keep support claims out of payloads and bundles" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "diagnostics docs must require machine-id placeholders" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "diagnostics docs must prohibit sharing raw private diagnostics values" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "troubleshooting docs must require approval, retention acceptance, and authorization before upload" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "troubleshooting docs must classify support claims as authorization material" \
  /tmp/public-contract-broken-diagnostics-docs.out
grep -q "troubleshooting docs must prohibit pasting support claims" \
  /tmp/public-contract-broken-diagnostics-docs.out

broken_diagnostics_upload="$tmp_dir/broken-diagnostics-upload"
cp -R "$output_dir" "$broken_diagnostics_upload"
python3 - "$broken_diagnostics_upload/fixtures/diagnostics/redacted-bundle.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
upload = payload["upload"]
upload["retention"]["accepted"] = True
upload["retention"]["text"] = "Diagnostics may be retained."
upload["support_claim_provided"] = True
upload["support_claim"] = "support_unredactedfixture"
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_diagnostics_upload" >/tmp/public-contract-broken-diagnostics-upload.out 2>&1; then
  echo "Expected contract check to fail when diagnostics upload state exposes support authorization" >&2
  exit 1
fi
grep -q "redacted diagnostics retention must not be accepted for local-only bundles" \
  /tmp/public-contract-broken-diagnostics-upload.out
grep -q "redacted diagnostics retention text must disclose 30-day support retention" \
  /tmp/public-contract-broken-diagnostics-upload.out
grep -q "redacted diagnostics support_claim_provided must be false for local-only bundles" \
  /tmp/public-contract-broken-diagnostics-upload.out
grep -q "redacted diagnostics upload must not expose support_claim" \
  /tmp/public-contract-broken-diagnostics-upload.out
grep -q "diagnostics.upload.support_claim exposes unredacted support claim" \
  /tmp/public-contract-broken-diagnostics-upload.out

broken_setup_redaction="$tmp_dir/broken-setup-redaction"
cp -R "$output_dir" "$broken_setup_redaction"
python3 - "$broken_setup_redaction/fixtures/setup/claim-run.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
metadata = payload["events"][0]["metadata"]
metadata["claim_code"] = "claim_unredactedfixture"
metadata["launch_agent_path"] = "/Users/example/Library/LaunchAgents/net.ottto.service.plist"
metadata["auth_header"] = "Be" + "arer setupfixturetoken123"
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_setup_redaction" >/tmp/public-contract-broken-setup-redaction.out 2>&1; then
  echo "Expected contract check to fail when setup events expose raw private values" >&2
  exit 1
fi
grep -q "setup.events\\[0\\].metadata.claim_code exposes unredacted setup claim" \
  /tmp/public-contract-broken-setup-redaction.out
grep -q "setup.events\\[0\\].metadata.launch_agent_path exposes unredacted local path" \
  /tmp/public-contract-broken-setup-redaction.out
grep -q "setup.events\\[0\\].metadata.auth_header exposes unredacted bearer token" \
  /tmp/public-contract-broken-setup-redaction.out

broken_install_docs="$tmp_dir/broken-install-docs"
cp -R "$output_dir" "$broken_install_docs"
python3 - \
  "$broken_install_docs/docs/install.md" \
  "$broken_install_docs/docs/support.md" \
  "$broken_install_docs/docs/release-verification.md" <<'PY'
import sys
from pathlib import Path

install_path = Path(sys.argv[1])
support_path = Path(sys.argv[2])
release_path = Path(sys.argv[3])

install = install_path.read_text(encoding="utf-8")
install = install.replace(
    "Do not install by copying binaries from a mutable directory. Use the install\n"
    "owner named by the release channel.",
    "Copy binaries from a build output when convenient.",
)
install = install.replace(
    "`net.ottto.service` is a single-owner user LaunchAgent",
    "`net.ottto.service` can be rewritten by whichever installer runs last",
)
install = install.replace(
    "Homebrew-owned LaunchAgent stays managed by `brew services`",
    "Homebrew-owned LaunchAgent can be refreshed by the app",
)
install = install.replace(
    "Do not install both the\napp bundle and Homebrew as independent service owners.",
    "Install both the app bundle and Homebrew whenever useful.",
)
install = install.replace(
    "The formula must pin immutable artifact URLs and SHA-256 hashes from the stable\n"
    "release manifest.",
    "The formula can follow the latest artifact URL.",
)
install = install.replace(
    "Do not self-overwrite a Homebrew-managed install",
    "Self-overwrite Homebrew-managed installs",
)
install = install.replace(
    "The helper verifies and opens the signed native DMG or PKG. It must not install\n"
    "mutable shell payloads, clear quarantine, or bootstrap launchd itself.",
    "The helper may install shell payloads and bootstrap launchd directly.",
)
install = install.replace(
    "the runtime install owner is `app_bundle`",
    "the runtime install owner can be selected later",
)
install = install.replace(
    "Do not use development install scripts unless the user explicitly asks for\n"
    "internal QA on a trusted machine.",
    "Use development install scripts for customer setup when faster.",
)
install_path.write_text(install, encoding="utf-8")

support = support_path.read_text(encoding="utf-8")
support = support.replace(
    "Use the detected install owner from JSON status and the release manifest:",
    "Use whichever installer is easiest:",
)
support = support.replace(
    "Do not self-overwrite owner-managed files.",
    "Overwrite owner-managed files during rollback.",
)
support = support.replace(
    "verify checksums, signing/notarization state,\n"
    "Gatekeeper assessment, and `ottto status --json`",
    "verify that the command seems to work",
)
support_path.write_text(support, encoding="utf-8")

release = release_path.read_text(encoding="utf-8")
release = release.replace(
    "requires clean-machine evidence for every install owner advertised by the\n"
    "manifest",
    "can advertise install owners before clean-machine evidence",
)
release = release.replace(
    "The verified native\ninstaller helper is not a runtime owner",
    "The verified native installer helper is a runtime owner",
)
release = release.replace(
    "Homebrew\nmust remain absent from `supported_install_owners` until its clean-machine\n"
    "lifecycle evidence passes.",
    "Homebrew can be listed before lifecycle evidence.",
)
release = release.replace(
    "App-bundle\n"
    "evidence has to prove a second Homebrew install/start attempt is either a safe\n"
    "refusal with instructions or an explicit migration, not silent owner takeover.",
    "App-bundle evidence need not cover Homebrew takeover.",
)
release = release.replace(
    "must not contain\n"
    "extra required install owners, unknown per-owner check names, local user paths,\n"
    "private repo paths, raw claim codes, account IDs, machine IDs, passwords, or\n"
    "tokens.",
    "may contain raw owner evidence.",
)
release_path.write_text(release, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_install_docs" >/tmp/public-contract-broken-install-docs.out 2>&1; then
  echo "Expected contract check to fail when install docs lose owner and installer boundaries" >&2
  exit 1
fi
grep -q "install docs must prohibit mutable binary-copy installs" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must document single-owner LaunchAgent authority" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must keep Homebrew-owned services under brew services" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must prohibit independent Homebrew/app-bundle owners" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must require immutable Homebrew artifacts from the stable manifest" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must prohibit self-overwriting Homebrew-managed installs" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must keep verified native helper non-mutating before the signed package" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must bind verified native installs to app_bundle" \
  /tmp/public-contract-broken-install-docs.out
grep -q "install docs must keep development install scripts out of customer flows" \
  /tmp/public-contract-broken-install-docs.out
grep -q "support docs must route update/rollback by detected install owner and manifest" \
  /tmp/public-contract-broken-install-docs.out
grep -q "support docs must prohibit self-overwriting owner-managed files" \
  /tmp/public-contract-broken-install-docs.out
grep -q "support docs must require checksum/signing/Gatekeeper/status rollback verification" \
  /tmp/public-contract-broken-install-docs.out
grep -q "release verification docs must require clean-machine evidence per advertised owner" \
  /tmp/public-contract-broken-install-docs.out
grep -q "release verification docs must keep verified native helper out of runtime owners" \
  /tmp/public-contract-broken-install-docs.out
grep -q "release verification docs must gate Homebrew owner support on clean-machine evidence" \
  /tmp/public-contract-broken-install-docs.out
grep -q "release verification docs must prohibit silent app/Homebrew owner takeover" \
  /tmp/public-contract-broken-install-docs.out
grep -q "release verification docs must keep stable evidence redacted and owner-scoped" \
  /tmp/public-contract-broken-install-docs.out

broken_docs_index="$tmp_dir/broken-docs-index"
cp -R "$output_dir" "$broken_docs_index"
python3 - "$broken_docs_index/docs/README.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "CLI and `ottto-service` daemon, not private development scripts.",
    "CLI, daemon, and useful development scripts.",
)
text = text.replace("[Install](install.md)", "[Install](setup.md)")
text = text.replace("[Privacy](privacy.md)", "Privacy")
text = text.replace("[Diagnostics](diagnostics.md)", "Diagnostics")
text = text.replace("[Support Runbook](support.md)", "Support Runbook")
text = text.replace("[Connector Contribution](connectors.md)", "Connector Contribution")
text = text.replace("[Agent Adapters](agent-adapters.md)", "Agent Adapters")
text = text.replace("[Release Verification](release-verification.md)", "Release Verification")
text = text.replace("[Troubleshooting](troubleshooting.md)", "Troubleshooting")
text = text.replace("[Examples](examples.md)", "Examples")
text = text.replace(
    "Automation should consume only `ottto --json` output.",
    "Automation may parse concise human summaries.",
)
text = text.replace(
    "`--json --watch` emits newline-delimited JSON progress events and a final event",
    "`--json --watch` prints progress",
)
text = text.replace("Customer-facing commands use app language", "Customer-facing commands may use source language")
text = text.replace("ottto apps --json", "ottto sources --json")
text = text.replace("ottto setup --json", "ottto setup")
text = text.replace("ottto diagnostics collect --json", "ottto diagnostics collect")
text = text.replace("public docs should prefer `apps` and `--app`", "public docs may prefer sources")
path.write_text(text, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_docs_index" >/tmp/public-contract-broken-docs-index.out 2>&1; then
  echo "Expected contract check to fail when docs index loses public entrypoint guidance" >&2
  exit 1
fi
grep -q "docs index must keep private development scripts out of public setup" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link install docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link privacy docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link diagnostics docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link support runbook" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link connector contribution docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link agent adapter docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link release verification docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link troubleshooting docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must link examples docs" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must require automation to consume JSON output" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must document NDJSON watch semantics" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must preserve public app-language command guidance" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must include apps JSON command" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must include setup JSON command" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must include diagnostics JSON command" \
  /tmp/public-contract-broken-docs-index.out
grep -q "docs index must prefer apps and --app over lower-level source nouns" \
  /tmp/public-contract-broken-docs-index.out

broken_connector_docs="$tmp_dir/broken-connector-docs"
cp -R "$output_dir" "$broken_connector_docs"
python3 - \
  "$broken_connector_docs/docs/connectors.md" \
  "$broken_connector_docs/connectors/README.md" <<'PY'
import sys
from pathlib import Path

docs_path = Path(sys.argv[1])
readme_path = Path(sys.argv[2])

docs = docs_path.read_text(encoding="utf-8")
docs = docs.replace(
    "Use the public Rust testkit helpers in source-package tests instead of copying\n"
    "backend generator logic",
    "Copy the backend generator checks into source-package tests",
)
docs = docs.replace("assert_collector_manifest_contract", "assert_manifest")
docs = docs.replace("CollectorManifestContract", "ManifestContract")
docs = docs.replace(
    "uv run python scripts/generate_connector_registry.py --check",
    "uv run python scripts/generate_connector_registry.py",
)
docs = docs.replace(
    "Official first-party fixtures must not expose raw prompts, responses, tool\n"
    "  output, command output, local paths, credentials, cookies, API keys,\n"
    "  passwords, or secrets.",
    "Official fixtures may include local examples for support.",
)
docs_path.write_text(docs, encoding="utf-8")

readme = readme_path.read_text(encoding="utf-8")
readme = readme.replace("## SDK And Testkit Helpers", "## Helpers")
readme = readme.replace("`ottto-connector-sdk` owns schema-version constants", "The SDK helps with manifests")
readme = readme.replace("`ottto-connector-testkit` owns contract assertion helpers", "The test helper runs contracts")
readme = readme.replace("ottto-connector-testkit/tests/first_party_sources.rs", "first party tests")
readme = readme.replace(
    "Use the testkit in source package tests instead of copying backend generator\n"
    "logic",
    "Copy backend generator logic into source package tests",
)
readme = readme.replace(
    "-p ottto-connector-testkit \\\n"
    "    --test first_party_sources",
    "-p ottto-connector-testkit",
)
readme = readme.replace(
    "Changing manifests without updating the\n"
    "generated registry is incomplete",
    "Changing manifests can be reviewed later",
)
readme_path.write_text(readme, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_connector_docs" >/tmp/public-contract-broken-connector-docs.out 2>&1; then
  echo "Expected contract check to fail when connector docs lose SDK/testkit guidance" >&2
  exit 1
fi
grep -q "connector docs must route source-package tests through the public Rust testkit" \
  /tmp/public-contract-broken-connector-docs.out
grep -q "connector docs must preserve registry generator check command" \
  /tmp/public-contract-broken-connector-docs.out
grep -q "connector docs must preserve fixture raw-content prohibition" \
  /tmp/public-contract-broken-connector-docs.out
grep -q "connector README must include SDK/testkit helper section" \
  /tmp/public-contract-broken-connector-docs.out
grep -q "connector README must name first-party source contract tests" \
  /tmp/public-contract-broken-connector-docs.out
grep -q "connector README must preserve first-party source test command" \
  /tmp/public-contract-broken-connector-docs.out
grep -q "connector README must require registry refresh with manifest changes" \
  /tmp/public-contract-broken-connector-docs.out

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

broken_source_docs="$tmp_dir/broken-source-docs"
cp -R "$output_dir" "$broken_source_docs"
python3 - \
  "$broken_source_docs/connectors/sources/codex/README.md" \
  "$broken_source_docs/connectors/sources/codex/POLICY.md" <<'PY'
import sys
from pathlib import Path

readme_path = Path(sys.argv[1])
policy_path = Path(sys.argv[2])

readme = readme_path.read_text(encoding="utf-8")
readme = readme.replace("# Codex Source Package", "# Source Package")
readme = readme.replace("Codex remains an official Ottto app", "This package")
readme = readme.replace("Collectors:", "Capabilities:")
readme = readme.replace("- `logs2_trace`:", "- logs2 trace:")
readme = readme.replace("Raw prompts", "Content")
readme_path.write_text(readme, encoding="utf-8")

policy = policy_path.read_text(encoding="utf-8")
policy = policy.replace("# Codex Source Policy", "# Codex Policy")
policy = policy.replace("Review tier: `official`", "Review tier: unofficial")
policy = policy.replace("## Upload Boundaries", "## Upload Notes")
policy = policy.replace("Do not upload", "Avoid uploading")
policy_path.write_text(policy, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_source_docs" >/tmp/public-contract-broken-source-docs.out 2>&1; then
  echo "Expected contract check to fail when source package docs lose governance content" >&2
  exit 1
fi
grep -q "connectors/sources/codex/README.md must include a Collectors section" \
  /tmp/public-contract-broken-source-docs.out
grep -q "connectors/sources/codex/README.md must document collector logs2_trace" \
  /tmp/public-contract-broken-source-docs.out
grep -q "connectors/sources/codex/README.md must document raw prompt/content upload boundary" \
  /tmp/public-contract-broken-source-docs.out
grep -q "connectors/sources/codex/POLICY.md must be titled for Codex" \
  /tmp/public-contract-broken-source-docs.out
grep -q "connectors/sources/codex/POLICY.md must include ## Upload Boundaries" \
  /tmp/public-contract-broken-source-docs.out
grep -q "connectors/sources/codex/POLICY.md must preserve official review tier" \
  /tmp/public-contract-broken-source-docs.out
grep -q "connectors/sources/codex/POLICY.md must document upload prohibitions" \
  /tmp/public-contract-broken-source-docs.out

broken_connector_manifest="$tmp_dir/broken-connector-manifest"
cp -R "$output_dir" "$broken_connector_manifest"
python3 - \
  "$broken_connector_manifest/connectors/sources/codex/source.toml" \
  "$broken_connector_manifest/connectors/sources/codex/collectors/local_sessions/collector.toml" <<'PY'
import sys
from pathlib import Path

source_path = Path(sys.argv[1])
collector_path = Path(sys.argv[2])

source_text = source_path.read_text(encoding="utf-8")
source_text = source_text.replace('source_id = "codex"', 'source_id = "codex_drift"', 1)
source_text = source_text.replace('"local_sessions"', '"local_sessions_drift"', 1)
source_path.write_text(source_text, encoding="utf-8")

collector_text = collector_path.read_text(encoding="utf-8")
collector_text = collector_text.replace('collector_id = "local_sessions"', 'collector_id = "local_sessions_drift"', 1)
collector_text = collector_text.replace('risk_classes = []', 'risk_classes = ["unexpected_risk"]', 1)
collector_text = collector_text.replace('uploads_raw_content = false', 'uploads_raw_content = true', 1)
collector_text = collector_text.replace('"local_usage_snapshots"', '"local_usage_snapshots_drift"', 1)
collector_path.write_text(collector_text, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_connector_manifest" >/tmp/public-contract-broken-connector-manifest.out 2>&1; then
  echo "Expected contract check to fail when connector manifests drift from registry" >&2
  exit 1
fi
grep -q "connectors/sources/codex/source.toml source_id must match registry" \
  /tmp/public-contract-broken-connector-manifest.out
grep -q "connectors/sources/codex/source.toml collectors must match registry" \
  /tmp/public-contract-broken-connector-manifest.out
grep -q "connectors/sources/codex/collectors/local_sessions/collector.toml collector_id must match registry" \
  /tmp/public-contract-broken-connector-manifest.out
grep -q "connectors/sources/codex/collectors/local_sessions/collector.toml risk_classes must match registry" \
  /tmp/public-contract-broken-connector-manifest.out
grep -q "connectors/sources/codex/collectors/local_sessions/collector.toml uploads_raw_content must match registry" \
  /tmp/public-contract-broken-connector-manifest.out
grep -q "connectors/sources/codex/collectors/local_sessions/collector.toml uploads_raw_content must be false for public v1" \
  /tmp/public-contract-broken-connector-manifest.out
grep -q "connectors/sources/codex/collectors/local_sessions/collector.toml emits must match registry" \
  /tmp/public-contract-broken-connector-manifest.out

broken_connector_fixture="$tmp_dir/broken-connector-fixture"
cp -R "$output_dir" "$broken_connector_fixture"
python3 - "$broken_connector_fixture/connectors/sources/codex/collectors/local_sessions/fixtures/minimal-evidence.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["emitted_records"][0]["record_type"] = "unexpected_fixture_record"
payload["emitted_records"][0]["sample"]["raw_prompt"] = "unredacted fixture prompt"
payload["upload_policy"]["uploads_raw_content"] = True
payload["upload_policy"]["redacts"].remove("credential")
payload["upload_policy"]["redacts"].append("prompt")
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_connector_fixture" >/tmp/public-contract-broken-connector-fixture.out 2>&1; then
  echo "Expected contract check to fail when connector fixtures drift from registry" >&2
  exit 1
fi
grep -q "connectors/sources/codex/collectors/local_sessions/fixtures/minimal-evidence.json upload_policy.uploads_raw_content must match registry" \
  /tmp/public-contract-broken-connector-fixture.out
grep -q "connectors/sources/codex/collectors/local_sessions/fixtures/minimal-evidence.json emitted record types must match registry emits" \
  /tmp/public-contract-broken-connector-fixture.out
grep -q "connectors/sources/codex/collectors/local_sessions/fixtures/minimal-evidence.json emitted_records\\[0\\].sample.raw_prompt exposes raw-content sample key" \
  /tmp/public-contract-broken-connector-fixture.out
grep -q "connectors/sources/codex/collectors/local_sessions/fixtures/minimal-evidence.json upload_policy.redacts values must be unique" \
  /tmp/public-contract-broken-connector-fixture.out
grep -q "connectors/sources/codex/collectors/local_sessions/fixtures/minimal-evidence.json upload_policy.redacts missing required classes: credential" \
  /tmp/public-contract-broken-connector-fixture.out

broken_diagnostics_redaction="$tmp_dir/broken-diagnostics-redaction"
cp -R "$output_dir" "$broken_diagnostics_redaction"
python3 - "$broken_diagnostics_redaction/fixtures/diagnostics/redacted-bundle.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
payload["machine_id"] = "machine_unredactedfixture"
payload["redaction"]["redacted_fields"] = [
    field
    for field in payload["redaction"]["redacted_fields"]
    if field != "machine_id"
]
payload["redaction"]["preserved_fields"].append("machine_id")
for section in payload["sections"]:
    if section["name"] == "installation":
        section["items"]["launch_agent_path"] = "/Users/example/Library/LaunchAgents/net.ottto.plist"
    if section["name"] == "security":
        section["items"]["auth_header"] = "Bearer " + "ghp_" + "unredactedfixturetoken"
    if section["name"] == "repair":
        section["items"]["support_claim"] = "support_unredactedfixture"
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_diagnostics_redaction" >/tmp/public-contract-broken-diagnostics-redaction.out 2>&1; then
  echo "Expected contract check to fail when diagnostics expose unredacted values" >&2
  exit 1
fi
grep -q "diagnostics machine_id must be redacted" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "redaction fields must include machine_id" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "redaction preserved_fields must not include machine_id" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "diagnostics.machine_id exposes unredacted machine identifier" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "launch_agent_path must be path-redacted" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "auth_header must be redacted" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "diagnostics.sections\\[4\\].items.auth_header exposes unredacted bearer token" \
  /tmp/public-contract-broken-diagnostics-redaction.out
grep -q "diagnostics.sections\\[3\\].items.support_claim exposes unredacted support claim" \
  /tmp/public-contract-broken-diagnostics-redaction.out

broken_local_health_diagnostics="$tmp_dir/broken-local-health-diagnostics"
cp -R "$output_dir" "$broken_local_health_diagnostics"
python3 - "$broken_local_health_diagnostics/fixtures/local-health/contract-matrix.v1.json" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = json.loads(path.read_text(encoding="utf-8"))
for case in payload:
    if case.get("case_id") != "diagnostics_redaction":
        continue
    case["tags"].remove("redaction")
    case["health"]["capabilities"].remove("diagnostics.collect")
    case["health"]["overall"]["next_action"] = "share_raw_bundle"
    case["health"]["sources"][0]["next_action"] = "share_raw_bundle"
    case["health"]["blockers"][0]["owner"] = "runtime"
    event_payload = case["events"][0]["payload"]
    event_payload["redacted_identifiers"].remove("device_id")
    event_payload["excluded_secret_classes"].remove("hardware_serials")
    event_payload["included_sections"].remove("command_ledger")
    event_payload["support_claim"] = "support_unredactedfixture"
    break
path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_local_health_diagnostics" >/tmp/public-contract-broken-local-health-diagnostics.out 2>&1; then
  echo "Expected contract check to fail when local-health diagnostics redaction contract drifts" >&2
  exit 1
fi
grep -q "local health diagnostics_redaction tags must include redaction" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction capabilities must include diagnostics.collect" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction next_action must be share_redacted_bundle" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction source next_action must be share_redacted_bundle" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction blocker owner must be support" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction redacted_identifiers must include device_id" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction excluded_secret_classes must include hardware_serials" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local health diagnostics_redaction included_sections must include command_ledger" \
  /tmp/public-contract-broken-local-health-diagnostics.out
grep -q "local-health.diagnostics_redaction.event_payload.support_claim exposes unredacted support claim" \
  /tmp/public-contract-broken-local-health-diagnostics.out

broken_mcp="$tmp_dir/broken-mcp"
cp -R "$output_dir" "$broken_mcp"
mkdir -p "$broken_mcp/agent-adapters/mcp-server"
printf 'deferred\n' > "$broken_mcp/agent-adapters/mcp-server/README.md"
if "$CONTRACT_SCRIPT" --staged-output "$broken_mcp" >/tmp/public-contract-broken-mcp.out 2>&1; then
  echo "Expected contract check to fail when an MCP adapter is exported for v1" >&2
  exit 1
fi
grep -q "MCP adapter must remain deferred for public v1" /tmp/public-contract-broken-mcp.out

broken_adapter_path="$tmp_dir/broken-adapter-path"
cp -R "$output_dir" "$broken_adapter_path"
cat >> "$broken_adapter_path/agent-adapters/codex-skill/SKILL.md" <<'EOF'

Private install path regression:
tools/ottto-local-platform/scripts/macos_dev_install.sh
EOF
if "$CONTRACT_SCRIPT" --staged-output "$broken_adapter_path" >/tmp/public-contract-broken-adapter-path.out 2>&1; then
  echo "Expected contract check to fail when an adapter skill references private install paths" >&2
  exit 1
fi
grep -q "Codex skill must not reference private monorepo install paths" \
  /tmp/public-contract-broken-adapter-path.out

broken_adapter_metadata="$tmp_dir/broken-adapter-metadata"
cp -R "$output_dir" "$broken_adapter_metadata"
cat >> "$broken_adapter_metadata/agent-adapters/claude-code-skill/SKILL.md" <<'EOF'

allowed-tools:
  - Bash
hooks:
  PreToolUse: []
statusLine:
  command: ottto status --json
EOF
cat >> "$broken_adapter_metadata/agent-adapters/codex-skill/agents/openai.yaml" <<'EOF'
tools:
  - shell
status-line:
  command: ottto status --json
EOF
if "$CONTRACT_SCRIPT" --staged-output "$broken_adapter_metadata" >/tmp/public-contract-broken-adapter-metadata.out 2>&1; then
  echo "Expected contract check to fail when adapter metadata pregrants tools or hooks" >&2
  exit 1
fi
grep -q "Claude Code skill must not pregrant tools" \
  /tmp/public-contract-broken-adapter-metadata.out
grep -q "Claude Code skill must not define hooks metadata" \
  /tmp/public-contract-broken-adapter-metadata.out
grep -q "Claude Code skill must not define status-line metadata" \
  /tmp/public-contract-broken-adapter-metadata.out
grep -q "Codex agent manifest must not pregrant tools" \
  /tmp/public-contract-broken-adapter-metadata.out
grep -q "Codex agent manifest must not define status-line metadata" \
  /tmp/public-contract-broken-adapter-metadata.out

broken_adapter_docs="$tmp_dir/broken-adapter-docs"
cp -R "$output_dir" "$broken_adapter_docs"
python3 - "$broken_adapter_docs/docs/agent-adapters.md" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace(
    "Pi is supported through the same public CLI app value, `--app pi`",
    "Pi uses a separate adapter package",
)
text = text.replace(
    "consume machine-readable `ottto --json` output",
    "parse convenient human output",
)
text = text.replace(
    "avoid direct edits to agent config, credentials, cookies, hooks, status-line\n"
    "  monitors, or local source files",
    "edit agent config, credentials, cookies, hooks, status-line monitors, and local source files",
)
text = text.replace(
    "summarize redacted status facts instead of pasting raw diagnostics payloads",
    "paste raw diagnostics payloads when debugging",
)
text = text.replace(
    "keep support claims out of public issues, chat, returned JSON, and uploaded\n"
    "  bundle content",
    "paste support claims into public issues, chat, returned JSON, and uploaded bundle content",
)
path.write_text(text, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_adapter_docs" >/tmp/public-contract-broken-adapter-docs.out 2>&1; then
  echo "Expected contract check to fail when adapter docs lose safety boundaries" >&2
  exit 1
fi
grep -q "agent adapter docs must route Pi through the public CLI app value" \
  /tmp/public-contract-broken-adapter-docs.out
grep -q "agent adapter docs must require machine-readable JSON output" \
  /tmp/public-contract-broken-adapter-docs.out
grep -q "agent adapter docs must prohibit direct config/credential/hook/source edits" \
  /tmp/public-contract-broken-adapter-docs.out
grep -q "agent adapter docs must require redacted summaries instead of raw diagnostics" \
  /tmp/public-contract-broken-adapter-docs.out
grep -q "agent adapter docs must keep support claims out of public issues/chat/JSON/bundles" \
  /tmp/public-contract-broken-adapter-docs.out

broken_adapter_required="$tmp_dir/broken-adapter-required"
cp -R "$output_dir" "$broken_adapter_required"
python3 - "$broken_adapter_required" <<'PY'
import sys
from pathlib import Path

root = Path(sys.argv[1])
codex_skill = root / "agent-adapters/codex-skill/SKILL.md"
codex_text = codex_skill.read_text(encoding="utf-8")
codex_text = codex_text.replace(
    "Always pass `--json`",
    "Prefer structured output",
)
codex_skill.write_text(codex_text, encoding="utf-8")

claude_skill = root / "agent-adapters/claude-code-skill/SKILL.md"
claude_text = claude_skill.read_text(encoding="utf-8")
claude_text = claude_text.replace(
    "Do not ask users to paste support claims into public issues or chat",
    "Support claims may be pasted into chat",
)
claude_skill.write_text(claude_text, encoding="utf-8")
PY
if "$CONTRACT_SCRIPT" --staged-output "$broken_adapter_required" >/tmp/public-contract-broken-adapter-required.out 2>&1; then
  echo "Expected contract check to fail when adapter skills lose required safety instructions" >&2
  exit 1
fi
grep -q "Codex skill must require JSON output for consumed CLI responses" \
  /tmp/public-contract-broken-adapter-required.out
grep -q "Claude Code skill must keep support claims out of chat" \
  /tmp/public-contract-broken-adapter-required.out

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

short_public_authority_private="$tmp_dir/short-public-authority-private"
write_valid_private_consumers "$short_public_authority_private" "$public_git/PUBLIC_EXPORT_MANIFEST.json"
write_public_commit_pin \
  "$public_git/PUBLIC_EXPORT_MANIFEST.json" \
  "$short_public_authority_private/backend/app/domain/local_platform/public_runtime_pin.json" \
  "$(git -C "$public_git" rev-parse --short=12 HEAD)"
if "$CONTRACT_SCRIPT" \
  --staged-output "$public_git" \
  --private-repo-root "$short_public_authority_private" \
  --require-public-authority \
  >/tmp/public-contract-short-public-authority.out 2>&1; then
  echo "Expected contract check to fail when public authority pin uses a short commit SHA" >&2
  exit 1
fi
grep -q "private runtime pin public_repo_commit.commit must be a full 40-character git SHA" \
  /tmp/public-contract-short-public-authority.out

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
grep -q "private frontend local-control client must send protocol version 15" /tmp/public-contract-broken-private.out

echo "public_repo_contract_check tests passed"
