#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PUBLIC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PUBLIC_ROOT="${PUBLIC_CONTRACT_REPO_ROOT:-$DEFAULT_PUBLIC_ROOT}"
PRIVATE_REPO_ROOT="${PUBLIC_CONTRACT_PRIVATE_REPO_ROOT:-}"
PRIVATE_RUNTIME_PIN="${PUBLIC_CONTRACT_PRIVATE_RUNTIME_PIN:-}"
REQUIRE_PUBLIC_AUTHORITY="${PUBLIC_CONTRACT_REQUIRE_PUBLIC_AUTHORITY:-false}"

usage() {
  cat <<'USAGE'
Usage: public_repo_contract_check.sh [--staged-output <dir>] [--private-repo-root <dir>] [--private-runtime-pin <path>] [--require-public-authority]

Checks that a root-shaped public ottto repository checkout carries the JSON,
schema, registry, setup, and redaction contracts consumed by the private Ottto
backend/frontend. By default the script checks the repository root containing
scripts/. Use --staged-output to check a generated public export bundle. When
--private-repo-root is supplied, the private repository must also carry a
public-runtime pin whose manifest digest matches the checked public root.
Use --require-public-authority after public repo cutover: it requires the
private pin to name a public repo commit and verifies that the checked public
root is a clean git checkout at that commit.

Environment overrides:
  PUBLIC_CONTRACT_REPO_ROOT
  PUBLIC_CONTRACT_PRIVATE_REPO_ROOT
  PUBLIC_CONTRACT_PRIVATE_RUNTIME_PIN
  PUBLIC_CONTRACT_REQUIRE_PUBLIC_AUTHORITY
USAGE
}

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --staged-output)
      [[ "$#" -ge 2 ]] || {
        echo "public-contract: --staged-output requires a value" >&2
        exit 2
      }
      PUBLIC_ROOT="$2"
      shift 2
      ;;
    --private-repo-root)
      [[ "$#" -ge 2 ]] || {
        echo "public-contract: --private-repo-root requires a value" >&2
        exit 2
      }
      PRIVATE_REPO_ROOT="$2"
      shift 2
      ;;
    --private-runtime-pin)
      [[ "$#" -ge 2 ]] || {
        echo "public-contract: --private-runtime-pin requires a value" >&2
        exit 2
      }
      PRIVATE_RUNTIME_PIN="$2"
      shift 2
      ;;
    --require-public-authority)
      REQUIRE_PUBLIC_AUTHORITY="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "public-contract: unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

python3 - "$PUBLIC_ROOT" "$PRIVATE_REPO_ROOT" "$PRIVATE_RUNTIME_PIN" "$REQUIRE_PUBLIC_AUTHORITY" <<'PY'
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

PUBLIC_PROTOCOL_VERSION = 15
PUBLIC_ROOT = Path(sys.argv[1]).resolve()
PRIVATE_REPO_ROOT = Path(sys.argv[2]).resolve() if sys.argv[2] else None
PRIVATE_RUNTIME_PIN_ARG = sys.argv[3]
REQUIRE_PUBLIC_AUTHORITY = sys.argv[4].lower() in {"1", "true", "yes"}
REQUIRED_CONNECTOR_REDACTION_CLASSES = {
    "prompt",
    "response",
    "tool_output",
    "command_output",
    "local_path",
    "credential",
}

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


def die(message: str, code: int = 2) -> None:
    print(f"public-contract: {message}", file=sys.stderr)
    sys.exit(code)


def require_file(relative_path: str) -> Path | None:
    path = PUBLIC_ROOT / relative_path
    if not path.is_file():
        fail(f"required file is missing: {relative_path}")
        return None
    return path


def require_private_file(relative_path: str) -> Path | None:
    if PRIVATE_REPO_ROOT is None:
        return None
    path = PRIVATE_REPO_ROOT / relative_path
    if not path.is_file():
        fail(f"private consumer file is missing: {relative_path}")
        return None
    return path


def private_runtime_pin_path() -> tuple[Path | None, str]:
    default_relative = "backend/app/domain/local_platform/public_runtime_pin.json"
    if PRIVATE_REPO_ROOT is None:
        return None, default_relative
    if PRIVATE_RUNTIME_PIN_ARG:
        path = Path(PRIVATE_RUNTIME_PIN_ARG)
        if not path.is_absolute():
            path = PRIVATE_REPO_ROOT / path
        return path.resolve(), PRIVATE_RUNTIME_PIN_ARG
    return (PRIVATE_REPO_ROOT / default_relative).resolve(), default_relative


def load_json(relative_path: str) -> Any | None:
    path = require_file(relative_path)
    if path is None:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"{relative_path}: invalid JSON: {error}")
        return None


def load_ndjson(relative_path: str) -> list[dict[str, Any]]:
    path = require_file(relative_path)
    if path is None:
        return []
    events: list[dict[str, Any]] = []
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            event = json.loads(stripped)
        except json.JSONDecodeError as error:
            fail(f"{relative_path}:{line_number}: invalid NDJSON event: {error}")
            continue
        if not isinstance(event, dict):
            fail(f"{relative_path}:{line_number}: event must be a JSON object")
            continue
        events.append(event)
    if not events:
        fail(f"{relative_path}: no NDJSON events found")
    return events


def expect(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def expect_protocol(value: Any, context: str) -> None:
    expect(value == PUBLIC_PROTOCOL_VERSION, f"{context} protocol_version must be {PUBLIC_PROTOCOL_VERSION}")


def git_output(args: list[str]) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(PUBLIC_ROOT), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"public authority git check failed for {' '.join(args)}: {error}")
        return None
    return result.stdout.strip()


def require_dict(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail(f"{context} must be a JSON object")
        return {}
    return value


def require_list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        fail(f"{context} must be a JSON array")
        return []
    return value


def check_setup_output_shape(payload: dict[str, Any], context: str) -> list[dict[str, Any]]:
    source_count = payload.get("source_count")
    detected_sources = require_list(payload.get("detected_sources"), f"{context} detected_sources")
    actions = require_list(payload.get("actions"), f"{context} actions")
    agent_action = require_dict(payload.get("agent_action"), f"{context} agent_action")
    expect(isinstance(agent_action.get("kind"), str) and bool(agent_action.get("kind")), f"{context} agent_action.kind must be non-empty")
    expect(isinstance(agent_action.get("requires_user"), bool), f"{context} agent_action.requires_user must be boolean")
    expect(isinstance(agent_action.get("retryable"), bool), f"{context} agent_action.retryable must be boolean")
    expect(isinstance(agent_action.get("description"), str) and bool(agent_action.get("description")), f"{context} agent_action.description must be non-empty")
    expect(isinstance(source_count, int) and source_count >= 0, f"{context} source_count must be a non-negative integer")
    if isinstance(source_count, int):
        expect(source_count == len(detected_sources), f"{context} source_count must match detected_sources length")
    expect(not (payload.get("next_question") is not None and payload.get("next_action") is not None), f"{context} must not set both next_question and next_action")
    for index, source_value in enumerate(detected_sources):
        source = require_dict(source_value, f"{context} detected_sources[{index}]")
        expect(isinstance(source.get("source"), str) and bool(source.get("source")), f"{context} detected_sources[{index}].source must be non-empty")
        expect(isinstance(source.get("state"), str) and bool(source.get("state")), f"{context} detected_sources[{index}].state must be non-empty")
        readiness = source.get("readiness_percent")
        expect(isinstance(readiness, int) and 0 <= readiness <= 100, f"{context} detected_sources[{index}].readiness_percent must be 0-100")
        missing_fields = require_list(source.get("missing_fields"), f"{context} detected_sources[{index}].missing_fields")
        for field_index, field in enumerate(missing_fields):
            expect(isinstance(field, str) and bool(field), f"{context} detected_sources[{index}].missing_fields[{field_index}] must be non-empty")
    for index, action_value in enumerate(actions):
        action = require_dict(action_value, f"{context} actions[{index}]")
        expect(isinstance(action.get("type"), str) and bool(action.get("type")), f"{context} actions[{index}].type must be non-empty")
    return [source for source in detected_sources if isinstance(source, dict)]


def check_connector_fixture_contract(
    fixture_path: Path,
    source_id: str,
    collector_id: str,
    emits: list[str],
    uploads_raw_content: bool,
) -> None:
    relative_path = fixture_path.relative_to(PUBLIC_ROOT).as_posix()
    fixture = require_dict(load_json(relative_path), f"{relative_path} fixture")
    expect(
        fixture.get("schema_version") == "collector_fixture.v1",
        f"{relative_path} schema_version must be collector_fixture.v1",
    )
    expect(fixture.get("source_id") == source_id, f"{relative_path} source_id must match registry")
    expect(
        fixture.get("collector_id") == collector_id,
        f"{relative_path} collector_id must match registry",
    )

    input_fixture_paths = require_list(
        fixture.get("input_fixture_paths"), f"{relative_path} input_fixture_paths"
    )
    fixture_root = fixture_path.parent.resolve()
    for index, input_path_value in enumerate(input_fixture_paths):
        expect(
            isinstance(input_path_value, str) and bool(input_path_value),
            f"{relative_path} input_fixture_paths[{index}] must be non-empty",
        )
        if not isinstance(input_path_value, str) or not input_path_value:
            continue
        resolved_input_path = (fixture_root / input_path_value).resolve()
        expect(
            resolved_input_path.is_file(),
            f"{relative_path} input_fixture_paths[{index}] must point to a file",
        )
        expect(
            resolved_input_path.is_relative_to(PUBLIC_ROOT),
            f"{relative_path} input_fixture_paths[{index}] must stay inside public repo",
        )

    upload_policy = require_dict(fixture.get("upload_policy"), f"{relative_path} upload_policy")
    expect(
        upload_policy.get("uploads_raw_content") == uploads_raw_content,
        f"{relative_path} upload_policy.uploads_raw_content must match registry",
    )
    expect(
        upload_policy.get("uploads_raw_content") is False,
        f"{relative_path} upload_policy.uploads_raw_content must be false for public v1",
    )
    redacts = [
        value
        for value in require_list(
            upload_policy.get("redacts"), f"{relative_path} upload_policy.redacts"
        )
        if isinstance(value, str)
    ]
    expect(
        len(redacts) == len(set(redacts)),
        f"{relative_path} upload_policy.redacts values must be unique",
    )
    missing_redactions = sorted(REQUIRED_CONNECTOR_REDACTION_CLASSES.difference(redacts))
    expect(
        not missing_redactions,
        f"{relative_path} upload_policy.redacts missing required classes: {', '.join(missing_redactions)}",
    )

    emitted_records = require_list(
        fixture.get("emitted_records"), f"{relative_path} emitted_records"
    )
    actual_record_types = []
    for index, record_value in enumerate(emitted_records):
        record = require_dict(record_value, f"{relative_path} emitted_records[{index}]")
        record_type = record.get("record_type")
        expect(
            isinstance(record_type, str) and bool(record_type),
            f"{relative_path} emitted_records[{index}].record_type must be non-empty",
        )
        if isinstance(record_type, str):
            actual_record_types.append(record_type)
        require_dict(record.get("sample"), f"{relative_path} emitted_records[{index}].sample")
    expect(
        sorted(actual_record_types) == sorted(emits),
        f"{relative_path} emitted record types must match registry emits",
    )
    expect(
        len(actual_record_types) == len(set(actual_record_types)),
        f"{relative_path} emitted record types must be unique",
    )


def iter_json_strings(value: Any, path: str) -> list[tuple[str, str]]:
    if isinstance(value, str):
        return [(path, value)]
    if isinstance(value, dict):
        strings: list[tuple[str, str]] = []
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            strings.extend(iter_json_strings(item, child_path))
        return strings
    if isinstance(value, list):
        strings = []
        for index, item in enumerate(value):
            strings.extend(iter_json_strings(item, f"{path}[{index}]"))
        return strings
    return []


DIAGNOSTICS_ALLOWED_PLACEHOLDERS = {
    "[REDACTED]",
    "[account_id]",
    "[machine_id]",
    "[path]",
    "[prompt]",
}

DIAGNOSTICS_FORBIDDEN_VALUE_PATTERNS = (
    (re.compile(r"(?i)(^|[\s:=])Bearer\s+[A-Za-z0-9._~+/=-]{8,}"), "bearer token"),
    (re.compile(r"(?i)(^|[\s:=])x-api-key\s*[:=]\s*[A-Za-z0-9._-]{8,}"), "API key header"),
    (re.compile(r"\b(?:ghp|github_pat|sk|xox[baprs])[-_A-Za-z0-9]{8,}\b"), "secret token"),
    (re.compile(r"\bsupport_[A-Za-z0-9]{6,}\b"), "support claim"),
    (re.compile(r"\b(?:org|usr|acct)_[A-Za-z0-9]{6,}\b"), "account identifier"),
    (re.compile(r"\b(?:machine|otm|device)_[A-Za-z0-9]{6,}\b"), "machine identifier"),
    (re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"), "UUID identifier"),
    (re.compile(r"(?i)\b(?:serial|serial_number|hardware_serial)\s*[:=]\s*[A-Z0-9]{8,}\b"), "hardware serial"),
    (re.compile(r"(?:^|\s)(?:/Users|/private|/var|/tmp|/etc|/opt|/Applications)/[^\s]+"), "local path"),
    (re.compile(r"(?:^|\s)~/[^\s]+"), "home-relative path"),
    (re.compile(r"(?i)(?:raw_prompt|prompt_text|completion_text|command_output)\s*[:=]"), "raw prompt or command output"),
)


def check_diagnostics_values_are_redacted(value: Any, context: str) -> None:
    for path, raw in iter_json_strings(value, context):
        if raw in DIAGNOSTICS_ALLOWED_PLACEHOLDERS:
            continue
        for pattern, label in DIAGNOSTICS_FORBIDDEN_VALUE_PATTERNS:
            if pattern.search(raw):
                fail(f"{path} exposes unredacted {label}: {raw!r}")


def check_schema_contracts() -> None:
    schema_expectations = {
        "schemas/connector-registry.schema.json": ("connector registry schema", "connector_registry.v1"),
        "schemas/source-manifest.schema.json": ("source manifest schema", "source_manifest.v1"),
        "schemas/collector-manifest.schema.json": ("collector manifest schema", "collector_manifest.v1"),
        "schemas/collector-fixture.schema.json": ("collector fixture schema", None),
    }
    for path, (label, schema_version) in schema_expectations.items():
        schema = require_dict(load_json(path), label)
        expect(schema.get("type") == "object", f"{path} must define an object schema")
        if schema_version is not None:
            properties = require_dict(schema.get("properties"), f"{path} properties")
            version = require_dict(properties.get("schema_version"), f"{path} schema_version")
            expect(version.get("const") == schema_version, f"{path} must pin {schema_version}")

    release_schema = require_dict(
        load_json("release/manifest.schema.json"), "release manifest schema"
    )
    release_properties = require_dict(
        release_schema.get("properties"), "release manifest schema properties"
    )
    product = require_dict(release_properties.get("product"), "release manifest product")
    expect(product.get("const") == "ottto-local-platform", "release manifest product must be ottto-local-platform")
    expect(
        "min_protocol_version" in require_list(
            release_schema.get("required"), "release manifest required fields"
        ),
        "release manifest schema must require min_protocol_version",
    )


def check_registry_contract() -> None:
    registry = require_dict(load_json("connectors/registry.generated.json"), "connector registry")
    expect(registry.get("schema_version") == "connector_registry.v1", "registry schema_version must be connector_registry.v1")
    sources = require_list(registry.get("sources"), "registry sources")
    source_ids = [source.get("source_id") for source in sources if isinstance(source, dict)]
    expected_sources = {"claude_code", "codex", "pi"}
    missing = sorted(expected_sources.difference(source_ids))
    expect(not missing, f"registry is missing required source(s): {', '.join(missing)}")
    expect(len(source_ids) == len(set(source_ids)), "registry source_id values must be unique")

    for source_value in sources:
        source = require_dict(source_value, "registry source")
        source_id = source.get("source_id")
        context = f"registry source {source_id or '<unknown>'}"
        manifest_path = source.get("manifest_path")
        expect(isinstance(manifest_path, str) and manifest_path.startswith("connectors/sources/"), f"{context} manifest_path must point under connectors/sources")
        if isinstance(manifest_path, str):
            require_file(manifest_path)
        operations = require_list(source.get("operations"), f"{context} operations")
        for operation in ("detect", "verify", "repair", "collect_usage", "monitor_quota", "upload_snapshot", "diagnostics"):
            expect(operation in operations, f"{context} operations must include {operation}")
        collectors = require_list(source.get("collectors"), f"{context} collectors")
        collector_ids = [
            collector.get("collector_id") for collector in collectors if isinstance(collector, dict)
        ]
        expect(collector_ids, f"{context} must expose at least one collector")
        expect(
            len(collector_ids) == len(set(collector_ids)),
            f"{context} collector_id values must be unique",
        )
        for collector_value in collectors:
            collector = require_dict(collector_value, f"{context} collector")
            collector_context = f"{context} collector {collector.get('collector_id') or '<unknown>'}"
            collector_manifest_path = collector.get("manifest_path")
            expect(
                isinstance(collector_manifest_path, str)
                and collector_manifest_path.startswith("connectors/sources/")
                and collector_manifest_path.endswith("/collector.toml"),
                f"{collector_context} manifest_path must point to a collector manifest",
            )
            if isinstance(collector_manifest_path, str):
                collector_manifest = require_file(collector_manifest_path)
            expect(isinstance(collector.get("uploads_raw_content"), bool), f"{collector_context} uploads_raw_content must be boolean")
            emits = [
                emit
                for emit in require_list(collector.get("emits"), f"{collector_context} emits")
                if isinstance(emit, str)
            ]
            expect(emits, f"{collector_context} emits must not be empty")
            if not isinstance(source_id, str) or not isinstance(collector.get("collector_id"), str):
                continue
            if not isinstance(collector.get("uploads_raw_content"), bool):
                continue
            if isinstance(collector_manifest_path, str) and collector_manifest is not None:
                fixture_dir = collector_manifest.parent / "fixtures"
                expect(fixture_dir.is_dir(), f"{collector_context} fixtures directory must exist")
                fixture_paths = sorted(fixture_dir.glob("*.json")) if fixture_dir.is_dir() else []
                expect(fixture_paths, f"{collector_context} must include at least one fixture")
                for fixture_path in fixture_paths:
                    check_connector_fixture_contract(
                        fixture_path,
                        source_id,
                        collector.get("collector_id"),
                        emits,
                        collector.get("uploads_raw_content"),
                    )


def check_cli_contracts() -> None:
    status_output = require_dict(load_json("fixtures/cli/status-json-output.json"), "CLI status output")
    expect_protocol(status_output.get("protocol_version"), "CLI status output")
    expect(status_output.get("daemon") == "running", "CLI status output daemon must be running")

    error_output = require_dict(load_json("fixtures/cli/daemon-unavailable-error.json"), "CLI daemon error")
    error = require_dict(error_output.get("error"), "CLI daemon error payload")
    expect(error.get("code") == "daemon_unavailable", "daemon error code must be daemon_unavailable")
    expect(error.get("retryable") is True, "daemon error must be retryable")

    setup_claim = require_dict(load_json("fixtures/cli/setup-claim-request.json"), "CLI setup claim request")
    expect_protocol(setup_claim.get("protocol_version"), "CLI setup claim request")
    expect(setup_claim.get("client_kind") == "cli", "CLI setup claim request client_kind must be cli")
    expect(setup_claim.get("command") == "setup", "CLI setup claim request command must be setup")

    setup_headless = require_dict(
        load_json("fixtures/cli/setup-headless-request.json"),
        "CLI setup headless request",
    )
    expect_protocol(setup_headless.get("protocol_version"), "CLI setup headless request")
    expect(setup_headless.get("client_kind") == "cli", "CLI setup headless request client_kind must be cli")
    expect(setup_headless.get("command") == "setup", "CLI setup headless request command must be setup")
    expect(setup_headless.get("claim_code") is None, "CLI setup headless request claim_code must be null")

    login_headless = require_dict(
        load_json("fixtures/cli/login-headless-request.json"),
        "CLI login headless request",
    )
    expect_protocol(login_headless.get("protocol_version"), "CLI login headless request")
    expect(login_headless.get("client_kind") == "cli", "CLI login headless request client_kind must be cli")
    expect(login_headless.get("command") == "setup", "CLI login headless request must use daemon setup command")
    expect(login_headless.get("claim_code") is None, "CLI login headless request claim_code must be null")

    account = require_dict(load_json("fixtures/cli/account-request.json"), "CLI account request")
    expect_protocol(account.get("protocol_version"), "CLI account request")
    expect(account.get("client_kind") == "cli", "CLI account request client_kind must be cli")
    expect(account.get("command") == "account", "CLI account request command must be account")

    logout = require_dict(load_json("fixtures/cli/logout-request.json"), "CLI logout request")
    expect_protocol(logout.get("protocol_version"), "CLI logout request")
    expect(logout.get("client_kind") == "cli", "CLI logout request client_kind must be cli")
    expect(logout.get("command") == "auth_reset", "CLI logout request command must be auth_reset")
    expect(logout.get("local_only") is False, "CLI logout request must be cloud-first by default")

    logout_local = require_dict(
        load_json("fixtures/cli/logout-local-request.json"),
        "CLI logout local-only request",
    )
    expect_protocol(logout_local.get("protocol_version"), "CLI logout local-only request")
    expect(logout_local.get("client_kind") == "cli", "CLI logout local-only request client_kind must be cli")
    expect(logout_local.get("command") == "auth_reset", "CLI logout local-only request command must be auth_reset")
    expect(logout_local.get("local_only") is True, "CLI logout local-only request local_only must be true")

    diagnostics_collect = require_dict(
        load_json("fixtures/cli/diagnostics-collect-request.json"),
        "CLI diagnostics collect request",
    )
    expect_protocol(diagnostics_collect.get("protocol_version"), "CLI diagnostics collect request")
    expect(diagnostics_collect.get("command") == "diagnostics_collect", "CLI diagnostics collect request command must be diagnostics_collect")
    expect(diagnostics_collect.get("upload") is False, "CLI diagnostics collect request upload must be false")

    diagnostics_upload = require_dict(
        load_json("fixtures/cli/diagnostics-upload-request.json"),
        "CLI diagnostics upload request",
    )
    expect_protocol(diagnostics_upload.get("protocol_version"), "CLI diagnostics upload request")
    expect(diagnostics_upload.get("command") == "diagnostics_collect", "CLI diagnostics upload request command must be diagnostics_collect")
    expect(diagnostics_upload.get("upload") is True, "CLI diagnostics upload request upload must be true")
    upload_approval = require_dict(
        diagnostics_upload.get("upload_approval"), "CLI diagnostics upload approval"
    )
    expect(upload_approval.get("approved") is True, "CLI diagnostics upload approval must be accepted")
    expect(
        upload_approval.get("retention_disclosure_accepted") is True,
        "CLI diagnostics upload retention disclosure must be accepted",
    )

    doctor = require_dict(load_json("fixtures/cli/doctor-request.json"), "CLI doctor request")
    expect_protocol(doctor.get("protocol_version"), "CLI doctor request")
    expect(doctor.get("client_kind") == "cli", "CLI doctor request client_kind must be cli")
    expect(doctor.get("command") == "status", "CLI doctor request command must be status")
    expect(doctor.get("refresh_agent_status") is False, "CLI doctor request must not refresh agent status")

    verify_repair = require_dict(
        load_json("fixtures/cli/verify-repair-request.json"),
        "CLI verify repair request",
    )
    expect_protocol(verify_repair.get("protocol_version"), "CLI verify repair request")
    expect(verify_repair.get("client_kind") == "cli", "CLI verify repair request client_kind must be cli")
    expect(verify_repair.get("command") == "verify", "CLI verify repair request command must be verify")
    expect(verify_repair.get("source") == "codex", "CLI verify repair request source must be codex")
    expect(verify_repair.get("repair") is True, "CLI verify repair request repair must be true")

    apps_root = require_dict(
        load_json("fixtures/cli/apps-root-request.json"),
        "CLI apps root request",
    )
    expect_protocol(apps_root.get("protocol_version"), "CLI apps root request")
    expect(apps_root.get("client_kind") == "cli", "CLI apps root request client_kind must be cli")
    expect(apps_root.get("command") == "status", "CLI apps root request command must be status")
    expect(apps_root.get("refresh_agent_status") is False, "CLI apps root request must not refresh agent status")

    apps_detect = require_dict(
        load_json("fixtures/cli/apps-detect-request.json"),
        "CLI apps detect request",
    )
    expect_protocol(apps_detect.get("protocol_version"), "CLI apps detect request")
    expect(apps_detect.get("client_kind") == "cli", "CLI apps detect request client_kind must be cli")
    expect(apps_detect.get("command") == "status", "CLI apps detect request command must be status")
    expect(apps_detect.get("refresh_agent_status") is True, "CLI apps detect request must refresh agent status")

    apps_status = require_dict(
        load_json("fixtures/cli/apps-status-pi-request.json"),
        "CLI apps status request",
    )
    expect_protocol(apps_status.get("protocol_version"), "CLI apps status request")
    expect(apps_status.get("client_kind") == "cli", "CLI apps status request client_kind must be cli")
    expect(apps_status.get("command") == "agent_status_refresh", "CLI apps status request command must be agent_status_refresh")
    expect(apps_status.get("source") == "pi", "CLI apps status request source must be pi")

    update_check = require_dict(
        load_json("fixtures/cli/update-check-request.json"),
        "CLI update check request",
    )
    expect_protocol(update_check.get("protocol_version"), "CLI update check request")
    expect(update_check.get("client_kind") == "cli", "CLI update check request client_kind must be cli")
    expect(update_check.get("command") == "update_check", "CLI update check request command must be update_check")

    browser_claim = require_dict(
        load_json("fixtures/cli/setup-browser-claim-output.json"),
        "CLI browser claim output",
    )
    browser_claim_sources = check_setup_output_shape(browser_claim, "browser claim output")
    expect(browser_claim.get("status") == "waiting_for_browser", "browser claim status must be waiting_for_browser")
    expect(browser_claim.get("setup_run_id") is None, "browser claim setup_run_id must be null before claim")
    expect(browser_claim.get("claim_code_provided") is False, "browser claim output must not mark claim_code_provided")
    expect(browser_claim.get("claim_code"), "browser claim output must include claim_code")
    expect(browser_claim.get("claim_url"), "browser claim output must include claim_url")
    expect(browser_claim.get("next_question") is None, "browser claim next_question must be null")
    expect(browser_claim_sources == [], "browser claim detected_sources must be empty")
    next_action = require_dict(browser_claim.get("next_action"), "browser claim next_action")
    expect(next_action.get("type") == "browser_claim", "browser claim next_action type must be browser_claim")
    expect(next_action.get("claim_code") == browser_claim.get("claim_code"), "browser claim next_action must repeat claim_code")
    expect(next_action.get("claim_url") == browser_claim.get("claim_url"), "browser claim next_action must repeat claim_url")
    agent_action = require_dict(browser_claim.get("agent_action"), "browser claim agent_action")
    expect(agent_action.get("kind") == "open_browser_claim", "browser claim agent_action kind must be open_browser_claim")
    expect(agent_action.get("requires_user") is True, "browser claim agent_action requires_user must be true")
    expect(agent_action.get("retryable") is True, "browser claim agent_action retryable must be true")

    needs_user = require_dict(
        load_json("fixtures/cli/setup-needs-user-action-output.json"),
        "CLI needs-user-action output",
    )
    needs_user_sources = check_setup_output_shape(needs_user, "needs-user-action output")
    expect(needs_user.get("status") == "waiting_for_approval", "needs-user-action status must be waiting_for_approval")
    expect(needs_user.get("claim_code_provided") is False, "needs-user-action output must not mark claim_code_provided")
    expect(needs_user.get("next_action") is None, "needs-user-action next_action must be null while waiting for approval")
    question = require_dict(needs_user.get("next_question"), "needs-user-action next_question")
    expect(question.get("type") == "approval", "needs-user-action next_question type must be approval")
    expect(question.get("source") == "codex", "needs-user-action next_question source must be codex")
    agent_action = require_dict(needs_user.get("agent_action"), "needs-user-action agent_action")
    expect(agent_action.get("kind") == "answer_setup_question", "needs-user-action agent_action kind must be answer_setup_question")
    expect(agent_action.get("requires_user") is True, "needs-user-action agent_action requires_user must be true")
    expect(agent_action.get("retryable") is True, "needs-user-action agent_action retryable must be true")
    expect(len(needs_user_sources) == 1, "needs-user-action output must expose one detected source")
    if needs_user_sources:
        source = needs_user_sources[0]
        expect(source.get("source") == "codex", "needs-user-action detected source must be codex")
        expect(source.get("state") == "ready_to_install", "needs-user-action detected source state must be ready_to_install")
        expect("browser_approval" in require_list(source.get("missing_fields"), "needs-user-action missing_fields"), "needs-user-action missing_fields must include browser_approval")

    timed_out = require_dict(
        load_json("fixtures/cli/setup-timed-out-output.json"), "CLI setup timed-out output"
    )
    timed_out_sources = check_setup_output_shape(timed_out, "setup timed-out output")
    expect(timed_out.get("status") == "timed_out", "setup timed-out status must be timed_out")
    expect(timed_out.get("claim_code_provided") is True, "setup timed-out output must preserve claim_code_provided")
    expect(timed_out.get("next_question") is None, "setup timed-out next_question must be null")
    expect(timed_out.get("next_action") is None, "setup timed-out next_action must be null")
    agent_action = require_dict(timed_out.get("agent_action"), "setup timed-out agent_action")
    expect(agent_action.get("kind") == "retry_setup", "setup timed-out agent_action kind must be retry_setup")
    expect(agent_action.get("requires_user") is False, "setup timed-out agent_action requires_user must be false")
    expect(agent_action.get("retryable") is True, "setup timed-out agent_action retryable must be true")
    expect(len(timed_out_sources) == 1, "setup timed-out output must expose one detected source")
    if timed_out_sources:
        source = timed_out_sources[0]
        expect(source.get("source") == "codex", "setup timed-out detected source must be codex")
        expect(source.get("state") == "waiting_for_telemetry", "setup timed-out detected source state must be waiting_for_telemetry")
        expect("fresh_telemetry" in require_list(source.get("missing_fields"), "setup timed-out missing_fields"), "setup timed-out missing_fields must include fresh_telemetry")

    status_events = load_ndjson("fixtures/cli/status-watch-output.ndjson")
    if status_events:
        final = status_events[-1]
        expect(final.get("event") == "final", "status watch final event must be final")
        expect(final.get("ok") is True, "status watch final event must be ok")
        expect(final.get("exit_code") == 0, "status watch final exit_code must be 0")
        payload = require_dict(final.get("payload"), "status watch final payload")
        expect_protocol(payload.get("protocol_version"), "status watch final payload")

    error_events = load_ndjson("fixtures/cli/daemon-unavailable-watch-output.ndjson")
    if error_events:
        final = error_events[-1]
        expect(final.get("event") == "final", "daemon error watch final event must be final")
        expect(final.get("ok") is False, "daemon error watch final event must not be ok")
        expect(final.get("exit_code") == 10, "daemon error watch final exit_code must be 10")
        watch_error = require_dict(final.get("error"), "daemon error watch final error")
        expect(watch_error.get("code") == "daemon_unavailable", "daemon error watch code must be daemon_unavailable")


def check_control_contracts() -> None:
    request = require_dict(load_json("fixtures/control/status-request.json"), "control status request")
    expect(request.get("command") == "status", "control status request command must be status")
    expect_protocol(request.get("protocol_version"), "control status request")
    expect(request.get("token") == "[REDACTED]", "control status request token must be redacted")

    response = require_dict(load_json("fixtures/control/status-response.json"), "control status response")
    expect(response.get("ok") is True, "control status response must be ok")
    expect(response.get("error") is None, "control status response error must be null")
    payload = require_dict(response.get("payload"), "control status response payload")
    expect_protocol(payload.get("protocol_version"), "control status response payload")
    expect(payload.get("daemon") == "running", "control status response daemon must be running")


def check_setup_and_redaction_contracts() -> None:
    bundle = require_dict(
        load_json("fixtures/diagnostics/redacted-bundle.json"), "redacted diagnostics bundle"
    )
    expect(bundle.get("bundle_id"), "redacted diagnostics bundle must include bundle_id")
    upload = require_dict(bundle.get("upload"), "redacted diagnostics upload")
    expect(upload.get("requested") is False, "redacted diagnostics upload requested must be false")
    expect(upload.get("status") == "local_only", "redacted diagnostics upload status must be local_only")
    expect(upload.get("approval_required") is True, "redacted diagnostics upload must require approval")
    expect(upload.get("approved") is False, "redacted diagnostics upload approved must be false")
    expect(upload.get("authorization") == "not_requested", "redacted diagnostics authorization must be not_requested")
    redaction = require_dict(bundle.get("redaction"), "redacted diagnostics redaction")
    expect(redaction.get("policy_version") == 1, "redacted diagnostics policy_version must be 1")
    covered_surfaces = set(require_list(redaction.get("covered_surfaces"), "redaction covered surfaces"))
    for surface in (
        "diagnostics",
        "support_output",
        "agent_output",
        "setup_error",
        "command_output",
    ):
        expect(surface in covered_surfaces, f"redaction covered surfaces must include {surface}")
    categories = set(require_list(redaction.get("redacted_categories"), "redacted categories"))
    for category in (
        "local_path",
        "secret_token",
        "account_identifier",
        "machine_identifier",
        "raw_prompt",
        "command_output",
    ):
        expect(category in categories, f"redaction categories must include {category}")
    fields = set(require_list(redaction.get("redacted_fields"), "redacted fields"))
    expect("installation.launch_agent_path" in fields, "redaction fields must include launch_agent_path")
    expect("security.auth_header" in fields, "redaction fields must include auth_header")
    sections = require_list(bundle.get("sections"), "redacted diagnostics sections")
    section_items = {
        section.get("name"): section.get("items")
        for section in sections
        if isinstance(section, dict) and isinstance(section.get("items"), dict)
    }
    expect(len(section_items) == len(sections), "redacted diagnostics sections must have object items")
    installation = require_dict(section_items.get("installation"), "redacted installation section")
    expect(installation.get("launch_agent_path") == "[path]", "launch_agent_path must be path-redacted")
    security = require_dict(section_items.get("security"), "redacted security section")
    expect(security.get("auth_header") == "[REDACTED]", "auth_header must be redacted")
    check_diagnostics_values_are_redacted(section_items, "diagnostics.sections")

    setup = require_dict(load_json("fixtures/setup/claim-run.json"), "setup claim run")
    expect(setup.get("status") == "waiting_for_approval", "setup claim run status must be waiting_for_approval")
    expect(setup.get("setup_run_id"), "setup claim run must include setup_run_id")
    events = require_list(setup.get("events"), "setup claim run events")
    event_by_step = {
        event.get("step"): event for event in events if isinstance(event, dict)
    }
    claim_machine = require_dict(event_by_step.get("claim_machine"), "claim_machine setup event")
    expect(claim_machine.get("status") == "succeeded", "claim_machine setup event must succeed")
    metadata = require_dict(claim_machine.get("metadata"), "claim_machine metadata")
    expect(metadata.get("setup_code") == "[REDACTED]", "claim_machine setup_code must be redacted")
    request_approval = require_dict(
        event_by_step.get("request_approval"), "request_approval setup event"
    )
    expect(request_approval.get("status") == "waiting", "request_approval setup event must be waiting")
    expect(request_approval.get("source") == "codex", "request_approval setup event source must be codex")


def check_agent_adapter_contracts() -> None:
    docs_path = require_file("docs/agent-adapters.md")
    if docs_path is not None:
        text = docs_path.read_text(encoding="utf-8")
        expect(
            "MCP adapter is intentionally deferred" in text,
            "agent adapter docs must document the public-v1 MCP deferral",
        )
        expect(
            "must not own setup authority" in text,
            "agent adapter docs must prohibit MCP setup authority ownership",
        )
        expect(
            "agent-adapters/codex-skill/" in text,
            "agent adapter docs must name the exported Codex skill",
        )
        expect(
            "agent-adapters/claude-code-skill/" in text,
            "agent adapter docs must name the exported Claude Code skill",
        )
        docs_expectations = [
            (
                "Pi is supported through the same public CLI app value, `--app pi`",
                "agent adapter docs must route Pi through the public CLI app value",
            ),
            (
                "consume machine-readable `ottto --json` output",
                "agent adapter docs must require machine-readable JSON output",
            ),
            (
                "avoid direct edits to agent config, credentials, cookies, hooks, status-line\n  monitors, or local source files",
                "agent adapter docs must prohibit direct config/credential/hook/source edits",
            ),
            (
                "summarize redacted status facts instead of pasting raw diagnostics payloads",
                "agent adapter docs must require redacted summaries instead of raw diagnostics",
            ),
            (
                "keep support claims out of public issues, chat, returned JSON, and uploaded\n  bundle content",
                "agent adapter docs must keep support claims out of public issues/chat/JSON/bundles",
            ),
        ]
        for needle, message in docs_expectations:
            expect(needle in text, message)

    require_file("agent-adapters/codex-skill/SKILL.md")
    require_file("agent-adapters/claude-code-skill/SKILL.md")
    for relative_path in (
        "agent-adapters/mcp",
        "agent-adapters/mcp-server",
        "mcp",
        "mcp-server",
    ):
        if (PUBLIC_ROOT / relative_path).exists():
            fail(f"MCP adapter must remain deferred for public v1: {relative_path}")

    skill_expectations = {
        "agent-adapters/codex-skill/SKILL.md": {
            "required": [
                ("Always pass `--json`", "Codex skill must require JSON output for consumed CLI responses"),
                ("`--json --watch` emits compact\nNDJSON", "Codex skill must document NDJSON watch semantics"),
                ("Do not parse human output", "Codex skill must prohibit parsing human output"),
                ("bypass browser/setup authority", "Codex skill must preserve browser/setup authority"),
                ("do not hand-edit local app config", "Codex skill must prohibit direct config edits"),
                ("Do not ask users to paste support claims into public issues or chat", "Codex skill must keep support claims out of chat"),
                ("must not appear in returned JSON", "Codex skill must keep support claims out of returned JSON"),
                ("uploaded bundle content", "Codex skill must document support-claim upload containment"),
            ],
            "forbidden": [
                ("allowed-tools:", "Codex skill must not pregrant tools"),
                ("hooks:", "Codex skill must not install hooks"),
                ("statusline:", "Codex skill must not install status-line metadata"),
                ("status-line:", "Codex skill must not install status-line metadata"),
                ("tools/ottto-local-platform", "Codex skill must not reference private monorepo install paths"),
            ],
        },
        "agent-adapters/claude-code-skill/SKILL.md": {
            "required": [
                ("Always pass `--json`", "Claude Code skill must require JSON output for consumed CLI responses"),
                ("`--json --watch` emits compact\nNDJSON", "Claude Code skill must document NDJSON watch semantics"),
                ("Do not parse human output", "Claude Code skill must prohibit parsing human output"),
                ("bypass browser/setup authority", "Claude Code skill must preserve browser/setup authority"),
                ("do not write telemetry\nenvironment variables", "Claude Code skill must prohibit direct telemetry config edits"),
                ("Do not ask users to paste support claims into public issues or chat", "Claude Code skill must keep support claims out of chat"),
                ("must not appear in returned JSON", "Claude Code skill must keep support claims out of returned JSON"),
                ("uploaded bundle content", "Claude Code skill must document support-claim upload containment"),
            ],
            "forbidden": [
                ("allowed-tools:", "Claude Code skill must not pregrant tools"),
                ("hooks:", "Claude Code skill must not define hooks metadata"),
                ("statusline:", "Claude Code skill must not define status-line metadata"),
                ("status-line:", "Claude Code skill must not define status-line metadata"),
                ("tools/ottto-local-platform", "Claude Code skill must not reference private monorepo install paths"),
            ],
        },
        "agent-adapters/codex-skill/agents/openai.yaml": {
            "required": [
                ("Manage Ottto local setup", "Codex agent manifest must stay scoped to Ottto lifecycle"),
            ],
            "forbidden": [
                ("allowed_tools:", "Codex agent manifest must not pregrant tools"),
                ("tools:", "Codex agent manifest must not pregrant tools"),
                ("mcp", "Codex agent manifest must not advertise MCP for public v1"),
                ("hooks:", "Codex agent manifest must not define hooks"),
                ("statusline:", "Codex agent manifest must not define status-line metadata"),
                ("status-line:", "Codex agent manifest must not define status-line metadata"),
            ],
        },
    }
    for relative_path, expectations in skill_expectations.items():
        path = require_file(relative_path)
        if path is None:
            continue
        text = path.read_text(encoding="utf-8")
        for needle, message in expectations["required"]:
            expect(needle in text, message)
        lowered = text.lower()
        for needle, message in expectations["forbidden"]:
            if needle.lower() in lowered:
                fail(message)


def check_setup_docs_contracts() -> None:
    setup_docs = require_file("docs/setup.md")
    if setup_docs is None:
        return

    text = setup_docs.read_text(encoding="utf-8")
    expectations = [
        (
            "branch on `agent_action.kind` before inspecting human text",
            "setup docs must require branching on agent_action.kind before human text",
        ),
        (
            "not treat the nonzero exit as corrupt JSON",
            "setup docs must treat setup exit 60/61 payloads as parseable JSON",
        ),
        ("`open_browser_claim`", "setup docs must document open_browser_claim"),
        (
            "Show the structured `claim_url` or `claim_code`",
            "setup docs must tell agents to surface structured claim URL/code",
        ),
        ("`answer_setup_question`", "setup docs must document answer_setup_question"),
        (
            "Ask the user for the structured `next_question`",
            "setup docs must tell agents to use structured next_question",
        ),
        ("`run_next_action`", "setup docs must document run_next_action"),
        (
            "Follow the structured `next_action` object",
            "setup docs must tell agents to use structured next_action",
        ),
        ("`retry_setup`", "setup docs must document retry_setup"),
        ("`wait_or_check_status`", "setup docs must document wait_or_check_status"),
        ("`inspect_failure`", "setup docs must document inspect_failure"),
        ("`check_status`", "setup docs must document check_status"),
        (
            "Agents must consume the structured setup JSON and `agent_action` values rather\nthan parsing human output.",
            "setup docs must prohibit parsing human output for setup state",
        ),
    ]
    for needle, message in expectations:
        expect(needle in text, message)


def check_private_runtime_pin() -> int:
    if PRIVATE_REPO_ROOT is None:
        return 0

    pin_path, pin_label = private_runtime_pin_path()
    if pin_path is None:
        return 0
    if not pin_path.is_file():
        fail(f"private runtime pin is missing: {pin_label}")
        return 0

    try:
        pin = json.loads(pin_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        fail(f"private runtime pin is invalid JSON: {error}")
        return 0
    if not isinstance(pin, dict):
        fail("private runtime pin must be a JSON object")
        return 0

    expect(pin.get("schema_version") == 1, "private runtime pin schema_version must be 1")
    expect(
        pin.get("generated_by") == "public_runtime_pin.v1",
        "private runtime pin generated_by must be public_runtime_pin.v1",
    )
    expect(
        pin.get("expected_repository") == "ottto-ai/ottto",
        "private runtime pin expected_repository must be ottto-ai/ottto",
    )
    authority_state = pin.get("authority_state")
    expect(
        authority_state in {"pre_public_repo_export", "public_repo_commit"},
        "private runtime pin authority_state must be pre_public_repo_export or public_repo_commit",
    )
    if REQUIRE_PUBLIC_AUTHORITY and authority_state != "public_repo_commit":
        fail("private runtime pin authority_state must be public_repo_commit when public authority is required")

    pinned_manifest = require_dict(
        pin.get("public_export_manifest"), "private runtime pin public_export_manifest"
    )
    public_manifest = require_dict(load_json("PUBLIC_EXPORT_MANIFEST.json"), "public export manifest")
    public_files = public_manifest.get("files")
    public_file_record_count = len(public_files) if isinstance(public_files, list) else None

    content_sha256 = pinned_manifest.get("content_sha256")
    expect(
        isinstance(content_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", content_sha256) is not None,
        "private runtime pin content_sha256 must be a lowercase SHA-256 hex digest",
    )
    expect(
        content_sha256 == public_manifest.get("content_sha256"),
        "private runtime pin content_sha256 must match public manifest content_sha256",
    )
    expect(
        pinned_manifest.get("output_file_count") == public_manifest.get("output_file_count"),
        "private runtime pin output_file_count must match public manifest output_file_count",
    )
    expect(
        pinned_manifest.get("file_record_count") == public_file_record_count,
        "private runtime pin file_record_count must match public manifest file record count",
    )

    if authority_state == "public_repo_commit":
        public_commit = require_dict(
            pin.get("public_repo_commit"), "private runtime pin public_repo_commit"
        )
        expect(
            public_commit.get("repository") == pin.get("expected_repository"),
            "private runtime pin public_repo_commit.repository must match expected_repository",
        )
        commit = public_commit.get("commit")
        expect(
            isinstance(commit, str)
            and re.fullmatch(r"[0-9a-f]{7,40}", commit) is not None,
            "private runtime pin public_repo_commit.commit must be a git SHA prefix",
        )
        expect(
            public_commit.get("manifest_path") == "PUBLIC_EXPORT_MANIFEST.json",
            "private runtime pin public_repo_commit.manifest_path must be PUBLIC_EXPORT_MANIFEST.json",
        )
        expect(
            public_commit.get("manifest_content_sha256") == content_sha256,
            "private runtime pin public_repo_commit.manifest_content_sha256 must match pinned manifest content_sha256",
        )
        git_toplevel = git_output(["rev-parse", "--show-toplevel"])
        if git_toplevel is not None:
            expect(
                Path(git_toplevel).resolve() == PUBLIC_ROOT,
                "public authority check requires the public root to be the git checkout root",
            )
        git_head = git_output(["rev-parse", "HEAD"])
        if isinstance(commit, str) and git_head:
            expect(
                git_head.startswith(commit),
                "private runtime pin public_repo_commit.commit must match public root HEAD",
            )
        git_status = git_output(["status", "--porcelain"])
        if git_status is not None:
            expect(
                git_status == "",
                "public authority check requires a clean public root git checkout",
            )
    return 1


def check_private_consumers() -> int:
    if PRIVATE_REPO_ROOT is None:
        return 0
    if not PRIVATE_REPO_ROOT.is_dir():
        fail(f"private repo root is not a directory: {PRIVATE_REPO_ROOT}")
        return 0

    checks = 0
    checks += check_private_runtime_pin()

    registry_loader = require_private_file("backend/app/domain/connectors/registry.py")
    if registry_loader is not None:
        text = registry_loader.read_text(encoding="utf-8")
        expect(
            'REPO_ROOT / "connectors" / "registry.generated.json"' in text,
            "private backend registry loader must read root connectors/registry.generated.json",
        )
        expect("schema_version: Literal[\"connector_registry.v1\"]" in text, "private backend registry model must pin connector_registry.v1")
        checks += 1

    setup_schema = require_private_file("backend/app/schemas/setup_runs.py")
    if setup_schema is not None:
        text = setup_schema.read_text(encoding="utf-8")
        expect(
            'product: Literal["ottto-local-platform"]' in text,
            "private backend release response must pin ottto-local-platform product",
        )
        checks += 1

    setup_service = require_private_file("backend/app/features/setup_runs/service.py")
    if setup_service is not None:
        text = setup_service.read_text(encoding="utf-8")
        expect(
            'manifest.get("schema_version") != 1' in text,
            "private backend release loader must reject unsupported release manifest schema_version",
        )
        expect(
            'manifest.get("product") != "ottto-local-platform"' in text,
            "private backend release loader must reject unexpected release manifest product",
        )
        checks += 1

    frontend_control = require_private_file("frontend/src/lib/apps/local-telemetry-control.ts")
    if frontend_control is not None:
        text = frontend_control.read_text(encoding="utf-8")
        expect(
            "LOCAL_CONTROL_PROTOCOL_VERSION = 15" in text
            or re.search(r"LOCAL_CONTROL_PROTOCOL_VERSIONS\s*=\s*\[\s*15\b", text) is not None,
            "private frontend local-control client must send protocol version 15",
        )
        expect(
            'command: "telemetry_control"' in text,
            "private frontend local-control client must send telemetry_control command",
        )
        expect(
            'targetAddressSpace?: "loopback"' in text,
            "private frontend local-control client must request loopback target address space",
        )
        checks += 1

    return checks


if not PUBLIC_ROOT.is_dir():
    die(f"public repository root is not a directory: {PUBLIC_ROOT}")

check_schema_contracts()
check_registry_contract()
check_cli_contracts()
check_control_contracts()
check_setup_and_redaction_contracts()
check_agent_adapter_contracts()
check_setup_docs_contracts()
private_check_count = check_private_consumers()

if failures:
    for failure in failures:
        print(f"public-contract: {failure}", file=sys.stderr)
    die(f"failed with {len(failures)} issue(s) under {PUBLIC_ROOT}", code=1)

if private_check_count:
    print(
        "public-contract: checked public contracts at "
        f"{PUBLIC_ROOT} and {private_check_count} private consumer file(s)"
    )
else:
    print(f"public-contract: checked public contracts at {PUBLIC_ROOT}; private consumer checks skipped")
PY
