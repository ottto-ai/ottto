#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_release_paths.sh
source "$ROOT/scripts/macos_release_paths.sh"

MANIFEST=""
STAGE="final"
EVIDENCE=""

usage() {
  cat <<'USAGE'
Usage: macos_stable_closeout_gate.sh --manifest <release-manifest.json> [--stage final]
       macos_stable_closeout_gate.sh --manifest <release-manifest.json> --stage pre-hosted --evidence <pre-hosted-summary.json>
       macos_stable_closeout_gate.sh --list-never-carry-checks
       macos_stable_closeout_gate.sh --supports-stages

Validates the public stable clean-machine QA summary (evidence schema 2) before
a stable local-platform release is promoted as externally ready. This gate is
intentionally separate from packaging preflight: it runs after clean-machine
install QA and macos_stable_qa_summary.sh have written the summary beside the
manifest. Every required check must have passed in this release:
  method live      driven by hand on the QA host
  method scripted  run end-to-end by an automated script on the QA host
  method static    artifact inspection only; allowed just for artifact_checksum,
                   formula_syntax, gatekeeper and native_gatekeeper
The schema also has result=carried (with from=<version>) for a check that last
ran in an earlier release of the same X.Y line, at most 5 patches back. The gate
validates its shape but does not accept it until verified carry ships.
--list-never-carry-checks prints the checks that can never be carried.

Stages. A stable release is published in two stages, because the hosted
installer downloads only from the immutable versioned prefix:
  pre-hosted  before the immutable upload. --evidence names the pre-hosted
              summary (macos_stable_qa_summary.sh --stage pre-hosted), which
              lives outside the release folder; stable-clean-machine-qa.json
              must not be beside the manifest yet. Every final rule applies,
              except that each required hosted_installer check is exactly
              {"result":"not_run"}, the hosted_installer owner status and the
              top-level status are not_run, and the summary has
              "stage":"pre-hosted".
  final       (default) the summary beside the manifest, every check passed,
              and no stage field.
A hosted lane failure after the immutable stage burns that version; the next
release uses the next patch number. --supports-stages prints the stages this
gate knows.

The release folder must hold plain files and directories only: the gate fails
on any symlink in it, on a private QA record under any name, and on a scan
error.

Host classes (environment.host_class), least clean that fits: clean_vm (clean
guest VM), clean_macos (clean physical Mac), qa_user_on_shared_mac,
signing_mac (the signing host, for every user on it), developer_mac.

Owner checks with specific meaning:
  homebrew.headless_no_app_process         the QA user has no Ottto app process
                                           for the whole Homebrew lane, also after
                                           a service restart
  homebrew.post_upgrade_service_restarts_owned
                                           after brew upgrade ottto and a service
                                           restart, launchd runs a new process at
                                           the target version; install_owner stays
                                           homebrew
  app_bundle.move_service_to_app           start from a serving Homebrew job;
                                           launch the installed target app in the
                                           QA user's desktop session; it must offer
                                           Move; click Move; then exactly one
                                           app-owned launchd job serves the target
                                           and no Homebrew process remains; on the
                                           isolated VM, check after app health that
                                           the formula is removed
  app_bundle.homebrew_second_install_safe_refusal
                                           a separate run, not a Move: a formula
                                           installed beside a running app never
                                           gets a second serving job and never
                                           silently takes ownership (the keg may
                                           exist). The packaging gate's step-aside
                                           check is not evidence for this live run
  app_bundle.upgrade                       includes the target app relaunch and
                                           the app keeping ownership
USAGE
}

# Checks that bind this release's exact bytes, install or runtime. They must
# pass in this release and are never carried. Keep this the only copy.
never_carry_checks() {
  printf '%s\n' \
    artifact_checksum \
    gatekeeper \
    native_gatekeeper \
    wrapper_download \
    wrapper_checksum \
    formula_syntax \
    status_json \
    upgrade \
    install \
    service_start \
    service_ready \
    app_launch \
    apps_detect_json \
    update_check \
    update_check_owner_json \
    headless_no_app_process \
    post_upgrade_service_restarts_owned
}

# Checks that artifact inspection alone can prove (checksum, formula syntax,
# Gatekeeper assessment). Runtime checks and real downloads must have run.
static_method_check() {
  case "$1" in
    artifact_checksum|formula_syntax|gatekeeper|native_gatekeeper) return 0 ;;
    *) return 1 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest)
      MANIFEST="${2:?--manifest requires a value}"
      shift 2
      ;;
    --stage)
      STAGE="${2:?--stage requires a value}"
      shift 2
      ;;
    --evidence)
      EVIDENCE="${2:?--evidence requires a value}"
      shift 2
      ;;
    --list-never-carry-checks)
      never_carry_checks
      exit 0
      ;;
    --supports-stages)
      echo "pre-hosted final"
      exit 0
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

failures=0

fail() {
  echo "$*" >&2
  failures=$((failures + 1))
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Required command not found: $1" >&2
    exit 2
  }
}

# The homebrew owner is the headless variant: the formula's service runs with
# no Ottto app process for that macOS user.
required_checks_for_owner() {
  case "$1" in
    homebrew)
      printf '%s\n' \
        formula_syntax \
        install \
        service_start \
        headless_no_app_process \
        status_json \
        setup_browser_claim \
        apps_detect_json \
        verify_codex_json \
        doctor_json \
        doctor_owner_drift_json \
        fix_codex_json \
        diagnostics_collect_json \
        logout_json \
        update_check \
        update_check_owner_json \
        upgrade \
        post_upgrade_service_restarts_owned \
        uninstall \
        reinstall \
        post_reinstall_status_json \
        reonboard_after_keychain_wipe
      ;;
    hosted_installer)
      printf '%s\n' \
        wrapper_download \
        wrapper_checksum \
        native_gatekeeper \
        install \
        app_launch \
        service_ready \
        status_json \
        setup_browser_claim \
        apps_detect_json \
        verify_codex_json \
        doctor_json \
        fix_codex_json \
        diagnostics_collect_json \
        logout_json \
        update_check \
        upgrade \
        uninstall \
        reinstall \
        post_reinstall_status_json \
        reonboard_after_keychain_wipe
      ;;
    app_bundle)
      printf '%s\n' \
        artifact_checksum \
        gatekeeper \
        install \
        app_launch \
        service_ready \
        homebrew_second_install_safe_refusal \
        status_json \
        setup_browser_claim \
        apps_detect_json \
        verify_codex_json \
        doctor_json \
        doctor_owner_drift_json \
        fix_codex_json \
        diagnostics_collect_json \
        logout_json \
        update_check \
        update_check_owner_json \
        upgrade \
        move_service_to_app \
        uninstall \
        reinstall \
        post_reinstall_status_json \
        reonboard_after_keychain_wipe
      ;;
    *)
      return 1
      ;;
  esac
}

contains_value() {
  local needle="$1"
  shift
  local value
  for value in "$@"; do
    [[ "$value" == "$needle" ]] && return 0
  done
  return 1
}

# Diagnostics never repeat a value from the files: a name is printed only when
# it is one this gate already knows, otherwise a fixed label stands in for it.
known_owner_label() {
  case "$1" in
    homebrew|hosted_installer|app_bundle) printf '%s' "$1" ;;
    *) printf '%s' "<unknown owner>" ;;
  esac
}

known_check_label() {
  local owner
  for owner in homebrew hosted_installer app_bundle; do
    if required_checks_for_owner "$owner" | grep -qxF -- "$1"; then
      printf '%s' "$1"
      return 0
    fi
  done
  case "$1" in
    # Pre-headless Homebrew owner checks, named so an old summary gets a clear message.
    app_launch_preserves_owner|post_upgrade_app_relaunch_preserves_owner) printf '%s' "$1" ;;
    *) printf '%s' "<unknown check>" ;;
  esac
}

require_command jq
require_command python3
require_command shasum
require_command grep
require_command find

if [[ -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi
case "$STAGE" in
  final)
    if [[ -n "$EVIDENCE" ]]; then
      echo "--evidence goes with --stage pre-hosted only; the final gate reads the summary beside the manifest" >&2
      exit 2
    fi
    ;;
  pre-hosted)
    if [[ -z "$EVIDENCE" ]]; then
      echo "--stage pre-hosted requires --evidence <pre-hosted-summary.json>" >&2
      exit 2
    fi
    ;;
  *)
    echo "--stage must be pre-hosted or final" >&2
    exit 2
    ;;
esac
if [[ ! -f "$MANIFEST" ]]; then
  echo "Release manifest is missing" >&2
  exit 1
fi

# I/O errors get fixed messages: a tool's own error would print the path.
if ! manifest_dir="$(macos_release_manifest_dir "$MANIFEST" 2>/dev/null)" || [[ -z "$manifest_dir" ]]; then
  echo "Release manifest folder is not readable" >&2
  exit 1
fi
if ! manifest_sha="$(shasum -a 256 "$MANIFEST" 2>/dev/null | awk '{print $1}')" || [[ ! "$manifest_sha" =~ ^[0-9a-f]{64}$ ]]; then
  echo "Release manifest is not readable" >&2
  exit 1
fi

# Strict manifest check, the same rules as the release API reader: whole-string
# matches (no trailing newline survives), JSON integers (15.0 is not 15) and
# exact owner names. It runs before any value reaches the shell.
if ! python3 - "$MANIFEST" <<'PY'
import json
import re
import sys

NAME = re.compile(r"[a-z0-9_]{1,64}")
VERSION = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})")
COMMIT = re.compile(r"[0-9a-f]{7,40}")


def reject_constant(_value):
    raise ValueError("non-finite number")


try:
    with open(sys.argv[1], "rb") as stream:
        manifest = json.loads(stream.read().decode("utf-8"), parse_constant=reject_constant)
except (OSError, UnicodeDecodeError, ValueError):
    print("Release manifest is not readable JSON", file=sys.stderr)
    sys.exit(1)

problems = []
if not isinstance(manifest, dict):
    print("Release manifest is not a JSON object", file=sys.stderr)
    sys.exit(1)


def string_is(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def owner_list(value):
    return isinstance(value, list) and all(string_is(item, NAME) for item in value)


if manifest.get("product") != "ottto-local-platform":
    problems.append("Stable closeout requires product=ottto-local-platform")
if manifest.get("channel") != "stable":
    problems.append("Stable closeout requires channel=stable")
if not string_is(manifest.get("version"), VERSION):
    problems.append("Stable closeout manifest version must be X.Y.Z (canonical numbers, at most 9 digits each)")
if not string_is(manifest.get("commit"), COMMIT):
    problems.append("Stable closeout manifest commit is not a git SHA prefix")
min_protocol_version = manifest.get("min_protocol_version")
if type(min_protocol_version) is not int or min_protocol_version != 15:
    problems.append("Stable closeout manifest min_protocol_version must be the integer 15")
if not owner_list(manifest.get("supported_install_owners")):
    problems.append("Stable manifest supported_install_owners must be a list of owner names")

quality_gates = manifest.get("quality_gates")
gate = quality_gates.get("stable_clean_machine_qa") if isinstance(quality_gates, dict) else None
if not isinstance(gate, dict):
    problems.append("Stable manifest is missing quality_gates.stable_clean_machine_qa")
else:
    if gate.get("status") not in ("passed", "not_run"):
        problems.append("Stable clean-machine QA manifest gate status must be passed or not_run")
    # One canonical summary name, so it never collides with the manifest or
    # another release file.
    if gate.get("evidence_path") != "stable-clean-machine-qa.json":
        problems.append("Stable clean-machine QA gate evidence_path must be stable-clean-machine-qa.json")
    if "required_install_owners" in gate and not owner_list(gate.get("required_install_owners")):
        problems.append("Stable clean-machine QA manifest gate required_install_owners must be a list of owner names")

for problem in problems:
    print(problem, file=sys.stderr)
if problems:
    print(f"Stable closeout gate failed with {len(problems)} issue(s).", file=sys.stderr)
    sys.exit(1)
PY
then
  exit 1
fi

version="$(jq -r '.version' "$MANIFEST")"
commit="$(jq -r '.commit' "$MANIFEST")"
channel="stable"

# The publisher uploads the whole release folder and follows links, so the
# folder holds plain files and directories only. A scan error fails closed.
if ! symlinks="$(find "$manifest_dir" -type l -print 2>/dev/null)"; then
  echo "Could not scan the release folder for symlinks" >&2
  exit 1
fi
if [[ -n "$symlinks" ]]; then
  symlink_count="$(printf '%s\n' "$symlinks" | wc -l | tr -d ' ')"
  echo "The release folder contains $symlink_count symlink(s); replace them with plain files or move them out before publishing" >&2
  exit 1
fi

if [[ "$STAGE" == "pre-hosted" ]]; then
  # The immutable stage uploads the release folder without the summary; the
  # final stage adds it as the one late file. A summary already beside the
  # manifest would be uploaded early and could never be replaced.
  if [[ -e "$manifest_dir/stable-clean-machine-qa.json" || -L "$manifest_dir/stable-clean-machine-qa.json" ]]; then
    echo "The pre-hosted stage runs before the final summary: stable-clean-machine-qa.json must not be beside the manifest" >&2
    exit 1
  fi
  if [[ -L "$EVIDENCE" || ! -f "$EVIDENCE" ]]; then
    echo "The pre-hosted summary is missing or is not a plain file" >&2
    exit 1
  fi
  if ! evidence_dir="$(macos_release_manifest_dir "$EVIDENCE" 2>/dev/null)" || [[ -z "$evidence_dir" ]]; then
    echo "The pre-hosted summary folder is not readable" >&2
    exit 1
  fi
  if [[ "$evidence_dir" == "$manifest_dir" || "$evidence_dir" == "$manifest_dir"/* ]]; then
    echo "The pre-hosted summary must live outside the release folder" >&2
    exit 1
  fi
  evidence_path="$evidence_dir/$(basename "$EVIDENCE")"
  evidence_name="the pre-hosted summary"
else
  # The summary is a plain file name beside the manifest, never a path or a symlink.
  if ! evidence_path="$(macos_release_path "$manifest_dir" "stable-clean-machine-qa.json")" || [[ ! -f "$evidence_path" ]]; then
    echo "Stable clean-machine QA summary stable-clean-machine-qa.json is missing beside the manifest" >&2
    exit 1
  fi
  evidence_name="stable-clean-machine-qa.json"
fi

# The publisher copies the original file bytes. Identify private records by
# their decoded top-level members, even when renamed or reserialized.
if ! python3 - "$manifest_dir" <<'PY'
import codecs
import json
import os
import stat
import sys

MAX_JSON_BYTES = 16 * 1024 * 1024
JSON_WHITESPACE = " \t\r\n"


def read_object(stream):
    bom = stream.peek(4)[:4]
    if bom.startswith((codecs.BOM_UTF32_LE, codecs.BOM_UTF32_BE)):
        encoding = "utf-32"
    elif bom.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        encoding = "utf-16"
    elif len(bom) == 4 and bom[0] == 0 and bom[1] == 0:
        # BOM-less encodings by the NUL pattern of the first characters.
        encoding = "utf-32-be"
    elif len(bom) == 4 and bom[1] == 0 and bom[2] == 0:
        encoding = "utf-32-le"
    elif len(bom) == 4 and bom[0] == 0:
        encoding = "utf-16-be"
    elif len(bom) == 4 and bom[1] == 0:
        encoding = "utf-16-le"
    else:
        encoding = "utf-8-sig"

    # Archives and other binary files need only a prefix probe. Decode again
    # strictly if the file starts like a JSON object.
    decoder = codecs.getincrementaldecoder(encoding)(errors="replace")
    remaining = MAX_JSON_BYTES
    while remaining:
        chunk = stream.read(min(8192, remaining))
        if not chunk:
            return None
        remaining -= len(chunk)
        prefix = decoder.decode(chunk).lstrip(JSON_WHITESPACE)
        if prefix:
            if prefix[0] != "{":
                return None
            break
    else:
        if stream.read(1):
            raise ValueError("JSON prefix exceeds scan limit")
        return None

    stream.seek(0)
    raw = stream.read(MAX_JSON_BYTES + 1)
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("JSON object exceeds scan limit")
    try:
        # Keep all members, including repeated keys, for the privacy check.
        # json.loads on bytes detects UTF-8/16/32 with or without a BOM.
        return json.loads(raw, object_pairs_hook=tuple)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def raise_scan_error(error):
    raise error


private_records = 0
try:
    for folder, _, names in os.walk(sys.argv[1], onerror=raise_scan_error):
        for name in names:
            path = os.path.join(folder, name)
            if not stat.S_ISREG(os.lstat(path).st_mode):
                continue
            with open(path, "rb") as stream:
                members = read_object(stream)
            # The RC evidence beside the manifest also has operator_notes, so
            # notes count only together with the stable QA gate marker.
            pairs = members if isinstance(members, tuple) else ()
            private_kind = any(k == "evidence_kind" and v == "private_record" for k, v in pairs)
            stable_notes = any(k == "operator_notes" for k, _ in pairs) and any(
                k == "gate" and v == "stable_clean_machine_qa" for k, v in pairs
            )
            if name.endswith(".record.json") or private_kind or stable_notes:
                private_records += 1
except (OSError, ValueError, RecursionError):
    print("Could not scan the release folder for private QA records", file=sys.stderr)
    sys.exit(1)

if private_records:
    print(
        f"A private QA record is inside the release folder ({private_records} file(s)); move it out before publishing",
        file=sys.stderr,
    )
    sys.exit(1)
PY
then
  exit 1
fi

if grep -Eiq "/Users/|docs/dev|\\.agents|\\.claude|Bearer[[:space:]]+|claim_code|setup_run_token|account_id|machine_id|api[_-]?key|password" "$evidence_path" 2>/dev/null; then
  echo "Stable clean-machine QA evidence contains private path or secret-like material: $evidence_name" >&2
  exit 1
fi
# The stage field says which gate a summary is for, so neither summary can
# stand in for the other.
if [[ "$STAGE" == "final" ]] && jq -e 'type == "object" and has("stage")' "$evidence_path" >/dev/null 2>&1; then
  echo "Stable clean-machine QA evidence has a stage field; the final gate needs the final summary (macos_stable_qa_summary.sh without --stage): $evidence_name" >&2
  exit 1
fi
if [[ "$STAGE" == "pre-hosted" ]] && ! jq -e 'type == "object" and .stage == "pre-hosted"' "$evidence_path" >/dev/null 2>&1; then
  echo "The pre-hosted gate needs a pre-hosted summary (\"stage\":\"pre-hosted\", from macos_stable_qa_summary.sh --stage pre-hosted)" >&2
  exit 1
fi
placeholder_filter='.. | strings | select(. == "not_run" or test("^TODO"))'
if [[ "$STAGE" == "pre-hosted" ]]; then
  # The hosted lane has not run yet: its checks, its owner status and the
  # top-level status are checked for exact values below instead.
  placeholder_filter='del(.status) | .install_owners |= map(if .owner == "hosted_installer" then del(.status, .checks) else . end) | '"$placeholder_filter"
fi
if jq -e "$placeholder_filter" "$evidence_path" >/dev/null 2>&1; then
  echo "Stable clean-machine QA evidence still contains template placeholders: $evidence_name" >&2
  exit 1
fi
if jq -e '.schema_version == 1' "$evidence_path" >/dev/null 2>&1; then
  echo "Stable clean-machine QA evidence must be schema_version 2 (v1 cannot record carried checks); write it with macos_stable_qa_summary.sh" >&2
  exit 1
fi

# Closed public schema, the same rules as the release API reader: exact keys
# at every level, whole-string matches, JSON integers and the binding to this
# manifest. Neither free text nor a private record can pass.
summary_status=0
python3 - "$evidence_path" "$MANIFEST" "$manifest_sha" "$STAGE" <<'PY' || summary_status=$?
import json
import re
import sys

NAME = re.compile(r"[a-z0-9_]{1,64}")
CHECKED_AT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
MACOS_VERSION = re.compile(r"[0-9]{1,3}(\.[0-9]{1,3}){0,2}")
CARRY_FROM = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})(-rc[1-9][0-9]*)?")
HOST_CLASSES = {"clean_vm", "clean_macos", "qa_user_on_shared_mac", "signing_mac", "developer_mac"}
ARCHES = {"arm64", "x86_64", "universal"}
LOCAL_PLATFORM_KEYS = {
    "install_owner",
    "protocol_version",
    "release_channel",
    "release_manifest_sha256",
    "runtime",
    "service_label",
    "version",
}


def reject_constant(_value):
    raise ValueError("non-finite number")


class DuplicateKeyError(ValueError):
    pass


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError
        obj[key] = value
    return obj


def load(path, *, object_pairs_hook=None):
    with open(path, "rb") as stream:
        return json.loads(
            stream.read().decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=object_pairs_hook,
        )


def string_is(value, pattern):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def check_entry_ok(entry):
    # Pre-hosted: a hosted_installer check that has not run yet; the owner
    # loop decides where this shape is allowed.
    if pre_hosted and entry == {"result": "not_run"}:
        return True
    if not isinstance(entry, dict) or set(entry) not in ({"result", "method"}, {"result", "method", "from"}):
        return False
    if not (string_is(entry["result"], NAME) and string_is(entry["method"], NAME)):
        return False
    return "from" not in entry or string_is(entry["from"], CARRY_FROM)


def owner_entry_ok(entry):
    if not isinstance(entry, dict) or set(entry) != {"checks", "local_platform", "owner", "status"}:
        return False
    local_platform = entry["local_platform"]
    checks = entry["checks"]
    hosted_not_run = pre_hosted and entry["owner"] == "hosted_installer"
    return (
        string_is(entry["owner"], NAME)
        and entry["status"] == ("not_run" if hosted_not_run else "passed")
        and isinstance(local_platform, dict)
        and set(local_platform) == LOCAL_PLATFORM_KEYS
        and type(local_platform["protocol_version"]) is int
        and all(isinstance(local_platform[key], str) for key in LOCAL_PLATFORM_KEYS - {"protocol_version"})
        and isinstance(checks, dict)
        and len(checks) > 0
        and all(string_is(name, NAME) and check_entry_ok(value) for name, value in checks.items())
    )


try:
    summary = load(sys.argv[1], object_pairs_hook=unique_object)
    manifest = load(sys.argv[2])
except DuplicateKeyError:
    sys.exit(2)
except (OSError, UnicodeDecodeError, ValueError):
    sys.exit(1)
manifest_sha = sys.argv[3]
pre_hosted = sys.argv[4] == "pre-hosted"
SUMMARY_KEYS = {"checked_at", "environment", "gate", "install_owners", "manifest", "schema_version", "status"}


def summary_ok():
    return (
        isinstance(summary, dict)
        and set(summary) == (SUMMARY_KEYS | {"stage"} if pre_hosted else SUMMARY_KEYS)
        and (not pre_hosted or summary["stage"] == "pre-hosted")
        and type(summary["schema_version"]) is int
        and summary["schema_version"] == 2
        and summary["gate"] == "stable_clean_machine_qa"
        and summary["status"] == ("not_run" if pre_hosted else "passed")
        and string_is(summary["checked_at"], CHECKED_AT)
        and isinstance(summary["manifest"], dict)
        and summary["manifest"] == {
            "product": manifest.get("product"),
            "channel": manifest.get("channel"),
            "version": manifest.get("version"),
            "commit": manifest.get("commit"),
            "sha256": manifest_sha,
        }
        and isinstance(summary["environment"], dict)
        and set(summary["environment"]) == {"arch", "host_class", "macos_version"}
        and isinstance(summary["environment"]["host_class"], str)
        and summary["environment"]["host_class"] in HOST_CLASSES
        and string_is(summary["environment"]["macos_version"], MACOS_VERSION)
        and isinstance(summary["environment"]["arch"], str)
        and summary["environment"]["arch"] in ARCHES
        and isinstance(summary["install_owners"], list)
        and len(summary["install_owners"]) > 0
        and all(owner_entry_ok(entry) for entry in summary["install_owners"])
    )


# A shape this check did not foresee fails closed, without a traceback.
try:
    ok = summary_ok()
except Exception:
    ok = False
sys.exit(0 if ok else 1)
PY
if [[ "$summary_status" -eq 2 ]]; then
  echo "Stable clean-machine QA evidence contains duplicate JSON keys" >&2
  exit 1
elif [[ "$summary_status" -ne 0 ]]; then
  echo "Stable clean-machine QA evidence is not a schema 2 summary of this manifest (unexpected or missing fields, wrong value types, or another manifest): $evidence_name" >&2
  exit 1
fi

supported_owners=()
while IFS= read -r owner; do
  supported_owners+=("$owner")
done < <(jq -r '.supported_install_owners[]?' "$MANIFEST" | sort -u)

if [[ "${#supported_owners[@]}" -eq 0 ]]; then
  fail "Stable manifest has no supported_install_owners"
fi

required_gate_owners=()
while IFS= read -r owner; do
  required_gate_owners+=("$owner")
done < <(jq -r '.quality_gates.stable_clean_machine_qa.required_install_owners[]? // empty' "$MANIFEST" | sort -u)

for owner in "${required_gate_owners[@]}"; do
  if ! contains_value "$owner" "${supported_owners[@]}"; then
    fail "Stable clean-machine QA manifest gate includes unsupported required install owner: $(known_owner_label "$owner")"
  fi
done

never_carry_list=()
while IFS= read -r check_name; do
  never_carry_list+=("$check_name")
done < <(never_carry_checks)

for owner in "${supported_owners[@]}"; do
  if ! required_checks_for_owner "$owner" >/dev/null; then
    fail "Stable closeout does not know how to validate install owner: $(known_owner_label "$owner")"
    continue
  fi
  if ! contains_value "$owner" "${required_gate_owners[@]}"; then
    fail "Stable clean-machine QA manifest gate does not require supported install owner: $owner"
  fi
  if ! jq -e --arg owner "$owner" '[.install_owners[] | select(.owner == $owner)] | length == 1' "$evidence_path" >/dev/null; then
    fail "Stable clean-machine QA evidence must include exactly one entry for install owner: $owner"
    continue
  fi
  if ! jq -e \
    --arg owner "$owner" \
    --arg version "$version" \
    --arg channel "$channel" \
    --arg manifest_sha "$manifest_sha" \
    '
      .install_owners[]
      | select(.owner == $owner)
      | .local_platform.runtime == "ottto-service"
        and .local_platform.service_label == "net.ottto.service"
        and .local_platform.version == $version
        and .local_platform.release_channel == $channel
        and .local_platform.install_owner == $owner
        and .local_platform.protocol_version == 15
        and .local_platform.release_manifest_sha256 == $manifest_sha
    ' "$evidence_path" >/dev/null; then
    fail "Stable clean-machine QA evidence has invalid local-platform runtime binding for install owner: $owner"
  fi
  required_owner_checks=()
  while IFS= read -r check_name; do
    required_owner_checks+=("$check_name")
    never_carry=0
    if contains_value "$check_name" "${never_carry_list[@]}"; then
      never_carry=1
    fi
    static_ok=0
    if static_method_check "$check_name"; then
      static_ok=1
    fi
    check_json="$(jq -c --arg owner "$owner" --arg check_name "$check_name" \
      '.install_owners[] | select(.owner == $owner) | .checks[$check_name] // null' "$evidence_path")"
    # Pre-hosted: the hosted lane runs only after the immutable upload, so
    # every hosted_installer check is exactly not run.
    if [[ "$STAGE" == "pre-hosted" && "$owner" == "hosted_installer" ]]; then
      if ! jq -e '. == {"result": "not_run"}' <<<"$check_json" >/dev/null 2>&1; then
        fail "Stable clean-machine QA check $owner.$check_name must be exactly {\"result\":\"not_run\"} in the pre-hosted stage (the hosted lane runs after the immutable upload)"
      fi
      continue
    fi
    # passed: ran in this release (method static only for artifact checks).
    if jq -e --argjson static_ok "$static_ok" '
        type == "object"
        and .result == "passed"
        and keys == ["method", "result"]
        and (.method == "live" or .method == "scripted" or ($static_ok == 1 and .method == "static"))
      ' <<<"$check_json" >/dev/null; then
      continue
    fi
    # carried: from names an earlier X.Y.Z of the same X.Y line at most 5
    # patches back (or an RC of a version up to this one) where the check ran
    # live or scripted. The shape is checked for a precise message; carry is
    # not accepted until verified carry (against the earlier published
    # summary) ships.
    if ! jq -e '.result == "carried"' <<<"$check_json" >/dev/null 2>&1; then
      fail "Stable clean-machine QA check $owner.$check_name must be passed in this release, with method live or scripted (static only for artifact_checksum, formula_syntax, gatekeeper and native_gatekeeper)"
    elif [[ "$never_carry" == 1 ]]; then
      fail "Stable clean-machine QA check $owner.$check_name cannot be carried; it must pass in this release"
    elif ! jq -e --arg version "$version" '
        def ver: split(".") | map(tonumber);
        keys == ["from", "method", "result"]
        and (.method == "live" or .method == "scripted")
        and ((.from | sub("-rc[1-9][0-9]*$"; "") | ver) as $from
          | ($version | ver) as $this
          | $from[0] == $this[0]
            and $from[1] == $this[1]
            and $this[2] - $from[2] <= 5
            and (if (.from | test("-rc")) then $from[2] <= $this[2] else $from[2] < $this[2] end))
      ' <<<"$check_json" >/dev/null 2>&1; then
      fail "Stable clean-machine QA check $owner.$check_name is carried without a valid from (an earlier release of the same X.Y line at most 5 patches back) and method live or scripted"
    else
      fail "Stable clean-machine QA check $owner.$check_name is carried; carry is not accepted until verified carry ships, so it must pass in this release"
    fi
  done < <(required_checks_for_owner "$owner")
  while IFS= read -r check_name; do
    if ! contains_value "$check_name" "${required_owner_checks[@]}"; then
      fail "Stable clean-machine QA evidence includes unknown check $owner.$(known_check_label "$check_name")"
    fi
  done < <(jq -r --arg owner "$owner" '.install_owners[] | select(.owner == $owner) | .checks | keys[]' "$evidence_path" | sort -u)
done

while IFS= read -r owner; do
  if ! contains_value "$owner" "${supported_owners[@]}"; then
    fail "Stable clean-machine QA evidence includes unsupported install owner: $(known_owner_label "$owner")"
  fi
done < <(jq -r '.install_owners[].owner' "$evidence_path" | sort -u)

if [[ "$failures" -gt 0 ]]; then
  echo "Stable closeout gate failed with $failures issue(s)." >&2
  exit 1
fi

jq -r '
  .install_owners[] | .owner as $owner | .checks | to_entries[]
  | select(.value.result == "carried")
  | "stable-closeout: \($owner).\(.key) carried from \(.value.from) (\(.value.method))"
' "$evidence_path"
host_class="$(jq -r '.environment.host_class' "$evidence_path")"
passed_count="$(jq '[.install_owners[].checks[] | select(.result == "passed")] | length' "$evidence_path")"
if [[ "$STAGE" == "pre-hosted" ]]; then
  not_run_count="$(jq '[.install_owners[].checks[] | select(.result == "not_run")] | length' "$evidence_path")"
  echo "stable-closeout: pre-hosted summary (host class $host_class; $passed_count passed in this release, $not_run_count hosted_installer checks not run yet)"
  echo "Stable closeout pre-hosted gate passed for $version ($commit)"
  exit 0
fi
carried_count="$(jq '[.install_owners[].checks[] | select(.result == "carried")] | length' "$evidence_path")"
echo "Stable closeout gate passed for $version ($commit): $evidence_name (host class $host_class; $passed_count passed in this release, $carried_count carried)"
