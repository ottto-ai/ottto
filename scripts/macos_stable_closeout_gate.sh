#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/macos_release_paths.sh
source "$ROOT/scripts/macos_release_paths.sh"

MANIFEST=""

usage() {
  cat <<'USAGE'
Usage: macos_stable_closeout_gate.sh --manifest <release-manifest.json>
       macos_stable_closeout_gate.sh --list-never-carry-checks

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
  app_bundle.move_service_to_app           from a serving Homebrew job, the
                                           installed app offers Move; after it, one
                                           app-owned job serves the target and no
                                           Homebrew process remains
  app_bundle.homebrew_second_install_safe_refusal
                                           a formula beside a running app never
                                           gets a second serving job and never
                                           silently takes ownership (the keg may
                                           exist)
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
    --list-never-carry-checks)
      never_carry_checks
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

# Diagnostics repeat a name from the evidence only when it is a plain
# identifier, so a failure message never echoes free text from the file.
safe_label() {
  if [[ "$1" =~ ^[a-z0-9_]{1,64}$ ]]; then
    printf '%s' "$1"
  else
    printf '%s' "<invalid name>"
  fi
}

require_command jq
require_command shasum
require_command grep
require_command find

if [[ -z "$MANIFEST" ]]; then
  usage >&2
  exit 2
fi
if [[ ! -f "$MANIFEST" ]]; then
  echo "Release manifest is missing: $MANIFEST" >&2
  exit 1
fi

manifest_dir="$(macos_release_manifest_dir "$MANIFEST")"

product="$(jq -r '.product // empty' "$MANIFEST")"
channel="$(jq -r '.channel // empty' "$MANIFEST")"
version="$(jq -r '.version // empty' "$MANIFEST")"
commit="$(jq -r '.commit // empty' "$MANIFEST")"
manifest_sha="$(shasum -a 256 "$MANIFEST" | awk '{print $1}')"

if [[ "$product" != "ottto-local-platform" ]]; then
  fail "Stable closeout requires product=ottto-local-platform, got: $product"
fi
if [[ "$channel" != "stable" ]]; then
  fail "Stable closeout requires channel=stable, got: $channel"
fi
# Canonical numeric triple: no leading zeros, at most 9 digits per component.
version_component='(0|[1-9][0-9]{0,8})'
if [[ ! "$version" =~ ^${version_component}\.${version_component}\.${version_component}$ ]]; then
  fail "Stable closeout manifest version must be X.Y.Z (canonical numbers, at most 9 digits each)"
fi
if [[ ! "$commit" =~ ^[0-9a-f]{7,40}$ ]]; then
  fail "Stable closeout manifest commit is not a git SHA prefix: $commit"
fi
if ! jq -e '.min_protocol_version == 15' "$MANIFEST" >/dev/null; then
  fail "Stable closeout manifest min_protocol_version must be 15"
fi

gate="$(jq -c '.quality_gates.stable_clean_machine_qa // empty' "$MANIFEST")"
if [[ -z "$gate" ]]; then
  fail "Stable manifest is missing quality_gates.stable_clean_machine_qa"
fi

gate_status="$(jq -r '.quality_gates.stable_clean_machine_qa.status // empty' "$MANIFEST")"
gate_evidence_path="$(jq -r '.quality_gates.stable_clean_machine_qa.evidence_path // empty' "$MANIFEST")"
if [[ "$gate_status" != "passed" && "$gate_status" != "not_run" ]]; then
  fail "Stable clean-machine QA manifest gate status must be passed or not_run"
fi
if [[ -z "$gate_evidence_path" ]]; then
  fail "Stable clean-machine QA gate is missing evidence_path"
fi

if [[ "$failures" -gt 0 ]]; then
  echo "Stable closeout gate failed with $failures issue(s)." >&2
  exit 1
fi

# The summary is a plain file name beside the manifest, never a path or a symlink.
if ! evidence_path="$(macos_release_path "$manifest_dir" "$gate_evidence_path")" || [[ ! -f "$evidence_path" ]]; then
  echo "Stable clean-machine QA summary is missing beside the manifest, or evidence_path is not a plain file name" >&2
  exit 1
fi
evidence_name="$(basename "$evidence_path")"

# The full QA record is private. The publisher uploads the release folder, so
# refuse a record anywhere in it, under any name.
private_records=0
while IFS= read -r record; do
  [[ -n "$record" ]] || continue
  record_name="$(basename "$record")"
  macos_release_filename "$record_name" || record_name="<invalid name>"
  echo "A private QA record is inside the release folder; move it out before publishing: $record_name" >&2
  private_records=$((private_records + 1))
done < <(
  {
    find "$manifest_dir" -name '*.record.json' -print
    grep -rlaF '"private_record"' "$manifest_dir" || true
  } | sort -u
)
if [[ "$private_records" -gt 0 ]]; then
  exit 1
fi

if grep -Eiq "/Users/|docs/dev|\\.agents|\\.claude|Bearer[[:space:]]+|claim_code|setup_run_token|account_id|machine_id|api[_-]?key|password" "$evidence_path"; then
  echo "Stable clean-machine QA evidence contains private path or secret-like material: $evidence_name" >&2
  exit 1
fi
if jq -e '.. | strings | select(. == "not_run" or test("^TODO"))' "$evidence_path" >/dev/null; then
  echo "Stable clean-machine QA evidence still contains template placeholders: $evidence_name" >&2
  exit 1
fi
if jq -e '.schema_version == 1' "$evidence_path" >/dev/null 2>&1; then
  echo "Stable clean-machine QA evidence must be schema_version 2 (v1 cannot record carried checks); write it with macos_stable_qa_summary.sh" >&2
  exit 1
fi

# Closed public schema: every object has exactly these keys and every leaf has
# a fixed shape, so neither free text nor a private record can pass.
if ! jq -e \
  --arg product "$product" \
  --arg channel "$channel" \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg manifest_sha "$manifest_sha" \
  '
    def name: type == "string" and test("^[a-z0-9_]{1,64}$");
    type == "object"
    and keys == ["checked_at", "environment", "gate", "install_owners", "manifest", "schema_version", "status"]
    and .schema_version == 2
    and .gate == "stable_clean_machine_qa"
    and .status == "passed"
    and (.checked_at | type == "string" and test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"))
    and (.manifest | type == "object" and keys == ["channel", "commit", "product", "sha256", "version"])
    and .manifest.product == $product
    and .manifest.channel == $channel
    and .manifest.version == $version
    and .manifest.commit == $commit
    and .manifest.sha256 == $manifest_sha
    and (.environment | type == "object" and keys == ["arch", "host_class", "macos_version"])
    and (.environment.host_class | IN("clean_vm", "clean_macos", "qa_user_on_shared_mac", "signing_mac", "developer_mac"))
    and (.environment.macos_version | type == "string" and test("^[0-9]{1,3}(\\.[0-9]{1,3}){0,2}$"))
    and (.environment.arch | IN("arm64", "x86_64", "universal"))
    and (.install_owners | type == "array" and length > 0)
    and all(.install_owners[];
      type == "object"
      and keys == ["checks", "local_platform", "owner", "status"]
      and (.owner | name)
      and .status == "passed"
      and (.local_platform | type == "object"
        and keys == ["install_owner", "protocol_version", "release_channel", "release_manifest_sha256", "runtime", "service_label", "version"])
      and (.checks | type == "object" and length > 0)
      and all(.checks | to_entries[];
        (.key | name)
        and (.value | type == "object")
        and ((.value | keys) == ["method", "result"] or (.value | keys) == ["from", "method", "result"])
        and (.value.result | name)
        and (.value.method | name)
        and (if (.value | has("from"))
          then (.value.from | type == "string"
            and test("^(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})\\.(0|[1-9][0-9]{0,8})(-rc[1-9][0-9]*)?$"))
          else true end)))
  ' "$evidence_path" >/dev/null 2>&1; then
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
    fail "Stable clean-machine QA manifest gate includes unsupported required install owner: $owner"
  fi
done

never_carry_list=()
while IFS= read -r check_name; do
  never_carry_list+=("$check_name")
done < <(never_carry_checks)

for owner in "${supported_owners[@]}"; do
  if ! required_checks_for_owner "$owner" >/dev/null; then
    fail "Stable closeout does not know how to validate install owner: $owner"
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
      fail "Stable clean-machine QA evidence includes unknown check $owner.$(safe_label "$check_name")"
    fi
  done < <(jq -r --arg owner "$owner" '.install_owners[] | select(.owner == $owner) | .checks | keys[]' "$evidence_path" | sort -u)
done

while IFS= read -r owner; do
  if ! contains_value "$owner" "${supported_owners[@]}"; then
    fail "Stable clean-machine QA evidence includes unsupported install owner: $(safe_label "$owner")"
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
carried_count="$(jq '[.install_owners[].checks[] | select(.result == "carried")] | length' "$evidence_path")"
echo "Stable closeout gate passed for $version ($commit): $evidence_name (host class $host_class; $passed_count passed in this release, $carried_count carried)"
