#!/usr/bin/env bash
# Linux contract: every external command is inert; never run native work here.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
resource_test_tmp="$(mktemp -d)"
trap 'rm -rf "$resource_test_tmp"' EXIT
mkdir "$resource_test_tmp/bin" "$resource_test_tmp/receipts"
cat > "$resource_test_tmp/bin/uname" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${RESOURCE_FAKE_OS:-Darwin}"
STUB
cat > "$resource_test_tmp/bin/git" <<'STUB'
#!/usr/bin/env bash
if [[ "$1" == status ]]; then
  [[ "${RESOURCE_FAKE_DIRTY:-0}" == 0 ]] || echo ' M changed.rs'
else
  echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
fi
STUB
cat > "$resource_test_tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${RESOURCE_FAKE_HEAD:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
STUB
cat > "$resource_test_tmp/bin/pmset" <<'STUB'
#!/usr/bin/env bash
if [[ "${2:-}" == batt ]]; then
  printf "Now drawing from '%s'\n" "${RESOURCE_FAKE_POWER:-AC Power}"
else
  printf ' lowpowermode %s\n' "${RESOURCE_FAKE_LPM:-0}"
fi
STUB
cat > "$resource_test_tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$RESOURCE_FAKE_CALLS"
[[ "$*" == *'--exact --ignored --nocapture --test-threads=1'* ]]
[[ "${OTTTO_RESOURCE_QOS_PR:-}" == 1727 ]]
if [[ "$*" == *resource_native_ordinary_stage_qos* ]]; then
  [[ "${RESOURCE_FAKE_CARGO:-pass}" != ordinary_fail ]] || exit 1
  echo 'resource_native_qos ordinary=utility paced=background cycle_replay=tripped restoration=passed'
else
  [[ "$*" == *native_qos::foreground_gate::resource_native_first_import_foreground_gate* ]]
  [[ "${OTTTO_RESOURCE_QOS_HEAD:-}" == aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ]]
  case "${RESOURCE_FAKE_CARGO:-pass}" in
    gate_fail) exit 1 ;;
    zero) echo 'test result: ok. 0 passed; 0 failed;'; exit 0 ;;
    missing) echo 'test result: ok. 1 passed; 0 failed;'; exit 0 ;;
  esac
  verdict=pass
  [[ "${RESOURCE_FAKE_CARGO:-pass}" != verdict_fail ]] || verdict=fail
  receipt_head=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  [[ "${RESOURCE_FAKE_CARGO:-pass}" != receipt_head ]] || receipt_head=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  printf 'resource_native_first_import_gate pr=1727 head=%s cpu_p95_ratio=1.000000 io_p95_ratio=1.000000 rss_max_mib=100.000 importer_cpu_share=0.900000 energy_j=unavailable pages=3 thermal=unavailable->unavailable verdict=%s\n' "$receipt_head" "$verdict"
fi
echo 'test result: ok. 1 passed; 0 failed;'
STUB
chmod +x "$resource_test_tmp/bin/"*
export PATH="$resource_test_tmp/bin:$PATH" TMPDIR="$resource_test_tmp/receipts"
export RESOURCE_FAKE_CALLS="$resource_test_tmp/calls"
reset_case() {
  export RESOURCE_FAKE_OS=Darwin RESOURCE_FAKE_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export RESOURCE_FAKE_CARGO=pass RESOURCE_FAKE_DIRTY=0 RESOURCE_FAKE_POWER='AC Power' RESOURCE_FAKE_LPM=0
  export GITHUB_EVENT_NAME=pull_request OTTTO_RESOURCE_GATE_PHASE_SECONDS=120
  : > "$RESOURCE_FAKE_CALLS"
}
run_native() { bash "$repo_root/scripts/resource_native_first_import_gate.sh" 1727 > "$resource_test_tmp/output" 2>&1; }
reset_case
run_native
[[ "$(wc -l < "$RESOURCE_FAKE_CALLS" | tr -d ' ')" == 2 ]]
head -1 "$RESOURCE_FAKE_CALLS" | grep -q 'resource_native_ordinary_stage_qos'
[[ "$(find "$TMPDIR" -type f | wc -l | tr -d ' ')" == 1 ]]
for failure in os head event dirty battery lpm unknown_lpm ordinary_fail gate_fail zero missing verdict_fail receipt_head smoke; do
  reset_case
  case "$failure" in
    os) RESOURCE_FAKE_OS=Linux ;;
    head) RESOURCE_FAKE_HEAD=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    event) GITHUB_EVENT_NAME=merge_group ;;
    dirty) RESOURCE_FAKE_DIRTY=1 ;;
    battery) RESOURCE_FAKE_POWER='Battery Power' ;;
    lpm) RESOURCE_FAKE_LPM=1 ;;
    unknown_lpm) RESOURCE_FAKE_LPM=unknown ;;
    smoke) OTTTO_RESOURCE_GATE_PHASE_SECONDS=1 ;;
    *) RESOURCE_FAKE_CARGO="$failure" ;;
  esac
  if run_native; then echo "gate wrapper accepted invalid $failure" >&2; exit 1; fi
  case "$failure" in
    os|head|event|dirty|battery|lpm|unknown_lpm) [[ ! -s "$RESOURCE_FAKE_CALLS" ]] ;;
    ordinary_fail) [[ "$(wc -l < "$RESOURCE_FAKE_CALLS" | tr -d ' ')" == 1 ]] ;;
  esac
done
printf '%s\n' 'resource_native_first_import_gate wrapper tests passed'
