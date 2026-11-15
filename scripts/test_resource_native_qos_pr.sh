#!/usr/bin/env bash
# Portable wrapper contracts; cargo/gh/git/uname are inert stubs, not Mac tests.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
resource_test_tmp="$(mktemp -d)"
trap 'rm -rf "$resource_test_tmp"' EXIT
mkdir "$resource_test_tmp/bin"
cat > "$resource_test_tmp/bin/uname" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${RESOURCE_FAKE_OS:-Darwin}"
SH
cat > "$resource_test_tmp/bin/git" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
SH
cat > "$resource_test_tmp/bin/gh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "${RESOURCE_FAKE_HEAD:-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
SH
cat > "$resource_test_tmp/bin/cargo" <<'SH'
#!/usr/bin/env bash
if [[ "${RESOURCE_FAKE_CARGO:-pass}" == zero ]]; then
  printf '%s\n' 'test result: ok. 0 passed; 0 failed;'
  exit 0
fi
if [[ "${RESOURCE_FAKE_CARGO:-pass}" == fail ]]; then exit 1; fi
printf '%s\n' 'resource_native_qos ordinary=utility paced=background cycle_replay=tripped restoration=passed'
printf '%s\n' 'test result: ok. 1 passed; 0 failed;'
SH
chmod +x "$resource_test_tmp/bin/"*
export PATH="$resource_test_tmp/bin:$PATH"
run_native() { bash "$repo_root/scripts/resource_native_qos_pr.sh" 1 > "$resource_test_tmp/output" 2>&1; }
export GITHUB_EVENT_NAME=pull_request
export RESOURCE_FAKE_OS=Darwin RESOURCE_FAKE_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa RESOURCE_FAKE_CARGO=pass
run_native
for failure in os head event zero cargo; do
  export RESOURCE_FAKE_OS=Darwin RESOURCE_FAKE_HEAD=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa RESOURCE_FAKE_CARGO=pass GITHUB_EVENT_NAME=pull_request
  case "$failure" in
    os) RESOURCE_FAKE_OS=Linux ;;
    head) RESOURCE_FAKE_HEAD=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
    event) GITHUB_EVENT_NAME=merge_group ;;
    zero) RESOURCE_FAKE_CARGO=zero ;;
    cargo) RESOURCE_FAKE_CARGO=fail ;;
  esac
  if run_native; then echo "native PR wrapper accepted invalid $failure" >&2; exit 1; fi
done
printf '%s\n' 'resource_native_qos_pr wrapper tests passed'
