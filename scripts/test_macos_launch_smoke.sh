#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SMOKE="$ROOT/scripts/macos_launch_smoke.sh"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "Skipping macOS launch smoke test on non-Darwin host."
  exit 0
fi

fail() {
  echo "$*" >&2
  exit 1
}

# make_app <name> <body>: a bundle whose executable is a shell script.
make_app() {
  local name="$1"
  local body="$2"
  local app="$TMP_DIR/$name.app"
  mkdir -p "$app/Contents/MacOS"
  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>$name</string>
  <key>CFBundleIdentifier</key><string>net.ottto.SmokeTest.$name</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>CFBundleShortVersionString</key><string>0.0.1</string>
</dict>
</plist>
PLIST
  printf '#!/usr/bin/env bash\n%s\n' "$body" > "$app/Contents/MacOS/$name"
  chmod +x "$app/Contents/MacOS/$name"
  printf '%s' "$app"
}

# The survivor mimics the Companion guard: it takes its lock under the
# Foundation home the smoke hands it, and refuses to run against the real one.
SEEN_HOME="$TMP_DIR/seen-home"
survivor="$(make_app SmokeSurvivor "
[[ -n \"\${CFFIXED_USER_HOME:-}\" && \"\$CFFIXED_USER_HOME\" != \"\$HOME\" ]] || exit 0
printf '%s' \"\$CFFIXED_USER_HOME\" > '$SEEN_HOME'
mkdir -p \"\$CFFIXED_USER_HOME/Library/Application Support/Ottto\"
: > \"\$CFFIXED_USER_HOME/Library/Application Support/Ottto/companion.lock\"
exec sleep 30")"
bash "$SMOKE" --app "$survivor" --wait-seconds 1 --output "$TMP_DIR/survivor.json" >/dev/null
jq -e '.status == "passed" and .process_survived_wait == true
  and .failure_reason == null and .isolated_user_home == true
  and .singleton_lock_isolated == true' "$TMP_DIR/survivor.json" >/dev/null \
  || fail "survivor app should pass with an isolated singleton lock: $(cat "$TMP_DIR/survivor.json")"
[[ -s "$SEEN_HOME" && "$(cat "$SEEN_HOME")" != "$HOME" ]] \
  || fail "smoke must launch the app with an isolated CFFIXED_USER_HOME"
[[ ! -e "$(cat "$SEEN_HOME")" ]] || fail "smoke must remove its isolated home"

handoff="$(make_app SmokeHandoff 'exit 0')"
if bash "$SMOKE" --app "$handoff" --wait-seconds 1 --output "$TMP_DIR/handoff.json" \
  >/dev/null 2>"$TMP_DIR/handoff.err"; then
  fail "an early clean exit must fail the smoke"
fi
jq -e '.status == "failed" and .exit_code == 0
  and .failure_reason == "clean_exit_before_wait"' "$TMP_DIR/handoff.json" >/dev/null \
  || fail "clean early exit evidence is wrong: $(cat "$TMP_DIR/handoff.json")"
grep -q 'single-instance handoff' "$TMP_DIR/handoff.err" \
  || fail "clean early exit must explain the single-instance handoff"

# Packaged mode names the app by its release filename and refuses an app or
# output outside the release folder.
release_dir="$(cd "$TMP_DIR" && pwd -P)"
bash "$SMOKE" --app "$survivor" --manifest-dir "$TMP_DIR" --wait-seconds 1 \
  --output "$TMP_DIR/packaged.json" >/dev/null
jq -e '.status == "passed" and .app_path == "SmokeSurvivor.app"' "$TMP_DIR/packaged.json" >/dev/null \
  || fail "packaged evidence must record the app filename: $(cat "$TMP_DIR/packaged.json")"
if grep -Fq "$release_dir" "$TMP_DIR/packaged.json" || grep -Fq "$TMP_DIR" "$TMP_DIR/packaged.json"; then
  fail "packaged evidence must not carry a build-host path"
fi
mkdir -p "$TMP_DIR/elsewhere"
if bash "$SMOKE" --app "$survivor" --manifest-dir "$TMP_DIR/elsewhere" --wait-seconds 1 \
  --output "$TMP_DIR/elsewhere/packaged.json" >/dev/null 2>"$TMP_DIR/outside.err"; then
  fail "packaged mode must refuse an app outside the release folder"
fi
grep -q 'directly inside --manifest-dir' "$TMP_DIR/outside.err" \
  || fail "packaged mode must explain the refused app location"
if bash "$SMOKE" --app "$survivor" --manifest-dir "$TMP_DIR" --wait-seconds 1 \
  --output "$TMP_DIR/elsewhere/packaged.json" >/dev/null 2>&1; then
  fail "packaged mode must refuse evidence written outside the release folder"
fi
ln -s "$(basename "$survivor")" "$TMP_DIR/Linked.app"
if bash "$SMOKE" --app "$TMP_DIR/Linked.app" --manifest-dir "$TMP_DIR" --wait-seconds 1 \
  --output "$TMP_DIR/linked.json" >/dev/null 2>&1; then
  fail "packaged mode must refuse a symlinked app"
fi

crasher="$(make_app SmokeCrasher 'exit 3')"
if bash "$SMOKE" --app "$crasher" --wait-seconds 1 --output "$TMP_DIR/crasher.json" \
  >/dev/null 2>"$TMP_DIR/crasher.err"; then
  fail "a nonzero early exit must fail the smoke"
fi
jq -e '.status == "failed" and .exit_code == 3
  and .failure_reason == "exited_before_wait"' "$TMP_DIR/crasher.json" >/dev/null \
  || fail "nonzero early exit evidence is wrong: $(cat "$TMP_DIR/crasher.json")"
if grep -q 'single-instance handoff' "$TMP_DIR/crasher.err"; then
  fail "a nonzero exit must not be reported as a single-instance handoff"
fi

# Diagnostic report filenames carry the host name: evidence records one fixed
# entry per report, at most five, and never the name.
REPORT_HOME="$TMP_DIR/report-home"
mkdir -p "$REPORT_HOME/Library/Logs/DiagnosticReports"
reporter="$(make_app SmokeReporter "
for n in 1 2 3 4 5 6 7; do
  : > \"\$HOME/Library/Logs/DiagnosticReports/SmokeReporter_2026-01-01-00000\${n}_example-host.ips\"
done
exit 4")"
if HOME="$REPORT_HOME" bash "$SMOKE" --app "$reporter" --wait-seconds 1 \
  --output "$TMP_DIR/reporter.json" >/dev/null 2>&1; then
  fail "a crash report must fail the smoke"
fi
jq -e '.status == "failed" and .failure_reason == "crash_report"
  and .crash_reports == ["diagnostic_report", "diagnostic_report", "diagnostic_report", "diagnostic_report", "diagnostic_report"]' \
  "$TMP_DIR/reporter.json" >/dev/null \
  || fail "crash evidence must be redacted and capped: $(cat "$TMP_DIR/reporter.json")"
if grep -q 'example-host' "$TMP_DIR/reporter.json"; then
  fail "crash evidence must not carry diagnostic report filenames"
fi

echo "macOS launch smoke tests passed"
