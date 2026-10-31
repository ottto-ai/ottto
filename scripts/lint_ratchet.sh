#!/usr/bin/env bash
# Pull-request lint ratchet, run inside the Linux "Runtime clippy" step.
#
# Fails when the diff from <base> to HEAD adds a Rust suppression that hides
# unused code: allow(dead_code), allow(unused...), a blanket #![allow(...)] or
# cfg_attr(not(test), allow(...)). A needed suppression is
# #[expect(<lint>, reason = "...")] on the smallest item. A line that the same
# diff also removes counts as moved, not added.
#
# When the diff touches Rust files, the PR body (PR_BODY) must also carry a
# "Reuse:" line naming what was searched and reused.
#
# Usage: PR_BODY="..." scripts/lint_ratchet.sh <base-rev>
set -euo pipefail

base=${1:?usage: PR_BODY=... lint_ratchet.sh <base-rev>}
diff=$(git diff --unified=0 --no-color --no-ext-diff "$base" HEAD -- '*.rs')
[ -n "$diff" ] || exit 0

status=0
offenders=$(printf '%s\n' "$diff" | awk '
  # Each attribute on the line, without spaces and reason strings, so adding a
  # reason to an existing allow compares equal to the removed original.
  function attrs(text, out,   n, i, j, d, a) {
    n = 0
    for (i = 1; i <= length(text); i++) {
      if (substr(text, i, 2) != "#[" && substr(text, i, 3) != "#![") continue
      d = 0
      for (j = i; j <= length(text); j++) {
        if (substr(text, j, 1) == "[") d++
        else if (substr(text, j, 1) == "]" && --d == 0) break
      }
      a = substr(text, i, j - i + 1); i = j
      gsub(/[ \t]/, "", a); gsub(/,?reason="[^"]*"/, "", a)
      out[++n] = a
    }
    return n
  }
  function hides(a) {
    return a ~ /allow\(([^)]*,)?(dead_code|unused)/ || a ~ /^#!\[allow\(/ ||
      a ~ /cfg_attr\(not\(test\),allow\(/
  }
  /^\+\+\+ / { file = substr($0, 7); next }
  /^--- / { next }
  /^@@ / { split($3, h, ","); line = substr(h[1], 2) + 0; next }
  /^-/ { k = attrs($0, got); for (i = 1; i <= k; i++) removed[got[i]] = 1; next }
  /^\+/ {
    k = attrs($0, got)
    for (i = 1; i <= k; i++) if (hides(got[i])) { hits[++n] = file ":" line ": " got[i]; keys[n] = got[i] }
    line++
  }
  END { for (i = 1; i <= n; i++) if (!(keys[i] in removed)) print hits[i] }
')
if [ -n "$offenders" ]; then
  echo "error: this PR adds suppressions that hide unused code:" >&2
  printf '%s\n' "$offenders" | sed 's/^/  /' >&2
  echo "Delete the unused code, or use #[expect(<lint>, reason = \"...\")] on the smallest item." >&2
  status=1
fi

if ! printf '%s\n' "${PR_BODY:-}" | grep -qE '^[[:space:]>*_`-]*Reuse:'; then
  echo "error: the PR body has no 'Reuse:' line (Reuse: <item> | searched: <terms> | reused/extended <path::fn>)." >&2
  echo "Add it, then push a commit: a re-run reads the body from the original event." >&2
  status=1
fi
exit "$status"
