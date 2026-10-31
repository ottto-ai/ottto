#!/usr/bin/env bash
# Pull-request lint ratchet, run inside the Linux "Runtime clippy" step.
#
# Fails when HEAD has more Rust suppressions that hide unused code than <base>
# had, counted per attribute across all changed .rs files: allow(dead_code),
# allow(unused...), a blanket #![allow(...)] or cfg_attr(not(test), allow(...)).
# Attributes are read whole from both full file versions (multiline ones too,
# skipping strings and comments) and compared without whitespace and reason, so
# moving one or adding a reason passes, while each extra copy fails. A needed
# suppression is #[expect(<lint>, reason = "...")] on the smallest item.
#
# When the diff touches Rust files, the PR body (PR_BODY) must also carry a
# "Reuse:" line naming what was searched and reused.
#
# Usage: PR_BODY="..." scripts/lint_ratchet.sh <base-rev>
set -euo pipefail

base=${1:?usage: PR_BODY=... lint_ratchet.sh <base-rev>}
[ -n "$(git diff --name-only "$base" HEAD -- '*.rs')" ] || exit 0

status=0
python3 -I - "$base" <<'PY' || status=1
import collections, re, subprocess, sys

base = sys.argv[1]
# Comments, string/char literals and attribute brackets; everything else is code.
TOKEN = re.compile(r"""//[^\n]*|/\*|[bc]?r(\#*)"|[bc]?"(?:\\.|[^"\\])*"|b?'(?:\\.|[^'\\])'|\#!?\[|\[|\]""", re.S)
HIDES = re.compile(r"allow\(([^)]*,)?(dead_code|unused)|^#!\[allow\(|cfg_attr\(not\(test\),allow\(")

def attributes(text):
    """Yield (offset, attribute without whitespace, comments and reason)."""
    pos, depth, start, parts = 0, 0, 0, []
    while (m := TOKEN.search(text, pos)):
        tok, end = m.group(), m.end()
        if depth:
            parts.append(re.sub(r"\s+", "", text[pos:m.start()]))
        if tok.startswith("//"):
            pass
        elif tok == "/*":
            nest = 1
            while nest and end < len(text):
                if text.startswith("/*", end): nest, end = nest + 1, end + 2
                elif text.startswith("*/", end): nest, end = nest - 1, end + 2
                else: end += 1
        elif m.group(1) is not None:  # raw string r#"..."#
            close = text.find('"' + m.group(1), end)
            end = len(text) if close < 0 else close + 1 + len(m.group(1))
        if not depth:
            if tok.startswith("#"):
                depth, start, parts = 1, m.start(), [tok]
            pos = end
            continue
        if tok.startswith(("//", "/*")):
            pass
        elif tok[-1] in "\"'":  # a literal: drop it when it is the reason
            if "".join(parts).endswith("reason="):
                parts = [re.sub(r",?reason=$", "", "".join(parts))]
            else:
                parts.append(text[m.start():end])
        else:
            depth += 1 if tok.endswith("[") else -1
            parts.append(tok)
            if not depth:
                yield start, "".join(parts).replace(",)", ")")
        pos = end

def show(rev, path):
    out = subprocess.run(["git", "show", f"{rev}:{path}"], capture_output=True)
    return out.stdout.decode("utf-8", "replace") if out.returncode == 0 else ""

paths = subprocess.run(["git", "diff", "--name-only", "--no-renames", "-z", base, "HEAD", "--", "*.rs"],
                       capture_output=True, check=True).stdout.decode().split("\0")
counts = {rev: collections.Counter() for rev in (base, "HEAD")}
where = collections.defaultdict(list)
for path in filter(None, paths):
    for rev in counts:
        text = show(rev, path)
        for start, attr in attributes(text):
            if HIDES.search(attr):
                counts[rev][attr] += 1
                if rev == "HEAD":
                    line = text.count("\n", 0, start) + 1
                    where[attr].append(f"{path}:{line}")
bad = [a for a in counts["HEAD"] if counts["HEAD"][a] > counts[base][a]]
if bad:
    print("error: this PR adds suppressions that hide unused code:", file=sys.stderr)
    for a in bad:
        print(f"  {a}: {counts[base][a]} before, {counts['HEAD'][a]} now ({', '.join(where[a])})", file=sys.stderr)
    print('Delete the unused code, or use #[expect(<lint>, reason = "...")] on the smallest item.', file=sys.stderr)
    sys.exit(1)
PY

if ! printf '%s\n' "${PR_BODY:-}" | grep -qE '^[[:space:]>*_`-]*Reuse:'; then
  echo "error: the PR body has no 'Reuse:' line (Reuse: <item> | searched: <terms> | reused/extended <path::fn>)." >&2
  echo "Add it, then push a commit: a re-run reads the body from the original event." >&2
  status=1
fi
exit "$status"
