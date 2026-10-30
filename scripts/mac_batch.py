#!/usr/bin/env python3
"""Combine several open PRs into ONE branch Mac run of Public CI (ci.yml).

A branch Mac run ("Rust contracts" on workflow_dispatch) takes ~35-49 min of
one of the org's five hosted Macs. When several PRs wait for one, this helper
merges their heads onto the base branch as one temporary integration branch
(mac-batch/<stamp>-<prs>), dispatches one run on it, and afterwards maps each
failing test back to the PR(s) whose diff touches it.

Usage:
  mac_batch.py plan     [options] <pr> <pr> [<pr>...]
  mac_batch.py dispatch [options] [--dry-run] --gate <script> <pr> <pr> [...]
  mac_batch.py report   [options] --run <run-id> [--pr <n>] [--log-file <f>]
                        [--members <n>[=<sha>],...] [--delete-branch]
  mac_batch.py detect   [options] (<pr>... | --range <base>..<head>)

  plan      Fetch the PR heads, refuse PRs that are closed, from forks, not on
            the base branch, without green Linux checks on the exact head, or
            already in another live mac-batch branch; merge them in memory
            (git merge-tree, no worktree) and print the pairs that conflict,
            the integration commit, the macOS-only risk of each PR and the
            dispatch it would do. Never pushes or dispatches. Exit 2 = refused.
  dispatch  plan, then run the Mac dispatch gate (--gate or
            OTTTO_MAC_DISPATCH_GATE; exit 0 = go, 1 = wait, 3 = stale state),
            push the branch and dispatch ci.yml on it. --dry-run stops after
            the plan and does NOT call the gate (an OK reserves a Mac slot).
  report    After the run completes: per failing test, which PR(s) touch the
            test function, its file or the code under test; per PR whether the
            run counts as its Mac evidence (CLEARED), it must fix and re-run
            (SUSPECT, exit 4), or the run proved nothing for this head
            (NO-EVIDENCE or STALE, exit 5); exit 0 = every member CLEARED.
            --members replays attribution on any finished run (evaluation).
  detect    Pre-queue check from the diff alone: does the PR add or change
            tests or code that only macOS exercises (cfg(target_os = "macos"),
            cfg_attr(not(target_os = "macos"), ignore), early returns on
            layout_supported(), HeapLayoutBound impls)? Exit 10 = branch Mac
            run needed before the merge guard, 11 = advised, 0 = Linux enough.

Options: --repo <owner/name> (default ottto-ai/ottto), --remote <name>
(default origin), --base <branch> (default main), --max-members <n>
(default 4), --skip-linux-check, --allow-overlap.

Combined-run evidence: a CLEARED PR may cite the run as its branch Mac evidence
only while its head is exactly the head recorded in the integration commit
(Mac-Batch-Member trailer) or a head with the identical patch (report checks
both). The merge queue still re-tests every PR on top of the current base.
Delete the branch afterwards (report --delete-branch). Needs git >= 2.38 and
an authenticated gh; dispatch needs a token allowed to run workflows.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

WORKFLOW = "ci.yml"
MAC_JOB = "Rust contracts"
LINUX_CHECKS = ("Rust tests (Linux)", "Rust format (Linux)")
BRANCH_PREFIX = "mac-batch/"
TRAILER_BASE = "Mac-Batch-Base"
TRAILER_MEMBER = "Mac-Batch-Member"
EXIT_REFUSED = 2
EXIT_WAIT = 1
EXIT_STALE = 3
EXIT_MAC_NEEDED = 10
EXIT_MAC_ADVISED = 11


class Refused(Exception):
    pass


class Runner:
    """All external commands go through here; tests replace gh()."""

    def __init__(self, cwd: str):
        self.cwd = cwd

    def run(self, args: Sequence[str], check: bool = True, input_text: Optional[str] = None,
            env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        full_env = None
        if env:
            full_env = dict(os.environ)
            full_env.update(env)
        proc = subprocess.run(list(args), cwd=self.cwd, input=input_text, text=True,
                              capture_output=True, env=full_env)
        if check and proc.returncode != 0:
            raise Refused(f"command failed ({proc.returncode}): {' '.join(args)}\n{proc.stderr.strip()}")
        return proc

    def git(self, *args: str, check: bool = True, input_text: Optional[str] = None,
            env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
        return self.run(["git", *args], check=check, input_text=input_text, env=env)

    def gh(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        return self.run(["gh", *args], check=check)

    def gate(self, path: str) -> subprocess.CompletedProcess:
        return self.run(["bash", path], check=False)


# ---------------------------------------------------------------- Rust parsing

ITEM_RE = re.compile(
    r'^[ \t]*(?:pub(?:\([^)\n]*\))?\s+)?(?:(?:const|async|unsafe|default|extern(?:\s+"[^"\n]*")?)\s+)*'
    r'(?:(fn)\s+([A-Za-z_]\w*)|(mod)\s+([A-Za-z_]\w*)\s*\{|(impl)\b([^{;]*)\{)', re.M)
TEST_ATTR_RE = re.compile(r'#\[\s*(?:[\w:]+::)?test\b')
LINUX_IGNORE_RE = re.compile(r'cfg_attr\(\s*not\(\s*target_os\s*=\s*"macos"\s*\)\s*,\s*ignore')
CFG_RE = re.compile(r'#!?\[\s*cfg\s*\(')
PLATFORM_PROBE_RE = re.compile(r'\blayout_supported\s*\(\s*\)|cfg!\(\s*target_os\s*=\s*"macos"\s*\)')
LAYOUT_USE_RE = re.compile(r'\blayout_supported\s*\(|heap_layout_bound::bound\s*\(|cfg!\(\s*target_os\s*=\s*"macos"\s*\)')
LAYOUT_CORE_FILES = ("heap_layout_bound.rs", "owned_heap.rs")


def mask_rust(text: str) -> str:
    """Blank comments and string/char literal contents, keeping offsets and newlines."""
    out = list(text)
    n = len(text)

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    i = 0
    while i < n:
        c = text[i]
        prev_ident = i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "rb" and not prev_ident and re.match(r'(?:br|r)(#*)"', text[i:i + 300]):
            m = re.match(r'(?:br|r)(#*)"', text[i:i + 300])
            close = '"' + m.group(1)
            start = i + m.end()
            j = text.find(close, start)
            j = n if j < 0 else j
            blank(start, j)
            i = j + len(close)
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif c == "'":
            m = re.match(r"'(?:\\(?:u\{[0-9A-Fa-f]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])'", text[i:i + 12])
            if m:
                blank(i + 1, i + m.end() - 1)
                i += m.end()
            else:
                i += 1  # lifetime or label
        else:
            i += 1
    return "".join(out)


@dataclass
class Item:
    kind: str          # fn | mod | impl
    name: str          # fn/mod name, or the impl header text
    start: int         # first line incl. attributes (1-based)
    decl: int          # declaration line
    end: int           # closing brace line
    attrs: str         # raw attribute and doc lines above the item
    body: str          # raw text of the item from decl to end

    @property
    def is_test(self) -> bool:
        return self.kind == "fn" and bool(TEST_ATTR_RE.search(self.attrs))


def _macos_cfg(attrs: str) -> bool:
    """True when a #[cfg(...)] on the item requires macOS."""
    for m in CFG_RE.finditer(attrs):
        depth, j = 1, m.end()
        while j < len(attrs) and depth:
            depth += {"(": 1, ")": -1}.get(attrs[j], 0)
            j += 1
        expr = attrs[m.end():j - 1]
        if re.search(r'target_os\s*=\s*"macos"', expr) and "not(" not in expr and "any(" not in expr:
            return True
    return False


def _attrs_above(lines: List[str], decl_idx: int) -> Tuple[int, str]:
    k = decl_idx - 1
    while k >= 0 and decl_idx - k <= 40:
        s = lines[k].strip()
        if s.startswith("//") or s.startswith("#"):
            k -= 1
            continue
        if not s or s.endswith(("}", ";", "{")):
            break
        k -= 1
    return k + 2, "\n".join(lines[k + 1:decl_idx])


def rust_items(text: str) -> List[Item]:
    masked = mask_rust(text)
    pairs: Dict[int, int] = {}
    stack: List[int] = []
    for pos, ch in enumerate(masked):
        if ch == "{":
            stack.append(pos)
        elif ch == "}" and stack:
            pairs[stack.pop()] = pos
    line_starts = [0]
    for pos, ch in enumerate(text):
        if ch == "\n":
            line_starts.append(pos + 1)

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    lines = text.split("\n")
    items: List[Item] = []
    for m in ITEM_RE.finditer(masked):
        if m.group(1):
            kind, name = "fn", m.group(2)
            depth, j = 0, m.end()
            open_pos = None
            while j < len(masked):
                ch = masked[j]
                if ch in "([":
                    depth += 1
                elif ch in ")]":
                    depth -= 1
                elif ch == ";" and depth <= 0:
                    break
                elif ch == "{" and depth <= 0:
                    open_pos = j
                    break
                j += 1
        elif m.group(3):
            kind, name, open_pos = "mod", m.group(4), m.end() - 1
        else:
            kind, name, open_pos = "impl", " ".join(text[m.start(6):m.end(6)].split()), m.end() - 1
        if open_pos is None or open_pos not in pairs:
            continue
        decl = line_of(m.start() + (len(m.group(0)) - len(m.group(0).lstrip())))
        start, attrs = _attrs_above(lines, decl - 1)
        end = line_of(pairs[open_pos])
        items.append(Item(kind, name, start, decl, end, attrs, "\n".join(lines[decl - 1:end])))
    return items


def enclosing(items: List[Item], line: int) -> List[Item]:
    """Items containing the line, innermost first."""
    hits = [it for it in items if it.start <= line <= it.end]
    return sorted(hits, key=lambda it: it.end - it.start)


def probe_fns(items: List[Item]) -> Set[str]:
    """File-local helpers returning bool that ask whether the platform is macOS/layout."""
    names = set()
    for it in items:
        if it.kind == "fn" and not it.is_test and PLATFORM_PROBE_RE.search(it.body):
            header = it.body.split("{", 1)[0]
            if re.search(r"->\s*bool", header):
                names.add(it.name)
    return names


# ---------------------------------------------------------------- git helpers

HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_new_lines(diff_text: str) -> Dict[str, Set[int]]:
    """New-side line numbers per file from a -U0 diff (pure deletions mark the
    lines around the cut)."""
    out: Dict[str, Set[int]] = {}
    cur: Optional[str] = None
    for line in diff_text.splitlines():
        if line.startswith("+++ "):
            path = line[4:]
            cur = path[2:] if path.startswith("b/") else None
            if cur is not None:
                out.setdefault(cur, set())
            continue
        m = HUNK_RE.match(line)
        if m and cur is not None:
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            if count == 0:
                out[cur].update({max(start, 1), start + 1})
            else:
                out[cur].update(range(start, start + count))
    return out


@dataclass
class Change:
    files: Set[str]
    lines: Dict[str, Set[int]]
    head: str
    base: str


def member_change(r: Runner, base: str, head: str) -> Change:
    mb = r.git("merge-base", base, head).stdout.strip()
    names = r.git("diff", "--name-only", "--no-renames", mb, head).stdout.split()
    diff = r.git("diff", "-U0", "--no-color", "--no-ext-diff", "--no-renames", mb, head).stdout
    return Change(set(names), changed_new_lines(diff), head, mb)


def file_at(r: Runner, rev: str, path: str) -> Optional[str]:
    p = r.git("show", f"{rev}:{path}", check=False)
    return p.stdout if p.returncode == 0 else None


def macos_only_paths(r: Runner, rev: str) -> Set[str]:
    """Files compiled only on macOS: #![cfg(target_os = "macos")] files and
    modules declared under #[cfg(target_os = "macos")] (paths, plus dir prefixes
    ending in '/')."""
    found: Set[str] = set()
    p = r.git("grep", "-l", "-E", r'^#!\[cfg\(target_os = "macos"\)\]', rev, "--", "*.rs", check=False)
    for line in p.stdout.splitlines():
        found.add(line.split(":", 1)[1])
    p = r.git("grep", "-n", "-B4", "-E", r"^\s*(pub(\([^)]*\))?\s+)?mod\s+\w+\s*;", rev, "--", "*.rs", check=False)
    block: List[str] = []
    for line in p.stdout.splitlines() + ["--"]:
        if line == "--":
            _resolve_block(block, found)
            block = []
        else:
            block.append(line)
    return found


def _resolve_block(block: List[str], found: Set[str]) -> None:
    attrs: List[str] = []
    for raw in block:
        m = re.match(r"^[^:]+:(.+?)[:-](\d+)[:-](.*)$", raw)
        if not m:
            continue
        path, text = m.group(1), m.group(3)
        md = re.match(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;", text)
        if not md:
            s = text.strip()
            attrs = attrs + [s] if (s.startswith("#") or s.startswith("//")) else []
            continue
        joined = "\n".join(attrs)
        attrs = []
        if not _macos_cfg(joined):
            continue
        parent_dir = os.path.dirname(path)
        pm = re.search(r'#\[\s*path\s*=\s*"([^"]+)"', joined)
        if pm:
            found.add(os.path.normpath(os.path.join(parent_dir, pm.group(1))))
            continue
        base = os.path.basename(path)
        mod_dir = parent_dir if base in ("lib.rs", "main.rs", "mod.rs") else path[:-3]
        name = md.group(1)
        found.add(f"{mod_dir}/{name}.rs")
        found.add(f"{mod_dir}/{name}/")


def in_macos_only(path: str, macos_paths: Set[str]) -> bool:
    if path in macos_paths:
        return True
    return any(p.endswith("/") and path.startswith(p) for p in macos_paths) or any(
        path.startswith(p[:-3] + "/") for p in macos_paths if p.endswith(".rs"))


# ---------------------------------------------------------------- detector

@dataclass
class Finding:
    level: str   # NEEDED | ADVISED
    path: str
    line: int
    what: str


@dataclass
class Detection:
    findings: List[Finding] = field(default_factory=list)
    mac_tests: Set[Tuple[str, str]] = field(default_factory=set)   # (file, fn) that only run on macOS
    changed_fns: Set[Tuple[str, str]] = field(default_factory=set)

    @property
    def verdict(self) -> str:
        levels = {f.level for f in self.findings}
        return "MAC-NEEDED" if "NEEDED" in levels else ("MAC-ADVISED" if levels else "LINUX-ENOUGH")


def detect_change(r: Runner, ch: Change, macos_paths: Optional[Set[str]] = None) -> Detection:
    det = Detection()
    if macos_paths is None:
        macos_paths = macos_only_paths(r, ch.head)
    for path in sorted(ch.files):
        name = os.path.basename(path)
        if path == ".github/workflows/ci.yml":
            det.findings.append(Finding("NEEDED", path, 0, "changes the workflow that runs the macOS job"))
        elif name in ("rust-toolchain", "rust-toolchain.toml") or name in LAYOUT_CORE_FILES:
            det.findings.append(Finding("NEEDED", path, 0, "changes the heap-layout core or toolchain the macOS layout gates pin"))
        elif name == "Cargo.lock":
            det.findings.append(Finding("ADVISED", path, 0, "dependency versions change heap layouts checked only on macOS"))
        if not path.endswith(".rs"):
            continue
        text = file_at(r, ch.head, path)
        if text is None:
            continue  # deleted file
        lines = ch.lines.get(path, set())
        file_gated = in_macos_only(path, macos_paths) or re.search(r'^#!\[cfg\(target_os = "macos"\)\]', text, re.M)
        if file_gated and lines:
            det.findings.append(Finding("NEEDED", path, min(lines), "file is compiled only on macOS"))
        items = rust_items(text)
        probes = probe_fns(items)
        probe_call = re.compile(r"\b(?:%s)\s*\(" % "|".join(sorted(probes))) if probes else None
        reported: Set[Tuple[str, int, str]] = set()
        for ln in sorted(lines):
            chain = enclosing(items, ln)
            fn = next((it for it in chain if it.kind == "fn"), None)
            test = next((it for it in chain if it.is_test), None)
            if fn is not None:
                det.changed_fns.add((path, fn.name))
            gated_by = next((it for it in chain if _macos_cfg(it.attrs)), None)
            hl = next((it for it in chain if it.kind == "impl" and "HeapLayoutBound" in it.name), None)
            reasons: List[Tuple[str, int, str]] = []
            if test is not None:
                if LINUX_IGNORE_RE.search(test.attrs):
                    reasons.append(("NEEDED", test.decl, f"test {test.name} is ignored off macOS"))
                elif gated_by is not None or file_gated:
                    reasons.append(("NEEDED", test.decl, f"test {test.name} compiles only on macOS"))
                elif PLATFORM_PROBE_RE.search(test.body) or (probe_call and probe_call.search(test.body)):
                    reasons.append(("NEEDED", test.decl, f"test {test.name} returns early unless macOS layout is supported"))
                if reasons:
                    det.mac_tests.add((path, test.name))
            elif gated_by is not None and not file_gated:
                reasons.append(("NEEDED", gated_by.decl, f"code under cfg(target_os = \"macos\") ({gated_by.kind} {gated_by.name})"))
            elif hl is not None:
                reasons.append(("NEEDED", hl.decl, f"heap layout bound impl ({hl.name}) runs only where layout is supported (macOS)"))
            elif fn is not None and LAYOUT_USE_RE.search(fn.body):
                reasons.append(("ADVISED", fn.decl, f"fn {fn.name} branches on macOS layout support"))
            for key in reasons:
                if key not in reported:
                    reported.add(key)
                    det.findings.append(Finding(key[0], path, key[1], key[2]))
    return det


# ---------------------------------------------------------------- GitHub/PR model

@dataclass
class Member:
    number: int
    head: str
    branch: str
    linux: Dict[str, str] = field(default_factory=dict)


def gh_json(r: Runner, *args: str):
    return json.loads(r.gh(*args).stdout or "null")


def pr_member(r: Runner, repo: str, number: int, base: str, linux_check: bool) -> Member:
    pr = gh_json(r, "pr", "view", str(number), "-R", repo, "--json",
                 "number,state,headRefOid,headRefName,baseRefName,isCrossRepository,statusCheckRollup")
    if pr["state"] != "OPEN":
        raise Refused(f"#{number} is {pr['state'].lower()}")
    if pr["isCrossRepository"]:
        raise Refused(f"#{number} comes from a fork; batch only same-repository branches")
    if pr["baseRefName"] != base:
        raise Refused(f"#{number} targets {pr['baseRefName']}, not {base}")
    head = pr["headRefOid"]
    linux: Dict[str, str] = {}
    for c in pr.get("statusCheckRollup") or []:
        name = c.get("name")
        if name in LINUX_CHECKS and linux.get(name) != "SUCCESS":
            linux[name] = (c.get("conclusion") or c.get("status") or "").upper()
    if linux_check:
        bad = [f"{n}={linux.get(n, 'MISSING')}" for n in LINUX_CHECKS if linux.get(n) != "SUCCESS"]
        if bad:
            raise Refused(f"#{number} head {head[:10]} lacks green Linux checks ({', '.join(bad)}); Linux first")
    return Member(number, head, pr["headRefName"], linux)


def remote_base(r: Runner, remote: str, base: str) -> str:
    out = r.git("ls-remote", remote, f"refs/heads/{base}").stdout.split()
    if not out:
        raise Refused(f"{remote} has no branch {base}")
    return out[0]


def fetch(r: Runner, remote: str, refs: Iterable[str]) -> None:
    r.git("fetch", "-q", "--no-tags", remote, *refs)


def parse_trailers(message: str) -> Tuple[Optional[str], List[Tuple[int, str]]]:
    base = None
    members: List[Tuple[int, str]] = []
    for line in message.splitlines():
        m = re.match(rf"^{TRAILER_BASE}:\s*([0-9a-f]{{40}})\s*$", line)
        if m:
            base = m.group(1)
        m = re.match(rf"^{TRAILER_MEMBER}:\s*#?(\d+)\s+([0-9a-f]{{40}})\b", line)
        if m:
            members.append((int(m.group(1)), m.group(2)))
    return base, members


def live_batches(r: Runner, remote: str) -> Dict[str, List[Tuple[int, str]]]:
    out = r.git("ls-remote", remote, f"refs/heads/{BRANCH_PREFIX}*").stdout
    found: Dict[str, List[Tuple[int, str]]] = {}
    for line in out.splitlines():
        sha, ref = line.split()
        fetch(r, remote, [sha])
        _, members = parse_trailers(r.git("log", "-1", "--format=%B", sha).stdout)
        found[ref[len("refs/heads/"):]] = members
    return found


# ---------------------------------------------------------------- integration

def merge_tree(r: Runner, ours: str, theirs: str) -> Tuple[Optional[str], List[str]]:
    p = r.git("merge-tree", "--write-tree", "--name-only", "--no-messages", ours, theirs, check=False)
    lines = p.stdout.splitlines()
    if p.returncode == 0:
        return lines[0].strip(), []
    if p.returncode == 1:
        return None, [x for x in lines[1:] if x.strip()]
    raise Refused(f"git merge-tree failed: {p.stderr.strip()}")


COMMIT_ENV = {"GIT_AUTHOR_NAME": "mac-batch", "GIT_AUTHOR_EMAIL": "mac-batch@users.noreply.github.com",
              "GIT_COMMITTER_NAME": "mac-batch", "GIT_COMMITTER_EMAIL": "mac-batch@users.noreply.github.com"}


def commit(r: Runner, tree: str, parents: Sequence[str], message: str) -> str:
    args = ["commit-tree", tree]
    for p in parents:
        args += ["-p", p]
    return r.git(*args, input_text=message, env=COMMIT_ENV).stdout.strip()


@dataclass
class Plan:
    base: str
    members: List[Member]
    conflicts: List[str]
    commit: Optional[str]
    branch: str


def integrate(r: Runner, base: str, members: List[Member], stamp: str) -> Plan:
    conflicts: List[str] = []
    single: Dict[int, str] = {}
    for m in members:
        tree, files = merge_tree(r, base, m.head)
        if tree is None:
            conflicts.append(f"#{m.number} conflicts with the base: {', '.join(files)}")
        else:
            single[m.number] = commit(r, tree, [base, m.head], f"mac-batch probe #{m.number}\n")
    ok = [m for m in members if m.number in single]
    for i, a in enumerate(ok):
        for b in ok[i + 1:]:
            tree, files = merge_tree(r, single[a.number], b.head)
            if tree is None:
                conflicts.append(f"#{a.number} and #{b.number} conflict: {', '.join(files)}")
    nums = "-".join(str(m.number) for m in members)
    branch = f"{BRANCH_PREFIX}{stamp}-{nums}"
    if conflicts:
        return Plan(base, members, conflicts, None, branch)
    cur = base
    for idx, m in enumerate(members):
        tree, files = merge_tree(r, cur, m.head)
        if tree is None:
            done = " ".join(f"#{x.number}" for x in members[:idx])
            conflicts.append(f"#{m.number} conflicts only with the combination of {done}: {', '.join(files)}")
            return Plan(base, members, conflicts, None, branch)
        last = idx == len(members) - 1
        msg = f"mac-batch: merge #{m.number} ({m.branch})\n"
        if last:
            msg = (f"mac-batch: {' '.join('#%d' % x.number for x in members)} on {base[:10]}\n\n"
                   "Temporary integration commit for one branch Mac run; never merge it.\n\n"
                   f"{TRAILER_BASE}: {base}\n" +
                   "".join(f"{TRAILER_MEMBER}: #{x.number} {x.head} {x.branch}\n" for x in members))
        cur = commit(r, tree, [cur, m.head], msg)
    return Plan(base, members, [], cur, branch)


def build_plan(r: Runner, a: argparse.Namespace) -> Tuple[Plan, List[str]]:
    prs = sorted(set(a.prs))
    if len(prs) < 2:
        raise Refused("a batch needs at least two PRs; dispatch a single PR's branch directly")
    if len(prs) > a.max_members:
        raise Refused(f"{len(prs)} PRs exceed --max-members {a.max_members}: one failure would void "
                      "evidence for too many; split into smaller batches")
    notes: List[str] = []
    members: List[Member] = []
    refused: List[str] = []
    for n in prs:
        try:
            members.append(pr_member(r, a.repo, n, a.base, not a.skip_linux_check))
        except Refused as e:
            refused.append(str(e))
    base = remote_base(r, a.remote, a.base)
    fetch(r, a.remote, [base] + [f"refs/heads/{m.branch}" for m in members])
    for m in members:
        if r.git("cat-file", "-e", f"{m.head}^{{commit}}", check=False).returncode != 0:
            refused.append(f"#{m.number} head {m.head[:10]} is not fetchable (moved?); retry")
    if not a.allow_overlap:
        for branch, mem in live_batches(r, a.remote).items():
            clash = sorted({n for n, _ in mem} & {m.number for m in members})
            if clash:
                refused.append(f"{' '.join('#%d' % n for n in clash)} already in live batch {branch}; "
                               "report/delete it first or pass --allow-overlap")
    if refused:
        raise Refused("refused:\n  " + "\n  ".join(refused))
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    plan = integrate(r, base, members, stamp)
    macos_paths = macos_only_paths(r, plan.commit or base)
    for m in members:
        det = detect_change(r, member_change(r, base, m.head), macos_paths)
        notes.append(f"#{m.number} {m.branch} {m.head[:10]}: {det.verdict}"
                     + (f" ({len(det.mac_tests)} macOS-only test fns)" if det.mac_tests else ""))
    return plan, notes


def print_plan(plan: Plan, notes: List[str], repo: str) -> None:
    print(f"base: {plan.base}")
    for line in notes:
        print(f"member {line}")
    if plan.conflicts:
        print("REFUSED: conflicts")
        for c in plan.conflicts:
            print(f"  {c}")
        return
    print(f"integration commit: {plan.commit}")
    print(f"branch: {plan.branch}")
    print(f"would push: git push <remote> {plan.commit}:refs/heads/{plan.branch}")
    print(f"would dispatch: gh workflow run {WORKFLOW} -R {repo} --ref {plan.branch}")


# ---------------------------------------------------------------- dispatch

def cmd_plan(r: Runner, a: argparse.Namespace) -> int:
    plan, notes = build_plan(r, a)
    print_plan(plan, notes, a.repo)
    return EXIT_REFUSED if plan.conflicts else 0


def cmd_dispatch(r: Runner, a: argparse.Namespace) -> int:
    plan, notes = build_plan(r, a)
    print_plan(plan, notes, a.repo)
    if plan.conflicts:
        return EXIT_REFUSED
    if a.dry_run:
        print("dry run: gate not called (an OK would reserve a Mac slot), nothing pushed or dispatched")
        return 0
    gate = a.gate or os.environ.get("OTTTO_MAC_DISPATCH_GATE")
    if not gate or not os.path.isfile(gate):
        raise Refused("no Mac dispatch gate: pass --gate <mac_dispatch_ok.sh> or set OTTTO_MAC_DISPATCH_GATE")
    g = r.gate(gate)
    sys.stdout.write(g.stdout)
    if g.returncode == EXIT_STALE:
        print("gate: CI state stale; do not retry for 10 minutes")
        return EXIT_STALE
    if g.returncode != 0:
        print("gate: wait; nothing pushed or dispatched")
        return EXIT_WAIT
    r.git("push", "-q", a.remote, f"{plan.commit}:refs/heads/{plan.branch}")
    try:
        r.gh("workflow", "run", WORKFLOW, "-R", a.repo, "--ref", plan.branch)
    except Refused:
        r.git("push", "-q", a.remote, "--delete", plan.branch, check=False)
        raise
    run_id = None
    for delay in (5, 10, 15):
        time.sleep(delay)
        runs = gh_json(r, "run", "list", "-R", a.repo, "-w", WORKFLOW, "-b", plan.branch,
                       "-e", "workflow_dispatch", "--limit", "1", "--json", "databaseId,url")
        if runs:
            run_id = runs[0]["databaseId"]
            print(f"dispatched run {run_id} {runs[0]['url']}")
            break
    if run_id is None:
        print(f"dispatched on {plan.branch}; run id not visible yet (gh run list -b {plan.branch})")
    print(f"after it completes (poll at most every 5 min): {sys.argv[0]} report --run {run_id or '<id>'} --delete-branch")
    return 0


# ---------------------------------------------------------------- log parsing

PREFIX_RE = re.compile(r"^[^\t]*\t[^\t]*\t\d{4}-\d\d-\d\dT[\d:.]+Z ?")
RESULT_RE = re.compile(r"\btest (\S+) \.\.\. (ok|FAILED|ignored)\b")
PANIC_RE = re.compile(r"thread '([^']+)'(?: \(\d+\))? panicked at ([^\s:]+\.rs):(\d+)")
RERUN_RE = re.compile(r"error: test failed, to rerun pass `([^`]+)`")
RUNNING_RE = re.compile(r"^\s*Running (?:unittests )?(\S+) \(target/[^/]+/deps/([A-Za-z0-9_]+)-[0-9a-f]+\)")
LOCATION_RE = re.compile(r"^\s*--> ((?:crates|src|tests)/\S+?\.rs):(\d+)")


@dataclass
class TestLog:
    results: Dict[str, str] = field(default_factory=dict)
    panics: Dict[str, Set[str]] = field(default_factory=dict)
    binary_of: Dict[str, str] = field(default_factory=dict)
    failed_binaries: List[str] = field(default_factory=list)
    error_locations: Set[str] = field(default_factory=set)

    @property
    def failed(self) -> List[str]:
        return sorted(n for n, s in self.results.items() if s == "FAILED")


def parse_log(text: str) -> TestLog:
    log = TestLog()
    binary = ""
    for raw in text.splitlines():
        line = PREFIX_RE.sub("", raw)
        m = RUNNING_RE.match(line)
        if m:
            binary = f"{m.group(2)}:{m.group(1)}"
        for m in RESULT_RE.finditer(line):
            name, status = m.group(1), m.group(2)
            if log.results.get(name) != "FAILED":
                log.results[name] = status
            log.binary_of.setdefault(name, binary)
        m = PANIC_RE.search(line)
        if m:
            log.panics.setdefault(m.group(1), set()).add(m.group(2))
        m = RERUN_RE.search(line)
        if m:
            log.failed_binaries.append(m.group(1))
        m = LOCATION_RE.match(line)
        if m:
            log.error_locations.add(m.group(1))
    return log


# ---------------------------------------------------------------- attribution

@dataclass
class Attribution:
    test: str
    files: Set[str]
    under_test: Set[str]
    owners: Dict[int, str]  # pr -> tier (changes-test | touches-test-file | touches-code-under-test)

    @property
    def top(self) -> Tuple[Optional[str], List[int]]:
        for tier in ("changes-test", "touches-test-file", "touches-code-under-test"):
            prs = sorted(p for p, t in self.owners.items() if t == tier)
            if prs:
                return tier, prs
        return None, []


def test_files(r: Runner, rev: str, test: str, log: TestLog) -> Tuple[Set[str], Set[str]]:
    leaf = test.split("::")[-1]
    files = {p for p in log.panics.get(test, set()) if not p.startswith("/")}
    p = r.git("grep", "-l", "-E", rf"(^|[^A-Za-z0-9_])fn {leaf}([^A-Za-z0-9_]|$)", rev, "--", "*.rs", check=False)
    found = [x.split(":", 1)[1] for x in p.stdout.splitlines()]
    mods = test.split("::")[:-1]
    if len(found) > 1 and mods:
        narrowed = [f for f in found if any(seg in f for seg in mods)]
        found = narrowed or found
    files.update(found)
    under: Set[str] = set()
    for f in [x for x in files if "/tests/" in x]:
        # Integration test: the crate modules it imports are the code under test.
        text = file_at(r, rev, f) or ""
        crate_dir = f.split("/tests/", 1)[0]
        for crate, mod in set(re.findall(r"\b(ottto_\w+)::(\w+)", text)):
            if crate.replace("_", "-") == os.path.basename(crate_dir):
                under.update({f"{crate_dir}/src/{mod}.rs", f"{crate_dir}/src/{mod}/mod.rs"})
    for f in files:
        d, b = os.path.split(f)
        stem = b[:-3]
        for suffix in ("_tests", "_test"):
            if stem.endswith(suffix):
                under.add(os.path.join(d, stem[:-len(suffix)] + ".rs"))
        if stem in ("tests", "test"):
            under.add(d + ".rs")
            under.add(os.path.join(d, "mod.rs"))
        if "/tests/" not in f and not stem.endswith(("_tests", "_test")) and stem not in ("tests", "test"):
            under.add(f)  # inline #[cfg(test)] module: the file is the code under test
        # Module-path files: crates/<crate>/src/<a>/<b>.rs for each prefix.
        src = f.split("/src/", 1)[0] + "/src" if "/src/" in f else None
        if src:
            for k in range(1, len(mods) + 1):
                under.add(f"{src}/{'/'.join(mods[:k])}.rs")
    return files, under


def attribute(r: Runner, rev: str, log: TestLog, changes: Dict[int, Change],
              changed_fns: Dict[int, Set[Tuple[str, str]]]) -> List[Attribution]:
    out = []
    for test in log.failed:
        files, under = test_files(r, rev, test, log)
        leaf = test.split("::")[-1]
        owners: Dict[int, str] = {}
        for pr, ch in changes.items():
            if any(fn == leaf and f in files for f, fn in changed_fns[pr]) or any(
                    fn == leaf for f, fn in changed_fns[pr] if not files):
                owners[pr] = "changes-test"
            elif ch.files & files:
                owners[pr] = "touches-test-file"
            elif ch.files & under:
                owners[pr] = "touches-code-under-test"
        out.append(Attribution(test, files, under, owners))
    return out


def ok_by_name(log: TestLog, mac_tests: Set[Tuple[str, str]]) -> Tuple[List[str], List[str]]:
    seen, missing = [], []
    for f, fn in sorted(mac_tests):
        hits = [n for n in log.results if n == fn or n.endswith("::" + fn)]
        if hits and all(log.results[h] == "ok" for h in hits):
            seen.extend(f"{h} ... ok" for h in sorted(hits))
        else:
            missing.append(f"{fn} ({f}): " + (", ".join(f"{h}={log.results[h]}" for h in hits) or "did not run"))
    return seen, missing


def patch_id(r: Runner, base: str, head: str) -> str:
    mb = r.git("merge-base", base, head).stdout.strip()
    diff = r.git("diff", "--no-color", "--no-ext-diff", mb, head).stdout
    out = r.git("patch-id", "--stable", input_text=diff).stdout.split()
    return out[0] if out else ""


def cmd_report(r: Runner, a: argparse.Namespace) -> int:
    run = gh_json(r, "run", "view", str(a.run), "-R", a.repo, "--json",
                  "status,conclusion,headSha,headBranch,event,url,jobs")
    if run["status"] != "completed":
        print(f"run {a.run} is {run['status']}; report after it completes (poll at most every 5 min)")
        return EXIT_WAIT
    fetch(r, a.remote, [run["headSha"]])
    base, trailer_members = parse_trailers(r.git("log", "-1", "--format=%B", run["headSha"]).stdout)
    if a.members:
        trailer_members = []
        for item in a.members.split(","):
            num, _, sha = item.partition("=")
            if not sha:
                sha = gh_json(r, "pr", "view", num, "-R", a.repo, "--json", "headRefOid")["headRefOid"]
            trailer_members.append((int(num), sha))
        if base is None:
            # Replay: diff each member against the current base tip so only
            # its own changes count (an older base would add later base commits).
            base = remote_base(r, a.remote, a.base)
            fetch(r, a.remote, [base])
    if base is None or not trailer_members:
        raise Refused(f"run {a.run} ({run['headBranch']}) is not a mac-batch run; pass --members to replay")
    fetch(r, a.remote, [sha for _, sha in trailer_members])
    job = next((j for j in run["jobs"] if j["name"] == MAC_JOB), None)
    if job is None:
        raise Refused(f"run {a.run} has no {MAC_JOB} job")
    steps = job.get("steps") or []
    failed_steps = [s["name"] for s in steps if s.get("conclusion") == "failure"]
    names = [s["name"] for s in steps]
    tests_reached = "Runtime tests" in names and next(
        (s.get("conclusion") for s in steps if s["name"] == "Runtime tests"), None) in ("success", "failure")
    if a.log_file:
        with open(a.log_file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    else:
        # The whole job log, once: --log-failed would drop a passing "Runtime
        # tests" step when a later step failed.
        text = r.gh("run", "view", str(a.run), "-R", a.repo, "--job", str(job["databaseId"]), "--log").stdout
    log = parse_log(text)
    macos_paths = macos_only_paths(r, run["headSha"])
    changes = {n: member_change(r, base, sha) for n, sha in trailer_members}
    dets = {n: detect_change(r, changes[n], macos_paths) for n in changes}
    attributions = attribute(r, run["headSha"], log, changes, {n: d.changed_fns for n, d in dets.items()})

    print(f"run {a.run} {run['url']}")
    print(f"{MAC_JOB}: {job['conclusion']}" + (f" (failed step: {', '.join(failed_steps)})" if failed_steps else ""))
    print(f"base {base[:10]}; members: " + " ".join(f"#{n}@{s[:10]}" for n, s in trailer_members))
    pre_test = job["conclusion"] != "success" and not tests_reached
    blamed: Dict[int, List[str]] = {}
    if pre_test:
        print("failed before Runtime tests: no test evidence for any member")
        for n, ch in changes.items():
            hit = sorted(ch.files & log.error_locations)
            if hit:
                blamed.setdefault(n, []).append(f"{failed_steps[0] if failed_steps else 'build'} error in {', '.join(hit)}")
    if log.failed_binaries:
        print("stopped at failing test binary: " + "; ".join(log.failed_binaries)
              + " (later test binaries and steps did not run)")
    for at in attributions:
        tier, prs = at.top
        if not prs:
            print(f"FAILED {at.test}: no member touches it (files: {', '.join(sorted(at.files)) or '?'}); "
                  "likely flaky, broken on the base, or an interaction: re-run the members alone")
            for n in changes:
                blamed.setdefault(n, []).append(f"unattributed failure {at.test}")
            continue
        who = " ".join(f"#{p}" for p in prs)
        print(f"FAILED {at.test}: {who} ({tier}; {', '.join(sorted(at.files)) or '?'})")
        for p in prs:
            blamed.setdefault(p, []).append(f"{at.test} ({tier}{', shared' if len(prs) > 1 else ''})")

    print("")
    rc = 0
    wanted = [a.pr] if a.pr else [n for n, _ in trailer_members]
    current = {}
    for n in wanted:
        current[n] = gh_json(r, "pr", "view", str(n), "-R", a.repo, "--json", "headRefOid,state")
    for n, sha in trailer_members:
        if n not in wanted:
            continue
        det = dets[n]
        seen, missing = ok_by_name(log, det.mac_tests)
        if pre_test:
            verdict = "SUSPECT" if n in blamed else "NO-EVIDENCE"
        elif n in blamed:
            verdict = "SUSPECT"
        elif job["conclusion"] == "success":
            verdict = "CLEARED" if not missing or not tests_reached else "NO-EVIDENCE"
        elif not missing and attributions and all(
                at.top[0] == "changes-test" and n not in at.top[1] for at in attributions):
            # Red run: clear a bystander only when every failure is a test
            # another member added or changed, and its own macOS-only tests ran.
            verdict = "CLEARED"
        else:
            verdict = "NO-EVIDENCE"
        now = current[n]["headRefOid"]
        if now == sha:
            head_state = "head unchanged"
        else:
            fetch(r, a.remote, [now])
            same = patch_id(r, base, now) == patch_id(r, base, sha)
            head_state = (f"head moved to {now[:10]} with the identical patch (carry)" if same
                          else f"head moved to {now[:10]}: run is NOT evidence for the new head")
            if not same and verdict == "CLEARED":
                verdict = "STALE"
        print(f"#{n} {verdict} ({det.verdict}; {head_state})")
        for why in blamed.get(n, []):
            print(f"  cause: {why}")
        for line in seen:
            print(f"  macOS-only test {line}")
        for line in missing:
            print(f"  macOS-only test missing: {line}")
        if verdict == "SUSPECT":
            shared = any("shared" in w or "unattributed" in w for w in blamed.get(n, []))
            print(f"  next: {'re-run #%d alone to split the shared failure' % n if shared else 'fix, then re-run #%d alone' % n}")
            rc = 4
        elif verdict in ("NO-EVIDENCE", "STALE"):
            print("  next: include in the next batch (this run proved nothing for this head)")
            rc = rc or 5
        elif verdict == "CLEARED":
            print(f"  evidence: branch Mac run {a.run} (combined {' '.join('#%d' % x for x, _ in trailer_members)} on "
                  f"{base[:10]}) covers head {sha[:10]}; valid only while the PR merges this head or the identical "
                  "patch; the merge queue re-tests it")
    if a.delete_branch:
        if not run["headBranch"].startswith(BRANCH_PREFIX):
            raise Refused(f"refusing to delete {run['headBranch']}: not a {BRANCH_PREFIX} branch")
        r.git("push", "-q", a.remote, "--delete", run["headBranch"])
        print(f"deleted {run['headBranch']}")
    return rc


# ---------------------------------------------------------------- detect command

def cmd_detect(r: Runner, a: argparse.Namespace) -> int:
    targets: List[Tuple[str, Change]] = []
    if a.range:
        base, _, head = a.range.partition("..")
        targets.append((a.range, member_change(r, base, head or "HEAD")))
    else:
        base = remote_base(r, a.remote, a.base)
        for n in a.prs:
            pr = gh_json(r, "pr", "view", str(n), "-R", a.repo, "--json", "headRefOid,headRefName")
            head = pr["headRefOid"]
            fetch(r, a.remote, [base, f"refs/heads/{pr['headRefName']}"])
            targets.append((f"#{n}@{head[:10]}", member_change(r, base, head)))
    worst = 0
    for label, ch in targets:
        det = detect_change(r, ch)
        print(f"{label}: {det.verdict}")
        for f in det.findings:
            print(f"  {f.level} {f.path}:{f.line} {f.what}")
        if det.verdict == "MAC-NEEDED":
            worst = EXIT_MAC_NEEDED
        elif det.verdict == "MAC-ADVISED" and worst == 0:
            worst = EXIT_MAC_ADVISED
    return worst


def main(argv: Optional[Sequence[str]] = None, runner: Optional[Runner] = None) -> int:
    p = argparse.ArgumentParser(prog="mac_batch.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp: argparse.ArgumentParser) -> None:
        sp.add_argument("--repo", default="ottto-ai/ottto")
        sp.add_argument("--remote", default="origin")
        sp.add_argument("--base", default="main")

    for name in ("plan", "dispatch"):
        sp = sub.add_parser(name)
        common(sp)
        sp.add_argument("prs", nargs="+", type=int)
        sp.add_argument("--max-members", type=int, default=4)
        sp.add_argument("--skip-linux-check", action="store_true")
        sp.add_argument("--allow-overlap", action="store_true")
        if name == "dispatch":
            sp.add_argument("--dry-run", action="store_true")
            sp.add_argument("--gate")
    sp = sub.add_parser("report")
    common(sp)
    sp.add_argument("--run", required=True, type=int)
    sp.add_argument("--pr", type=int)
    sp.add_argument("--log-file")
    sp.add_argument("--members")
    sp.add_argument("--delete-branch", action="store_true")
    sp = sub.add_parser("detect")
    common(sp)
    sp.add_argument("prs", nargs="*", type=int)
    sp.add_argument("--range")
    a = p.parse_args(argv)
    if a.cmd == "detect" and not a.prs and not a.range:
        p.error("detect needs PR numbers or --range")
    r = runner or Runner(Runner(os.getcwd()).git("rev-parse", "--show-toplevel").stdout.strip())
    try:
        return {"plan": cmd_plan, "dispatch": cmd_dispatch, "report": cmd_report, "detect": cmd_detect}[a.cmd](r, a)
    except Refused as e:
        print(f"mac-batch: {e}", file=sys.stderr)
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
