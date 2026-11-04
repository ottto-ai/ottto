#!/usr/bin/env python3
"""Check that a change keeps every Rust test, under its old or a mapped new ID.

The test list is static: no build. A test ID is the module path of a `#[test]`
function (as libtest prints it) in one target, found by following `mod`,
`#[path]` and item-level `include!` from each target root (rust_source_tree.py).
Tests that a macro generates are not seen.

For every target of every crate the change touches, the base and head lists
must have the same number of tests and the same multiset of function names.
Every ID that exists only at base must map to an ID that exists only at head
through exactly one row this change adds to scripts/test_id_renames.tsv
(columns: target root, old ID, new ID); rows already there may not change.

Then, for every test (unchanged or mapped), the never-retry decision of
scripts/ci_runtime_tests.py must be the same at base and head: each side uses
its own copy of that script, its own `--require-pass` receipts from
.github/workflows and its own money-oracle modules.

Exit status: 0 when the map is exact (or with --report), 1 when it is not, 2 on
a usage or setup error.
"""

from __future__ import annotations

import argparse
import posixpath
import re
import sys
import tempfile
import types
from collections import Counter
from pathlib import Path

import rust_source_tree as rst

RENAMES = "scripts/test_id_renames.tsv"
RUNNER = "scripts/ci_runtime_tests.py"
HEADER = ("target", "old_test", "new_test")
REQUIRE_PASS = re.compile(r"--require-pass[ =]+([A-Za-z0-9_:]+)")
REPORT_LIMIT = 50


def target_root(crate: str, label: str) -> str:
    """The root file of a target label from rust_source_tree.crate_tree."""
    return f"{crate}/src/lib.rs" if label == "crate" else f"{crate}/{label[len('crate['):-1]}"


def test_ids(source: rst.Source, crate: str) -> dict[str, Counter]:
    """Target root -> multiset of static test IDs."""
    tree = rst.crate_tree(source, crate)
    found: dict[str, Counter] = {}
    for root in rst.crate_roots(crate, source):
        found[root] = Counter()

    def collect(items, module) -> None:
        for item in items:
            if item.kind == "mod" and item.members is not None:
                collect(item.members, module + (item.name,))
            elif item.kind == "fn" and any(rst.is_test_attr(attr) for attr in item.attrs):
                found.setdefault(target_root(crate, module[0]), Counter())["::".join(module[1:] + (item.name,))] += 1

    for path, contexts in sorted(tree.contexts.items()):
        lexed = source.lexed(path)
        for context in contexts:
            collect(lexed.items, context.module)
    return found


def read_renames(source: rst.Source, where: str) -> list[tuple[str, str, str]]:
    if not source.exists(RENAMES):
        return []
    rows = []
    for number, line in enumerate(source.read(RENAMES).splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = tuple(line.split("\t"))
        if fields == HEADER:
            continue
        if len(fields) != 3 or not all(fields):
            raise rst.SourceError(f"{where}:{RENAMES}:{number}: expected 3 tab-separated fields")
        rows.append(fields)
    return rows


def leaf(test: str) -> str:
    return test.rsplit("::", 1)[-1]


def load_runner(source: rst.Source, rev: str):
    """That commit's ci_runtime_tests.py as a module (it imports the current libtest_log)."""
    if not source.exists(RUNNER):
        raise rst.SourceError(f"{rev}: no {RUNNER}")
    module = types.ModuleType(f"ci_runtime_tests_{rev[:12]}")
    module.__file__ = RUNNER
    sys.modules[module.__name__] = module
    exec(compile(source.read(RUNNER), f"{rev}:{RUNNER}", "exec"), module.__dict__)  # noqa: S102
    return module


def retry_rules(source: rst.Source, rev: str):
    """(runner module, required receipts, never-retry modules) at one commit."""
    runner = load_runner(source, rev)
    required = set()
    for path in source.files():
        if path.startswith(".github/workflows/") and path.endswith((".yml", ".yaml")):
            required |= set(REQUIRE_PASS.findall(source.read(path)))
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for path in source.files():
            if path.startswith("crates/") and path.endswith(".rs"):
                target = root / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(source.read_bytes(path))
        modules = runner.NEVER_RETRY_MODULES | runner.oracle_modules(root / "crates")
    return runner, required, modules


def compare(base: dict[str, Counter], head: dict[str, Counter], base_rows, head_rows):
    """(problems, mapping old -> new per target, suggested rows)."""
    problems: list[str] = []
    suggestions: list[str] = []
    mapping: dict[str, list[tuple[str, str]]] = {}
    remaining = Counter(head_rows)
    for row in base_rows:
        if remaining[row]:
            remaining[row] -= 1
        else:
            problems.append(f"{RENAMES}: existing row removed or changed: {chr(9).join(row)}")
    added_rows = []
    for row in head_rows:
        if remaining[row]:
            remaining[row] -= 1
            added_rows.append(row)
    rows_by_target: dict[str, list[tuple[str, str]]] = {}
    for target, old, new in added_rows:
        rows_by_target.setdefault(target, []).append((old, new))
    for target in sorted(set(base) | set(head) | set(rows_by_target)):
        before, after = base.get(target, Counter()), head.get(target, Counter())
        if sum(before.values()) != sum(after.values()):
            problems.append(f"{target}: {sum(before.values())} tests at base, {sum(after.values())} at head")
        leaves_before = Counter(leaf(t) for t in before.elements())
        leaves_after = Counter(leaf(t) for t in after.elements())
        if leaves_before != leaves_after:
            lost, gained = leaves_before - leaves_after, leaves_after - leaves_before
            problems.append(f"{target}: test names differ: only at base {sorted(lost)[:10]}, "
                            f"only at head {sorted(gained)[:10]}")
        removed, added = before - after, after - before
        pairs = [(test, test) for test in (before & after).elements()]
        for old, new in rows_by_target.get(target, []):
            if old == new:
                problems.append(f"{target}: row maps {old} to itself")
            elif leaf(old) != leaf(new):
                problems.append(f"{target}: row renames the test function: {old} -> {new}")
            elif not removed[old]:
                problems.append(f"{target}: row old ID is not a test that this change removes: {old}")
            elif not added[new]:
                problems.append(f"{target}: row new ID is not a test that this change adds: {new}")
            else:
                removed[old] -= 1
                added[new] -= 1
                pairs.append((old, new))
        removed, added = +removed, +added
        for old in sorted(removed.elements()):
            problems.append(f"{target}: test without a new ID: {old}")
            twins = [new for new in added if leaf(new) == leaf(old)]
            if len(twins) == 1:
                suggestions.append(f"{target}\t{old}\t{twins[0]}")
        for new in sorted(added.elements()):
            problems.append(f"{target}: test without an old ID: {new}")
        mapping[target] = pairs
    return problems, mapping, suggestions


def crates_to_scan(changed: list[str], sources) -> list[str]:
    crates: set[str] = set()
    whole = any(path in (RUNNER, RENAMES) for path in changed)
    for source in sources:
        for path in changed:
            if path.endswith(".rs") and source.exists(path):
                crate = rst.crate_dir(path, source)
                if crate:
                    crates.add(crate)
        if whole:
            crates |= {posixpath.dirname(path) for path in source.files()
                       if re.match(r"^crates/[^/]+/Cargo\.toml$", path)}
    return sorted(crates)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="base commit (default: merge-base of origin/main and HEAD)")
    parser.add_argument("--head", default="HEAD", help="head commit (default: HEAD)")
    parser.add_argument("--repo", default=".", help="repository root (default: .)")
    parser.add_argument("--report", action="store_true", help="print the findings and exit 0")
    args = parser.parse_args(argv)
    repo = Path(args.repo)
    try:
        base = args.base or rst.default_base(repo)
        base_sha = rst.git(repo, "rev-parse", "--verify", f"{base}^{{commit}}").strip()
        head_sha = rst.git(repo, "rev-parse", "--verify", f"{args.head}^{{commit}}").strip()
        changed = rst.changed_files(repo, base_sha, head_sha)
        base_source, head_source = rst.GitSource(repo, base_sha), rst.GitSource(repo, head_sha)
        crates = crates_to_scan(changed, (base_source, head_source))
        print(f"test-ids: base {base_sha[:12]} head {head_sha[:12]}: {len(crates)} crates to compare")
        if not crates:
            print("test-ids: nothing to compare")
            return 0
        base_ids: dict[str, Counter] = {}
        head_ids: dict[str, Counter] = {}
        for crate in crates:
            if base_source.exists(f"{crate}/Cargo.toml"):
                base_ids.update(test_ids(base_source, crate))
            head_source.share_with(base_source)
            if head_source.exists(f"{crate}/Cargo.toml"):
                head_ids.update(test_ids(head_source, crate))
        problems, mapping, suggestions = compare(base_ids, head_ids, read_renames(base_source, "base"),
                                                 read_renames(head_source, "head"))
        base_rules, head_rules = retry_rules(base_source, base_sha), retry_rules(head_source, head_sha)
    except rst.SourceError as error:
        print(f"test-ids: {error}", file=sys.stderr)
        return 2
    flips = 0
    for target, pairs in sorted(mapping.items()):
        renamed = sum(1 for old, new in pairs if old != new)
        counts = sum(base_ids.get(target, Counter()).values()), sum(head_ids.get(target, Counter()).values())
        for old, new in pairs:
            before = base_rules[0].never_retry(old, base_rules[1], base_rules[2])
            after = head_rules[0].never_retry(new, head_rules[1], head_rules[2])
            if before != after:
                flips += 1
                problems.append(f"{target}: never-retry changes for {old}"
                                + (f" -> {new}" if new != old else "") + f": {before} -> {after}")
        if any(counts):
            print(f"test-ids: {target}: {counts[0]} tests at base, {counts[1]} at head, {renamed} renamed")
    print(f"test-ids: {flips} never-retry decisions changed")
    for source in (base_source, head_source):
        source.close()
    shown = problems[:REPORT_LIMIT] if args.report else problems
    stream = sys.stdout if args.report else sys.stderr
    for problem in shown:
        print(f"test-ids: {'note' if args.report else 'FAIL'} {problem}", file=stream)
    if len(problems) > len(shown):
        print(f"test-ids: ... {len(problems) - len(shown)} more", file=stream)
    if suggestions and not args.report:
        print(f"test-ids: rows to review for {RENAMES}:", file=stream)
        for row in suggestions:
            print(row, file=stream)
    if args.report:
        print("test-ids: report only")
        return 0
    if problems:
        print(f"test-ids: {len(problems)} problems", file=sys.stderr)
        return 1
    print("test-ids: every test kept its ID or has an exact rename")
    return 0


if __name__ == "__main__":
    sys.exit(main())
