#!/usr/bin/env python3
"""Report how the ottto-service snapshots module tree measures up to its target layout.

Scope: crates/ottto-service/src/snapshots.rs and everything under
crates/ottto-service/src/snapshots/. Each finding belongs to one rule. The
check reports and exits 0; `--enforce <rule,...>` makes findings of those rules
fail (exit 1). Notes never fail.

  size          a .rs file over 3,000 lines needs a row in
                scripts/source_layout_limits.tsv and must stay under it. The
                ceilings are a ratchet: against the base commit no row may rise
                and their total may not rise. Over 1,500 lines is a note.
  tree          every .rs file is reachable by `mod` from the crate root; every
                module directory has its `<dir>.rs`; no `mod.rs`; files other
                than .rs only under tests/fixtures/ and
                state_v2/sqlite/migrations/*.sql.
  budget        at most 25 entries per directory; module depth at most 3 below
                snapshots/, 5 inside a tests/ directory.
  path-include  `#[path]` and item-level `include!` only as listed in
                scripts/source_layout_includes.tsv, a list that may only shrink:
                against the base commit a new row must replace a removed row
                of the same kind and target file name (a moved include).
  names         no generic stems (util(s), helper(s), misc, common, shared,
                base, core, types, stuff, tmp, new, old) in any `_` part of a
                file or directory name, and no coded stems (a1_, e2_, g7_,
                p2_, stage2, fe_, h123).
  header        a non-test .rs file starts with a `//!` module doc.
  stutter       a file or directory name does not start with its parent
                directory's name.

Exit status: 0, or 1 when an enforced rule has findings, 2 on a usage error (or a
setup error while a rule is enforced).
"""

from __future__ import annotations

import argparse
import os
import posixpath
import re
import sys
from dataclasses import dataclass
from pathlib import Path

import rust_source_tree as rst

CRATE = "crates/ottto-service"
SCOPE_FILE = f"{CRATE}/src/snapshots.rs"
SCOPE_DIR = f"{CRATE}/src/snapshots"
LIMITS = "scripts/source_layout_limits.tsv"
INCLUDES = "scripts/source_layout_includes.tsv"
RULES = ("size", "tree", "budget", "path-include", "names", "header", "stutter")
MAX_LINES, NOTE_LINES = 3000, 1500
MAX_ENTRIES, MAX_DEPTH, TESTS_EXTRA_DEPTH = 25, 3, 2
BANNED = {"util", "utils", "helper", "helpers", "misc", "common", "shared", "base", "core", "types",
          "stuff", "tmp", "new", "old"}
BANNED_EXCEPTIONS = {"kinds_misc"}
CODED = [re.compile(pattern) for pattern in (
    r"^[a-z]\d+_", r"(?:^|_)e2_", r"(?:^|_)g7_", r"(?:^|_)p\d+_", r"(?:^|_)stage\d", r"(?:^|_)fe_",
    r"(?:^|_)h\d{3}(?:_|$)",
)]


@dataclass
class Finding:
    rule: str
    path: str
    message: str
    note: bool = False


def line_count(data: bytes) -> int:
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def read_table(text: str | None, columns: int, where: str) -> list[tuple[str, ...]]:
    rows = []
    for number, line in enumerate((text or "").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        fields = tuple(line.split("\t"))
        if len(fields) != columns:
            raise rst.SourceError(f"{where}:{number}: expected {columns} tab-separated fields")
        rows.append(fields)
    return rows


def limits_table(text: str | None, where: str) -> dict[str, int]:
    table = {}
    for path, ceiling in read_table(text, 2, where):
        if not ceiling.isdigit():
            raise rst.SourceError(f"{where}: ceiling for {path} is not a number: {ceiling}")
        table[path] = int(ceiling)
    return table


def scope_files(root: Path) -> list[str]:
    found = [SCOPE_FILE] if (root / SCOPE_FILE).is_file() else []
    for directory, dirs, files in os.walk(root / SCOPE_DIR):
        dirs.sort()
        for name in sorted(files):
            found.append(Path(directory, name).relative_to(root).as_posix())
    return found


def scope_dirs(root: Path) -> list[str]:
    found = []
    for directory, dirs, _ in os.walk(root / SCOPE_DIR):
        dirs.sort()
        found.append(Path(directory).relative_to(root).as_posix())
    return found


def inside(path: str) -> str:
    """`path` relative to the snapshots directory ('' for the directory itself)."""
    return posixpath.relpath(path, SCOPE_DIR) if path != SCOPE_DIR else ""


def is_fixture(path: str) -> bool:
    rel = inside(path)
    return (rel.startswith("tests/fixtures/") or "/tests/fixtures/" in rel
            or bool(re.match(r"^state_v2/sqlite/migrations/[^/]+\.sql$", rel)))


def is_test_file(path: str) -> bool:
    stem = posixpath.basename(path)[:-3]
    return stem == "tests" or stem.endswith("_tests") or "tests" in inside(path).split("/")[:-1]


def module_depth(path: str) -> int:
    return 0 if path == SCOPE_FILE else len(inside(path).split("/"))


def check_size(root: Path, files: list[str], limits: dict[str, int], base_limits: dict[str, int] | None,
               out: list[Finding]) -> None:
    for path in files:
        if not path.endswith(".rs"):
            continue
        lines = line_count((root / path).read_bytes())
        ceiling = limits.get(path)
        if ceiling is not None:
            if lines > ceiling:
                out.append(Finding("size", path, f"{lines} lines, over its ceiling of {ceiling} in {LIMITS}"))
            elif lines <= MAX_LINES:
                out.append(Finding("size", path, f"{lines} lines; its row in {LIMITS} can go", note=True))
            elif lines < ceiling:
                out.append(Finding("size", path, f"{lines} lines; its ceiling can fall from {ceiling}", note=True))
        elif lines > MAX_LINES:
            out.append(Finding("size", path, f"{lines} lines, over {MAX_LINES} and not in {LIMITS}"))
        if lines > NOTE_LINES and not (ceiling is not None or lines > MAX_LINES):
            out.append(Finding("size", path, f"{lines} lines, over {NOTE_LINES}", note=True))
    for path in sorted(set(limits) - set(files)):
        out.append(Finding("size", path, f"row in {LIMITS} for a file that does not exist"))
    if base_limits is not None:
        for path, ceiling in sorted(limits.items()):
            if path in base_limits and ceiling > base_limits[path]:
                out.append(Finding("size", path, f"ceiling rose from {base_limits[path]} to {ceiling}"))
        if sum(limits.values()) > sum(base_limits.values()):
            out.append(Finding("size", LIMITS, f"ceilings total {sum(limits.values())}, "
                                               f"up from {sum(base_limits.values())} at base"))


def check_tree(root: Path, files: list[str], dirs: list[str], tree: rst.Tree, out: list[Finding]) -> None:
    for path in files:
        if path.endswith(".rs"):
            if path not in tree.contexts:
                out.append(Finding("tree", path, "not reachable by mod from the crate root"))
            if posixpath.basename(path) == "mod.rs":
                out.append(Finding("tree", path, "mod.rs; name the module file after its directory"))
        elif not is_fixture(path):
            out.append(Finding("tree", path, "not a .rs file outside tests/fixtures/ and "
                                             "state_v2/sqlite/migrations/*.sql"))
    for directory in dirs:
        has_rs = any(name.endswith(".rs") for name in os.listdir(root / directory))
        if has_rs and not (root / f"{directory}.rs").is_file():
            out.append(Finding("tree", directory, f"module directory without {posixpath.basename(directory)}.rs"))


def check_budget(root: Path, files: list[str], dirs: list[str], out: list[Finding]) -> None:
    for directory in dirs:
        if is_fixture(f"{directory}/x") or inside(directory).startswith("state_v2/sqlite/migrations"):
            continue
        entries = len(os.listdir(root / directory))
        if entries > MAX_ENTRIES:
            out.append(Finding("budget", directory, f"{entries} entries, over {MAX_ENTRIES}"))
    for path in files:
        if not path.endswith(".rs"):
            continue
        depth = module_depth(path)
        limit = MAX_DEPTH + (TESTS_EXTRA_DEPTH if "tests" in inside(path).split("/") else 0)
        if depth > limit:
            out.append(Finding("budget", path, f"module depth {depth}, over {limit}"))


def link_rows(tree: rst.Tree, files: list[str]) -> list[tuple[str, str, str]]:
    in_scope = set(files)
    return sorted({(link.file, link.how, link.literal or "") for link in tree.links
                   if link.how in ("path", "include") and (link.file in in_scope or link.target in in_scope)})


def check_path_include(rows: list[tuple[str, str, str]], allowed: list[tuple[str, ...]],
                       base_allowed: list[tuple[str, ...]] | None, out: list[Finding]) -> None:
    allowed_set = set(allowed)
    for row in rows:
        if row not in allowed_set:
            out.append(Finding("path-include", row[0], f"{'#[path]' if row[1] == 'path' else 'include!'} "
                                                       f"\"{row[2]}\" is not in {INCLUDES}"))
    for row in sorted(allowed_set - set(rows)):
        out.append(Finding("path-include", row[0], f"row \"{row[2]}\" in {INCLUDES} can go", note=True))
    if base_allowed is None:
        return
    if len(allowed) > len(base_allowed):
        out.append(Finding("path-include", INCLUDES, f"{len(allowed)} rows, up from {len(base_allowed)} at base"))
    # A new row is only a relocated old one: same kind and target file name.
    gone = [row for row in base_allowed if row not in allowed_set]
    for row in [row for row in allowed if row not in set(base_allowed)]:
        twin = next((old for old in gone if old[1] == row[1]
                     and posixpath.basename(old[2]) == posixpath.basename(row[2])), None)
        if twin is None:
            out.append(Finding("path-include", row[0], f"row \"{row[2]}\" in {INCLUDES} is new, not a relocated row"))
        else:
            gone.remove(twin)


def names_of(files: list[str], dirs: list[str]) -> list[tuple[str, str]]:
    """(path, stem) of every .rs file and module directory in scope."""
    named = [(path, posixpath.basename(path)[:-3]) for path in files if path.endswith(".rs")]
    named += [(directory, posixpath.basename(directory)) for directory in dirs
              if directory != SCOPE_DIR and not is_fixture(f"{directory}/x")
              and not inside(directory).startswith("tests/fixtures")]
    return named


def check_names(named: list[tuple[str, str]], out: list[Finding]) -> None:
    for path, stem in named:
        banned = sorted(set(stem.split("_")) & BANNED)
        if banned and stem not in BANNED_EXCEPTIONS:
            out.append(Finding("names", path, f"generic stem {', '.join(banned)}"))
        coded = [found.group().strip("_") for found in (pattern.search(stem) for pattern in CODED) if found]
        if coded:
            out.append(Finding("names", path, f"coded stem {', '.join(dict.fromkeys(coded))}"))


def check_header(root: Path, files: list[str], source: rst.Source, out: list[Finding]) -> None:
    for path in files:
        if not path.endswith(".rs") or is_test_file(path):
            continue
        try:
            items = source.lexed(path).items
        except rst.SourceError as error:
            out.append(Finding("header", path, f"cannot read: {error}"))
            continue
        first = next((item for item in items if item.kind != "comment"), None)
        if first is None or first.kind != "inner-doc":
            out.append(Finding("header", path, "no //! module doc at the top"))


def check_stutter(named: list[tuple[str, str]], out: list[Finding]) -> None:
    for path, stem in named:
        parent = posixpath.basename(posixpath.dirname(path))
        if path != SCOPE_FILE and (stem == parent or stem.startswith(f"{parent}_")):
            out.append(Finding("stutter", path, f"name starts with its directory name {parent}"))


def base_text(repo: Path, base: str, path: str) -> str | None:
    try:
        return rst.git(repo, "show", f"{base}:{path}")
    except rst.SourceError:
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=".", help="repository root (default: .)")
    parser.add_argument("--base", help="base commit for the ratchets (default: merge-base of origin/main and HEAD, "
                                       "skipped when there is none)")
    parser.add_argument("--enforce", default="", metavar="RULE,...", help=f"fail on these rules: {', '.join(RULES)}")
    args = parser.parse_args(argv)
    root = Path(args.root)
    enforce = {rule for rule in args.enforce.split(",") if rule}
    unknown = sorted(enforce - set(RULES))
    if unknown:
        print(f"source-layout: unknown rule {', '.join(unknown)} (rules: {', '.join(RULES)})", file=sys.stderr)
        return 2
    try:
        base = args.base
        if base is None:
            try:
                base = rst.default_base(root)
            except rst.SourceError:
                base = None
        source = rst.DirSource(root)
        limits = limits_table((root / LIMITS).read_text(encoding="utf-8"), LIMITS)
        allowed = read_table((root / INCLUDES).read_text(encoding="utf-8"), 3, INCLUDES)
        base_limits = base_allowed = None
        if base:
            limits_then, allowed_then = base_text(root, base, LIMITS), base_text(root, base, INCLUDES)
            base_limits = limits_table(limits_then, f"{base}:{LIMITS}") if limits_then is not None else None
            base_allowed = read_table(allowed_then, 3, f"{base}:{INCLUDES}") if allowed_then is not None else None
        files, dirs = scope_files(root), scope_dirs(root)
        tree = rst.crate_tree(source, CRATE)
    except (OSError, rst.SourceError) as error:
        print(f"source-layout: {error}", file=sys.stderr)
        # A report never blocks a change; an enforced check does.
        return 2 if enforce else 0
    findings: list[Finding] = []
    check_size(root, files, limits, base_limits, findings)
    check_tree(root, files, dirs, tree, findings)
    check_budget(root, files, dirs, findings)
    check_path_include(link_rows(tree, files), allowed, base_allowed, findings)
    named = names_of(files, dirs)
    check_names(named, findings)
    check_header(root, files, source, findings)
    check_stutter(named, findings)
    for finding in findings:
        kind = "note" if finding.note else finding.rule
        print(f"source-layout: {kind}: {finding.path}: {finding.message}")
    counts = {rule: sum(1 for f in findings if f.rule == rule and not f.note) for rule in RULES}
    notes = sum(1 for f in findings if f.note)
    rs_files = sum(1 for path in files if path.endswith(".rs"))
    print(f"source-layout: {rs_files} .rs files, {len(files) - rs_files} other files, {len(dirs)} directories; "
          + ", ".join(f"{rule} {count}" for rule, count in counts.items()) + f"; {notes} notes"
          + ("" if base else "; ratchets not compared (no base)"))
    failing = {rule: counts[rule] for rule in sorted(enforce) if counts[rule]}
    if failing:
        print(f"source-layout: enforced rules with findings: {', '.join(failing)}", file=sys.stderr)
        return 1
    print(f"source-layout: {'enforced: ' + ', '.join(sorted(enforce)) if enforce else 'report only'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
