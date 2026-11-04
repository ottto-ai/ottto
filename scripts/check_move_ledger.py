#!/usr/bin/env python3
"""Check that a change only moves Rust items, and print where each one went.

Every changed `.rs` file, and every file a changed file declares with `mod`,
`#[path]` or an item-level `include!`, is split into items at the base and the
head commit (see rust_source_tree.py). Inline `mod x { .. }` and `impl .. { .. }`
blocks are opened: their members are the items, so one impl block can be split
across files. Before comparing, only these glue classes are reversed:

  (a) visibility tokens (`pub`, `pub(..)`) on item, field, method and
      `thread_local!` static lines; not inside `macro_rules!`;
  (b) whole `use` / `pub(..) use` items, `mod x;` items and item-level
      `include!(..);` items, with their attributes, and `//!` file docs;
  (c) the path literal inside `#[path = ".."]`, `include!`, `include_str!` and
      `include_bytes!`;
  (d) the `impl X {` / `}` and inline `mod x {` / `}` wrappers;
  (e) the indentation an item loses when an inline module becomes a file.

Then every base item must equal exactly one head item byte for byte (comments,
attributes, cfgs), and items that land in one file keep their base order. An
item must sit under the same module attributes (`#[cfg(..)]` and the like), may
only lose nesting, and every path literal must resolve, from its new file, to
a target with the same bytes.

Visibility must stay equivalent: an item private in module M may become
`pub(super)` in a direct child of M or `pub(in M)` deeper; a `pub(super)` inside
a module subtree that moves intact stays `pub(super)`; `pub` and `pub(crate)`
stay as they are. A visibility that reaches further than before is a widened
row and fails unless that item is named with --allow-widened.

Exit status: 0 when the change is move-only (or with --report), 1 when it is
not, 2 on a usage or setup error.
"""

from __future__ import annotations

import argparse
import difflib
import itertools
import posixpath
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import rust_source_tree as rst

GLUE = {"use", "mod-decl", "include", "inner-doc"}
PATH_MACROS = {"include", "include_str", "include_bytes"}
REPORT_LIMIT = 50
DIFF_LIMIT = 40


@dataclass
class Unit:
    """One comparable item: its normalised text and what the glue reversal removed."""

    file: str
    line: int
    end_line: int
    seq: int  # position among the units of its file
    label: str  # e.g. `fn name`, `impl Foo for Bar :: fn name`
    name: str
    module: tuple[str, ...] | None
    chain: frozenset[str]
    depth: int
    container: str  # normalised impl header, or ""
    text: str
    vis: list[tuple[int, str]] = field(default_factory=list)  # (offset in text, token)
    paths: list[tuple[str, str, bytes | None]] = field(default_factory=list)  # (macro, literal, target bytes)

    @property
    def key(self) -> tuple[str, str]:
        return self.container, self.text

    def where(self) -> str:
        return f"{self.file}:{self.line}"


def squash(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text.replace("( ", "(").replace(" )", ")")


def dedent(text: str, columns: int) -> str:
    """Drop up to `columns` leading spaces from every line after the first."""
    if columns <= 0 or "\n" not in text:
        return text
    lines = text.split("\n")
    out = [lines[0]]
    for line in lines[1:]:
        spaces = len(line) - len(line.lstrip(" "))
        out.append(line[min(spaces, columns):])
    return "\n".join(out)


def normalise(lexed: rst.Lexed, first: int, last: int, depth: int, file: str, source: rst.Source,
              strip_vis: bool) -> tuple[str, list[tuple[int, str]], list[tuple[str, str, bytes | None]]]:
    """The text of tokens first..last with glue classes (a), (c) and (e) reversed."""
    out: list[str] = []
    size = 0
    vis: list[tuple[int, str]] = []
    paths: list[tuple[str, str, bytes | None]] = []
    literal_of: dict[int, str] = {}
    columns = 4 * depth
    index = first
    while index <= last:
        token = lexed.tokens[index]
        piece = lexed.text[token.start:token.end]
        if token.kind == "ident" and piece == "pub" and strip_vis:
            after = lexed.skip_vis(index)
            vis.append((size, squash(lexed.text[token.start:lexed.tokens[after - 1].end])))
            index = after
            if index <= last and lexed.tokens[index].kind == "ws" and "\n" not in lexed.tok(index):
                index += 1
            continue
        if token.kind == "ident" and piece in PATH_MACROS:
            bang = lexed.next_code(index + 1, last + 1)
            paren = lexed.next_code(bang + 1, last + 1)
            literal = lexed.next_code(paren + 1, last + 1)
            if (lexed.is_punct(bang, "!") and lexed.is_punct(paren, "(") and literal <= last
                    and lexed.tokens[literal].kind == "str"):
                literal_of[literal] = piece
        if token.kind == "ident" and piece == "path":
            equals = lexed.next_code(index + 1, last + 1)
            literal = lexed.next_code(equals + 1, last + 1)
            if (lexed.is_punct(equals, "=") and literal <= last and lexed.tokens[literal].kind == "str"
                    and index > 0 and lexed.is_punct(prev_code(lexed, index), "[")):
                literal_of[literal] = "path"
        if index in literal_of:
            value = string_value(piece)
            target = posixpath.normpath(posixpath.join(posixpath.dirname(file), value))
            data = source.read_bytes(target) if source.exists(target) else None
            paths.append((literal_of[index], value, data))
            piece = '"<path>"'
        elif token.kind in ("ws", "comment", "doc", "idoc"):
            piece = dedent(piece, columns)
        out.append(piece)
        size += len(piece)
        index += 1
    return "".join(out), vis, paths


def prev_code(lexed: rst.Lexed, index: int) -> int:
    index -= 1
    while index > 0 and lexed.tokens[index].kind in ("ws", "comment", "doc", "idoc"):
        index -= 1
    return index


def string_value(literal: str) -> str:
    """The value of a plain or raw string literal without escapes beyond `\\\\` and `\\"`."""
    raw = re.match(r'^r(#*)"(.*)"\1$', literal, re.DOTALL)
    if raw:
        return raw.group(2)
    return literal[1:-1].replace('\\"', '"').replace("\\\\", "\\")


def first_line(text: str) -> str:
    for line in text.splitlines():
        if line.strip() and not line.lstrip().startswith(("//", "#[", "/*", "*")):
            return line.strip()[:100]
    return text.strip().splitlines()[0][:100] if text.strip() else ""


def units_of(source: rst.Source, tree: rst.Tree, path: str) -> list[Unit]:
    lexed = source.lexed(path)
    contexts = tree.contexts.get(path, [])
    context = next((c for c in contexts if c.module[0] == "crate"), contexts[0] if contexts else None)
    units: list[Unit] = []

    def add(item_first: int, item_last: int, start: int, label: str, name: str, module, chain, depth,
            container: str, strip_vis: bool = True) -> None:
        text, vis, paths = normalise(lexed, item_first, item_last, depth, path, source, strip_vis)
        end_line = lexed.line(lexed.tokens[item_last].end - 1)
        units.append(Unit(path, lexed.line(start), end_line, len(units), label, name, module, chain,
                          depth, container, text, vis, paths))

    def lead_comments(item: rst.Item, module, chain, container: str) -> None:
        if item.start >= item.lead:
            return
        last = item.first_token
        while lexed.tokens[last + 1].start < item.lead:
            last += 1
        while lexed.tokens[last].kind == "ws":
            last -= 1
        add(item.first_token, last, item.start, f"comment before {item.kind} {item.name}", "comment",
            module, chain, item.depth, container)

    def visit(items: list[rst.Item], module, chain, container: str) -> None:
        for item in items:
            if item.kind in GLUE:
                lead_comments(item, module, chain, container)
            elif item.kind == "mod" and item.members is not None:
                # Plain comments above the wrapper are kept; its docs may become `//!`.
                lead_comments(item, module, chain, container)
                inner = module + (item.name,) if module else None
                visit(item.members, inner, chain | rst.module_attrs(item.attrs), "")
            elif item.kind == "impl" and item.members is not None:
                lead_comments(item, module, chain, container)
                lead = next(i for i in range(item.first_token, item.last_token + 1)
                            if lexed.tokens[i].start == item.lead)
                body = next(i for i in range(lead, item.last_token + 1) if lexed.tokens[i].start == item.body_open)
                header, _, _ = normalise(lexed, lead, body, item.depth, path, source, True)
                visit(item.members, module, chain, header)
            else:
                label = f"{item.kind} {item.name}" if item.kind != "comment" else "comment"
                if container:
                    label = f"{squash(container.rstrip('{'))} :: {label}"
                add(item.first_token, item.last_token, item.start, label, item.name, module, chain, item.depth,
                    container, strip_vis=item.kind != "macro_rules")

    visit(lexed.items, context.module if context else None, context.chain if context else frozenset(), "")
    return units


def scope(token: str, module: tuple[str, ...]) -> tuple[str, ...]:
    """The module subtree a visibility token opens the item to; () is everywhere."""
    if token in ("", "pub(self)"):
        return module
    if token == "pub":
        return ()
    if token == "pub(super)":
        return module[:-1]
    if token == "pub(crate)":
        return module[:1]
    found = re.match(r"^pub\(in (.+)\)$", token)
    if not found:
        return ()
    parts = [p.strip() for p in found.group(1).split("::")]
    here = list(module)
    if parts[0] == "crate":
        here, parts = list(module[:1]), parts[1:]
    for part in parts:
        if part == "super":
            here = here[:-1]
        elif part != "self":
            here.append(part)
    return tuple(here)


def show(module: tuple[str, ...] | None) -> str:
    if module is None:
        return "?"
    return "::".join(module) if module else "everywhere"


@dataclass
class Ledger:
    pairs: list[tuple[Unit, Unit]] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    widened: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def match_units(base: list[Unit], head: list[Unit]) -> tuple[list[tuple[Unit, Unit]], list[Unit], list[Unit]]:
    """Pair equal units: same file first, then in base order."""
    head_by_key: dict[tuple[str, str], list[Unit]] = {}
    for unit in head:
        head_by_key.setdefault(unit.key, []).append(unit)
    pairs, lost = [], []
    pending: list[Unit] = []
    for unit in base:
        candidates = head_by_key.get(unit.key)
        same = next((c for c in candidates or [] if c.file == unit.file), None)
        if same is not None:
            candidates.remove(same)
            pairs.append((unit, same))
        else:
            pending.append(unit)
    for unit in pending:
        candidates = head_by_key.get(unit.key)
        if candidates:
            pairs.append((unit, candidates.pop(0)))
        else:
            lost.append(unit)
    gained = [unit for units in head_by_key.values() for unit in units]
    gained.sort(key=lambda u: (u.file, u.seq))
    return pairs, lost, gained


def module_moves(pairs: list[tuple[Unit, Unit]], head_modules: set[tuple[str, ...]]) -> dict:
    """Base modules that no longer exist at head and whose whole subtree moved to one new place."""
    candidates: dict[tuple[str, ...], set] = {}
    for old, new in pairs:
        if old.module is None or new.module is None:
            continue
        for cut in range(1, len(old.module) + 1):
            prefix, rest = old.module[:cut], old.module[cut:]
            if prefix in head_modules:
                continue
            if rest and new.module[len(new.module) - len(rest):] != rest:
                target = None
            else:
                target = new.module[:len(new.module) - len(rest)]
            candidates.setdefault(prefix, set()).add(target)
    return {module: next(iter(targets)) for module, targets in candidates.items()
            if len(targets) == 1 and None not in targets}


def check(base: list[Unit], head: list[Unit], head_modules: set[tuple[str, ...]],
          allow_widened: set[str]) -> Ledger:
    ledger = Ledger()
    pairs, lost, gained = match_units(base, head)
    ledger.pairs = sorted(pairs, key=lambda pair: (pair[0].file, pair[0].seq))
    moves = module_moves(pairs, head_modules)
    explain_differences(ledger, lost, gained)
    by_destination: dict[tuple[str, str], list[tuple[Unit, Unit]]] = {}
    for old, new in ledger.pairs:
        by_destination.setdefault((old.file, new.file), []).append((old, new))
        if new.depth > old.depth:
            ledger.failures.append(f"nested deeper: {old.label} ({old.where()} -> {new.where()})")
        if old.chain != new.chain:
            ledger.failures.append(
                f"module attributes changed for {old.label} ({old.where()} -> {new.where()}): "
                f"{sorted(old.chain)} -> {sorted(new.chain)}")
        check_paths(ledger, old, new)
        check_visibility(ledger, old, new, moves, allow_widened)
    for (_, new_file), group in sorted(by_destination.items()):
        group.sort(key=lambda pair: pair[1].seq)
        for before, after in itertools.pairwise(group):
            if after[0].seq < before[0].seq:
                ledger.failures.append(
                    f"order changed in {new_file}: {after[0].label} ({after[0].where()}) now follows "
                    f"{before[0].label} ({before[0].where()})")
                break
    return ledger


def check_paths(ledger: Ledger, old: Unit, new: Unit) -> None:
    for (macro, old_literal, old_bytes), (_, new_literal, new_bytes) in zip(old.paths, new.paths, strict=True):
        if new_bytes is None:
            ledger.failures.append(f"{macro} target missing: \"{new_literal}\" from {new.where()}")
        elif old_bytes is None:
            ledger.failures.append(f"{macro} target missing at base: \"{old_literal}\" from {old.where()}")
        elif old_bytes != new_bytes:
            ledger.failures.append(
                f"{macro} target bytes differ: \"{old_literal}\" ({old.where()}) vs \"{new_literal}\" ({new.where()})")


def check_visibility(ledger: Ledger, old: Unit, new: Unit, moves: dict, allow_widened: set[str]) -> None:
    if old.module is None or new.module is None:
        if old.vis != new.vis:
            ledger.failures.append(f"visibility changed outside the module tree: {old.label} ({new.where()})")
        return
    old_vis, new_vis = dict(old.vis), dict(new.vis)
    for offset in sorted(set(old_vis) | set(new_vis)):
        before, after = old_vis.get(offset, ""), new_vis.get(offset, "")
        reach = scope(before, old.module)
        for cut in range(len(reach), 0, -1):
            if reach[:cut] in moves:
                reach = moves[reach[:cut]] + reach[cut:]
                break
        now = scope(after, new.module)
        if now[:len(reach)] == reach:
            if before != after and now != reach:
                ledger.notes.append(f"narrowed: {old.label} {before or 'private'} -> {after or 'private'}")
            continue
        row = (f"widened: {old.label} ({new.where()}): {before or 'private'} in {show(old.module)} -> "
               f"{after or 'private'} in {show(new.module)} (reach {show(reach)} -> {show(now)})")
        if allowed(old, new, allow_widened):
            ledger.widened.append(row + " [allowed]")
        else:
            ledger.widened.append(row)
            ledger.failures.append(row)


def allowed(old: Unit, new: Unit, names: set[str]) -> bool:
    item_path = "::".join(new.module[1:] + (new.name,)) if new.module else new.name
    return bool(names & {new.name, new.label, item_path, f"{show(new.module)}::{new.name}"})


def explain_differences(ledger: Ledger, lost: list[Unit], gained: list[Unit]) -> None:
    gained_by_label: dict[tuple[str, str], list[Unit]] = {}
    for unit in gained:
        gained_by_label.setdefault((unit.container, unit.label), []).append(unit)
    for unit in lost:
        twins = gained_by_label.get((unit.container, unit.label))
        if twins:
            twin = twins.pop(0)
            diff = list(difflib.unified_diff(unit.text.splitlines(), twin.text.splitlines(),
                                             f"base {unit.where()}", f"head {twin.where()}", n=2, lineterm=""))
            shown = diff[:DIFF_LIMIT] + ([f"... {len(diff) - DIFF_LIMIT} more diff lines"]
                                        if len(diff) > DIFF_LIMIT else [])
            ledger.failures.append(f"changed: {unit.label} ({unit.where()} -> {twin.where()})\n"
                                   + "\n".join(f"    {line}" for line in shown))
        else:
            ledger.failures.append(f"removed or changed: {unit.label} at {unit.where()}: {first_line(unit.text)}")
    for twins in gained_by_label.values():
        for unit in twins:
            ledger.failures.append(f"added or changed: {unit.label} at {unit.where()}: {first_line(unit.text)}")


def span(first: Unit, last: Unit) -> str:
    return f"{first.line}" if first.line == last.end_line else f"{first.line}-{last.end_line}"


def ledger_rows(pairs: list[tuple[Unit, Unit]]) -> list[str]:
    """One row per run of consecutive items that moved together to one place."""
    rows: list[str] = []
    run: list[tuple[Unit, Unit]] = []

    def flush() -> None:
        if not run:
            return
        (old_a, new_a), (old_b, new_b) = run[0], run[-1]
        what = old_a.label if len(run) == 1 else f"{old_a.label} .. {old_b.label} ({len(run)} items)"
        modules = "" if old_a.module == new_a.module else f"  [{show(old_a.module)} -> {show(new_a.module)}]"
        rows.append(f"{old_a.file}:{span(old_a, old_b)} {what} -> {new_a.file}:{span(new_a, new_b)}{modules}")
        run.clear()

    for old, new in pairs:
        moved = old.file != new.file or old.module != new.module
        if not moved:
            flush()
            continue
        if run:
            prev_old, prev_new = run[-1]
            if not (old.file == prev_old.file and old.seq == prev_old.seq + 1 and new.file == prev_new.file
                    and new.seq == prev_new.seq + 1 and old.module == prev_old.module
                    and new.module == prev_new.module):
                flush()
        run.append((old, new))
    flush()
    return rows


def scope_files(source: rst.Source, tree: rst.Tree, changed: list[str]) -> list[str]:
    files = {path for path in changed if path.endswith(".rs") and source.exists(path)}
    for link in tree.links:
        if link.file in files and link.target:
            files.add(link.target)
    return sorted(files)


def side(repo: Path, rev: str, changed: list[str], other: rst.GitSource | None = None):
    source = rst.GitSource(repo, rev)
    if other is not None:
        source.share_with(other)
    crates = sorted({crate for path in changed if path.endswith(".rs") and source.exists(path)
                     for crate in [rst.crate_dir(path, source)] if crate})
    tree = rst.Tree()
    for crate in crates:
        part = rst.crate_tree(source, crate)
        tree.contexts.update(part.contexts)
        tree.modules |= part.modules
        tree.links += part.links
    files = scope_files(source, tree, changed)
    units = [unit for path in files for unit in units_of(source, tree, path)]
    return source, tree, files, units


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base", help="base commit (default: merge-base of origin/main and HEAD)")
    parser.add_argument("--head", default="HEAD", help="head commit (default: HEAD)")
    parser.add_argument("--repo", default=".", help="repository root (default: .)")
    parser.add_argument("--allow-widened", action="append", default=[], metavar="ITEM",
                        help="accept a widened visibility for this item (name or path as printed; repeatable)")
    parser.add_argument("--report", action="store_true",
                        help="print a short summary and exit 0 even when the change is not move-only")
    args = parser.parse_args(argv)
    repo = Path(args.repo)
    try:
        base = args.base or rst.default_base(repo)
        base_sha = rst.git(repo, "rev-parse", "--verify", f"{base}^{{commit}}").strip()
        head_sha = rst.git(repo, "rev-parse", "--verify", f"{args.head}^{{commit}}").strip()
        changed = [path for path in rst.changed_files(repo, base_sha, head_sha) if path.endswith(".rs")]
        print(f"move-ledger: base {base_sha[:12]} head {head_sha[:12]}: {len(changed)} changed .rs files")
        if not changed:
            print("move-ledger: nothing to check")
            return 0
        base_source, _, base_files, base_units = side(repo, base_sha, changed)
        head_source, head_tree, head_files, head_units = side(repo, head_sha, changed, base_source)
    except rst.SourceError as error:
        print(f"move-ledger: {error}", file=sys.stderr)
        # A report never blocks a change; an enforced check does.
        return 0 if args.report else 2
    ledger = check(base_units, head_units, head_tree.modules, set(args.allow_widened))
    for path in head_files:
        if path in changed and path not in head_tree.contexts:
            ledger.failures.append(f"not reachable by mod: {path}")
    for link in head_tree.links:
        if link.file in changed and link.target is None:
            ledger.failures.append(f"unresolved {link.how} at {link.file}:{link.line}"
                                   + (f": \"{link.literal}\"" if link.literal else ""))
    for source in (base_source, head_source):
        source.close()
    rows = ledger_rows(ledger.pairs)
    moved = sum(1 for old, new in ledger.pairs if old.file != new.file or old.module != new.module)
    print(f"move-ledger: {len(base_units)} base items in {len(base_files)} files, "
          f"{len(head_units)} head items in {len(head_files)} files: "
          f"{len(ledger.pairs) - moved} untouched, {moved} moved, {len(ledger.widened)} widened, "
          f"{len(ledger.failures)} problems")
    limit = REPORT_LIMIT if args.report else None
    for row in rows[:limit]:
        print(f"  moved {row}")
    for row in ledger.widened[:limit]:
        print(f"  {row}")
    for note in ledger.notes[:limit]:
        print(f"  note: {note}")
    if args.report:
        for failure in ledger.failures[:REPORT_LIMIT]:
            print(f"  not a move: {failure.splitlines()[0]}")
        if len(ledger.failures) > REPORT_LIMIT:
            print(f"  ... {len(ledger.failures) - REPORT_LIMIT} more")
        print("move-ledger: report only")
        return 0
    for failure in ledger.failures:
        print(f"move-ledger: FAIL {failure}", file=sys.stderr)
    if ledger.failures:
        print(f"move-ledger: {len(ledger.failures)} problems; the change is not move-only", file=sys.stderr)
        return 1
    print("move-ledger: move-only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
