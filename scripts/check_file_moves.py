#!/usr/bin/env python3
"""Check that a change only moves whole Rust module files, or only absolutizes paths.

Both modes fail closed: anything this script cannot prove is a problem.

Mode `move` (a pull request with a `File-move:` line). Every changed path is:

  (i)   a moved file: a deleted path whose bytes reappear in exactly one added
        path (git `-M100%` must agree), inside a moved subtree: a module file
        plus every file below its module, keeping their module layout. A file
        reached only through `include!`/`include_str!`/`include_bytes!` from the
        subtree moves with it;
  (ii)  an old parent: its only change removes a moved root's `mod x;` item
        (whole lines, with its attributes) and may add one facade alias,
        `pub(crate) use <path>;` or `pub(crate) use <path> as x;` (or with the
        removed item's visibility and attributes), whose path resolves through
        `mod` declarations only to exactly the moved module and binds the old
        name x;
  (iii) a new parent: its only change adds `mod x;` items for moved roots, with
        the removed item's attributes; the visibility may only stay or become
        `pub(crate)` when an alias needs it (reported);
  (iv)  scripts/source_layout_*.tsv or scripts/test_id_renames.tsv.

A moved root may itself be a new parent: it is then byte-identical to its old
file after removing whole added `mod <ident>;` items, where <ident> is a moved
root and never occurs as an identifier token in the old file.

Inside moved files, no `super` chain may reach above the moved root (tokens,
counting inline `mod {}` nesting outside macros), there is no `#[path]`, and
every include macro takes one plain string literal that resolves to the moved
counterpart of a file in the same subtree. Each moved file has exactly one
module context at base and head, its links (`mod`, `include!`) map to the moved
counterparts, and every other file's links are unchanged.

Names: an added `mod x;` must be the only binding of x in its new parent. If the
new parent has glob imports, each must be a glob of the old parent (which
declared x itself) and the name must stay x; otherwise x must not be an extern
crate, prelude or primitive name and the parent's item-level macros must be
defined in this crate without `use`. An old name without an alias needs the
same proof in the old parent with no glob imports at all. Bare macro names
invoked in a moved subtree must see the same textual `macro_rules!` at the new
declaration point as at the old one; `#[macro_use]` modules are not supported.

Mode `absolutize` (a pull request with an `Absolutize:` line): no file moves;
each changed `.rs` file differs only where a `super` chain at the start of a
path (`super::`.., `pub(super)`, `pub(in super..)`) is replaced by the
`crate::..` path of the module it denotes, computed from the file's single
module context and the inline modules around it. Chains inside attributes,
macro invocations or `macro_rules!` bodies, spaced chains, chains inside
modules that are not nameable, and files with attribute macros fail.

Exit status: 0 when the change is file-move-only / absolutize-only (or with
--report), 1 when it is not, 2 on a usage or setup error.
"""

from __future__ import annotations

import argparse
import bisect
import difflib
import posixpath
import re
import subprocess
import sys
import tomllib
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import rust_source_tree as rst

TSV = re.compile(r"^scripts/(?:source_layout_[^/]+|test_id_renames)\.tsv$")
TRIVIA = ("ws", "comment", "doc", "idoc")
PATH_MACROS = {"include", "include_str", "include_bytes"}
REGULAR = "100644"
REPORT_LIMIT = 60
# Keywords that can stand before `!` without naming a macro (`if !x`, `return !x`).
KEYWORDS = {
    "as", "async", "await", "box", "break", "const", "continue", "crate", "dyn", "else", "enum", "extern",
    "false", "fn", "for", "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref",
    "return", "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use",
    "where", "while", "yield",
}
# Built-in and derive-helper attributes; any other attribute may be a procedural macro.
INERT_ATTRS = {
    "allow", "automatically_derived", "backtrace", "cfg", "cfg_attr", "clippy", "cold", "coverage",
    "default", "deny", "deprecated", "derive", "diagnostic", "doc", "error", "expect", "export_name",
    "forbid", "from", "ignore", "inline", "link", "link_name", "link_section", "macro_export",
    "must_use", "no_mangle", "non_exhaustive", "path", "prost", "repr", "rustfmt", "serde",
    "should_panic", "source", "target_feature", "test", "track_caller", "transparent", "used", "warn",
}
# Standard macros; none emits a `use` item.
STD_MACROS = {
    "assert", "assert_eq", "assert_ne", "cfg", "column", "compile_error", "concat", "dbg",
    "debug_assert", "debug_assert_eq", "debug_assert_ne", "env", "eprint", "eprintln", "file", "format",
    "format_args", "include", "include_bytes", "include_str", "line", "matches", "module_path",
    "option_env", "panic", "print", "println", "stringify", "thread_local", "todo", "unimplemented",
    "unreachable", "vec", "write", "writeln",
}
PRELUDE = {
    "AsMut", "AsRef", "Box", "Clone", "Copy", "Default", "DoubleEndedIterator", "Drop", "Eq", "Err",
    "ExactSizeIterator", "Extend", "Fn", "FnMut", "FnOnce", "From", "FromIterator", "Into", "IntoIterator",
    "Iterator", "None", "Ok", "Option", "Ord", "PartialEq", "PartialOrd", "Result", "Send", "Sized", "Some",
    "String", "Sync", "ToOwned", "ToString", "TryFrom", "TryInto", "Unpin", "Vec", "drop",
}
PRIMITIVES = {
    "bool", "char", "str", "u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128",
    "isize", "f16", "f32", "f64", "f128",
}


class Unproven(Exception):
    """Something the checker cannot prove; always a problem."""


# ---------------------------------------------------------------- token helpers


def code_index(lx: rst.Lexed) -> list[int]:
    return [i for i, token in enumerate(lx.tokens) if token.kind not in TRIVIA]


def is_path_sep(lx: rst.Lexed, index: int) -> bool:
    """`::` starting at token `index` (two adjacent `:` tokens)."""
    return lx.is_punct(index, ":") and lx.is_punct(index + 1, ":")


def attr_name(lx: rst.Lexed, bracket: int) -> list[str]:
    """Names of the attributes inside `#[..]` whose `[` is token `bracket` (cfg_attr expanded)."""
    close = lx.match[bracket]
    first = lx.next_code(bracket + 1, close)
    path, probe = [], first
    while lx.is_ident(probe):
        path.append(lx.tok(probe))
        nxt = lx.next_code(probe + 1, close)
        if is_path_sep(lx, nxt):
            probe = lx.next_code(nxt + 2, close)
            continue
        break
    if not path:
        return ["?"]
    if path == ["cfg_attr"]:
        group = lx.next_code(probe + 1, close)
        names: list[str] = ["cfg_attr"]
        if lx.is_punct(group, "("):
            # Attributes after the first top-level comma.
            depth_close, cursor, seen_comma, start = lx.match[group], group + 1, False, True
            while cursor < depth_close:
                if lx.tokens[cursor].kind in TRIVIA:
                    cursor += 1
                    continue
                if cursor in lx.match:
                    cursor = lx.match[cursor] + 1
                    start = False
                    continue
                if lx.is_punct(cursor, ","):
                    seen_comma, start = True, True
                    cursor += 1
                    continue
                if seen_comma and start and lx.is_ident(cursor):
                    names.append(lx.tok(cursor))
                start = False
                cursor += 1
        return names
    return [path[0]]


@dataclass
class Shape:
    """Where attributes, macro token trees and `mod` blocks sit in one file."""

    opaque: list[tuple[int, int, str]] = field(default_factory=list)  # (first, last, what) token ranges
    attrs: list[tuple[int, list[str], bool]] = field(default_factory=list)  # (`#` token, names, has path =)
    mod_blocks: list[tuple[int, int, str]] = field(default_factory=list)  # (open, close, name) outside opaque
    bare_macros: list[tuple[str, int]] = field(default_factory=list)  # (name, token) invoked without a path
    path_macros: list[tuple[str, int, int]] = field(default_factory=list)  # (macro, `!` token, group token)


def shape(lx: rst.Lexed) -> Shape:
    out = Shape()
    code = code_index(lx)
    for pos, i in enumerate(code):
        if lx.is_punct(i, "#"):
            j = code[pos + 1] if pos + 1 < len(code) else None
            if j is not None and lx.is_punct(j, "!"):
                j = code[pos + 2] if pos + 2 < len(code) else None
            if j is not None and lx.is_punct(j, "["):
                close = lx.match[j]
                has_path = any(lx.is_ident(k, "path") and lx.is_punct(lx.next_code(k + 1, close), "=")
                               for k in range(j, close))
                out.opaque.append((i, close, "attribute"))
                out.attrs.append((i, attr_name(lx, j), has_path))
        elif lx.is_punct(i, "!") and pos > 0 and pos + 1 < len(code):
            prev, nxt = code[pos - 1], code[pos + 1]
            if lx.tokens[prev].kind != "ident" or lx.tok(prev) in KEYWORDS:
                continue
            name = lx.tok(prev)
            group = nxt
            if name == "macro_rules" and lx.is_ident(nxt) and pos + 2 < len(code):
                group = code[pos + 2]
            if group not in lx.match or lx.tok(group) not in "([{":
                continue
            out.opaque.append((prev, lx.match[group], f"{name}!"))
            before = code[pos - 2] if pos >= 2 else None
            pathed = before is not None and lx.is_punct(before, ":") and lx.is_punct(before - 1, ":")
            if name != "macro_rules" and not pathed:
                out.bare_macros.append((name, prev))
            if name in PATH_MACROS:
                out.path_macros.append((name, i, group))
    for pos, i in enumerate(code[:-2]):
        if lx.is_ident(i, "mod") and lx.is_ident(code[pos + 1]) and lx.is_punct(code[pos + 2], "{"):
            open_ = code[pos + 2]
            if not inside(out.opaque, i):
                out.mod_blocks.append((open_, lx.match[open_], lx.tok(code[pos + 1])))
    return out


def inside(ranges, index: int) -> str | None:
    for first, last, what in ranges:
        if first <= index <= last:
            return what
    return None


def super_chains(lx: rst.Lexed) -> list[tuple[int, int, int, bool]]:
    """(first token, last token, length, contiguous) of every `super` chain, spacing and comments skipped."""
    chains = []
    code = code_index(lx)
    at = {index: pos for pos, index in enumerate(code)}
    pos = 0
    while pos < len(code):
        i = code[pos]
        if not lx.is_ident(i, "super"):
            pos += 1
            continue
        length, last, contiguous, probe = 1, i, True, pos
        while probe + 1 < len(code) and is_path_sep(lx, code[probe + 1]):
            after = at.get(lx.next_code(code[probe + 1] + 2))
            if after is None or not lx.is_ident(code[after], "super"):
                break
            if code[probe + 1] != last + 1 or code[after] != code[probe + 1] + 2:
                contiguous = False
            length, last, probe = length + 1, code[after], after
        chains.append((i, last, length, contiguous))
        pos = probe + 1
    return chains


def literal_value(lx: rst.Lexed, macro: str, group: int) -> str | None:
    """The plain string literal that is the only argument of an include macro, else None."""
    close = lx.match[group]
    first = lx.next_code(group + 1, close)
    if first >= close or lx.tokens[first].kind != "str":
        return None
    after = lx.next_code(first + 1, close)
    if lx.is_punct(after, ","):
        after = lx.next_code(after + 1, close)
    text = lx.tok(first)
    if after != close or not (text.startswith('"') and text.endswith('"')) or "\\" in text:
        return None
    return text[1:-1]


def keyword_index(lx: rst.Lexed, item: rst.Item) -> int:
    """Token index of an item's visibility or first keyword, after its attributes and comments."""
    index = item.first_token
    while True:
        index = lx.next_code(index)
        if lx.is_punct(index, "#"):
            bracket = lx.next_code(index + 1)
            if lx.is_punct(bracket, "!"):
                bracket = lx.next_code(bracket + 1)
            index = lx.match[bracket] + 1
            continue
        return index


def visibility(lx: rst.Lexed, item: rst.Item) -> str:
    start = keyword_index(lx, item)
    stop = lx.skip_vis(start)
    if stop == start:
        return ""
    words = [lx.tok(i) for i in range(start, stop) if lx.tokens[i].kind not in TRIVIA]
    return re.sub(r"\bin(?=\w)", "in ", "".join(words))


def walk_items(items: list[rst.Item]):
    for item in items:
        yield item
        if item.kind == "mod" and item.members is not None:
            yield from walk_items(item.members)


# ---------------------------------------------------------------- use trees


def use_leaves(lx: rst.Lexed, item: rst.Item) -> list[tuple[tuple[str, ...], str | None, bool]]:
    """(path, binding, glob) for every leaf of a `use` item; binding None for `as _` and globs."""
    start = lx.skip_vis(keyword_index(lx, item))
    start = lx.next_code(start)
    if not lx.is_ident(start, "use"):
        raise Unproven(f"{lx.where}:{lx.line(item.lead)}: cannot read use item")
    toks = [i for i in range(start + 1, item.last_token + 1) if lx.tokens[i].kind not in TRIVIA]
    texts = [lx.tok(i) for i in toks]
    leaves: list[tuple[tuple[str, ...], str | None, bool]] = []

    def tree(pos: int, prefix: tuple[str, ...]) -> int:
        path = list(prefix)
        if pos + 1 < len(texts) and texts[pos] == ":" and texts[pos + 1] == ":":
            path.append("::")
            pos += 2
        while True:
            if texts[pos] == "*":
                leaves.append((tuple(path), None, True))
                return pos + 1
            if texts[pos] == "{":
                pos += 1
                while texts[pos] != "}":
                    pos = tree(pos, tuple(path))
                    if texts[pos] == ",":
                        pos += 1
                return pos + 1
            if not re.match(r"^(?:r#)?\w+$", texts[pos]):
                raise Unproven(f"{lx.where}:{lx.line(item.lead)}: cannot read use tree")
            path.append(texts[pos])
            pos += 1
            if pos + 1 < len(texts) and texts[pos] == ":" and texts[pos + 1] == ":":
                pos += 2
                continue
            binding: str | None = path[-1]
            if binding == "self":
                path.pop()
                binding = path[-1] if path else None
            if pos < len(texts) and texts[pos] == "as":
                binding = None if texts[pos + 1] == "_" else texts[pos + 1]
                pos += 2
            leaves.append((tuple(path), binding, False))
            return pos

    end = tree(0, ())
    if texts[end:] != [";"]:
        raise Unproven(f"{lx.where}:{lx.line(item.lead)}: cannot read use tree")
    return leaves


# ---------------------------------------------------------------- module facts


@dataclass
class Facts:
    """What one module binds at depth 0 across its files."""

    bindings: dict[str, list[str]] = field(default_factory=lambda: defaultdict(list))
    globs: list[tuple[tuple[str, ...], str]] = field(default_factory=list)
    macros: list[tuple[str, str]] = field(default_factory=list)
    opaque: list[str] = field(default_factory=list)


BINDING_KINDS = {"mod", "mod-decl", "struct", "enum", "union", "trait", "type", "fn", "const", "static"}


def module_files(tree: rst.Tree, module: tuple[str, ...]) -> list[str]:
    return sorted({path for path, contexts in tree.contexts.items()
                   for context in contexts if context.module == module})


_FACTS: dict[tuple[int, tuple[str, ...]], Facts] = {}


def attr_names_text(attr: str) -> list[str]:
    lx = rst.Lexed(attr + "\nfn f() {}")
    bracket = lx.next_code(lx.next_code(0) + 1)
    if lx.is_punct(bracket, "!"):
        bracket = lx.next_code(bracket + 1)
    return attr_name(lx, bracket)


def module_facts(tree: rst.Tree, source: rst.Source, module: tuple[str, ...]) -> Facts:
    key = (id(tree), module)
    if key not in _FACTS:
        _FACTS[key] = _module_facts(tree, source, module)
    return _FACTS[key]


def _module_facts(tree: rst.Tree, source: rst.Source, module: tuple[str, ...]) -> Facts:
    facts = Facts()
    files = module_files(tree, module)
    if not files:
        facts.opaque.append(f"module {'::'.join(module)} has no file")
    for path in files:
        lx = source.lexed(path)
        for item in lx.items:
            where = f"{path}:{lx.line(item.lead)}"
            for attr in item.attrs:
                if any(name not in INERT_ATTRS for name in attr_names_text(attr)):
                    facts.opaque.append(f"{where}: attribute {attr} may be a macro")
            if item.kind == "use":
                for leaf, binding, glob in use_leaves(lx, item):
                    if glob:
                        facts.globs.append((leaf, where))
                    elif binding:
                        facts.bindings[binding].append(f"use at {where}")
            elif item.kind in BINDING_KINDS:
                if item.name != "_":
                    facts.bindings[item.name].append(f"{item.kind} at {where}")
            elif item.kind == "extern-crate":
                words = [lx.tok(i) for i in range(item.first_token, item.last_token + 1)
                         if lx.tokens[i].kind == "ident"]
                facts.bindings[words[-1] if "as" in words else item.name].append(f"extern crate at {where}")
            elif item.kind == "macro":
                facts.macros.append((item.name.rstrip("!").split("::")[-1], where))
            elif item.kind in ("extern", "unknown"):
                facts.opaque.append(f"{where}: {item.kind} item")
    return facts


def resolve_mod_path(tree: rst.Tree, source: rst.Source, start: tuple[str, ...],
                     segments: tuple[str, ...]) -> tuple[str, ...]:
    """The module `segments` names from module `start`, through `mod` declarations only."""
    if not segments:
        raise Unproven("empty path")
    module, rest = start, list(segments)
    if rest[0] == "::":
        raise Unproven("path starts with `::`")
    if rest[0] == "crate":
        module, rest = start[:1], rest[1:]
    elif rest[0] == "self":
        rest = rest[1:]
    while rest and rest[0] == "super":
        if len(module) < 2:
            raise Unproven("`super` above the crate root")
        module, rest = module[:-1], rest[1:]
    for name in rest:
        if name in ("crate", "self", "super"):
            raise Unproven(f"`{name}` inside a path")
        child = module + (name,)
        if child not in tree.modules:
            raise Unproven(f"`{name}` is not a module declared in {'::'.join(module)}")
        bound = module_facts(tree, source, module).bindings.get(name, [])
        if len(bound) != 1 or not bound[0].startswith(("mod-decl ", "mod ")):
            raise Unproven(f"`{name}` in {'::'.join(module)} has bindings {bound or 'none'}")
        module = child
    return module


# ---------------------------------------------------------------- crate facts


def extern_names(source: rst.Source, crate: str, tree: rst.Tree) -> set[str]:
    names = {"std", "core", "alloc", "proc_macro", "test"}
    data = tomllib.loads(source.read(f"{crate}/Cargo.toml"))

    def deps(table: dict) -> None:
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            names.update(name.replace("-", "_") for name in table.get(key, {}))

    deps(data)
    for table in data.get("target", {}).values():
        deps(table)
    for key in ("package", "lib"):
        if "name" in data.get(key, {}):
            names.add(data[key]["name"].replace("-", "_"))
    for path, contexts in tree.contexts.items():
        if any(context.how == "root" for context in contexts):
            lx = source.lexed(path)
            for item in lx.items:
                if item.kind == "extern-crate":
                    words = [lx.tok(i) for i in range(item.first_token, item.last_token + 1)
                             if lx.tokens[i].kind == "ident"]
                    names.add(words[-1])
    return names


@dataclass
class MacroDef:
    path: str
    ordinal: int
    uses_use: bool
    invoked: set[str]


def crate_macros(tree: rst.Tree, source: rst.Source) -> dict[str, list[MacroDef]]:
    found: dict[str, list[MacroDef]] = defaultdict(list)
    for path in sorted(tree.contexts):
        lx = source.lexed(path)
        code = code_index(lx)
        count: dict[str, int] = defaultdict(int)
        for pos, i in enumerate(code[:-3]):
            if lx.is_ident(i, "macro_rules") and lx.is_punct(code[pos + 1], "!") and lx.is_ident(code[pos + 2]):
                name, group = lx.tok(code[pos + 2]), code[pos + 3]
                if group not in lx.match:
                    continue
                body = range(group, lx.match[group])
                idents = {lx.tok(k) for k in body if lx.tokens[k].kind == "ident"}
                invoked = {lx.tok(k) for k in body if lx.tokens[k].kind == "ident"
                           and lx.is_punct(lx.next_code(k + 1), "!") and lx.tok(k) not in KEYWORDS}
                found[name].append(MacroDef(path, count[name], "use" in idents, invoked))
                count[name] += 1
    return found


def macro_problem(name: str, macros: dict[str, list[MacroDef]], seen: set[str] | None = None) -> str | None:
    """Why an item-level `name!` might emit an import, or None when it cannot."""
    seen = set() if seen is None else seen
    if name in seen:
        return None
    seen.add(name)
    definitions = macros.get(name)
    if not definitions:
        return None if name in STD_MACROS else f"macro {name}! is not a macro_rules of this crate"
    for definition in definitions:
        if definition.uses_use:
            return f"macro {name}! ({definition.path}) contains `use`"
        for inner in sorted(definition.invoked):
            problem = macro_problem(inner, macros, seen)
            if problem:
                return problem
    return None


# ---------------------------------------------------------------- git


@dataclass
class Change:
    status: str
    path: str
    old_mode: str
    new_mode: str
    old_blob: str
    new_blob: str


def raw_changes(repo: Path, base: str, head: str) -> list[Change]:
    out = rst.git(repo, "diff", "--raw", "--no-renames", "--no-abbrev", "--no-ext-diff", "--no-color", "-z",
                  base, head)
    parts = out.split("\0")
    changes = []
    for index in range(0, len(parts) - 1, 2):
        meta, path = parts[index], parts[index + 1]
        old_mode, new_mode, old_blob, new_blob, status = meta.lstrip(":").split()
        changes.append(Change(status[0], path, old_mode, new_mode, old_blob, new_blob))
    return changes


def git_renames(repo: Path, base: str, head: str) -> set[tuple[str, str]]:
    out = rst.git(repo, "diff", "-M100%", "--name-status", "--no-ext-diff", "--no-color", "-z", base, head)
    parts = out.split("\0")
    renames, index = set(), 0
    while index < len(parts) - 1:
        status = parts[index]
        if status.startswith(("R", "C")):
            if status == "R100":
                renames.add((parts[index + 1], parts[index + 2]))
            index += 3
        else:
            index += 2
    return renames


def old_path_mentions(repo: Path, head: str, base: rst.Source, paths: list[str]) -> list[str]:
    """Files at head whose text names a moved file's old path (repo- or crate-relative)."""
    patterns = []
    for path in paths:
        patterns += ["-e", path]
        crate = crate_of(path, base)
        if crate:
            patterns += ["-e", posixpath.relpath(path, crate)]
    done = subprocess.run(["git", "-C", str(repo), "grep", "-l", "-F", *patterns, head],
                          capture_output=True, text=True, check=False)
    return sorted({line.split(":", 1)[1] for line in done.stdout.splitlines() if ":" in line})


# ---------------------------------------------------------------- line stripping


def strip_lines(lx: rst.Lexed, items: list[rst.Item]) -> tuple[str, list[int]]:
    """The text without the whole lines of `items`, and the original index of every kept line."""
    lines = lx.text.splitlines(keepends=True)
    drop: set[int] = set()
    for item in items:
        line_start = lx.text.rfind("\n", 0, item.start) + 1
        line_end = lx.text.find("\n", item.end)
        line_end = len(lx.text) if line_end < 0 else line_end
        if lx.text[line_start:item.start].strip() or lx.text[item.end:line_end].strip():
            raise Unproven(f"{lx.where}:{lx.line(item.lead)}: `{item.kind} {item.name}` does not fill whole lines")
        drop.update(range(lx.line(item.start) - 1, lx.line(item.end)))
    kept = [index for index in range(len(lines)) if index not in drop]
    return "".join(lines[index] for index in kept), kept


def blank_safe_lines(text: str) -> set[int]:
    """Indices of whitespace-only lines that lie in whitespace (not in a literal or comment)."""
    tokens = rst.tokenize(text)
    starts = [token.start for token in tokens]
    safe, offset = set(), 0
    for index, row in enumerate(text.splitlines(keepends=True)):
        if not row.strip():
            k = bisect.bisect_right(starts, offset) - 1
            if k < 0 or tokens[k].kind == "ws":
                safe.add(index)
        offset += len(row)
    return safe


def line_changes(old_text: str, new_text: str) -> tuple[list[int], list[str], int]:
    """(new line indices inserted, problems, blank lines added or dropped) from old_text to new_text.

    Whitespace-only lines outside literals and comments may come or go; every other old line must stay.
    """
    old_rows, new_rows = old_text.splitlines(keepends=True), new_text.splitlines(keepends=True)
    old_safe, new_safe = blank_safe_lines(old_text), blank_safe_lines(new_text)
    inserted, problems, blanks = [], [], 0
    matcher = difflib.SequenceMatcher(None, old_rows, new_rows, autojunk=False)
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag == "equal":
            continue
        lost = [index for index in range(a0, a1) if index not in old_safe]
        if lost:
            problems.append(f"base line {lost[0] + 1} is removed or edited")
            continue
        blanks += a1 - a0
        for index in range(b0, b1):
            if index in new_safe:
                blanks += 1
            else:
                inserted.append(index)
    return inserted, problems, blanks


def ident_tokens(text: str) -> set[str]:
    return {text[t.start:t.end] for t in rst.tokenize(text) if t.kind == "ident"}


# ---------------------------------------------------------------- textual macro scope


def textual_env(tree: rst.Tree, source: rst.Source, path: str, offset: int,
                canon) -> dict[str, tuple[str, str, int]]:
    """The last `macro_rules!` of each name visible, by textual scope, at `offset` in `path`."""
    chain: list[tuple[str, int]] = []
    current, at = path, offset
    while True:
        chain.append((current, at))
        contexts = tree.contexts.get(current, [])
        if len(contexts) != 1:
            raise Unproven(f"{current} has {len(contexts)} module contexts")
        context = contexts[0]
        if context.how == "root":
            break
        parent = context.declared_by
        links = [link for link in tree.links if link.file == parent and link.target == current]
        if len(links) != 1:
            raise Unproven(f"{current} is linked {len(links)} times from {parent}")
        lx = source.lexed(parent)
        owners = [item for item in walk_items(lx.items)
                  if item.kind in ("mod-decl", "include") and lx.line(item.lead) == links[0].line]
        if len(owners) != 1:
            raise Unproven(f"cannot find the item linking {current} in {parent}")
        current, at = parent, owners[0].lead
    env: dict[str, tuple[str, str, int]] = {}
    for file, point in reversed(chain):
        visible_defs(tree, source, file, source.lexed(file).items, point, env, canon)
    return env


def visible_defs(tree, source, file, items, point, env, canon) -> None:
    ordinals: dict[str, int] = defaultdict(int)
    for item in walk_items(source.lexed(file).items):
        if item.kind == "macro_rules":
            item_name = item.name.split()[-1]
            ordinals[(item_name, item.start)] = ordinals[item_name]
            ordinals[item_name] += 1
    _visible(tree, source, file, items, point, env, canon, ordinals)


def _visible(tree, source, file, items, point, env, canon, ordinals) -> None:
    for item in items:
        if point is not None and item.start >= point:
            break
        if any(re.match(r"^#\[\s*macro_use\b", attr) for attr in item.attrs):
            raise Unproven(f"{file}: #[macro_use] is not supported")
        if item.kind == "macro_rules":
            name = item.name.split()[-1]
            env[name] = (canon(file), name, ordinals[(name, item.start)])
        elif item.kind == "include":
            lx = source.lexed(file)
            targets = [link.target for link in tree.links
                       if link.file == file and link.how == "include" and link.line == lx.line(item.lead)]
            if len(targets) != 1 or targets[0] is None:
                raise Unproven(f"{file}: unresolved include before a declaration")
            visible_defs(tree, source, targets[0], source.lexed(targets[0]).items, None, env, canon)
        elif item.kind == "mod" and item.members is not None and point is not None and item.end > point:
            _visible(tree, source, file, item.members, point, env, canon, ordinals)


# ---------------------------------------------------------------- results


@dataclass
class Result:
    problems: list[str] = field(default_factory=list)
    lines: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    glue: set[str] = field(default_factory=set)

    def fail(self, text: str) -> None:
        self.problems.append(text)


def crate_of(path: str, source: rst.Source) -> str | None:
    return rst.crate_dir(path, source)


def single(tree: rst.Tree, path: str) -> rst.Context | None:
    contexts = tree.contexts.get(path, [])
    return contexts[0] if len(contexts) == 1 else None


def decl_item(lx: rst.Lexed, name: str, line: int) -> rst.Item | None:
    found = [item for item in lx.items if item.kind == "mod-decl" and item.name == name
             and lx.line(item.lead) == line]
    return found[0] if len(found) == 1 else None


# ---------------------------------------------------------------- mode: move


@dataclass
class Root:
    src: str
    dst: str
    old: tuple[str, ...]
    new: tuple[str, ...]
    old_parent: str
    new_parent: str
    old_decl: rst.Item
    new_decl: rst.Item
    old_vis: str = ""
    new_vis: str = ""
    members: list[str] = field(default_factory=list)
    alias: rst.Item | None = None


def check_move(repo: Path, base_sha: str, head_sha: str) -> Result:
    result = Result()
    _FACTS.clear()
    changes = raw_changes(repo, base_sha, head_sha)
    base, head = rst.GitSource(repo, base_sha), rst.GitSource(repo, head_sha)
    head.share_with(base)
    try:
        _check_move(repo, base_sha, head_sha, changes, base, head, result)
    except Unproven as error:
        result.fail(str(error))
    except rst.SourceError as error:
        result.fail(f"cannot read source: {error}")
    finally:
        base.close()
        head.close()
    return result


def _check_move(repo, base_sha, head_sha, changes, base, head, result) -> None:
    deleted, added, modified, tsv = {}, {}, set(), []
    for change in changes:
        modes = {mode for mode in (change.old_mode, change.new_mode) if mode != "000000"}
        if modes != {REGULAR}:
            result.fail(f"{change.path}: file mode {change.old_mode} -> {change.new_mode}")
            continue
        if TSV.match(change.path) and change.status == "M":
            tsv.append(change.path)
        elif change.status == "D":
            deleted[change.path] = change.old_blob
        elif change.status == "A":
            added[change.path] = change.new_blob
        elif change.status == "M":
            modified.add(change.path)
        else:
            result.fail(f"{change.path}: change type {change.status}")
    # (i) exact moves: one deleted and one added path with the same bytes.
    by_old, by_new = defaultdict(list), defaultdict(list)
    for path, blob in deleted.items():
        by_old[blob].append(path)
    for path, blob in added.items():
        by_new[blob].append(path)
    pairs: dict[str, str] = {}
    for blob, sources in by_old.items():
        targets = by_new.get(blob, [])
        if len(sources) == 1 and len(targets) == 1:
            pairs[sources[0]] = targets[0]
        elif targets:
            result.fail(f"identical bytes in deleted {sorted(sources)} and added {sorted(targets)}: ambiguous move")
    if git_renames(repo, base_sha, head_sha) != set(pairs.items()):
        result.fail("git -M100% rename detection disagrees with the exact byte pairs")
    # A moved root that gained `mod <ident>;` items for other moved roots (anchored on validated pairs).
    stripped: dict[str, list[rst.Item]] = {}
    progress = True
    while progress:
        progress = False
        targets = set(pairs.values())
        for dst in sorted(set(added) - targets):
            if not dst.endswith(".rs"):
                continue
            lx = head.lexed(dst)
            context = rst.file_context(dst, ())
            folder = posixpath.join(context.directory, context.relative or "")
            matches = []
            for src in sorted(set(deleted) - set(pairs)):
                if not src.endswith(".rs"):
                    continue
                old_text = base.read(src)
                names = ident_tokens(old_text)
                decls = []
                for item in lx.items:
                    if item.kind != "mod-decl" or rst.attr_path(item.attrs) is not None or item.name in names:
                        continue
                    child = [posixpath.normpath(posixpath.join(folder, f"{item.name}.rs")),
                             posixpath.normpath(posixpath.join(folder, item.name, "mod.rs"))]
                    if any(path in targets for path in child):
                        decls.append(item)
                if decls:
                    extra, problems, _ = line_changes(old_text, strip_lines(lx, decls)[0])
                    if not extra and not problems:
                        matches.append((src, decls))
            if len(matches) > 1:
                result.fail(f"{dst}: matches {[src for src, _ in matches]} after removing added mod items")
            elif matches:
                pairs[matches[0][0]], stripped[dst] = dst, matches[0][1]
                progress = True
    for src in sorted(set(deleted) - set(pairs)):
        copies = [path for path, blob in added.items() if blob == deleted[src]]
        result.fail(f"deleted {src} has no exact move" + (f" (same bytes as {copies})" if copies else ""))
    for dst in sorted(set(added) - set(pairs.values())):
        old = [path for path in base.files() if base._blobs.get(path) == added[dst]]
        reason = f" (copy of {old}, whose path is kept or reused)" if old else ""
        result.fail(f"added {dst} is not an exact move{reason}")
    if not pairs:
        result.lines.append("no moved files")
        if modified:
            for path in sorted(modified):
                result.fail(f"{path}: edited, but nothing moved")
        return
    inverse = {dst: src for src, dst in pairs.items()}
    crates = {crate_of(path, base) for path in pairs} | {crate_of(path, head) for path in pairs.values()}
    crates |= {crate_of(path, base) for path in modified if path.endswith(".rs")}
    if None in crates:
        raise Unproven("a changed file is outside any crate")
    for src, dst in pairs.items():
        if crate_of(src, base) != crate_of(dst, head):
            result.fail(f"{src} -> {dst} changes crate")
    for crate in sorted(crates):
        _check_crate(crate, pairs, inverse, stripped, modified, base, head, result)
    for path in sorted(modified - result.glue):
        result.fail(f"{path}: edited, but it is neither glue nor a layout TSV")
    mentions = old_path_mentions(repo, head_sha, base, sorted(pairs))
    if mentions:
        result.notes.append(f"old paths still named (by text) in: {', '.join(mentions[:10])}")
    if tsv:
        result.lines.append(f"layout TSV files: {', '.join(sorted(tsv))}")


def _check_crate(crate, pairs, inverse, stripped, modified, base, head, result) -> None:
    base_tree, head_tree = rst.crate_tree(base, crate), rst.crate_tree(head, crate)
    mine = {src: dst for src, dst in pairs.items() if crate_of(src, base) == crate}
    if not mine:
        return
    mapped = lambda path: mine.get(path, path)  # noqa: E731
    canon_head = lambda path: inverse.get(path, path)  # noqa: E731
    externs = extern_names(head, crate, head_tree) | extern_names(base, crate, base_tree)
    base_macros, head_macros = crate_macros(base_tree, base), crate_macros(head_tree, head)

    # Literal targets of include macros inside moved .rs files, per file.
    attached: dict[str, set[str]] = defaultdict(set)  # included file -> including moved files
    for src in mine:
        if src.endswith(".rs") and src in base_tree.contexts:
            lx = base.lexed(src)
            for macro, _bang, group in shape(lx).path_macros:
                literal = literal_value(lx, macro, group)
                if literal is not None:
                    attached[posixpath.normpath(posixpath.join(posixpath.dirname(src), literal))].add(src)

    # Rule E and roots.
    roots: dict[str, Root] = {}
    owner: dict[str, str] = {}
    for src, dst in sorted(mine.items()):
        b_contexts, h_contexts = base_tree.contexts.get(src, []), head_tree.contexts.get(dst, [])
        if not b_contexts and not h_contexts:
            continue  # not a module file: it must move with a file that includes it (below)
        if len(b_contexts) != 1 or len(h_contexts) != 1:
            result.fail(f"{src} -> {dst}: {len(b_contexts)} module contexts at base, {len(h_contexts)} at head; "
                        "a moved file needs exactly one")
            continue
        b, h = b_contexts[0], h_contexts[0]
        if b.how == "root" or h.how == "root":
            result.fail(f"{src}: a crate root cannot move")
            continue
        if b.how == "path" or h.how == "path":
            result.fail(f"{src}: declared with #[path]; not supported")
            continue
        if b.module[0] != h.module[0]:
            result.fail(f"{src} -> {dst}: changes target {b.module[0]} -> {h.module[0]}")
            continue
        if b.declared_by in mine:
            continue  # inside another moved subtree
        if b.how == "include":
            result.fail(f"{src}: included by {b.declared_by}, which does not move")
            continue
        old_parent, new_parent = b.declared_by, h.declared_by
        old_lx, new_lx = base.lexed(old_parent), head.lexed(new_parent)
        old_links = [link for link in base_tree.links if link.file == old_parent and link.target == src]
        new_links = [link for link in head_tree.links if link.file == new_parent and link.target == dst]
        if len(old_links) != 1 or len(new_links) != 1:
            result.fail(f"{src}: declared {len(old_links)} times at base, {len(new_links)} at head")
            continue
        old_decl = decl_item(old_lx, b.module[-1], old_links[0].line)
        new_decl = decl_item(new_lx, h.module[-1], new_links[0].line)
        if old_decl is None or new_decl is None:
            result.fail(f"{src}: its `mod` item is not at the top level of its parent file")
            continue
        roots[src] = Root(src, dst, b.module, h.module, old_parent, new_parent, old_decl, new_decl,
                          visibility(old_lx, old_decl), visibility(new_lx, new_decl))
    for src, dst in sorted(mine.items()):
        b = single(base_tree, src)
        if b is None:
            continue
        found = [root for root in roots.values() if b.module[:len(root.old)] == root.old
                 and b.module[0] == root.old[0]]
        found.sort(key=lambda root: len(root.old))
        if not found:
            if src not in roots:
                result.fail(f"{src}: moved, but not inside a moved subtree")
            continue
        root = found[-1]
        root.members.append(src)
        owner[src] = root.src
        h = single(head_tree, dst)
        expect = root.new + b.module[len(root.old):]
        if h is None or h.module != expect or h.how != b.how:
            result.fail(f"{src} -> {dst}: module {'::'.join(h.module) if h else '?'}, expected "
                        f"{'::'.join(expect)} (layout inside the subtree must stay)")
        elif src != root.src and mapped(b.declared_by) != h.declared_by:
            result.fail(f"{src}: declared by {b.declared_by} at base but {h.declared_by} at head")
    # Completeness: every base file below an old root moves with it; no other file joins a new root.
    nested = {root.src: [other for other in roots.values() if other is not root
                         and other.new[:len(root.new)] == root.new] for root in roots.values()}
    for path, contexts in base_tree.contexts.items():
        for context in contexts:
            for root in roots.values():
                if context.module[:len(root.old)] == root.old and path not in mine:
                    result.fail(f"{path} is inside moved {'::'.join(root.old)} but does not move")
    for path, contexts in head_tree.contexts.items():
        for context in contexts:
            for root in roots.values():
                if context.module[:len(root.new)] != root.new:
                    continue
                if any(context.module[:len(other.new)] == other.new for other in nested[root.src]):
                    continue
                if inverse.get(path) not in root.members:
                    result.fail(f"{path} joins moved {'::'.join(root.new)} at head")
    # Files reached only through include macros move with the files that include them.
    for src, dst in sorted(mine.items()):
        if src in owner or src in roots or base_tree.contexts.get(src):
            continue
        users = attached.get(src, set())
        if not users or any(user not in owner for user in users):
            result.fail(f"{src}: moved, but no moved file includes it")
        elif len({owner[user] for user in users}) != 1:
            result.fail(f"{src}: included from several moved subtrees")
        else:
            owner[src] = owner[next(iter(users))]

    # (C) relative reach, #[path], include literals; links.
    for src, dst in sorted(mine.items()):
        if not src.endswith(".rs") or src not in owner:
            continue
        root = roots[owner[src]]
        b = single(base_tree, src)
        lx = base.lexed(src)
        info = shape(lx)
        # A file reached only by an include macro has no module of its own: no `super` at all.
        depth = len(b.module) - len(root.old) if b else 0
        for first, _last, length, _contiguous in super_chains(lx):
            nesting = sum(1 for open_, close, _ in info.mod_blocks if open_ < first < close) if b else 0
            if length > depth + nesting or b is None:
                result.fail(f"{src}:{lx.line(lx.tokens[first].start)}: `super` x{length} reaches above "
                            f"moved {'::'.join(root.old)}")
        for index, _names, has_path in info.attrs:
            if has_path:
                result.fail(f"{src}:{lx.line(lx.tokens[index].start)}: #[path] inside a moved file")
        for macro, bang, group in info.path_macros:
            literal = literal_value(lx, macro, group)
            where = f"{src}:{lx.line(lx.tokens[bang].start)}"
            if literal is None:
                result.fail(f"{where}: {macro}! without one plain string literal")
                continue
            old_target = posixpath.normpath(posixpath.join(posixpath.dirname(src), literal))
            new_target = posixpath.normpath(posixpath.join(posixpath.dirname(dst), literal))
            if old_target not in mine or mine[old_target] != new_target or owner.get(old_target) != root.src:
                result.fail(f"{where}: {macro}!(\"{literal}\") does not resolve to the moved counterpart "
                            "of a file in the same subtree")
    added_lines = {dst: {head.lexed(dst).line(item.lead) for item in items} for dst, items in stripped.items()}

    def links_of(tree, path, skip=frozenset()):
        return [(link.how, link.literal, link.target) for link in tree.links
                if link.file == path and link.line not in skip]

    for src, dst in sorted(mine.items()):
        if not src.endswith(".rs") or src not in base_tree.contexts:
            continue
        old = [(how, literal, mapped(target) if target else None) for how, literal, target in links_of(base_tree, src)]
        new = links_of(head_tree, dst, added_lines.get(dst, set()))
        if old != new:
            result.fail(f"{src} -> {dst}: its mod/include links change ({old} -> {new})")

    # Moved roots that gained `mod` items (rule B).
    for dst, items in stripped.items():
        for item in items:
            child = [root for root in roots.values() if root.new_parent == dst and root.new_decl.name == item.name
                     and head.lexed(dst).line(root.new_decl.lead) == head.lexed(dst).line(item.lead)]
            if len(child) != 1:
                result.fail(f"{dst}:{head.lexed(dst).line(item.lead)}: added `mod {item.name};` is not a moved root")

    # (ii)/(iii) glue files.
    glue: set[str] = set()
    for root in roots.values():
        if root.old_parent in mine:
            result.fail(f"{root.src}: its old parent moves")
        glue.add(root.old_parent)
        if root.new_parent in inverse:
            if root.new_parent not in stripped:
                result.fail(f"{root.dst}: declared by moved {root.new_parent}, which did not add the item")
        else:
            glue.add(root.new_parent)
    result.glue |= glue
    removed_lines = added_total = alias_total = blank_total = 0
    for path in sorted(glue):
        if path not in modified:
            result.fail(f"{path}: declares a moved module but is unchanged (declaration retarget)")
            continue
        b_ctx, h_ctx = single(base_tree, path), single(head_tree, path)
        if b_ctx is None or h_ctx is None or b_ctx.module != h_ctx.module:
            result.fail(f"{path}: glue file needs one unchanged module context")
            continue
        removed = [root.old_decl for root in roots.values() if root.old_parent == path]
        adds = [root.new_decl for root in roots.values() if root.new_parent == path]
        old_lx, new_lx = base.lexed(path), head.lexed(path)
        old_text, _ = strip_lines(old_lx, removed)
        new_text, kept = strip_lines(new_lx, adds)
        removed_lines += old_lx.text.count("\n") - old_text.count("\n")
        added_total += new_lx.text.count("\n") - new_text.count("\n")
        new_rows, problems, blanks = line_changes(old_text, new_text)
        blank_total += blanks
        for problem in problems:
            result.fail(f"{path}: edited beyond mod items and aliases: {problem}")
        inserted = {kept[index] for index in new_rows}
        aliases = []
        covered: set[int] = set()
        for item in new_lx.items:
            span = set(range(new_lx.line(item.start) - 1, new_lx.line(item.end)))
            if span <= inserted and item.kind == "use":
                aliases.append(item)
                covered |= span
        if covered != inserted:
            result.fail(f"{path}: added lines that are not whole `use` items: "
                        f"{sorted(index + 1 for index in inserted - covered)[:5]}")
        for alias in aliases:
            alias_total += _check_alias(path, alias, roots, head_tree, head, h_ctx.module, result)

    # Names, visibility, attributes, textual macros.
    for root in sorted(roots.values(), key=lambda root: root.src):
        old_name, new_name = root.old[-1], root.new[-1]
        where = f"{root.src} -> {root.dst}"
        if root.old_decl.attrs != root.new_decl.attrs:
            result.fail(f"{where}: attributes change {root.old_decl.attrs} -> {root.new_decl.attrs}")
        if any(re.match(r"^#\[\s*macro_use\b", attr) for attr in root.old_decl.attrs):
            result.fail(f"{where}: #[macro_use] module")
        old_vis, new_vis = root.old_vis, root.new_vis
        if old_vis != new_vis:
            if root.alias is not None and new_vis == "pub(crate)":
                result.notes.append(f"{where}: visibility `{old_vis or 'private'}` -> `pub(crate)` for the alias")
            else:
                result.fail(f"{where}: visibility `{old_vis or 'private'}` -> `{new_vis or 'private'}`")
        # The new name: only binding in its new parent, and nothing it could have meant before.
        new_parent_module = root.new[:-1]
        head_facts = module_facts(head_tree, head, new_parent_module)
        if len(head_facts.bindings.get(new_name, [])) != 1:
            result.fail(f"{where}: `{new_name}` bound {head_facts.bindings.get(new_name)} in its new parent")
        old_new_parent = (base_tree.contexts.get(inverse.get(root.new_parent, root.new_parent)) or [None])[0]
        if old_new_parent is None:
            result.fail(f"{where}: new parent has no module at base")
        else:
            facts = module_facts(base_tree, base, old_new_parent.module)
            _check_fresh_name(where, new_name, facts, base_tree, base, old_new_parent.module,
                              root.old[:-1], old_name, externs, base_macros, result)
        if root.new_parent in stripped:
            names = ident_tokens(base.read(inverse[root.new_parent]))
            if new_name in names:
                result.fail(f"{where}: `{new_name}` already occurs in {inverse[root.new_parent]}")
        # The old name: an alias, or provably unbound.
        if root.alias is None:
            facts = module_facts(head_tree, head, root.old[:-1]) if root.old[:-1] in head_tree.modules else Facts()
            if facts.bindings.get(old_name):
                result.fail(f"{where}: old name `{old_name}` is bound by {facts.bindings[old_name]} at head")
            if facts.globs:
                result.fail(f"{where}: old parent has glob imports, so `{old_name}` needs an alias")
            for problem in _name_risks(old_name, facts, externs, head_macros):
                result.fail(f"{where}: old name: {problem}")
        # Textual macro scope at the old and the new declaration point.
        names = set()
        for member in root.members:
            if member.endswith(".rs"):
                names |= {name for name, _ in shape(base.lexed(member)).bare_macros}
        if names:
            try:
                old_env = textual_env(base_tree, base, root.old_parent, root.old_decl.lead, lambda p: p)
                new_env = textual_env(head_tree, head, root.new_parent, root.new_decl.lead, canon_head)
            except Unproven as error:
                result.fail(f"{where}: textual macro scope: {error}")
            else:
                for name in sorted(names):
                    if old_env.get(name) != new_env.get(name):
                        result.fail(f"{where}: bare {name}! sees {old_env.get(name)} at base, "
                                    f"{new_env.get(name)} at head")
    # Links of every other file stay the same.
    glue_skip_old = {root.old_parent: set() for root in roots.values()}
    glue_skip_new = {root.new_parent: set() for root in roots.values()}
    for root in roots.values():
        glue_skip_old[root.old_parent].add(base.lexed(root.old_parent).line(root.old_decl.lead))
        glue_skip_new[root.new_parent].add(head.lexed(root.new_parent).line(root.new_decl.lead))
    old_files = {path for path in base_tree.contexts if path not in mine}
    new_files = {path for path in head_tree.contexts if path not in inverse}
    if old_files != new_files:
        result.fail(f"files reached by mod/include change: {sorted(old_files ^ new_files)[:5]}")
    for path in sorted(old_files & new_files):
        old = [(how, literal, mapped(target) if target else None)
               for how, literal, target in links_of(base_tree, path, glue_skip_old.get(path, set()))]
        new = links_of(head_tree, path, glue_skip_new.get(path, set()))
        if old != new:
            result.fail(f"{path}: its mod/include links change")
        if len(base_tree.contexts[path]) != len(head_tree.contexts[path]):
            result.fail(f"{path}: number of module contexts changes")
    files = sum(1 for src in mine if src in owner)
    lines = sum(base.read(src).count("\n") for src in mine if src in owner)
    result.lines.append(f"{crate}: {len(roots)} moved subtrees, {files} files, {lines} lines; glue: "
                        f"{removed_lines} removed mod lines, {added_total} added mod lines, "
                        f"{alias_total} aliases, {blank_total} blank lines")
    for root in sorted(roots.values(), key=lambda root: root.src):
        alias = " (alias)" if root.alias is not None else ""
        result.lines.append(f"  {'::'.join(root.old)} -> {'::'.join(root.new)}{alias}: "
                            f"{root.src} -> {root.dst}, {len(root.members)} files")
        for member in sorted(root.members):
            if member != root.src:
                result.lines.append(f"    {member} -> {mine[member]}")
    for dst, items in sorted(stripped.items()):
        result.lines.append(f"  {dst}: identical to {inverse[dst]} after removing "
                            + ", ".join(f"`mod {item.name};`" for item in items))


def _check_alias(path, alias, roots, tree, source, module, result) -> int:
    lx = source.lexed(path)
    where = f"{path}:{lx.line(alias.lead)}"
    try:
        leaves = use_leaves(lx, alias)
    except Unproven as error:
        result.fail(str(error))
        return 0
    if len(leaves) != 1 or leaves[0][2] or leaves[0][1] is None:
        result.fail(f"{where}: an alias must be one plain `use <path> [as <name>];`")
        return 0
    segments, binding, _ = leaves[0]
    text = lx.text[lx.tokens[keyword_index(lx, alias)].start:alias.end]
    if "{" in text or "*" in text:
        result.fail(f"{where}: an alias must be one plain `use <path> [as <name>];`")
        return 0
    candidates = [root for root in roots.values() if root.old_parent == path and root.old[-1] == binding]
    if len(candidates) != 1:
        result.fail(f"{where}: `use ... as {binding}` does not restore the old name of a module moved from here")
        return 0
    root = candidates[0]
    if root.alias is not None:
        result.fail(f"{where}: second alias for {'::'.join(root.old)}")
        return 0
    vis = visibility(lx, alias)
    if vis not in ("pub(crate)", root.old_vis):
        result.fail(f"{where}: alias visibility `{vis or 'private'}`")
    if alias.attrs not in ([], root.old_decl.attrs):
        result.fail(f"{where}: alias attributes {alias.attrs} differ from the removed item's")
    try:
        target = resolve_mod_path(tree, source, module, segments)
    except Unproven as error:
        result.fail(f"{where}: alias path: {error}")
        return 0
    if target != root.new:
        result.fail(f"{where}: alias names {'::'.join(target)}, not moved {'::'.join(root.new)}")
        return 0
    bound = module_facts(tree, source, module).bindings.get(binding, [])
    if len(bound) != 1:
        result.fail(f"{where}: `{binding}` bound {bound} in {path}")
        return 0
    root.alias = alias
    result.notes.append(f"alias {where}: {text.strip()}")
    return 1


def _name_risks(name: str, facts: Facts, externs: set[str], macros) -> list[str]:
    problems = []
    if name in externs or name in PRELUDE or name in PRIMITIVES:
        problems.append(f"`{name}` is also an extern crate, prelude or primitive name")
    for macro, where in facts.macros:
        problem = macro_problem(macro, macros)
        if problem:
            problems.append(f"{where}: {problem}")
    problems.extend(facts.opaque)
    return problems


def _check_fresh_name(where, name, facts, tree, source, module, old_parent, old_name, externs, macros,
                      result) -> None:
    """At base, `name` in the new parent's namespace was unbound or already the moved module."""
    if facts.bindings.get(name):
        result.fail(f"{where}: `{name}` was already bound in the new parent: {facts.bindings[name]}")
    if facts.globs:
        for segments, glob_where in facts.globs:
            try:
                target = resolve_mod_path(tree, source, module, segments)
            except Unproven as error:
                result.fail(f"{where}: new parent glob at {glob_where}: {error}")
                continue
            if target != old_parent:
                result.fail(f"{where}: new parent glob at {glob_where} imports {'::'.join(target)}, "
                            "which may bind the new name")
        if name != old_name:
            result.fail(f"{where}: renamed module under a new parent with glob imports")
    for problem in _name_risks(name, facts, externs, macros):
        result.fail(f"{where}: new name: {problem}")


# ---------------------------------------------------------------- mode: absolutize


def check_absolutize(repo: Path, base_sha: str, head_sha: str) -> Result:
    result = Result()
    _FACTS.clear()
    base, head = rst.GitSource(repo, base_sha), rst.GitSource(repo, head_sha)
    head.share_with(base)
    try:
        _check_absolutize(raw_changes(repo, base_sha, head_sha), base, head, result)
    except Unproven as error:
        result.fail(str(error))
    except rst.SourceError as error:
        result.fail(f"cannot read source: {error}")
    finally:
        base.close()
        head.close()
    return result


def _check_absolutize(changes, base, head, result) -> None:
    files = []
    for change in changes:
        if change.status != "M" or change.old_mode != REGULAR or change.new_mode != REGULAR:
            result.fail(f"{change.path}: {change.status} {change.old_mode} -> {change.new_mode}; "
                        "absolutize changes only edit regular .rs files")
        elif not change.path.endswith(".rs"):
            result.fail(f"{change.path}: not a .rs file")
        else:
            files.append(change.path)
    trees: dict[str, tuple[rst.Tree, rst.Tree]] = {}
    total = 0
    for path in files:
        crate = crate_of(path, base)
        if crate is None:
            result.fail(f"{path}: outside any crate")
            continue
        if crate not in trees:
            trees[crate] = (rst.crate_tree(base, crate), rst.crate_tree(head, crate))
        base_tree, head_tree = trees[crate]
        b, h = single(base_tree, path), single(head_tree, path)
        if b is None or h is None or b.module != h.module:
            result.fail(f"{path}: needs exactly one module context, the same at base and head")
            continue
        count = _absolutize_file(path, b.module, base.lexed(path), head.lexed(path), result)
        if count:
            total += count
            result.lines.append(f"  {path}: {count} paths")
    result.lines.insert(0, f"{len(files)} files, {total} absolutized paths")


def _absolutize_file(path: str, module: tuple[str, ...], old: rst.Lexed, new: rst.Lexed, result: Result) -> int:
    info = shape(old)
    macros = [entry for entry in info.opaque if entry[2] != "attribute"]
    for index, names, _ in info.attrs:
        # An attribute inside a macro token tree only reaches that tree, where every chain fails anyway.
        unknown = [name for name in names if name not in INERT_ATTRS and not inside(macros, index)]
        if unknown:
            result.fail(f"{path}:{old.line(old.tokens[index].start)}: attribute {unknown[0]} may be a macro")
            return 0
    named = {}
    for item in walk_items(old.items):
        if item.kind == "mod" and item.members is not None:
            named[item.body_open] = item.name
    blocks = [(open_, close, name) for open_, close, name in info.mod_blocks]
    chains = {first: (last, length, contiguous) for first, last, length, contiguous in super_chains(old)}
    i = j = count = 0
    while i < len(old.tokens) and j < len(new.tokens):
        if old.tok(i) == new.tok(j) and old.tokens[i].kind == new.tokens[j].kind:
            i, j = i + 1, j + 1
            continue
        where = f"{path}:{old.line(old.tokens[i].start)}"
        if i not in chains:
            result.fail(f"{where}: edited beyond replacing a `super` chain")
            return count
        last, length, contiguous = chains[i]
        if not contiguous:
            result.fail(f"{where}: spaced or commented `super` chain")
            return count
        what = inside(info.opaque, i)
        if what:
            result.fail(f"{where}: `super` chain inside {what}")
            return count
        code = code_index(old)
        pos = code.index(i)
        before = [old.tok(code[k]) for k in range(max(0, pos - 3), pos)]
        if before[-1:] == [":"] and pos >= 2 and old.is_punct(code[pos - 2], ":") and code[pos - 1] == code[pos - 2] + 1:
            result.fail(f"{where}: `super` chain is not at the start of a path")
            return count
        enclosing = [(open_, close, name) for open_, close, name in blocks if open_ < i < close]
        nest = []
        for open_, close, name in sorted(enclosing):
            if old.tokens[open_].start not in named:
                result.fail(f"{where}: `super` chain inside module `{name}`, which has no path")
                return count
            nest.append(name)
        current = module + tuple(nest)
        if length > len(current) - 1:
            result.fail(f"{where}: `super` x{length} above the crate root")
            return count
        target = current[1:len(current) - length]
        absolute = "crate" + "".join(f"::{segment}" for segment in target)
        after = old.next_code(last + 1)
        if before[-2:] == ["pub", "("] and old.is_punct(after, ")"):
            expected = "crate" if not target else f"in {absolute}"
        else:
            expected = absolute
        start = new.tokens[j].start
        if not new.text.startswith(expected, start):
            result.fail(f"{where}: expected `{expected}` in place of the `super` chain")
            return count
        stop = start + len(expected)
        k = j
        while k < len(new.tokens) and new.tokens[k].start < stop:
            k += 1
        if k < len(new.tokens) and new.tokens[k].start != stop or (k == len(new.tokens) and stop != len(new.text)):
            result.fail(f"{where}: replacement does not end at a token boundary")
            return count
        i, j, count = last + 1, k, count + 1
    if i != len(old.tokens) or j != len(new.tokens):
        result.fail(f"{path}: edited beyond replacing `super` chains (at the end of the file)")
    return count


# ---------------------------------------------------------------- main


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("move", "absolutize"))
    parser.add_argument("--base", help="base commit (default: merge-base of origin/main and HEAD)")
    parser.add_argument("--head", default="HEAD", help="head commit (default: HEAD)")
    parser.add_argument("--repo", default=".", help="repository root (default: .)")
    parser.add_argument("--report", action="store_true", help="print the result and exit 0 even when it fails")
    args = parser.parse_args(argv)
    repo = Path(args.repo)
    tag = f"file-moves[{args.mode}]"
    try:
        base = args.base or rst.default_base(repo)
        base_sha = rst.git(repo, "rev-parse", "--verify", f"{base}^{{commit}}").strip()
        head_sha = rst.git(repo, "rev-parse", "--verify", f"{args.head}^{{commit}}").strip()
    except rst.SourceError as error:
        print(f"{tag}: {error}", file=sys.stderr)
        return 0 if args.report else 2
    print(f"{tag}: base {base_sha[:12]} head {head_sha[:12]}")
    check = check_move if args.mode == "move" else check_absolutize
    try:
        result = check(repo, base_sha, head_sha)
    except Exception:  # noqa: BLE001 - a crash proves nothing; a report never blocks
        traceback.print_exc()
        print(f"{tag}: internal error; not proven")
        return 0 if args.report else 2
    for line in result.lines:
        print(f"{tag}: {line}")
    for note in result.notes[:REPORT_LIMIT]:
        print(f"{tag}: note: {note}")
    limit = REPORT_LIMIT if args.report else None
    for problem in result.problems[:limit]:
        print(f"{tag}: FAIL {problem}", file=sys.stdout if args.report else sys.stderr)
    if args.report and len(result.problems) > REPORT_LIMIT:
        print(f"{tag}: ... {len(result.problems) - REPORT_LIMIT} more")
    verdict = "file-move-only" if args.mode == "move" else "absolutize-only"
    if result.problems:
        print(f"{tag}: {len(result.problems)} problems; not {verdict}" + (" (report only)" if args.report else ""))
        return 0 if args.report else 1
    print(f"{tag}: {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
