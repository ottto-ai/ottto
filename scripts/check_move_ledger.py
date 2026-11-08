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
      `include!(..);` items, with their attributes, and `//!` file docs; a
      `use` item is glue only under the binding rules below;
  (c) the path literal inside `#[path = ".."]`, `include!`, `include_str!` and
      `include_bytes!`;
  (d) the `impl X {` / `}` and inline `mod x {` / `}` wrappers;
  (e) the indentation an item loses when an inline module becomes a file.

Then every base item must equal exactly one head item byte for byte (comments,
attributes, cfgs), and items that land in one file keep their base order. Three
exceptions cover what rustfmt re-wraps once a visibility token makes a line too
long; each still matches, listed as `reflowed`, only if the part that may
re-wrap (the fn signature, the whole struct, the whole const/static/type item)
holds no `!` (a macro can see token boundaries this lexer does not keep):

  - a `fn` whose text before `fn` and whose body, from its opening `{`, are
    byte for byte equal and whose only visibility token is the item-level one
    before `fn`, when its signature tokens are equal with whitespace dropped;
    only a trailing `,` closing its own generic list or outer parameter list
    may be added or dropped;
  - a struct with named fields whose text is byte for byte equal outside its
    field declarations (from each field name to its `,`), when each field's
    tokens are equal with whitespace dropped; a visibility token may stand only
    at the start of a field or before `struct`, and is judged per field;
  - a `const`, `static` or `type` item whose text before its keyword is byte
    for byte equal and whose only visibility token is the item-level one, when
    its tokens from the keyword on are equal with whitespace dropped.

In all three, literals and comments stay exact, a number literal (`1.0`, `1e-3`,
`0x1F`, `1_000u64`, `1.0f32`) is one token, and whitespace between two
punctuation tokens that could join (`& &` vs `&&`) still counts. Every other
item must match byte for byte. An item must sit under the same module
attributes (`#[cfg(..)]` and the like), may only lose nesting, and every path
literal must resolve, from its new file, to a target with the same bytes.
A module's own `#[rustfmt::skip]` is left out of its attributes: a rustfmt tool
attribute changes formatting only, never the compiled item (an item's own
`#[rustfmt::skip]` is part of its text and still matches byte for byte).
In-place edits of the regular files in VALIDATOR_EDITS are listed and not
checked; adding, deleting or retyping one of them is checked as usual.

Module paths fail closed. A path is `crate::`, `super::` or `self::` followed by
`::`-joined names written without spaces (a `use` path may also start at a child
module). It "resolves through modules" when every step is the crate root,
`super`, `self` or a `mod` item, and its last name is a module or an item
defined there (never a `use` binding, alias or glob). An item names the same
target at head when the base item it named is paired, by this check, with an
item in the head module; a module does when its file is an exact rename or the
same unrenamed file. The file map pairs files instantiated in one module
context: an exact rename (`git diff -B -M100%`, R100); a file byte for byte equal
once the whole out-of-line `[vis] mod x;` declarations (with their attributes,
never `#[macro_use]`) that one side adds or removes are left out, each backed by
a child file declared there (a child maps only by its own pair); and an exact
copy (C100) whose source path is gone or rewritten by another pair (a copy
whose source stays never maps). Any other edited rename maps nothing.

  - A moved item (its module changed) must keep what every unchanged path in it
    names. Only a path outside any macro call and attribute token tree, in a
    file instantiated once, may be respelled, and only when both spellings
    resolve through modules to the same target and the base spelling needed it
    (`super`/`self` led: it means something else from the new module; `crate`
    led: its target moved and the head path is `crate` led too). Listed as
    `respelled`. Paths in `macro_rules!` items are never respelled.
  - `use` bindings: per module, a binding (its bound name, or a glob) that
    exists at base and head must name the same target: the same text naming the
    same place, or two spellings that resolve through modules to the same
    target (listed as `respelled`); a glob swapped for another fails. Added and
    removed bindings are glue. A binding at head of the name a gone module had
    in its old parent is glue only as the facade alias `use <new path> [as <old
    name>];` that resolves through modules to that module's mapped head path;
    any other alias or glob that can bind that name fails.

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
from dataclasses import dataclass, field, replace
from pathlib import Path

import rust_source_tree as rst

GLUE = {"use", "mod-decl", "include", "inner-doc"}
HEADER_REFLOW = ("const", "static", "type")
PATH_HEADS = ("crate", "super", "self")
# Items that define a name in their module (a `mod` defines one too, through the module tree).
DEFINES = {"fn", "struct", "enum", "union", "trait", "const", "static", "type"}
# Words that may stand before a `!` that negates a parenthesised expression rather than calling a macro.
NOT_MACRO = {"if", "while", "match", "return", "in", "else", "let", "break", "move", "as", "yield"}
PATH_MACROS = {"include", "include_str", "include_bytes"}
REPORT_LIMIT = 50
# Design rule: validator anchors move in the PR that moves their anchor. These files check moved source
# by path or text, so their edits are listed as validator edits and never checked as moves.
VALIDATOR_EDITS = {
    "crates/ottto-service/tests/support/scan_index_v201.rs",
    "scripts/test_codex_zst_downgrade.py",
}
DIFF_LIMIT = 40
# Module attributes that change formatting only, compared with whitespace dropped.
FORMATTING_MODULE_ATTRS = {"#[rustfmt::skip]"}


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
    kind: str = ""  # item kind (`fn`, `struct`, ..); "" for leading comments
    multi: bool = False  # its file is instantiated in more than one module context

    @property
    def key(self) -> tuple[str, str]:
        return self.container, self.text

    def where(self) -> str:
        return f"{self.file}:{self.line}"


def squash(text: str) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text.replace("( ", "(").replace(" )", ")")


# Punctuation that never joins a neighbour into one Rust token, so whitespace beside it is layout.
JOINLESS = set("()[]{},;")
Code = list[tuple[str, str, bool, int]]  # (kind, text, whitespace before it, offset) per non-whitespace token


# A Rust number literal from its first digit: a float's `.digits` (or a bare `1.` before anything but `.`
# or a name), an exponent with its sign, and a suffix. Hex, octal and binary literals end at the suffix.
NUMBER = re.compile(r"[0-9][0-9_]*(?:\.[0-9][0-9_]*|\.(?![.\w]))?(?:[eE][+-]?[0-9_]*[0-9][0-9_]*)?\w*")


def code_tokens(text: str) -> Code:
    """Non-whitespace tokens; a number literal the lexer splits at `.`, `+` or `-` is one token here."""
    tokens = rst.tokenize(text)
    out: Code = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        end, after = token.end, index + 1
        if token.kind == "num":
            found = NUMBER.match(text, token.start)
            stop = found.end() if found else token.end
            probe = index
            while probe < len(tokens) and tokens[probe].end < stop:
                probe += 1
            if probe < len(tokens) and tokens[probe].end == stop:
                end, after = stop, probe + 1
        if token.kind != "ws":
            out.append((token.kind, text[token.start:end], index > 0 and tokens[index - 1].kind == "ws",
                        token.start))
        index = after
    return out


def depth_at(code: Code, offset: int) -> int:
    """The bracket depth at text offset `offset` (where a removed visibility token stood)."""
    depth = 0
    for kind, piece, _, start in code:
        if start >= offset:
            break
        if kind == "punct":
            depth += (piece in "([{") - (piece in ")]}")
    return depth


def layout_free(code: Code, first: int, stop: int, drop: set[int] = frozenset()) -> tuple[str, ...]:
    """Tokens first..stop-1 without whitespace, but with a " " where whitespace separated two punctuation
    tokens that could join (`& &` vs `&&`); tokens in `drop` are left out."""
    out: list[str] = []
    prev = None
    for index in range(first, stop):
        if index in drop:
            continue
        kind, piece, spaced, _ = code[index]
        if (spaced and index - 1 not in drop and prev is not None and prev[0] == kind == "punct"
                and prev[1] not in JOINLESS and piece not in JOINLESS):
            out.append(" ")
        out.append(piece)
        prev = (kind, piece)
    return tuple(out)


def reflow(unit: Unit) -> tuple[tuple, list[tuple[int, str]]] | None:
    """(key, visibility) of a rustfmt re-wrap (see the module docs), or None when `unit` gets no reflow
    pass. Two units with equal keys are a reflowed move; the visibility rows are keyed by place (0 for
    the item, 1.. for each struct field) instead of text offset, which the re-wrap shifts. Any `!` means
    no pass: a macro call can see token boundaries this lexer does not keep."""
    if unit.kind not in ("fn", "struct", *HEADER_REFLOW):
        return None
    code = code_tokens(unit.text)
    keyword = next((index for index, (kind, piece, _, _) in enumerate(code)
                    if kind == "ident" and piece == unit.kind and depth_at(code, code[index][3]) == 0), None)
    if keyword is None:
        return None
    items = [offset for offset, _ in unit.vis if offset <= code[keyword][3] and depth_at(code, offset) == 0]
    if len(items) > 1:
        return None
    if unit.kind == "fn":
        return fn_reflow(unit, code, keyword, items)
    if unit.kind in HEADER_REFLOW:
        return header_reflow(unit, code, keyword, items)
    return struct_reflow(unit, code, keyword, items)


def header_reflow(unit: Unit, code: Code, keyword: int, items: list[int]):
    """(g) A const, static or type item whose text before its keyword is byte for byte equal; from the
    keyword on only whitespace may differ, and its only visibility token is the item-level one."""
    if len(unit.vis) != len(items) or any(code[index][:2] == ("punct", "!") for index in range(len(code))):
        return None
    key = (unit.container, unit.text[:code[keyword][3]], layout_free(code, keyword, len(code)))
    return key, [(0, token) for _, token in unit.vis]


def fn_reflow(unit: Unit, code: Code, fn_at: int, items: list[int]):
    """A fn whose text before `fn` and body are byte for byte equal; only its signature may re-wrap, and
    only a trailing `,` closing its own generic list or outer parameter list may be added or dropped."""
    if len(unit.vis) != len(items):
        return None
    depth = 0
    body_at = None
    for index in range(fn_at, len(code)):
        kind, piece, _, _ = code[index]
        if kind == "punct" and piece == "{" and depth == 0:
            body_at = index
            break
        if kind == "punct":
            depth += (piece in "([{") - (piece in ")]}")
    if body_at is None or any(code[index][:2] == ("punct", "!") for index in range(fn_at, body_at)):
        return None
    drop = set()
    at = fn_at + 2  # after `fn name`
    if at < body_at and code[at][:2] == ("punct", "<"):
        at = closing(code, at, body_at, angle=True)
        if at is None:
            return None
        if code[at - 1][:2] == ("punct", ","):
            drop.add(at - 1)
        at += 1
    if not (at < body_at and code[at][:2] == ("punct", "(")):
        return None
    at = closing(code, at, body_at, angle=False)
    if at is None:
        return None
    if code[at - 1][:2] == ("punct", ","):
        drop.add(at - 1)
    key = (unit.container, unit.text[:code[fn_at][3]], layout_free(code, fn_at, body_at, drop),
           unit.text[code[body_at][3]:])
    return key, [(0, token) for _, token in unit.vis]


def struct_reflow(unit: Unit, code: Code, struct_at: int, items: list[int]):
    """A struct with named fields whose text is byte for byte equal outside its field declarations (from
    each field name to its `,`); inside one, only whitespace may differ, and a field may only gain or lose
    a visibility token at its start."""
    if any(piece == "!" and kind == "punct" for kind, piece, _, _ in code):
        return None
    body_at = next((index for index in range(struct_at, len(code)) if code[index][0] == "punct"
                    and code[index][1] in "{(;"), None)
    if body_at is None or code[body_at][1] != "{":
        return None  # a tuple or unit struct, or a header with parentheses
    close_at = closing(code, body_at, len(code), angle=False)
    if close_at is None:
        return None
    # Field declarations: split the body at commas outside brackets and angle brackets.
    spans: list[tuple[int, int]] = []  # (field name, one past its last token)
    first = body_at + 1
    nest = level = 0
    for index in range(body_at + 1, close_at + 1):
        kind, piece, spaced, _ = code[index]
        if index < close_at and kind == "punct":
            if piece in "([{":
                nest += 1
            elif piece in ")]}":
                nest -= 1
            elif nest == 0 and piece == "<":
                level += 1
            elif nest == 0 and piece == ">" and not (code[index - 1][1] == "-" and not spaced):
                level -= 1
        if index == close_at or (nest == level == 0 and kind == "punct" and piece == ","):
            name = first
            while name < index and code[name][0] in ("doc", "comment"):
                name += 1
            while name + 1 < index and code[name][:2] == ("punct", "#") and code[name + 1][1] == "[":
                name = closing_bracket(code, name + 1, index) + 1
                while name < index and code[name][0] in ("doc", "comment"):
                    name += 1
            if name < index:
                if not (code[name][0] == "ident" and code[name + 1][:2] == ("punct", ":")
                        and code[name + 2][1] != ":"):
                    return None
                spans.append((name, index + 1 if index < close_at else index))
            first = index + 1
    if nest or level:
        return None
    field_vis = {code[name][3]: number for number, (name, _) in enumerate(spans, 1)}
    vis = []
    for offset, token in unit.vis:
        place = 0 if offset in items else field_vis.get(offset)
        if place is None:
            return None  # a visibility token that is not the item's or at the start of a field
        vis.append((place, token))
    parts: list = [unit.container]
    cursor = 0
    for name, stop in spans:
        parts += [unit.text[cursor:code[name][3]], layout_free(code, name, stop)]
        cursor = code[stop - 1][3] + len(code[stop - 1][1])
    parts.append(unit.text[cursor:])
    return tuple(parts), vis


def closing_bracket(code: Code, open_at: int, stop: int) -> int:
    """The index of the `]` that closes the `[` at `open_at` (or `stop` when it is missing)."""
    nest = 0
    for index in range(open_at, stop):
        if code[index][0] == "punct" and code[index][1] in "([{":
            nest += 1
        elif code[index][0] == "punct" and code[index][1] in ")]}":
            nest -= 1
            if nest == 0:
                return index
    return stop


def closing(code: list[tuple[str, str, bool, int]], open_at: int, stop: int, angle: bool) -> int | None:
    """The index of the `>` (angle) or `)` that closes the list opened at `open_at`, before `stop`."""
    nest = level = 0
    for index in range(open_at, stop):
        kind, piece, spaced, _ = code[index]
        if kind != "punct":
            continue
        if piece in "([{":
            nest += 1
        elif piece in ")]}":
            nest -= 1
            if not angle and nest == 0:
                return index
        elif angle and nest == 0 and piece == "<":
            level += 1
        elif angle and nest == 0 and piece == ">" and not (code[index - 1][1] == "-" and not spaced):
            level -= 1
            if level == 0:
                return index
    return None


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
    multi = len({c.module for c in contexts}) > 1
    units: list[Unit] = []

    def add(item_first: int, item_last: int, start: int, label: str, name: str, module, chain, depth,
            container: str, strip_vis: bool = True, kind: str = "") -> None:
        text, vis, paths = normalise(lexed, item_first, item_last, depth, path, source, strip_vis)
        end_line = lexed.line(lexed.tokens[item_last].end - 1)
        chain = frozenset(attr for attr in chain if re.sub(r"\s+", "", attr) not in FORMATTING_MODULE_ATTRS)
        units.append(Unit(path, lexed.line(start), end_line, len(units), label, name, module, chain,
                          depth, container, text, vis, paths, kind, multi))

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
                    container, strip_vis=item.kind != "macro_rules", kind=item.kind)

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
    reflowed: list[tuple[Unit, Unit]] = field(default_factory=list)
    respelled: list[tuple[Unit, Unit]] = field(default_factory=list)
    respelled_uses: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    widened: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        if message not in self.failures:
            self.failures.append(message)


def match_units(base: list[Unit], head: list[Unit], key=lambda unit: unit.key
                ) -> tuple[list[tuple[Unit, Unit]], list[Unit], list[Unit]]:
    """Pair units with equal keys: same file first, then in base order."""
    head_by_key: dict[tuple, list[Unit]] = {}
    for unit in head:
        head_by_key.setdefault(key(unit), []).append(unit)
    pairs, lost = [], []
    pending: list[Unit] = []
    for unit in base:
        candidates = head_by_key.get(key(unit))
        same = next((c for c in candidates or [] if c.file == unit.file), None)
        if same is not None:
            candidates.remove(same)
            pairs.append((unit, same))
        else:
            pending.append(unit)
    for unit in pending:
        candidates = head_by_key.get(key(unit))
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
          allow_widened: set[str], ident: Identity) -> Ledger:
    ledger = Ledger()
    pairs, lost, gained = match_units(base, head)
    # A unit with no reflow pass gets a key of its own, so it never pairs.
    reflow_of = {id(unit): reflow(unit) or ((id(unit),), unit.vis) for unit in lost + gained}
    reflowed, lost, gained = match_units(lost, gained, key=lambda unit: reflow_of[id(unit)][0])
    ident.use_units(base, pairs + reflowed)
    # A re-wrap shifts text offsets, so reflowed units compare visibility by place instead.
    ledger.reflowed = [(replace(old, vis=reflow_of[id(old)][1]), replace(new, vis=reflow_of[id(new)][1]))
                       for old, new in reflowed]
    ledger.respelled, lost, gained = respell_pairs(ident, lost, gained)
    ledger.pairs = sorted(pairs + ledger.reflowed + ledger.respelled, key=lambda pair: (pair[0].file, pair[0].seq))
    moves = module_moves(ledger.pairs, head_modules)
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
        check_kept_paths(ledger, ident, old, new)
    for (_, new_file), group in sorted(by_destination.items()):
        group.sort(key=lambda pair: pair[1].seq)
        for before, after in itertools.pairwise(group):
            if after[0].seq < before[0].seq:
                ledger.failures.append(
                    f"order changed in {new_file}: {after[0].label} ({after[0].where()}) now follows "
                    f"{before[0].label} ({before[0].where()})")
                break
    check_bindings(ledger, ident)
    return ledger


# ---------------------------------------------------------------- module paths and `use` bindings

Module = tuple[str, ...]
Found = tuple[Module, tuple[str, ...]]  # (module, the defined item's name and what follows it, or ())


@dataclass
class Namespace:
    """One commit's modules as names: the file holding each module's items, the modules each file is
    instantiated as, the names each module's items define and the names its `use` items bind."""

    modules: set[Module]
    owner: dict[Module, str] = field(default_factory=dict)
    contexts: dict[str, set[Module]] = field(default_factory=dict)
    defined: dict[Module, dict[str, set[str]]] = field(default_factory=dict)  # module -> name -> files
    bound: dict[Module, dict[str, list[tuple[str, tuple[str, ...]]]]] = field(default_factory=dict)  # "*" = glob
    unread: dict[str, int] = field(default_factory=dict)  # file -> line of a `use` item this cannot read


def namespace(source: rst.Source, tree: rst.Tree) -> Namespace:
    names = Namespace(set(tree.modules))

    def walk(lexed: rst.Lexed, items: list[rst.Item], module: Module, path: str) -> None:
        for item in items:
            if item.kind == "mod" and item.members is not None:
                names.owner.setdefault(module + (item.name,), path)
                walk(lexed, item.members, module + (item.name,), path)
            elif item.kind in ("use", "extern-crate"):
                found = use_bindings(lexed.text[item.lead:item.end])
                if found is None:
                    names.unread.setdefault(path, lexed.line(item.lead))
                for name, target in found or []:
                    names.bound.setdefault(module, {}).setdefault(name, []).append((path, target))
            elif item.kind in DEFINES:
                names.defined.setdefault(module, {}).setdefault(item.name, set()).add(path)

    for path, contexts in tree.contexts.items():
        lexed = source.lexed(path)
        for module in dict.fromkeys(context.module for context in contexts):
            names.contexts.setdefault(path, set()).add(module)
            if any(context.module == module and context.how != "include" for context in contexts):
                names.owner.setdefault(module, path)
            walk(lexed, lexed.items, module, path)
    return names


def use_bindings(text: str) -> list[tuple[str, tuple[str, ...]]] | None:
    """(bound name, or "*" for a glob, and path) for each name a `use` or `extern crate` item binds; None
    when its shape is not understood. A `self` leaf binds its parent's name; `as _` binds nothing."""
    code = [(kind, piece) for kind, piece, _, _ in code_tokens(text) if kind not in ("comment", "doc")]
    pieces = [piece for _, piece in code] + ["", ""]
    depth, at = 0, None
    for index, (kind, piece) in enumerate(code):
        if kind == "punct":
            depth += (piece in "([{") - (piece in ")]}")
        elif depth == 0 and kind == "ident" and piece in ("use", "extern"):
            at = index
            break
    if at is None:
        return None
    out: list[tuple[str, tuple[str, ...]]] = []

    def ident(index: int) -> bool:
        return index < len(code) and code[index][0] == "ident"

    def tree(index: int, prefix: tuple[str, ...]) -> int:
        path = list(prefix)
        if pieces[index] == ":" and pieces[index + 1] == ":":
            path.append("::")
            index += 2
        while True:
            if pieces[index] == "*":
                out.append(("*", tuple(path)))
                return index + 1
            if pieces[index] == "{":
                index += 1
                while pieces[index] != "}":
                    index = tree(index, tuple(path))
                    if pieces[index] == ",":
                        index += 1
                    elif pieces[index] != "}":
                        raise ValueError(index)
                return index + 1
            if not ident(index):
                raise ValueError(index)
            path.append(pieces[index])
            index += 1
            if pieces[index] == ":" and pieces[index + 1] == ":":
                index += 2
                continue
            name = path[-1]
            if pieces[index] == "as":
                if not ident(index + 1):
                    raise ValueError(index)
                name, index = pieces[index + 1], index + 2
            if path[-1] == "self":
                path.pop()
                if not path:
                    raise ValueError(index)
                name = path[-1] if name == "self" else name
            if name != "_":
                out.append((name, tuple(path)))
            return index

    try:
        if pieces[at] == "extern":
            if pieces[at + 1] != "crate" or not ident(at + 2):
                return None
            name, stop = pieces[at + 2], at + 3
            if pieces[stop] == "as" and ident(stop + 1):
                name, stop = pieces[stop + 1], stop + 2
            out = [] if name == "_" else [(name, ("::", pieces[at + 2]))]
        else:
            stop = tree(at + 1, ())
    except ValueError:
        return None
    return out if pieces[stop] == ";" and stop == len(code) - 1 else None


def resolve(names: tuple[str, ...], module: Module) -> Module | None:
    """The absolute path a `crate`/`super`/`self` led path names from `module`."""
    if names[0] == "crate":
        return module[:1] + names[1:]
    here, at = list(module), 0
    while at < len(names) and names[at] in ("super", "self"):
        if names[at] == "super":
            if len(here) <= 1:
                return None
            here.pop()
        at += 1
    return tuple(here) + names[at:]


def through_modules(names: Namespace, path: tuple[str, ...], module: Module) -> Found | None:
    """What `path` names from `module` when it resolves through modules (see the module docs), else None. A
    path that does not start with `crate`, `super` or `self` must start at a child module (a `use` path)."""
    if path[0] in PATH_HEADS:
        heads = next((at for at, name in enumerate(path) if name not in PATH_HEADS), len(path))
        here = resolve(path[:heads], module)
        at = heads
    else:
        here, at = module, 0
    if here is None or (path[0] == "crate" and heads > 1):
        return None
    while at < len(path):
        name = path[at]
        if name in names.bound.get(here, {}):
            return None  # a `use` binding of that name: never followed
        if here + (name,) in names.modules:
            here, at = here + (name,), at + 1
            continue
        if at == 0 or name not in names.defined.get(here, {}):
            return None
        return here, path[at:]
    return here, ()


class Identity:
    """Where a base module or item is at head (see the module docs), and the validated facade aliases."""

    def __init__(self, base: Namespace, head: Namespace, renames: dict[str, str], status: dict[str, set[str]],
                 changed: set[str]):
        self.base, self.head, self.renames, self.status, self.changed = base, head, renames, status, changed
        self.pairs: dict[int, Unit] = {}  # id(base unit) -> its head unit
        self.defined_units: dict[tuple[Module, str], list[Unit]] = {}
        self.facades: dict[Module, Module] = {}  # old module path -> the head module its alias names
        self.alias_failures: list[str] = []

    def use_units(self, base: list[Unit], pairs: list[tuple[Unit, Unit]]) -> None:
        self.defined_units = {}
        for unit in base:
            if unit.kind in DEFINES and not unit.container and unit.module is not None:
                self.defined_units.setdefault((unit.module, unit.name), []).append(unit)
        self.pairs = {id(old): new for old, new in pairs}

    def module(self, module: Module) -> Module | None:
        """The head path of a base module: through its file's exact rename, or the same path when its file
        stays in place (an inline module may become a new file); None otherwise."""
        owner = self.base.owner.get(module)
        if owner is None:
            return None
        if owner in self.renames:
            new = self.renames[owner]
            (own,), (now,) = self.base.contexts[owner], self.head.contexts[new]
            if module[:len(own)] != own:
                return None
            moved = now + module[len(own):]
            return moved if self.head.owner.get(moved) == new else None
        holder = self.head.owner.get(module)
        # `M` with a score is a rewrite the diff broke but paired with nothing: the file stays in place.
        in_place = all(code.startswith("M") for code in self.status.get(owner, {"M"}))
        if in_place and holder is not None and (
                holder == owner or self.status.get(holder) == {"A"}):
            return module
        return None

    def target(self, module: Module, rest: tuple[str, ...]) -> Module | None:
        """The head module of what `rest` names in base `module`: a defined item's paired home, else the
        module's own head path."""
        if not rest or rest[0] not in self.base.defined.get(module, {}):
            return self.module(module)
        units = self.defined_units.get((module, rest[0]))
        if units:
            homes = {self.pairs[id(unit)].module if id(unit) in self.pairs else None for unit in units}
            return homes.pop() if len(homes) == 1 and None not in homes else None
        files = self.base.defined[module][rest[0]]
        return self.module(module) if all(path not in self.status for path in files) else None

    def respelled_target(self, before: tuple[str, ...], old: Module, after: tuple[str, ...], new: Module
                         ) -> Module | None:
        """The head target when both spellings resolve through modules to the same one, else None."""
        found_before = through_modules(self.base, before, old)
        found_after = through_modules(self.head, after, new)
        if found_before is None or found_after is None or found_before[1] != found_after[1]:
            return None
        home = self.target(*found_before)
        return home + found_after[1] if home is not None and home == found_after[0] else None

    def meaning(self, path: tuple[str, ...], module: Module, head: bool) -> Found | None:
        """(module, rest) a path names by its spelling: the longest module prefix of its absolute path, with a
        base item mapped to its head home and a head facade alias followed."""
        names = self.head if head else self.base
        target = resolve(path, module) if path[0] in PATH_HEADS else module + path
        if target is None:
            return None
        if head:
            alias = next((cut for cut in range(len(target), 0, -1) if target[:cut] in self.facades), None)
            if alias is not None:
                target = self.facades[target[:alias]] + target[alias:]
        cut = next((cut for cut in range(len(target), 0, -1) if target[:cut] in names.modules), None)
        if cut is None:
            return None
        place, rest = target[:cut], target[cut:]
        if head:
            return place, rest
        home = self.target(place, rest)
        return None if home is None else (home, rest)

    def same_meaning(self, before: tuple[str, ...], old: Module, after: tuple[str, ...], new: Module) -> bool:
        was, now = self.meaning(before, old, False), self.meaning(after, new, True)
        if was is None or now is None:
            return False
        if was == now:
            return True
        # A moved item still named at its old place, through a head `use` that resolves to its new home.
        if (was[1] != now[1] or not now[1] or now[1][0] not in self.base.defined.get(now[0], {})
                or self.module(now[0]) != now[0]):
            return False
        return any(through_modules(self.head, path, now[0]) == (was[0], now[1][:1])
                   for _, path in self.head.bound.get(now[0], {}).get(now[1][0], []))

    def same_binding(self, before: tuple[str, ...], old: Module, after: tuple[str, ...], new: Module,
                     single: bool) -> bool:
        if before == after:
            if before[0] == "::" or (before[0] not in PATH_HEADS and old + before[:1] not in self.base.modules
                                     and new + after[:1] not in self.head.modules):
                return True  # an external crate or a name in scope: the same text names the same thing
            return self.same_meaning(before, old, after, new)
        return single and self.respelled_target(before, old, after, new) is not None


def check_aliases(ident: Identity) -> None:
    """A head binding of the name a gone module had in its old parent: a validated facade alias goes to
    ident.facades; any other alias, and a glob that can bind that name, fails."""
    base, head = ident.base, ident.head
    for old in sorted(module for module in base.modules if len(module) > 1 and module not in head.modules):
        parent, name = old[:-1], old[-1]
        bindings = head.bound.get(parent, {})
        if parent not in head.modules or not bindings:
            continue
        target = ident.module(old) if ident.module(parent) == parent else None
        for path, use in bindings.get(name, []):
            if target is not None and through_modules(head, use, parent) == (target, ()):
                ident.facades[old] = target
            else:
                ident.alias_failures.append(
                    f"`use` binds the old name of moved module {show(old)} without naming its mapped head path"
                    f" ({show(target)}): `{'::'.join(use)}` in {path}")
        for path, use in bindings.get("*", []):
            source = resolve(use, parent) if use[0] in PATH_HEADS else parent + use
            if source not in head.modules or name in head.defined.get(source, {}) or name in head.bound.get(
                    source, {}) or "*" in head.bound.get(source, {}) or source + (name,) in head.modules:
                ident.alias_failures.append(f"glob `use {'::'.join(use)}::*` in {path} can bind the old name of "
                                            f"moved module {show(old)}")


def check_bindings(ledger: Ledger, ident: Identity) -> None:
    """Class (b) for `use` items (see the module docs)."""
    base, head, changed = ident.base, ident.head, ident.changed
    for names, side_name in ((base, "base"), (head, "head")):
        for path, line in sorted(names.unread.items()):
            if path in changed:
                ledger.fail(f"cannot read the `use` item at {path}:{line} ({side_name})")
    for failure in ident.alias_failures:
        ledger.fail(failure)
    for module, bindings in sorted(base.bound.items()):
        now = ident.module(module) or (module if module in head.modules else None)
        if now is None:
            continue
        later = head.bound.get(now, {})
        for name, entries in sorted(bindings.items()):
            after = later.get(name, [])
            if not after or not any(path in changed for path, _ in entries + after):
                continue

            def same(a: tuple[str, tuple[str, ...]], b: tuple[str, tuple[str, ...]]) -> bool:
                single = len(base.contexts.get(a[0], ())) <= 1 and len(head.contexts.get(b[0], ())) <= 1
                return ident.same_binding(a[1], module, b[1], now, single)

            gone = [a for a in entries if not any(same(a, b) for b in after)]
            new = [b for b in after if not any(same(a, b) for a in entries)]
            if not new and name != "*":
                for b in after:
                    if all(a[1] != b[1] for a in entries):
                        was = next(a for a in entries if same(a, b))
                        ledger.respelled_uses.append(f"`use` {name} in {show(module)}: {'::'.join(was[1])} -> "
                                                     f"{'::'.join(b[1])} ({b[0]})")
            if new and (gone or name != "*"):
                what = "glob" if name == "*" else name
                ledger.fail(f"`use` binding {what} in {show(module)} now names something else: "
                            f"{', '.join('::'.join(a[1]) for a in gone) or 'nothing'} -> "
                            f"{', '.join('::'.join(b[1]) for b in new)} ({new[0][0]})")


def check_kept_paths(ledger: Ledger, ident: Identity, old: Unit, new: Unit) -> None:
    """A moved item's unchanged module paths must still name what they named (see the module docs)."""
    if old.module is None or new.module is None or old.module == new.module or old.kind == "macro_rules":
        return
    for before_text, after_text in ((old.container, new.container), (old.text, new.text)):
        before_uses, after_uses = path_uses(before_text), path_uses(after_text)
        if len(before_uses) != len(after_uses):
            ledger.fail(f"paths differ: {old.label} ({old.where()} -> {new.where()})")
            continue
        for (_, _, before, _), (_, _, after, _) in zip(before_uses, after_uses):
            if before == after and not ident.same_meaning(before, old.module, after, new.module):
                ledger.fail(f"path names something else after the move: {old.label} `{'::'.join(before)}` "
                            f"({old.where()} -> {new.where()})")


PathUse = tuple[int, int, tuple[str, ...], bool]  # (start, end, `::`-joined names, inside a token tree)
PLACEHOLDER = "\0path\0"


def token_trees(text: str, tokens: list[rst.Token]) -> list[tuple[int, int]]:
    """Text spans of macro call (`name!(..)`, `[..]`, `{..}`) and attribute (`#[..]`, `#![..]`) token trees;
    an unclosed one runs to the end of the text."""
    code = [token for token in tokens if token.kind not in ("ws", "comment", "doc", "idoc")]
    close: dict[int, int] = {}
    stack: list[int] = []
    for index, token in enumerate(code):
        if token.kind == "punct" and text[token.start] in "([{":
            stack.append(index)
        elif token.kind == "punct" and text[token.start] in ")]}" and stack:
            close[stack.pop()] = index
    spans = []
    for index, token in enumerate(code[:-1]):
        char = text[token.start] if token.kind == "punct" else ""
        opens = "([{"
        after = index + 1
        if char == "#":
            if text[code[after].start] == "!" and after + 1 < len(code):
                after += 1
            opens = "["
        elif not (char == "!" and index > 0 and code[index - 1].kind == "ident"
                  and text[code[index - 1].start:code[index - 1].end] not in NOT_MACRO):
            continue
        if code[after].kind == "punct" and text[code[after].start] in opens:
            spans.append((code[after].start, code[close[after]].end if after in close else len(text)))
    return spans


def path_uses(text: str) -> list[PathUse]:
    """`crate::`, `super::` and `self::` led paths written without spaces (not `$crate`)."""
    tokens = rst.tokenize(text)
    trees = token_trees(text, tokens)

    def punct(index: int, char: str) -> bool:
        return 0 <= index < len(tokens) and tokens[index].kind == "punct" and text[tokens[index].start] == char

    def joined(index: int) -> bool:
        return punct(index, ":") and punct(index + 1, ":")

    uses: list[PathUse] = []
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if (token.kind == "ident" and text[token.start:token.end] in PATH_HEADS and joined(index + 1)
                and not punct(index - 1, "$") and not joined(index - 2)):
            names, last, probe = [text[token.start:token.end]], index, index + 3
            while probe < len(tokens) and tokens[probe].kind == "ident":
                names.append(text[tokens[probe].start:tokens[probe].end])
                last = probe
                if not joined(probe + 1):
                    break
                probe += 3
            shielded = any(start <= token.start < end for start, end in trees)
            uses.append((token.start, tokens[last].end, tuple(names), shielded))
            index = last + 1
            continue
        index += 1
    return uses


def skeleton(text: str) -> tuple[str, list[PathUse]]:
    uses = path_uses(text)
    parts, cursor = [], 0
    for start, end, _, _ in uses:
        parts += [text[cursor:start], PLACEHOLDER]
        cursor = end
    parts.append(text[cursor:])
    return "".join(parts), uses


def respell_key(unit: Unit):
    """(key, paths in the container and the text, paths in the text) of a unit for respelling, or None."""
    if unit.kind == "macro_rules" or unit.module is None or unit.multi:
        return None
    container, container_uses = skeleton(unit.container)
    text, text_uses = skeleton(unit.text)
    if not container_uses and not text_uses:
        return None
    return (container, text), container_uses + text_uses, text_uses


def respelled(ident: Identity, old: Unit, old_uses: list[PathUse], new: Unit, new_uses: list[PathUse]) -> bool:
    """True when the units differ only by respelled paths (see the module docs)."""
    if old.module == new.module:
        return False
    changed = False
    for (_, _, before, shielded_before), (_, _, after, shielded_after) in zip(old_uses, new_uses, strict=True):
        if before == after:
            continue
        changed = True
        if shielded_before or shielded_after:
            return False  # inside a macro call or attribute token tree
        target = ident.respelled_target(before, old.module, after, new.module)
        if target is None:
            return False
        if before[0] == "crate":
            if after[0] != "crate" or target == resolve(before, old.module):
                return False  # its target did not move, or not respelled `crate` led
        elif resolve(before, new.module) == target:
            return False  # still means the same from the new module: no respelling is needed
    return changed


def on_skeleton(unit: Unit, text_uses: list[PathUse]) -> Unit:
    """`unit` with its visibility offsets moved onto its skeleton text, where both sides line up."""
    def shift(offset: int) -> int:
        return offset - sum(end - start - len(PLACEHOLDER) for start, end, _, _ in text_uses if end <= offset)
    return replace(unit, vis=[(shift(offset), token) for offset, token in unit.vis])


def respell_pairs(ident: Identity, lost: list[Unit], gained: list[Unit]
                  ) -> tuple[list[tuple[Unit, Unit]], list[Unit], list[Unit]]:
    """Pair units whose texts are equal outside their paths, when every changed path is a valid respelling."""
    keyed = {id(unit): respell_key(unit) for unit in lost + gained}
    by_key: dict[tuple, list[Unit]] = {}
    for unit in gained:
        if keyed[id(unit)]:
            by_key.setdefault(keyed[id(unit)][0], []).append(unit)
    # Pair provisionally first: a respelled path may name another respelled item. A provisional pair that
    # fails leaves both units unpaired, so the change fails either way.
    for unit in lost:
        key = keyed[id(unit)]
        candidate = next((c for c in by_key.get(key[0], []) if c.module != unit.module), None) if key else None
        if candidate is not None:
            ident.pairs.setdefault(id(unit), candidate)
    pairs, still_lost, taken = [], [], set()
    for unit in lost:
        key = keyed[id(unit)]
        candidates = by_key.get(key[0], []) if key else []
        match = next((c for c in candidates if id(c) not in taken
                      and respelled(ident, unit, key[1], c, keyed[id(c)][1])), None)
        if match is None:
            ident.pairs.pop(id(unit), None)
            still_lost.append(unit)
            continue
        taken.add(id(match))
        ident.pairs[id(unit)] = match
        pairs.append((unit, match))
    pairs = [(on_skeleton(old, keyed[id(old)][2]), on_skeleton(new, keyed[id(new)][2])) for old, new in pairs]
    return pairs, still_lost, [unit for unit in gained if id(unit) not in taken]


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


def validator_edits(repo: Path, base: str, head: str) -> list[str]:
    """Listed validator paths changed in place: a regular file at both revisions (status M, mode 100644
    on both sides). An added, deleted or type-changed listed path is checked like any other path."""
    fields = rst.git(repo, "diff", "--raw", "--no-renames", "-z", base, head).split("\0")
    edits = []
    for meta, path in zip(fields[0::2], fields[1::2]):
        old_mode, new_mode, _, _, status = meta.lstrip(":").split()
        if path in VALIDATOR_EDITS and status == "M" and old_mode == new_mode == "100644":
            edits.append(path)
    return sorted(edits)


def file_renames(repo: Path, base: str, head: str
                 ) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str], dict[str, set[str]]]:
    """The exact (R100) renames and exact (C100) copies of `.rs` files, the source of every other rename or
    copy, and the diff status of every path, with rewrites broken (`-B -M100%`) so that a path whose content
    moved away and was replaced still pairs exactly."""
    fields = rst.git(repo, "diff", "-B", "-M100%", "--name-status", "-z", base, head).split("\0")
    renames: list[tuple[str, str]] = []
    copies: list[tuple[str, str]] = []
    others: list[str] = []
    status: dict[str, set[str]] = {}
    at = 0
    while at + 1 < len(fields) and fields[at]:
        code = fields[at]
        if code[0] in "RC":
            old, new = fields[at + 1], fields[at + 2]
            at += 3
            status.setdefault(old, set()).add(code)
            status.setdefault(new, set()).add(code)
            if code in ("R100", "C100") and old.endswith(".rs") and new.endswith(".rs"):
                (renames if code == "R100" else copies).append((old, new))
            else:
                others.append(old)
        else:
            status.setdefault(fields[at + 1], set()).add(code)
            at += 2
    return renames, copies, others, status


def mod_decl_lines(lexed: rst.Lexed) -> dict[str, tuple[int, int] | None]:
    """Each top-level out-of-line `mod x;` of a file: its name -> the span of its whole lines, attributes and
    docs included; None when it shares a line with other code, carries `#[macro_use]` or its name is
    declared twice."""
    text, spans = lexed.text, {}
    for item in lexed.items:
        if item.kind != "mod-decl":
            continue
        start = text.rfind("\n", 0, item.lead) + 1
        stop = text.find("\n", item.end)
        stop = len(text) if stop < 0 else stop + 1
        whole = not text[start:item.lead].strip() and not text[item.end:stop].strip()
        fine = whole and item.name not in spans and not any("macro_use" in attr for attr in item.attrs)
        spans[item.name] = (start, stop) if fine else None
    return spans


def without_lines(text: str, spans: list[tuple[int, int]]) -> str:
    out, at = [], 0
    for start, stop in sorted(spans):
        out.append(text[at:start])
        at = stop
    return "".join(out) + text[at:]


def file_map(sides: tuple, exact: list[tuple[str, str]], copies: list[tuple[str, str]], others: list[str],
             changed: list[str]) -> tuple[dict[str, str], int, int]:
    """The file map (see the module docs), the number of its pairs that are exact only once added or removed
    `mod x;` declarations are left out, and of exact copies."""
    (base_source, base_tree, base_names), (head_source, head_tree, head_names) = sides

    def one(names: Namespace, path: str) -> bool:
        return len(names.contexts.get(path, ())) == 1

    def children(tree: rst.Tree) -> set[tuple[str, Module]]:
        return {(context.declared_by, context.module) for contexts in tree.contexts.values()
                for context in contexts if context.how in ("mod", "path")}

    def stripped(source: rst.Source, path: str) -> str:
        lexed = source.lexed(path)
        return without_lines(lexed.text, [span for span in mod_decl_lines(lexed).values() if span])

    sources = [old for old, _ in exact + copies] + others
    paired = {new for _, new in exact + copies}
    base_files = [path for path in changed if base_source.exists(path) and one(base_names, path)
                  and path not in sources]
    head_files = [path for path in changed if head_source.exists(path) and one(head_names, path)
                  and path not in paired]
    keys: dict[str, tuple[list[str], list[str]]] = {}
    for path in base_files:
        keys.setdefault(stripped(base_source, path), ([], []))[0].append(path)
    for path in head_files:
        keys.setdefault(stripped(head_source, path), ([], []))[1].append(path)
    base_kids, head_kids = children(base_tree), children(head_tree)
    decl_pairs = []
    for key, (olds, news) in keys.items():
        if len(olds) != 1 or len(news) != 1 or olds[0] == news[0]:
            continue
        old, new = olds[0], news[0]
        if (head_source.exists(old) and stripped(head_source, old) == key) or (
                base_source.exists(new) and stripped(base_source, new) == key):
            continue  # one side stays in place
        was, now = base_source.lexed(old), head_source.lexed(new)
        before, after = mod_decl_lines(was), mod_decl_lines(now)
        removed, added = before.keys() - after.keys(), after.keys() - before.keys()
        (old_module,), (new_module,) = base_names.contexts[old], head_names.contexts[new]
        if not (removed or added) or any(before[name] is None or (old, old_module + (name,)) not in base_kids
                                          for name in removed) or any(
                after[name] is None or (new, new_module + (name,)) not in head_kids for name in added):
            continue  # a phantom, shared-line or `#[macro_use]` declaration, or nothing left out
        if without_lines(was.text, [before[name] for name in removed]) == without_lines(
                now.text, [after[name] for name in added]):
            decl_pairs.append((old, new))
    # A copy maps only when no other rename or copy shares its source and the source path is gone or rewritten
    # by another pair; drop failing candidates until none is left.
    candidates = [(old, new) for old, new in copies if sources.count(old) == 1] + decl_pairs
    while True:
        targets = {new for _, new in exact + candidates}
        kept = [(old, new) for old, new in candidates if not head_source.exists(old) or old in targets]
        if kept == candidates:
            break
        candidates = kept
    pairs = exact + candidates
    targets = [new for _, new in pairs]
    renames = {old: new for old, new in pairs if one(base_names, old) and one(head_names, new)
               and targets.count(new) == 1}
    return renames, sum(pair in decl_pairs for pair in renames.items()), sum(
        pair in copies for pair in renames.items())


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
        validators = validator_edits(repo, base_sha, head_sha)
        changed = [path for path in rst.changed_files(repo, base_sha, head_sha)
                   if path.endswith(".rs") and path not in validators]
        print(f"move-ledger: base {base_sha[:12]} head {head_sha[:12]}: {len(changed)} changed .rs files")
        if validators:
            print(f"move-ledger: validator edits: {', '.join(validators)}")
        if not changed:
            print("move-ledger: nothing to check")
            return 0
        base_source, base_tree, base_files, base_units = side(repo, base_sha, changed)
        head_source, head_tree, head_files, head_units = side(repo, head_sha, changed, base_source)
        exact, copies, others, status = file_renames(repo, base_sha, head_sha)
        base_names, head_names = namespace(base_source, base_tree), namespace(head_source, head_tree)
        renames, decl_renames, copy_renames = file_map(
            ((base_source, base_tree, base_names), (head_source, head_tree, head_names)), exact, copies, others,
            changed)
    except rst.SourceError as error:
        print(f"move-ledger: {error}", file=sys.stderr)
        # A report never blocks a change; an enforced check does.
        return 0 if args.report else 2
    ident = Identity(base_names, head_names, renames, status, set(changed))
    check_aliases(ident)
    ledger = check(base_units, head_units, head_tree.modules, set(args.allow_widened), ident)
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
          f"{len(ledger.pairs) - moved} untouched, {moved} moved, {len(ledger.reflowed)} reflowed, "
          f"{len(ledger.respelled) + len(ledger.respelled_uses)} respelled, {len(ledger.widened)} widened, "
          f"{len(ledger.failures)} problems")
    module_map = sorted({(next(iter(base_names.contexts[old])), next(iter(head_names.contexts[new])))
                         for old, new in renames.items()} - {(m, m) for m in base_names.modules})
    if renames:
        extra = (f" ({decl_renames} exact once added or removed `mod` declarations are left out, {copy_renames} "
                 "copies of a rewritten or gone path)") if decl_renames or copy_renames else ""
        print(f"move-ledger: file map: {len(renames)} exact renames of .rs files{extra}, {len(module_map)} module "
              f"moves, {len(ident.facades)} facade aliases")
    limit = REPORT_LIMIT if args.report else None
    for before, after in module_map[:limit]:
        print(f"  module {show(before)} -> {show(after)}")
    for before, after in sorted(ident.facades.items())[:limit]:
        print(f"  facade alias {show(before)} -> {show(after)}")
    for row in rows[:limit]:
        print(f"  moved {row}")
    for old, new in ledger.reflowed[:limit]:
        print(f"  reflowed {old.label} ({old.where()} -> {new.where()})")
    for old, new in ledger.respelled[:limit]:
        print(f"  respelled {old.label} ({old.where()} -> {new.where()})")
    for row in ledger.respelled_uses[:limit]:
        print(f"  respelled {row}")
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
