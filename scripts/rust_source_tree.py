"""Rust source structure without a build: tokens, items and the module tree.

Shared by check_move_ledger.py, check_source_layout.py and check_test_id_map.py.
This is not a Rust parser. It knows enough to split a file into top-level items
and to follow `mod`, `#[path]` and item-level `include!` the way rustc does:

- tokens: whitespace, line and nested block comments (plain, outer doc, inner
  doc), string, byte, C and raw strings, chars versus lifetimes, identifiers,
  numbers and single-character punctuation;
- items: an item runs from its leading comments, doc comments and attributes
  through its last token: the `;` or the `}` that closes it. `use`, `const`,
  `static`, `type` and `extern crate` end only at `;`. A comment on the same
  line after an item belongs to that item. Inline `mod x { .. }` and
  `impl .. { .. }` items keep their members as child items;
- modules: `mod x;` resolves to `x.rs` or `x/mod.rs` next to a mod-rs file, or
  under the directory named after a non-mod-rs file; `#[path]` resolves from
  the declaring file's directory (or, inside inline modules, from the module
  directory); an included file's own `mod x;` lines resolve from its directory.
"""

from __future__ import annotations

import bisect
import posixpath
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_TOKEN = re.compile(
    r"""
      (?P<ws>\s+)
    | (?P<line>//[^\n]*)
    | (?P<block>/\*)
    | (?P<raw>(?:br|cr|r)(?P<hashes>\#*)")
    | (?P<str>[bc]?"(?:[^"\\]|\\.)*")
    | (?P<badstr>[bc]?")
    | (?P<char>b?'(?:[^'\\\n]|\\(?:[nrt\\0'"]|x[0-9a-fA-F]{2}|u\{[0-9a-fA-F_]{1,6}\}))')
    | (?P<life>'(?:r\#)?[^\W\d]\w*)
    | (?P<ident>(?:r\#)?[^\W\d]\w*)
    | (?P<num>\d\w*)
    | (?P<punct>.)
    """,
    re.VERBOSE | re.DOTALL,
)
_BLOCK_EDGE = re.compile(r"/\*|\*/")
OPEN = {"(": ")", "[": "]", "{": "}"}
CLOSE = {")", "]", "}"}
# Items that end only at their `;`, even after a `{ .. }` group.
SEMI_ONLY = {"use", "const", "static", "type", "extern-crate"}
QUALIFIERS = {"default", "async", "unsafe", "safe"}
KEYWORDS = {"fn", "struct", "enum", "union", "trait", "impl", "mod", "use", "type", "static", "const"}
TEST_ATTR = re.compile(r"^#\[(?:\w+::)*test(?:\(.*\))?\]$", re.DOTALL)


class SourceError(Exception):
    pass


class Token:
    __slots__ = ("end", "kind", "start")

    def __init__(self, kind: str, start: int, end: int):
        self.kind = kind  # ws, comment, doc, idoc, str, char, life, ident, num, punct
        self.start = start
        self.end = end


def tokenize(text: str, where: str = "<text>") -> list[Token]:
    tokens: list[Token] = []
    pos, size = 0, len(text)
    while pos < size:
        match = _TOKEN.match(text, pos)
        kind = match.lastgroup
        if kind == "hashes":  # the named group inside `raw`
            kind = "raw"
        end = match.end()
        if kind == "line":
            body = text[pos:end]
            if body.startswith("//!"):
                kind = "idoc"
            elif body.startswith("///") and not body.startswith("////"):
                kind = "doc"
            else:
                kind = "comment"
        elif kind == "block":
            depth, cursor = 1, end
            while depth:
                found = _BLOCK_EDGE.search(text, cursor)
                if found is None:
                    raise SourceError(f"{where}:{line_of(text, pos)}: unterminated block comment")
                depth += 1 if found.group() == "/*" else -1
                cursor = found.end()
            end = cursor
            body = text[pos:end]
            if body.startswith("/*!"):
                kind = "idoc"
            elif body.startswith("/**") and not body.startswith("/***") and body != "/**/":
                kind = "doc"
            else:
                kind = "comment"
        elif kind == "raw":
            closing = '"' + match.group("hashes")
            found = text.find(closing, end)
            if found < 0:
                raise SourceError(f"{where}:{line_of(text, pos)}: unterminated raw string")
            end = found + len(closing)
            kind = "str"
        elif kind == "badstr":
            raise SourceError(f"{where}:{line_of(text, pos)}: unterminated string")
        tokens.append(Token(kind, pos, end))
        pos = end
    return tokens


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


@dataclass
class Item:
    kind: str  # fn, struct, impl, mod (inline), mod-decl, use, include, macro, comment, inner-doc, inner-attr, ...
    name: str
    start: int  # offset of the first leading comment, attribute or keyword
    lead: int  # offset of the first attribute, doc comment or keyword
    end: int  # offset just after the last token (and any same-line comment)
    depth: int  # inline `mod`/`impl` levels around the item in its file
    attrs: list[str] = field(default_factory=list)  # outer attributes, docs excluded
    members: list[Item] | None = None  # inline mod / impl body items
    body_open: int = -1  # offset of the `{` of a container
    body_close: int = -1  # offset of its closing `}`
    first_token: int = 0
    last_token: int = 0


class Lexed:
    """One file's text, tokens and bracket matches."""

    def __init__(self, text: str, where: str = "<text>"):
        self.text = text
        self.where = where
        self.tokens = tokenize(text, where)
        self._newlines = [found.start() for found in re.finditer("\n", text)]
        self.match: dict[int, int] = {}  # open bracket token -> its close
        self.opener: dict[int, int] = {}  # close bracket token -> its open
        stack: list[int] = []
        for index, token in enumerate(self.tokens):
            if token.kind != "punct":
                continue
            char = text[token.start]
            if char in OPEN:
                stack.append(index)
            elif char in CLOSE:
                if not stack or OPEN[text[self.tokens[stack[-1]].start]] != char:
                    raise SourceError(f"{where}:{line_of(text, token.start)}: unbalanced '{char}'")
                opened = stack.pop()
                self.match[opened], self.opener[index] = index, opened
        if stack:
            raise SourceError(f"{where}:{line_of(text, self.tokens[stack[-1]].start)}: unclosed bracket")
        self.items = self.parse(0, len(self.tokens), 0)

    def line(self, offset: int) -> int:
        """1-based line of a text offset."""
        return bisect.bisect_left(self._newlines, offset) + 1

    def tok(self, index: int) -> str:
        token = self.tokens[index]
        return self.text[token.start:token.end]

    def is_punct(self, index: int, char: str) -> bool:
        return (index < len(self.tokens) and self.tokens[index].kind == "punct"
                and self.text[self.tokens[index].start] == char)

    def is_ident(self, index: int, word: str | None = None) -> bool:
        return (index < len(self.tokens) and self.tokens[index].kind == "ident"
                and (word is None or self.tok(index) == word))

    def next_code(self, index: int, hi: int | None = None) -> int:
        """Index of the next token at or after `index` that is not whitespace or a comment."""
        hi = len(self.tokens) if hi is None else hi
        while index < hi and self.tokens[index].kind in ("ws", "comment", "doc", "idoc"):
            index += 1
        return index

    def skip_vis(self, index: int) -> int:
        """Index after a `pub` / `pub(..)` visibility at `index` (unchanged if none)."""
        if not self.is_ident(index, "pub"):
            return index
        after = self.next_code(index + 1)
        if self.is_punct(after, "("):
            inner = self.next_code(after + 1)
            if self.is_ident(inner) and self.tok(inner) in ("crate", "super", "self", "in"):
                return self.match[after] + 1
        return index + 1

    def parse(self, lo: int, hi: int, depth: int) -> list[Item]:
        items: list[Item] = []
        tokens = self.tokens
        index = lo
        pending: int | None = None  # first token of leading plain comments
        while True:
            while index < hi and tokens[index].kind == "ws":
                index += 1
            if index >= hi:
                break
            kind = tokens[index].kind
            if kind == "idoc":
                if pending is not None:
                    items.append(self._comment_item(pending, index, depth))
                    pending = None
                last = index
                while True:
                    probe = last + 1
                    while probe < hi and tokens[probe].kind == "ws" and self.tok(probe).count("\n") <= 1:
                        probe += 1
                    if probe < hi and tokens[probe].kind == "idoc":
                        last = probe
                        continue
                    break
                items.append(Item("inner-doc", "//!", tokens[index].start, tokens[index].start,
                                  tokens[last].end, depth, first_token=index, last_token=last))
                index = last + 1
                continue
            if kind == "comment":
                if pending is None:
                    pending = index
                index += 1
                continue
            first = pending if pending is not None else index
            pending = None
            item, index = self._item(first, index, hi, depth)
            items.append(item)
        if pending is not None:
            items.append(self._comment_item(pending, hi, depth))
        return items

    def _comment_item(self, first: int, stop: int, depth: int) -> Item:
        last = stop - 1
        while self.tokens[last].kind == "ws":
            last -= 1
        return Item("comment", "comment", self.tokens[first].start, self.tokens[first].start,
                    self.tokens[last].end, depth, first_token=first, last_token=last)

    def _item(self, first: int, lead: int, hi: int, depth: int) -> tuple[Item, int]:
        text, tokens = self.text, self.tokens
        index, attrs = lead, []
        while index < hi:
            kind = tokens[index].kind
            if kind in ("ws", "comment", "doc"):
                index += 1
                continue
            if self.is_punct(index, "#"):
                after = self.next_code(index + 1, hi)
                if self.is_punct(after, "!") and index == lead:
                    bracket = self.next_code(after + 1, hi)
                    if self.is_punct(bracket, "["):
                        close = self.match[bracket]
                        name = self._squash(tokens[index].start, tokens[close].end)
                        item = Item("inner-attr", name, tokens[first].start, tokens[lead].start, 0, depth)
                        return self._finish(item, first, close, hi)
                if self.is_punct(after, "["):
                    close = self.match[after]
                    attrs.append(self._squash(tokens[index].start, tokens[close].end))
                    index = close + 1
                    continue
            break
        if index >= hi:
            raise SourceError(f"{self.where}:{line_of(text, tokens[lead].start)}: attributes without an item")
        kind, name, end_rule = self._classify(index, hi)
        last = self._find_end(index, hi, end_rule)
        item = Item(kind, name, tokens[first].start, tokens[lead].start, 0, depth, attrs=attrs)
        if kind in ("impl", "mod") and self.is_punct(last, "}"):
            open_index = self.opener[last]
            item.body_open, item.body_close = tokens[open_index].start, tokens[last].start
            item.members = self.parse(open_index + 1, last, depth + 1)
        elif kind == "mod":
            item.kind = "mod-decl"
        return self._finish(item, first, last, hi)

    def _finish(self, item: Item, first: int, last: int, hi: int) -> tuple[Item, int]:
        tokens = self.tokens
        after = last + 1
        if after < hi and tokens[after].kind == "ws" and "\n" not in self.tok(after):
            after += 1
        if after < hi and tokens[after].kind == "comment" and "\n" not in self.tok(after):
            last = after
        item.end = tokens[last].end
        item.first_token, item.last_token = first, last
        return item, last + 1

    def _squash(self, start: int, end: int) -> str:
        return re.sub(r"\s+", " ", self.text[start:end]).strip()

    def _classify(self, index: int, hi: int) -> tuple[str, str, str]:
        """(kind, name, end rule) of the item whose first keyword token is at `index`."""
        index = self.next_code(self.skip_vis(index), hi)
        while self.is_ident(index):
            word = self.tok(index)
            after = self.next_code(index + 1, hi)
            if word in QUALIFIERS and after < hi and self.tokens[after].kind in ("ident", "str"):
                index = after
                continue
            if word == "const" and self.is_ident(after) and self.tok(after) in ("fn", "unsafe", "async", "extern"):
                index = after
                continue
            if word == "extern":
                if after < hi and self.tokens[after].kind == "str":
                    after = self.next_code(after + 1, hi)
                if self.is_ident(after, "crate"):
                    return "extern-crate", self._name_after(after, hi), "semi"
                if self.is_punct(after, "{"):
                    return "extern", "extern", "any"
                index = after
                continue
            if word == "auto" and self.is_ident(after, "trait"):
                index = after
                continue
            break
        if self.is_ident(index):
            word = self.tok(index)
            after = self.next_code(index + 1, hi)
            if word == "union" and self.is_ident(after):
                return "union", self.tok(after), "struct"
            if word in KEYWORDS:
                if word == "impl":
                    return "impl", self._header(index, hi), "any"
                if word == "use":
                    return "use", self._header(index, hi, ";"), "semi"
                if word in ("const", "static", "type"):
                    return word, self._name_after(index, hi), "semi"
                return word, self._name_after(index, hi), "struct" if word == "struct" else "any"
            # Macro invocation: a path followed by `!`.
            probe, path = index, []
            while self.is_ident(probe):
                path.append(self.tok(probe))
                nxt = self.next_code(probe + 1, hi)
                if self.is_punct(nxt, ":") and self.is_punct(nxt + 1, ":"):
                    probe = self.next_code(nxt + 2, hi)
                    continue
                probe = nxt
                break
            if path and self.is_punct(probe, "!"):
                macro = "::".join(path)
                target = self.next_code(probe + 1, hi)
                if macro == "macro_rules":
                    return "macro_rules", f"macro_rules! {self.tok(target)}", "any"
                if macro == "include":
                    literal = self.next_code(target + 1, hi)
                    if self.is_punct(target, "(") and self.tokens[literal].kind == "str":
                        return "include", self.tok(literal), "any"
                return "macro", f"{macro}!", "any"
        return "unknown", self.tok(index) if index < hi else "", "any"

    def _name_after(self, index: int, hi: int) -> str:
        nxt = self.next_code(index + 1, hi)
        if self.is_ident(nxt, "mut"):
            nxt = self.next_code(nxt + 1, hi)
        return self.tok(nxt) if nxt < hi else ""

    def _header(self, index: int, hi: int, stops: str = "{;") -> str:
        probe = index
        while probe < hi and not any(self.is_punct(probe, stop) for stop in stops):
            probe = self.match.get(probe, probe) + 1
        return self._squash(self.tokens[index].start, self.tokens[probe - 1].end)

    def _find_end(self, index: int, hi: int, rule: str) -> int:
        """Index of the last token of the item starting at keyword `index`."""
        while index < hi:
            token = self.tokens[index]
            if token.kind == "punct":
                char = self.text[token.start]
                if char == ";":
                    return index
                if char in OPEN:
                    close = self.match[index]
                    if char == "{" and rule in ("any", "struct"):
                        return close
                    index = close + 1
                    continue
            index += 1
        raise SourceError(f"{self.where}:{line_of(self.text, self.tokens[index - 1].start)}: item without an end")


def attr_path(attrs: list[str]) -> str | None:
    for attr in attrs:
        found = re.match(r'^#\[\s*path\s*=\s*"([^"]*)"\s*\]$', attr)
        if found:
            return found.group(1)
    return None


def module_attrs(attrs: list[str]) -> frozenset[str]:
    """Attributes of a module declaration that apply to everything in it (not `#[path]`)."""
    return frozenset(attr for attr in attrs if attr_path([attr]) is None and not attr.startswith("#[doc"))


def is_test_attr(attr: str) -> bool:
    return bool(TEST_ATTR.match(re.sub(r"\s+", "", attr)))


# ---------------------------------------------------------------- file sources


class Source:
    """Files at one commit (GitSource) or in a directory (DirSource), by repo-relative path."""

    def exists(self, path: str) -> bool:
        raise NotImplementedError

    def read_bytes(self, path: str) -> bytes:
        raise NotImplementedError

    def files(self) -> list[str]:
        raise NotImplementedError

    def read(self, path: str) -> str:
        return self.read_bytes(path).decode("utf-8", "surrogateescape")

    def lexed(self, path: str) -> Lexed:
        cache = self.__dict__.setdefault("_lexed", {})
        if path not in cache:
            cache[path] = Lexed(self.read(path), path)
        return cache[path]




class DirSource(Source):
    def __init__(self, root: Path):
        self.root = Path(root)

    def exists(self, path: str) -> bool:
        return (self.root / path).is_file()

    def read_bytes(self, path: str) -> bytes:
        return (self.root / path).read_bytes()

    def files(self) -> list[str]:
        return sorted(p.relative_to(self.root).as_posix() for p in self.root.rglob("*")
                      if p.is_file() and ".git" not in p.relative_to(self.root).parts)


class GitSource(Source):
    def __init__(self, repo: Path, rev: str):
        self.repo, self.rev = Path(repo), rev
        listing = git(repo, "ls-tree", "-r", "-z", rev)
        self._blobs: dict[str, str] = {}
        for entry in listing.split("\0"):
            if entry:
                meta, _, name = entry.partition("\t")
                self._blobs[name] = meta.split()[2]
        self._files = set(self._blobs)
        self._cache: dict[str, bytes] = {}
        self._batch: subprocess.Popen | None = None

    def exists(self, path: str) -> bool:
        return path in self._files

    def files(self) -> list[str]:
        return sorted(self._files)

    def share_with(self, other: GitSource) -> None:
        """Reuse `other`'s parsed files whose blob is the same here."""
        mine = self.__dict__.setdefault("_lexed", {})
        for path, lexed in other.__dict__.get("_lexed", {}).items():
            if self._blobs.get(path) == other._blobs.get(path):
                mine.setdefault(path, lexed)

    def read_bytes(self, path: str) -> bytes:
        if path not in self._cache:
            if path not in self._files:
                raise SourceError(f"{self.rev}: no file {path}")
            if self._batch is None:
                self._batch = subprocess.Popen(
                    ["git", "-C", str(self.repo), "cat-file", "--batch"],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                )
            assert self._batch.stdin and self._batch.stdout
            self._batch.stdin.write(f"{self.rev}:{path}\n".encode())
            self._batch.stdin.flush()
            header = self._batch.stdout.readline().split()
            if len(header) != 3 or header[1] != b"blob":
                raise SourceError(f"{self.rev}: cannot read {path}")
            size = int(header[2])
            data = self._batch.stdout.read(size)
            self._batch.stdout.read(1)
            self._cache[path] = data
        return self._cache[path]

    def close(self) -> None:
        if self._batch is not None:
            assert self._batch.stdin
            self._batch.stdin.close()
            if self._batch.stdout:
                self._batch.stdout.close()
            self._batch.wait()
            self._batch = None


def git(repo: Path, *args: str) -> str:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          errors="surrogateescape", check=False)
    if done.returncode != 0:
        raise SourceError(f"git {' '.join(args[:3])}: {done.stderr.strip()}")
    return done.stdout


def default_base(repo: Path) -> str:
    return git(repo, "merge-base", "origin/main", "HEAD").strip()


def changed_files(repo: Path, base: str, head: str) -> list[str]:
    out = git(repo, "diff", "--no-renames", "--name-only", "-z", base, head)
    return sorted(name for name in out.split("\0") if name)


# ---------------------------------------------------------------- module tree


@dataclass
class Context:
    """Where one file sits in the module tree."""

    path: str
    module: tuple[str, ...]
    chain: frozenset[str]  # module and include attributes from the root down
    directory: str  # where its `mod x;` children live (with `relative`)
    relative: str | None  # the non-mod-rs file's own name, if any
    declared_by: str | None
    how: str  # root, mod, path, include


@dataclass
class Link:
    """One `mod x;`, `#[path] mod x;` or item-level `include!` in a file."""

    file: str
    line: int
    how: str  # mod, path, include
    literal: str | None
    target: str | None  # resolved path, None if missing


@dataclass
class Tree:
    contexts: dict[str, list[Context]] = field(default_factory=dict)
    modules: set[tuple[str, ...]] = field(default_factory=set)
    links: list[Link] = field(default_factory=list)

    def context(self, path: str) -> Context | None:
        found = self.contexts.get(path)
        return found[0] if found else None


def file_context(path: str, module: tuple[str, ...], how: str = "root") -> Context:
    """The context of a crate root or a module file reached by plain `mod`."""
    directory, name = posixpath.split(path)
    stem = name.removesuffix(".rs")
    mod_rs = how == "root" or stem == "mod"
    return Context(path, module, frozenset(), directory, None if mod_rs else stem, None, how)


def build_tree(source: Source, roots: list[Context]) -> Tree:
    tree = Tree()
    queue = list(roots)
    while queue:
        context = queue.pop(0)
        tree.contexts.setdefault(context.path, []).append(context)
        tree.modules.add(context.module)
        if any(seen.module == context.module for seen in tree.contexts[context.path][:-1]):
            continue  # the same module reached twice (an include cycle); walk it once
        lexed = source.lexed(context.path)
        _walk(source, tree, context, lexed, lexed.items, [], context.module, context.chain, queue)
    return tree


def _walk(source, tree, context, lexed, items, inline, module, chain, queue) -> None:
    def join(*parts: str) -> str:
        return posixpath.normpath(posixpath.join(*[p for p in parts if p]))

    for item in items:
        if item.kind == "mod" and item.members is not None:
            literal = attr_path(item.attrs)
            sub = [*inline, literal] if literal else [*inline, item.name]
            tree.modules.add(module + (item.name,))
            _walk(source, tree, context, lexed, item.members, sub, module + (item.name,),
                  chain | module_attrs(item.attrs), queue)
        elif item.kind == "mod-decl":
            literal = attr_path(item.attrs)
            line = lexed.line(item.lead)
            child_chain = chain | module_attrs(item.attrs)
            child_module = module + (item.name,)
            if literal is not None:
                base = (posixpath.dirname(context.path) if not inline
                        else join(context.directory, context.relative or "", *inline))
                target = join(base, literal)
                found = target if source.exists(target) else None
                tree.links.append(Link(context.path, line, "path", literal, found))
                if found:
                    queue.append(Context(found, child_module, child_chain, posixpath.dirname(found), None,
                                         context.path, "path"))
            else:
                base = join(context.directory, context.relative or "", *inline)
                flat, nested = join(base, f"{item.name}.rs"), join(base, item.name, "mod.rs")
                found = flat if source.exists(flat) else nested if source.exists(nested) else None
                tree.links.append(Link(context.path, line, "mod", None, found))
                if found:
                    child = file_context(found, child_module, "mod")
                    child.chain, child.declared_by = child_chain, context.path
                    queue.append(child)
            tree.modules.add(child_module)
        elif item.kind == "include":
            literal = item.name[1:-1]
            target = join(posixpath.dirname(context.path), literal)
            found = target if source.exists(target) else None
            tree.links.append(Link(context.path, lexed.line(item.lead), "include", literal, found))
            if found:
                queue.append(Context(found, module, chain | module_attrs(item.attrs), posixpath.dirname(found),
                                     None, context.path, "include"))


def crate_dir(path: str, source: Source) -> str | None:
    """The nearest directory above `path` that has a Cargo.toml."""
    directory = posixpath.dirname(path)
    while directory:
        if source.exists(f"{directory}/Cargo.toml"):
            return directory
        directory = posixpath.dirname(directory)
    return None


def crate_roots(crate: str, source: Source) -> list[str]:
    """Target root files of a crate: lib, main, bins, integration tests, benches, examples."""
    roots = [f"{crate}/src/lib.rs", f"{crate}/src/main.rs", f"{crate}/build.rs"]
    pattern = re.compile(rf"^{re.escape(crate)}/(?:src/bin|tests|benches|examples)/[^/]+\.rs$")
    roots += [path for path in source.files() if pattern.match(path)]
    return [path for path in dict.fromkeys(roots) if source.exists(path)]


def target_label(crate: str, root: str) -> str:
    """`crate` for the library root; `crate[<root>]` for every other target."""
    relative = posixpath.relpath(root, crate)
    return "crate" if relative == "src/lib.rs" else f"crate[{relative}]"


def crate_tree(source: Source, crate: str) -> Tree:
    """The module trees of every target of `crate`, merged; module[0] names the target."""
    roots = [file_context(path, (target_label(crate, path),)) for path in crate_roots(crate, source)]
    return build_tree(source, roots)
