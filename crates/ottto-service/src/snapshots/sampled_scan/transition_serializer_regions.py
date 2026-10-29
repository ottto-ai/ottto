"""Test-only Rust serializer source extraction; Python standard library only.

The same extractor hashes `git show <baseline>:<path>` for generation and the
Rust fixture's supplied source texts for verification. It is a lexical region
extractor, not a Rust compiler or an interprocedural resolver:
* comments/whitespace are ignored; literal bytes and token boundaries are kept;
* all durable_struct!/durable_enum! invocations and handwritten Durable,
  HDigest, key and empty trait impls in each catalog unit are balanced regions;
* referenced same-unit const/static definitions (including simple named format
  captures) and bare helper calls are
  followed to a fixed point (qualified external/method calls are not resolved);
* explicit roots cover the body encode/allowlist functions, session-start
  re-derivation helpers, source slug and owned-container Deref implementations;
* durable_tail_codec.rs stays wholly pinned: primitive codecs, macros, labels.

Limits: a helper moved to an unpinned file, a new macro generating serializers,
external method/helper implementation changes and changed import resolution need
owner review and catalog/root updates. New calls in pinned regions still change
the hash. Relevant definitions in a pinned unit are discovered, not hand-listed.
Unrelated functions/comments outside the selected regions do not change a hash.
"""
import hashlib
import json
import re
import subprocess
import sys


LEXEME = re.compile(
    r'\s+|//[^\n]*|/\*|(?:br|cr|r)(?P<hashes>\#*)"'
    r'|(?:b|c)?"(?:\\.|[^"\\])*"'
    r"|b?'(?:\\(?:u\{[0-9A-Fa-f]+\}|x[0-9A-Fa-f]{2}|.)|[^'\\\n])'"
    r'|[A-Za-z_][A-Za-z_0-9]*|[0-9][A-Za-z_0-9]*|.', re.DOTALL
)
TRAITS = {"Durable", "HDigest", "DurableKey", "HDigestKey", "DurableEmpty"}
ROOT_FUNCTIONS = {
    "snapshots/sampled_jsonl/durable.rs": {"encode", "allowlist_digest"},
    "snapshots/session_start.rs": {"durable_content_digest", "durable_content_hash"},
    "snapshots.rs": {"api_slug"},
}


def tokens(source):
    out = []
    at = 0
    while at < len(source):
        match = LEXEME.match(source, at)
        text = match.group()
        start, at = match.span()
        if text.isspace() or text.startswith("//"):
            continue
        if text == "/*":
            depth = 1
            while depth:
                edge = re.search(r'/\*|\*/', source[at:])
                if edge is None:
                    raise ValueError("unterminated block comment")
                at += edge.end()
                depth += 1 if edge.group() == "/*" else -1
            continue
        if match.group("hashes") is not None:
            end = source.find('"' + match.group("hashes"), at)
            if end < 0:
                raise ValueError("unterminated raw string")
            at = end + 1 + len(match.group("hashes"))
            text = source[start:at]
        out.append(text)
    return out


def balanced(t):
    stack, ends = [], {}
    for i, token in enumerate(t):
        if token in ("(", "[", "{"):
            stack.append((token, i))
        elif token in (")", "]", "}"):
            if not stack or stack[-1][0] != {")": "(", "]": "[", "}": "{"}[token]:
                raise ValueError("unbalanced Rust source")
            _, start = stack.pop()
            ends[start] = i + 1
    if stack:
        raise ValueError("unclosed Rust region")
    return ends


def body_start(t, ends, start):
    at = start
    while at < len(t) and t[at] not in ("{", ";"):
        at = ends.get(at, at + 1)
    return at


def definitions(t, ends):
    """Index helper functions and constants, including inherent impl methods."""
    out = []
    for i, token in enumerate(t[:-1]):
        if token == "fn" and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', t[i + 1]):
            body = body_start(t, ends, i + 2)
            if body < len(t) and t[body] == "{":
                out.append((t[i + 1], i, ends[body], "fn"))
        elif token in ("const", "static") and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', t[i + 1]) and t[i + 2:i + 3] == [":"]:
            # Skip const generic parameters; declarations end at a semicolon.
            if i and t[i - 1] in ("<", ","):
                continue
            at = i + 2
            while at < len(t) and t[at] not in (";", ">"):
                at = ends.get(at, at + 1)
            if at < len(t) and t[at] == ";":
                out.append((t[i + 1], i, at + 1, "const"))
    return out


def regions(path, source):
    t = tokens(source)
    ends = balanced(t)
    if path == "durable_tail_codec.rs":
        return t
    chosen = set()
    for i, token in enumerate(t):
        if token in ("durable_struct", "durable_enum") and t[i + 1:i + 3] == ["!", "("]:
            chosen.add((i, ends[i + 2]))
        elif token == "impl":
            body = body_start(t, ends, i + 1)
            header = t[i:body]
            for_at = [n for n, part in enumerate(header) if part == "for"]
            traits = {header[n - 1] for n in for_at if n}
            owned_deref = path == "owned_heap.rs" and "Deref" in traits and any(
                name in header for name in ("OwnedVec", "OwnedMap")
            )
            if body < len(t) and t[body] == "{" and (traits & TRAITS or owned_deref):
                chosen.add((i, ends[body]))
    defs = definitions(t, ends)
    roots = ROOT_FUNCTIONS.get(path, set())
    chosen.update((a, b) for name, a, b, kind in defs if kind == "fn" and name in roots)
    if {name for name, _, _, kind in defs if kind == "fn"} & roots != roots:
        raise ValueError("missing explicit serializer helper root: " + path)
    while True:
        identifiers, calls = set(), set()
        for a, b in chosen:
            identifiers.update(t[a:b])
            for token in t[a:b]:
                identifiers.update(re.findall(r'(?<!\{)\{([A-Za-z_][A-Za-z_0-9]*)(?=[:}])', token))
            for i in range(a, b - 1):
                # Local bare calls only: no guessed resolution of .method/::name.
                if t[i + 1] == "(" and (i == a or t[i - 1] not in (".", ":", "fn")):
                    calls.add(t[i])
        extended = chosen | {
            (a, b) for name, a, b, kind in defs
            if name in (identifiers if kind == "const" else calls)
        }
        if extended == chosen:
            break
        chosen = extended
    # Union overlapping/nested regions so helper definitions inside a selected
    # handwritten impl are represented once. Source order fixes concatenation.
    merged = []
    for a, b in sorted(chosen):
        if merged and a <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    if not merged:
        raise ValueError("no serializer regions: " + path)
    return [token for a, b in merged for token in t[a:b]]


def digest(path, source):
    # Separators retain token boundaries; literals retain their exact bytes.
    normalized = "\0".join(regions(path, source))
    return hashlib.sha256(normalized.encode()).hexdigest()


def main():
    sources = json.load(sys.stdin)
    if len(sys.argv) == 3 and sys.argv[1] == "--baseline":
        sources = {
            path: subprocess.check_output([
                "git", "show", sys.argv[2] + ":crates/ottto-service/src/" + path
            ]).decode() for path in sources
        }
    json.dump({path: digest(path, source) for path, source in sources.items()}, sys.stdout)


if __name__ == "__main__":
    main()
