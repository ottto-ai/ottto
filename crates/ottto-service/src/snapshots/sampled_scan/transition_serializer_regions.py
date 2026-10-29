"""Test-only Rust serializer source extraction; Python standard library only.

The same extractor reads the complete src tree (or git show baseline tree),
not an include_str! catalog that cannot notice newly added files. It strips
cfg(test)-only items and external test modules before discovering serializers.
Headers track generic angle depth and balanced const/type groups through where
clauses. Unparseable impl/durable-macro headers raise instead of being skipped.
Unknown cfg predicates stay included, so platform-specific codecs are covered.
Every durable_struct!/durable_enum! invocation and Durable-family impl is a
root. Referenced local constants/helpers are followed to a fixed point; explicit
roots cover body encoding, allowlist labels, session-start hashes, source slugs
and owned-container Deref. The serializer-only codec unit is pinned as a whole,
except test code. Tokens ignore whitespace/comments but preserve literal bytes.

The checked JSON inventory records calls (including methods/qualified calls),
macro invocations and constant references; unresolved references require explicit
reviewed exceptions, never an automatic exemption. This is lexical extraction,
not Rust type resolution: aliases, macro-generated helpers, dynamic dispatch and
external implementations require owner review. New names in a selected region
change both its hash and the reviewed reference set. Import resolution changes
must also be reviewed; the inventory names their pinned providers or exception.

Deliberate rebaseline: the fixture design owner reviews the serializer change,
confirms that it still emits MAIN 53d05a43 bytes (otherwise archive that writer
or add a separately versioned seed), then runs this SAME script with --baseline
<reviewed-ref> --source-root crates/ottto-service/src and empty JSON stdin.
Review all changed per-unit hashes, outside-catalog entries and helper inventory
classifications together; never copy current hashes merely to clear CI.
"""
import hashlib
import json
import os
from pathlib import Path
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
    "owned_heap.rs": {"new", "push", "insert"},
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
    """Find an item body after all generic/where-clause bounds, or fail closed.

    Balanced groups inside <...> are const arguments/type expressions, never
    the item's body. Arrows in Fn bounds/return types do not close a generic.
    This scans headers only; expressions inside groups are opaque token trees.
    """
    at, angle = start, 0
    while at < len(t):
        part = t[at]
        if part == "<":
            angle += 1
        elif part == ">" and (at == start or t[at - 1] not in ("-", "=")):
            if not angle:
                raise ValueError("unsupported item header: unmatched >")
            angle -= 1
        elif part == "{" and not angle:
            return at
        elif part == ";" and not angle:
            return at
        elif part in (";", "}"):
            raise ValueError("unsupported item header: unclosed generic bounds")
        if at in ends:
            at = ends[at]
        else:
            at += 1
    raise ValueError("unsupported item header: missing body or declaration end")


def impl_header(t, ends, start):
    """Return the fully scanned item body and top-level implemented trait.

    Skip generic parameters, const arguments and where predicates when locating
    `Trait for Type`. Inherent impls have no trait. Unsupported item headers
    raise; they must never silently turn into an empty serializer region set.
    """
    body = body_start(t, ends, start + 1)
    if t[body] != "{":
        raise ValueError("unsupported impl header: expected braced impl body")
    angle, top = 0, []
    at = start + 1
    while at < body:
        part = t[at]
        if part == "<":
            angle += 1
        elif part == ">" and t[at - 1] not in ("-", "="):
            angle -= 1
        elif not angle:
            top.append(part)
        at = ends.get(at, at + 1)
    if not top or any(part in top for part in ("=", ";", "!")):
        raise ValueError("unsupported impl header: cannot classify implementation")
    top = top[:top.index("where")] if "where" in top else top
    fors = [n for n, part in enumerate(top) if part == "for"]
    if len(fors) > 1 or (fors and (not fors[0] or fors[0] == len(top) - 1)):
        raise ValueError("unsupported impl header: ambiguous trait/self type")
    return body, {top[fors[0] - 1]} if fors else set()


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


def regions(path, t):
    ends = balanced(t)
    signatures = []
    for i, part in enumerate(t[:-1]):
        if part == "fn" and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', t[i + 1]):
            signatures.append((i, body_start(t, ends, i + 2)))
    chosen = set()
    for i, token in enumerate(t):
        if path == "snapshots/sampled_jsonl/durable.rs" and token == "struct" and t[i + 1:i + 2] == ["Rederive"]:
            body = body_start(t, ends, i + 2)
            start = i
            # Include the derive(Default) attribute, not just the field layout.
            while start and t[start - 1] in ("pub", "crate", "(", ")"):
                start -= 1
            if start and t[start - 1] == "]":
                attr_start = next(a for a, b in ends.items() if b == start)
                start = attr_start - 1
            chosen.add((start, ends[body]))
        if token in ("durable_struct", "durable_enum") and t[i + 1:i + 2] == ["!"]:
            if t[i + 2:i + 3] not in (["("], ["["], ["{"]):
                raise ValueError("unsupported durable macro header: missing token-tree delimiter")
            start = i
            while start >= 3 and t[start - 2:start] == [":", ":"] and re.fullmatch(
                r'[A-Za-z_][A-Za-z_0-9]*', t[start - 3]
            ):
                start -= 3
            chosen.add((start, ends[i + 2]))
        elif token == "impl":
            # `impl Trait` in a function signature is a type, not an item.
            if any(a < i < b for a, b in signatures):
                continue
            body, traits = impl_header(t, ends, i)
            header = t[i:body]
            owned_deref = path == "owned_heap.rs" and traits & {"Deref", "Default", "From"} and any(
                name in header for name in ("OwnedVec", "OwnedMap")
            )
            if body < len(t) and t[body] == "{" and (traits & TRAITS or owned_deref or ("Default" in traits and "Rederive" in header)):
                chosen.add((i, ends[body]))
    if path == "durable_tail_codec.rs":
        return t
    # This array extent is referenced through a qualified path in a durable
    # declaration; pin its definition rather than exempting the external label.
    defs = definitions(t, ends)
    if path == "codex_scan_diagnostics.rs":
        chosen.update((a, b) for name, a, b, kind in defs
                      if kind == "const" and name == "PARENT_UNRESOLVABLE_CAUSES")
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
    return [token for a, b in merged for token in t[a:b]]


def cfg_without_test(t):
    """Tri-state cfg evaluation: discard only predicates certainly false."""
    if t == ["test"]:
        return False
    if len(t) > 2 and t[0] in ("all", "any", "not") and t[1] == "(":
        ends = balanced(t)
        parts, at, start = [], 2, 2
        while at < len(t) - 1:
            if t[at] == ",":
                if at > start:
                    parts.append(cfg_without_test(t[start:at]))
                start = at + 1
            at = ends.get(at, at + 1)
        if at > start:
            parts.append(cfg_without_test(t[start:at]))
        if t[0] == "not":
            return None if parts[0] is None else not parts[0]
        if t[0] == "all":
            return False if False in parts else (None if None in parts else True)
        return True if True in parts else (None if None in parts else False)
    return None


def production_tokens(path, source):
    """Remove test items; return external test module roots to exclude too."""
    t = tokens(source)
    ends = balanced(t)
    removed, test_modules = set(), set()
    items = []
    for i, part in enumerate(t):
        if part in ("mod", "trait") or (part == "fn" and t[i + 1:i + 2] != ["("]):
            body = body_start(t, ends, i + 1)
            if t[body:body + 1] == ["{"]:
                items.append((i, body, ends[body]))
    for i in range(len(t)):
        if t[i:i + 3] != ["#", "!", "["]:
            continue
        attr = t[i + 3:ends[i + 2] - 1]
        if attr[:2] != ["cfg", "("] or cfg_without_test(attr[2:-1]) is not False:
            continue
        blocks = [(a, end) for a, end in ends.items() if t[a] == "{" and a < i < end]
        if not blocks:
            return [], {path}
        body, end = max(blocks)
        # Inner cfg belongs to its enclosing item/block, never the whole file
        # merely because it happens inside an inline module or function body.
        start = next((a for a, block, _ in items if block == body), body)
        removed.update(range(start, end))
    at = 0
    while at < len(t):
        if at in removed or t[at:at + 2] != ["#", "["]:
            at += 1
            continue
        start, attrs = at, []
        while t[at:at + 2] == ["#", "["]:
            end = ends[at + 1]
            attrs.append(t[at + 2:end - 1])
            at = end
        disabled = any(
            attr == ["test"] or (attr[:2] == ["cfg", "("] and
                cfg_without_test(attr[2:-1]) is False) for attr in attrs
        )
        if not disabled:
            continue
        # Attributes can also gate fields, enum variants and match arms.
        # Stop at their comma/enclosing brace, without consuming the parent.
        body = at
        while body < len(t) and t[body] not in ("{", ";", ",", "}"):
            body = ends.get(body, body + 1)
        end = body if t[body:body + 1] == ["}"] else ends.get(body, body + 1)
        header = t[at:body]
        if "mod" in header and t[body:body + 1] == [";"]:
            name = header[header.index("mod") + 1]
            parent = Path(path).parent
            explicit = [attr[2].strip('"') for attr in attrs if attr[:2] == ["path", "="]]
            if explicit:
                test_modules.add(str(parent / explicit[0]))
            else:
                base = parent if Path(path).name in ("lib.rs", "main.rs", "mod.rs") else parent / Path(path).stem
                test_modules.update((str(base / (name + ".rs")), str(base / name / "mod.rs")))
        removed.update(range(start, end))
        at = end
    return [part for i, part in enumerate(t) if i not in removed], test_modules


def source_tree(root, baseline):
    if baseline:
        prefix = "crates/ottto-service/src/"
        paths = subprocess.check_output([
            "git", "ls-tree", "-r", "--name-only", baseline, "--", prefix
        ]).decode().splitlines()
        return {path[len(prefix):]: subprocess.check_output([
            "git", "show", baseline + ":" + path
        ]).decode() for path in paths if path.endswith(".rs")}
    if not root.is_dir():
        raise ValueError("serializer source walk requires an existing src directory: " + str(root))
    def walk_failed(error):
        raise error
    sources = {}
    # Path.rglob can suppress directory-scan errors on some Python versions.
    # os.walk(onerror=...) makes inaccessible directories a hard failure.
    for directory, dirs, files in os.walk(root, onerror=walk_failed):
        dirs.sort()
        for name in sorted(files):
            if name.endswith(".rs"):
                path = Path(directory) / name
                sources[str(path.relative_to(root))] = path.read_text(encoding="utf-8")
    if not sources:
        raise ValueError("serializer source walk found no Rust files: " + str(root))
    return sources


def reference_names(t):
    """Conservative lexical inventory; known std-only operations are excluded.

    Include callback values, macro metavariables and constructors too.
    Over-reporting is safer
    than silently missing a method or a qualified external call. Paths and
    method spellings stay distinct; uppercase constants and format captures
    include labels even when they are not syntactic function calls.
    """
    refs = set()
    ends = balanced(t)
    attributes = set()
    for at in range(len(t)):
        if t[at:at + 2] == ["#", "["]:
            attributes.update(range(at, ends[at + 1]))
        elif t[at:at + 3] == ["#", "!", "["]:
            attributes.update(range(at, ends[at + 2]))
    keywords = {"if", "while", "for", "match", "return", "fn", "impl", "pub", "where", "loop"}
    for i, token in enumerate(t):
        if i in attributes or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', token):
            continue
        call = t[i + 1:i + 2] == ["("] or t[i + 1:i + 3] == ["!", "("]
        # Include turbofish calls and qualified function values, e.g. T::key.
        if t[i + 1:i + 4] == [":", ":", "<"]:
            call = True
        if t[max(0, i - 2):i] == [":", ":"] and token[0].islower() and t[i + 1:i + 2] in ([","], [")"], ["]"]):
            call = True
        function_value = token[0].islower() and t[max(0, i - 1):i] in (["("], [","], ["="]) and t[i + 1:i + 2] in ([","], [")"], [";"], ["as"])
        const = token.isupper() and len(token) > 1
        call = call or function_value
        if (not call and not const) or token in keywords or t[max(0, i - 1):i] == ["fn"]:
            continue
        start = i
        while start >= 3 and t[start - 2:start] == [":", ":"] and re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', t[start - 3]):
            start -= 3
        name = "".join(t[start:i + 1])
        if start and t[start - 1] == ".":
            name = "." + name
        if t[i + 1:i + 2] == ["!"]:
            name += "!"
        if name not in STD_REFERENCES and not name.startswith("std::"):
            refs.add(name)
    for token in t:
        refs.update(re.findall(r'(?<!\{)\{([A-Za-z_][A-Za-z_0-9]*)(?=[:}])', token))
    return refs - STD_REFERENCES


# Reviewed standard-library/language operations only. Ambiguous names such as
# .push/.insert/.into_bytes remain in the inventory because they also dispatch
# to pinned project implementations. Do not add project helpers to this set.
STD_REFERENCES = set("""
.all .and_then .any .as_bytes .as_encoded_bytes .as_os_str .as_ref .as_str
.checked_add .checked_sub .chunks_exact .collect .contains .copied
.extend_from_slice .filter .get .is_empty .is_none .is_some .iter .iter_mut
.keys .len .map .map_err .ok_or .position .push_str .replace .saturating_add
.set .step_by .then_some .to_le_bytes .try_for_each .try_into .unwrap_or .values
.with .zip .try_fold BTreeMap::new BTreeSet::new Box::new Err Fn FnMut FnOnce Ok Some
Self::from_le_bytes Self::try_from Vec Vec::new Vec::with_capacity VecDeque::from
allow assert! cfg_attr compile_error! concat! default derive doc format! i64::from
matches! not str::to_string stringify! try_from u64::from u64::try_from u8::from
usize::try_from bool i128 i32 i64 u128 u16 u32 u64 u8 usize str true false self
""".split())


def extract(sources):
    parsed, excluded = {}, set()
    for path, source in sources.items():
        parsed[path], modules = production_tokens(path, source)
        excluded.update(modules)
    # An external test module's directory descendants are test-only as well.
    def is_test(path):
        return path in excluded or any(
            path.startswith((item.removesuffix("/mod.rs") if item.endswith("/mod.rs")
                             else item.removesuffix(".rs")) + "/")
            for item in excluded
        )
    hashes, refs = {}, set()
    for path, t in parsed.items():
        if is_test(path):
            continue
        try:
            selected = regions(path, t)
        except ValueError as error:
            raise ValueError(path + ": " + str(error)) from error
        if selected:
            hashes[path] = hashlib.sha256("\0".join(selected).encode()).hexdigest()
            refs.update(reference_names(selected))
    return {"hashes": hashes, "references": sorted(refs)}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--baseline")
    args = parser.parse_args()
    sources = source_tree(args.source_root, args.baseline)
    sources.update(json.load(sys.stdin))  # In-memory discriminating controls.
    json.dump(extract(sources), sys.stdout, indent=2, sort_keys=True)


if __name__ == "__main__":
    main()
