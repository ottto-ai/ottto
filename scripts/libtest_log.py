"""Parse `cargo test` (libtest) output; shared by ci_runtime_tests.py and mac_batch.py."""

from __future__ import annotations

import re
from typing import Dict, Iterable, Optional, Set, Tuple

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SUMMARY = re.compile(
    r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
)
# Cargo right-aligns its status words to 12 columns; test output does not.
NEXT_TARGET = re.compile(r"^(?: {5}Running| {3}Doc-tests) ")
RESULT = re.compile(r"\btest (\S+) \.\.\. (ok|FAILED|ignored)\b")
PANIC = re.compile(r"thread '([^']+)'(?: \(\d+\))? panicked at ([^\s:]+\.rs):(\d+)")


def clean(raw: str) -> str:
    """One output line without colour codes or line ending."""
    return ANSI.sub("", raw).rstrip("\r\n")


def lib_marker(crate: str) -> re.Pattern:
    """Cargo's start line for the unit tests of `crate`'s lib target."""
    return re.compile(rf"^\s*Running unittests src/lib\.rs \(.*{crate}-[0-9a-f]+\)")


def lib_summary(lines: Iterable[str], crate: Optional[str]) -> Optional[Tuple[int, ...]]:
    """(passed, failed, ignored, measured, filtered) of `crate`'s lib run.

    With `crate` None the lines hold that run alone. Tests that re-run the test
    binary print their own summaries first, so the lib's is the last one before
    the next target starts.
    """
    marker = lib_marker(crate) if crate else None
    inside = marker is None
    summary = None
    for raw in lines:
        line = clean(raw)
        if marker is not None:
            if marker.match(line):
                inside = True
                continue
            if inside and NEXT_TARGET.match(line):
                break
        if inside:
            found = SUMMARY.match(line)
            if found:
                summary = tuple(int(value) for value in found.groups())
    return summary


def results(lines: Iterable[str]) -> Dict[str, str]:
    """Per test name: ok, ignored or FAILED; a FAILED run of the name wins."""
    found: Dict[str, str] = {}
    for raw in lines:
        for match in RESULT.finditer(clean(raw)):
            name, status = match.groups()
            if found.get(name) != "FAILED":
                found[name] = status
    return found


def panics(lines: Iterable[str]) -> Dict[str, Set[str]]:
    """Per panicking test (thread) name: the source files it panicked in."""
    found: Dict[str, Set[str]] = {}
    for raw in lines:
        match = PANIC.search(clean(raw))
        if match:
            found.setdefault(match.group(1), set()).add(match.group(2))
    return found
