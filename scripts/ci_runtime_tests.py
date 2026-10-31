#!/usr/bin/env python3
"""Run the root workspace tests with ottto-service's #[serial] tests split out.

`#[serial]` locks only order tests inside one process, and a libtest thread
that waits on one stays busy. On the 3-core macOS runner about 40% of all
test-thread time in the ottto-service lib run was spent waiting on these locks,
because libtest starts tests in name order and serial tests sit in clusters.

This runs the same tests as `cargo test --workspace --locked` in two cargo
processes at once:

- serial group: every ottto-service lib test with a `#[serial]` attribute, one
  at a time, in its own process. Serial tests never overlap each other, so
  every lock relation they had still holds.
- main group: everything else, with the serial tests skipped by exact name.

A serial test and a non-serial test could already run at the same time before
this split; now they run in different processes, so they no longer share
in-process state such as environment variables or statics.

Both groups print to this step's log as they run. The step fails if either
group fails, or if the lib test counts show a test ran twice or not at all.

If neither group prints anything for --idle-limit seconds (libtest itself
reports any test running over 60 s), the step dumps what each process is
blocked on, kills both groups and fails, instead of holding the runner until
the job timeout.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

SERVICE_SRC = Path("crates/ottto-service/src")
SERIAL_ATTR = re.compile(r"^\s*#\[\s*(?:serial_test\s*::\s*)?serial\s*(?:\([^()]*\))?\s*\]\s*$")
# Any other attribute or path that names serial_test needs a parser update.
SERIAL_LIKE = re.compile(
    r"#\[\s*(?:\w+\s*::\s*)*(?:serial|parallel|file_serial|file_parallel)\b"
    r"|serial_test\s*::|cfg_attr\s*\(.*\b(?:serial|parallel)\b"
)
SERIAL_USE = re.compile(r"^\s*use\s+serial_test::serial;\s*$")
TEST_FN = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(")
SKIPPABLE = re.compile(r"^\s*(?:#\[.*\]|//.*)?\s*$")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
RESULT = re.compile(
    r"^test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
)
LIB_MARKER = re.compile(r"^\s*Running unittests src/lib\.rs \(.*ottto_service-[0-9a-f]+\)")
# Cargo right-aligns its status words to 12 columns.
NEXT_TARGET = re.compile(r"^(?: {5}Running| {3}Doc-tests) ")


class SetupError(Exception):
    pass


def serial_test_functions(src: Path) -> set[str]:
    """Names of test functions in `src` that carry a #[serial] attribute."""
    names: set[str] = set()
    for path in sorted(src.rglob("*.rs")):
        lines = path.read_text(encoding="utf-8").splitlines()
        pending: int | None = None
        attr_depth = 0  # open brackets of a multi-line attribute after #[serial]
        for number, line in enumerate(lines, 1):
            where = f"{path}:{number}"
            code = line.split("//", 1)[0]
            if attr_depth:
                if re.search(r"\b(?:serial|parallel)\b", code):
                    raise SetupError(f"{where}: unrecognised serial_test usage: {line.strip()}")
                attr_depth += code.count("[") - code.count("]")
                continue
            if SERIAL_ATTR.match(line):
                pending = pending or number
                continue
            if SERIAL_LIKE.search(code) and not SERIAL_USE.match(line):
                raise SetupError(f"{where}: unrecognised serial_test usage: {line.strip()}")
            if pending is None:
                continue
            found = TEST_FN.match(line)
            if not found and code.lstrip().startswith("#["):
                depth = code.count("[") - code.count("]")
                if depth > 0:
                    # e.g. #[cfg_attr(\n    not(...),\n    ignore = "..."\n)]
                    attr_depth = depth
                    continue
            if found:
                names.add(found.group(1))
                pending = None
            elif not SKIPPABLE.match(line):
                raise SetupError(
                    f"{path}:{pending}: #[serial] is not followed by a plain fn: {line.strip()}"
                )
        if pending is not None:
            raise SetupError(f"{path}:{pending}: #[serial] without a following fn")
    if not names:
        raise SetupError(f"no #[serial] tests found under {src}")
    return names


def listed_tests(output: str) -> list[str]:
    """Test names from libtest `--list --format terse` output."""
    return [line[: -len(": test")] for line in output.splitlines() if line.endswith(": test")]


def serial_group(lib_tests: list[str], serial_fns: set[str], all_tests: list[str]) -> list[str]:
    """The lib tests to run in the serial group, checked against every target."""
    selected = [name for name in lib_tests if name.rsplit("::", 1)[-1] in serial_fns]
    if not selected:
        raise SetupError("no listed ottto-service lib test matches a #[serial] function")
    # --skip with --exact applies to every test target, so a serial lib test's
    # full name must not also name a test in another target.
    wanted = set(selected)
    counts: dict[str, int] = {}
    for name in all_tests:
        if name in wanted:
            counts[name] = counts.get(name, 0) + 1
    clashes = sorted(name for name in selected if counts.get(name, 0) != 1)
    if clashes:
        raise SetupError(f"serial test names also used by another test target: {clashes[:5]}")
    return selected


def lib_summary(lines: list[str], whole_stream: bool) -> tuple[int, ...] | None:
    """(passed, failed, ignored, measured, filtered) of the ottto-service lib run.

    Tests that re-run the test binary print their own summaries first, so the
    lib's is the last one before the next target starts.
    """
    inside = whole_stream
    summary = None
    for raw in lines:
        line = ANSI.sub("", raw).rstrip("\r\n")
        if not whole_stream:
            if LIB_MARKER.match(line):
                inside = True
                continue
            if inside and NEXT_TARGET.match(line):
                break
        if inside:
            found = RESULT.match(line)
            if found:
                summary = tuple(int(value) for value in found.groups())
    return summary


def check_counts(name: str, summary: tuple[int, ...] | None, ran: int, filtered: int) -> list[str]:
    if summary is None:
        return [f"{name}: no ottto-service lib test summary"]
    passed, failed, ignored, _, filtered_out = summary
    if passed + failed + ignored != ran or filtered_out != filtered:
        return [
            f"{name}: ottto-service lib ran {passed + failed + ignored} and filtered "
            f"{filtered_out}; expected {ran} and {filtered}"
        ]
    return []


def capture(command: list[str]) -> str:
    print(f"$ {' '.join(command[:8])}{' ...' if len(command) > 8 else ''}", flush=True)
    done = subprocess.run(command, stdout=subprocess.PIPE, text=True, errors="replace")
    if done.returncode != 0:
        raise SetupError(f"{command[:6]} exited {done.returncode}")
    return done.stdout


def start(label: str, command: list[str], out_lock: threading.Lock, last_output: list[float]):
    """Start `command`, copy its output to stdout line by line, keep the lines.

    Each group gets its own process group (session) so a hung group can be
    killed with its test binaries. `last_output[0]` is the monotonic time of
    the latest line from any group.
    """
    with out_lock:
        print(f"== {label}: {' '.join(command[:10])} ...", flush=True)
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True
    )
    lines: list[str] = []

    def relay() -> None:
        assert process.stdout is not None
        for raw in iter(process.stdout.readline, b""):
            with out_lock:
                sys.stdout.buffer.write(raw)
                sys.stdout.buffer.flush()
                last_output[0] = time.monotonic()
            lines.append(raw.decode("utf-8", "replace"))

    thread = threading.Thread(target=relay, daemon=True)
    thread.start()
    return process, thread, lines


def group_processes(pgids: set[int]) -> list[tuple[int, str]]:
    """(pid, command) of every live process in the given process groups."""
    listing = subprocess.run(
        ["ps", "-A", "-o", "pid=,pgid=,stat=,etime=,command="],
        stdout=subprocess.PIPE, text=True, errors="replace", check=False,
    ).stdout
    found = []
    for row in listing.splitlines():
        fields = row.split(None, 4)
        if len(fields) == 5 and fields[1].isdigit() and int(fields[1]) in pgids:
            found.append((int(fields[0]), row.strip()))
    return found


def dump_stuck_state(pgids: set[int]) -> None:
    """Best effort: print each process and the thread stacks of test binaries."""
    for pid, row in group_processes(pgids):
        print(f"ci_runtime_tests: still running: {row[:300]}", flush=True)
        if "/deps/" not in row:
            continue
        if sys.platform == "darwin":
            command = ["sample", str(pid), "2"]
        elif shutil.which("gdb"):
            command = ["sudo", "-n", "gdb", "-batch", "-p", str(pid), "-ex", "thread apply all bt"]
        else:
            command = ["sh", "-c", f'for t in /proc/{pid}/task/*; do echo "$t $(cat $t/comm) $(cat $t/wchan)"; done']
        try:
            stacks = subprocess.run(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, errors="replace", timeout=120, check=False,
            ).stdout
        except (OSError, subprocess.TimeoutExpired) as error:
            stacks = f"{command[0]} failed: {error}"
        print("\n".join(stacks.splitlines()[:600]), flush=True)


def wait_groups(runs, last_output: list[float], idle_limit: float, poll: float = 5.0) -> list[str]:
    """Wait for every (label, (process, thread, lines)) run.

    Returns problems. A group that exits non-zero is a problem; so is a stretch
    of `idle_limit` seconds with no output from any group, after which every
    still-running group is killed.
    """
    problems: list[str] = []
    while any(process.poll() is None for _, (process, _, _) in runs):
        idle = time.monotonic() - last_output[0]
        if idle >= idle_limit:
            live = {process.pid for _, (process, _, _) in runs if process.poll() is None}
            print(f"ci_runtime_tests: no test output for {idle:.0f} s; dumping state and stopping", flush=True)
            dump_stuck_state(live)
            for label, (process, _, _) in runs:
                if process.poll() is None:
                    problems.append(f"{label}: killed after {idle:.0f} s without output (hung)")
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            break
        time.sleep(min(poll, max(idle_limit - idle, 0.05)))
    for label, (process, thread, _) in runs:
        status = process.wait()
        # A leftover child of a killed or crashed test can keep the pipe open.
        thread.join(timeout=30)
        if status != 0 and not any(problem.startswith(f"{label}: killed") for problem in problems):
            problems.append(f"{label}: cargo test exited {status}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--threads", type=int, required=True, help="main group --test-threads")
    parser.add_argument("--serial-threads", type=int, default=1, help="serial group --test-threads")
    parser.add_argument("--no-fail-fast", action="store_true", help="main group keeps going past a failing target")
    parser.add_argument(
        "--idle-limit", type=float, default=600,
        help="seconds without output from either group before both are dumped and killed",
    )
    args = parser.parse_args()

    cargo = os.environ.get("CARGO", "cargo")
    try:
        subprocess.run([cargo, "test", "--workspace", "--locked", "--no-run"], check=True)
        serial_fns = serial_test_functions(SERVICE_SRC)
        lib_tests = listed_tests(
            capture([cargo, "test", "-p", "ottto-service", "--lib", "--locked", "--", "--list", "--format", "terse"])
        )
        # Doc-test names contain spaces, so they cannot clash with a lib test name.
        all_tests = listed_tests(
            capture([cargo, "test", "--workspace", "--locked", "--tests", "--", "--list", "--format", "terse"])
        )
        serial = serial_group(lib_tests, serial_fns, all_tests)
    except (SetupError, subprocess.CalledProcessError) as error:
        print(f"ci_runtime_tests: {error}", file=sys.stderr)
        return 2
    print(
        f"ci_runtime_tests: {len(serial)} of {len(lib_tests)} ottto-service lib tests are #[serial]; "
        f"serial group 1 process x {args.serial_threads} thread(s), main group x {args.threads}",
        flush=True,
    )

    out_lock = threading.Lock()
    last_output = [time.monotonic()]
    serial_run = start(
        "serial group",
        [cargo, "test", "-p", "ottto-service", "--lib", "--locked", "--", "--exact", "--nocapture",
         f"--test-threads={args.serial_threads}", *serial],
        out_lock,
        last_output,
    )
    skips = [arg for name in serial for arg in ("--skip", name)]
    main_run = start(
        "main group",
        [cargo, "test", "--workspace", "--locked", *(["--no-fail-fast"] if args.no_fail_fast else []), "--",
         "--nocapture", f"--test-threads={args.threads}", "--exact", *skips],
        out_lock,
        last_output,
    )

    problems = wait_groups(
        [("main group", main_run), ("serial group", serial_run)], last_output, args.idle_limit
    )
    problems += check_counts(
        "serial group", lib_summary(serial_run[2], whole_stream=True), len(serial), len(lib_tests) - len(serial)
    )
    main_summary = lib_summary(main_run[2], whole_stream=False)
    # A fail-fast main group can stop before the lib target when an earlier one fails.
    if main_summary is not None or main_run[0].returncode == 0:
        problems += check_counts("main group", main_summary, len(lib_tests) - len(serial), len(serial))
    for problem in problems:
        print(f"ci_runtime_tests: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
