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
group fails, if the lib test counts show a test ran twice or not at all, or if
a --require-pass test did not print `test <name> ... ok`.

If neither group prints anything for --idle-limit seconds (libtest itself
reports any test running over 60 s), the step dumps what each process is
blocked on, kills both groups and fails, instead of holding the runner until
the job timeout.

With --retry-failed N, a run whose only problem is a few failed tests re-runs
each failed test alone, one at a time, in a fresh process, after both groups
have finished (so a #[serial] test still overlaps nothing). A test that passes
on retry is reported as FLAKY (log line, step summary, --flaky-json) and no
longer fails the step. Nothing is retried when more than --retry-limit tests
failed in this job, when a failure cannot be tied to a test name (doc-test,
crash or signal, missing summary), when a group hung, or when any failed test
is never-retry: a money suite (NEVER_RETRY_MODULES, any module whose file uses
the money oracle, any path segment naming money) or a --require-pass receipt.
Each retry is killed after --retry-timeout, and all of them share
--retry-budget seconds.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import libtest_log

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
# Cargo's start line for one test binary, and for a crate's doc-tests.
RUNNING = re.compile(r"^\s*Running (?:unittests )?\S+ \((\S+)\)")
DOC_TESTS = re.compile(r"^\s*Doc-tests (\S+)")
# Cargo's line for each test binary that exited non-zero (--no-fail-fast keeps going).
PROCESS_FAILED = re.compile(r"process didn't exit successfully: `(\S+)[^`]*` \(([^)]*)\)")
DOCTEST_FAILED = re.compile(r"error: doctest failed")
SERVICE_LIB = ["-p", "ottto-service", "--lib"]
# Money suites must fail on the first red; a retry never hides one. Every
# module whose file calls the money oracle is added at startup (oracle_modules).
NEVER_RETRY_MODULES = frozenset({
    "authority_proof_correction_pipeline_tests",
    "census_convergence_pipeline_tests",
    "claude_census_money_invariant_tests",
    "claude_money_e2_pipeline_tests",
    "claude_request_identity_window_tests",
    "money_equivalence_tests",
    "money_oracle",
    "upload_context_receipt_tests",
})


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


def serial_group(lib_tests: list[str], serial_fns: set[str]) -> list[str]:
    """The ottto-service lib tests to run in the serial group."""
    selected = [name for name in lib_tests if name.rsplit("::", 1)[-1] in serial_fns]
    if not selected:
        raise SetupError("no listed ottto-service lib test matches a #[serial] function")
    return selected


def require_unique(skipped: list[str], all_tests: list[str]) -> None:
    """--skip with --exact applies to every test target, so a skipped lib test's
    full name must not also name a test in another target."""
    wanted = set(skipped)
    counts: dict[str, int] = {}
    for name in all_tests:
        if name in wanted:
            counts[name] = counts.get(name, 0) + 1
    clashes = sorted(name for name in wanted if counts.get(name, 0) != 1)
    if clashes:
        raise SetupError(f"skipped lib test names also used by another test target: {clashes[:5]}")


def shard_of(names: list[str], shard: tuple[int, int]) -> list[str]:
    """Round-robin share `index` of `count` (1-based), so slow neighbours spread out."""
    index, count = shard
    return names[index - 1::count]


def parse_shard(value: str) -> tuple[int, int]:
    index, _, count = value.partition("/")
    if not (index.isdigit() and count.isdigit() and 1 <= int(index) <= int(count)):
        raise argparse.ArgumentTypeError("--shard must be I/N with 1 <= I <= N")
    return int(index), int(count)


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


def require_passed(names: list[str], lines: list[str]) -> list[str]:
    """Problems for each of `names` whose libtest result line is not `ok`."""
    results = libtest_log.results(lines)
    return [f"{name}: did not pass ({results.get(name, 'not run')})" for name in names if results.get(name) != "ok"]


def oracle_modules(root: Path) -> set[str]:
    """Module names of the .rs files under `root` that use the money oracle."""
    found = set()
    for path in root.rglob("*.rs"):
        if "money_oracle" in path.read_text(encoding="utf-8", errors="replace"):
            found.add(path.parent.name if path.stem in ("mod", "lib", "main") else path.stem)
    return found


def never_retry(name: str, required: set[str], modules: frozenset[str] | set[str] = NEVER_RETRY_MODULES) -> bool:
    segments = name.split("::")
    return name in required or any(seg in modules or "money" in seg for seg in segments)


def failures_by_binary(lines: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Failed test names per test binary file name, plus the binaries whose
    failures cannot be retried by name.

    Retryable means: cargo reported the binary exiting with libtest's failure
    status 101 (not a signal or another code), it printed FAILED names, and its
    last summary counts exactly those. Anything else is unretriable: a crash or
    abort, a failed doc-test, a binary that exited non-zero with no FAILED name
    (a child probe's summary can look clean), FAILED names in a binary cargo did
    not report as failing, or a count mismatch.
    """
    failed: dict[str, set[str]] = {}
    summary_failed: dict[str, int] = {}
    exits: dict[str, str] = {}
    doctest_failed = False
    current = None
    for raw in lines:
        line = libtest_log.clean(raw)
        process = PROCESS_FAILED.search(line)
        if process:
            exits[Path(process.group(1)).name] = process.group(2)
            continue
        if DOCTEST_FAILED.search(line):
            doctest_failed = True
        running, doc = RUNNING.match(line), DOC_TESTS.match(line)
        if running or doc:
            current = Path(running.group(1)).name if running else f"doc-tests {doc.group(1)}"
            failed.setdefault(current, set())
            continue
        if current is None:
            continue
        for match in libtest_log.RESULT.finditer(line):
            if match.group(2) == "FAILED":
                failed[current].add(match.group(1))
        summary = libtest_log.SUMMARY.match(line)
        if summary:
            # Tests that re-run their binary print a summary first; the last one wins.
            summary_failed[current] = int(summary.group(2))
    unretriable = sorted({
        binary for binary, names in failed.items()
        if (names or binary in exits or summary_failed.get(binary)) and (
            binary not in summary_failed
            or summary_failed[binary] != len(names)
            or not names
            or exits.get(binary) != "exit status: 101"
            or binary.startswith("doc-tests ")
        )
    } | {binary for binary in exits if binary not in failed} | ({"doc-tests"} if doctest_failed else set()))
    return {binary: sorted(names) for binary, names in failed.items() if names}, unretriable


def retry_plan(groups, required: set[str], limit: int,
               modules: frozenset[str] | set[str] = NEVER_RETRY_MODULES) -> tuple[list[tuple[str, list[str]]], str | None]:
    """(test, cargo scope) to retry for (lines, scope_of_binary) groups, or the
    reason to retry nothing."""
    plan = []
    for lines, scope_of in groups:
        failed, unretriable = failures_by_binary(lines)
        if unretriable:
            return [], f"cannot retry by test name: {', '.join(sorted(unretriable))}"
        for binary, names in failed.items():
            scope = scope_of(binary)
            if scope is None:
                return [], f"unknown test binary {binary}"
            plan += [(name, scope) for name in names]
    if not plan:
        return [], "no failed test names in the output"
    if len(plan) > limit:
        return [], f"{len(plan)} tests failed, over the retry limit of {limit}"
    blocked = sorted(name for name, _ in plan if never_retry(name, required, modules))
    if blocked:
        return [], f"never retried: {', '.join(blocked)}"
    return plan, None


def test_binaries(build_output: str) -> dict[str, list[str]]:
    """Test binary file name -> cargo arguments that run its target from the
    same `--workspace` build (same features, so no rebuild), from
    `cargo test --no-run --message-format=json*` output."""
    found: dict[str, list[str]] = {}
    for line in build_output.splitlines():
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if message.get("reason") != "compiler-artifact" or not message.get("executable"):
            continue
        if not message.get("profile", {}).get("test"):
            continue
        target = message["target"]
        kinds = set(target["kind"])
        kind = next((k for k in ("bin", "test", "bench", "example") if k in kinds), None)
        found[Path(message["executable"]).name] = ["--workspace", *([f"--{kind}", target["name"]] if kind else ["--lib"])]
    return found


def retry_alone(cargo: str, name: str, scope: list[str], timeout: float, out_lock: threading.Lock) -> bool:
    """Run one test alone in a fresh process; True if it printed `... ok`."""
    last_output = [time.monotonic()]
    process, thread, lines = start(
        f"retry {name}",
        [cargo, "test", *scope, "--locked", "--", "--exact", name, "--nocapture", "--test-threads=1"],
        out_lock,
        last_output,
    )
    try:
        status = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"ci_runtime_tests: retry of {name} ran over {timeout:.0f} s; killed", flush=True)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        status = process.wait()
    thread.join(timeout=30)
    return status == 0 and libtest_log.results(lines).get(name) == "ok"


def record_flaky(flaky: list[tuple[str, int]], path: str | None, shard: tuple[int, int]) -> None:
    for name, attempt in flaky:
        print(f"ci_runtime_tests: FLAKY {name} (failed, then passed alone on retry {attempt})", flush=True)
        print(f"::warning title=Flaky test::{name} failed, then passed alone on retry {attempt}", flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write("### Flaky tests (passed on retry)\n\n")
            out.writelines(f"- `{name}` (retry {attempt})\n" for name, attempt in flaky)
    if path:
        record = {
            "sha": os.environ.get("GITHUB_SHA", ""),
            "event": os.environ.get("GITHUB_EVENT_NAME", ""),
            "run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "job": os.environ.get("GITHUB_JOB", ""),
            "shard": f"{shard[0]}/{shard[1]}",
            "flaky": [{"test": name, "retry": attempt} for name, attempt in flaky],
        }
        Path(path).write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")


def retry_failures(cargo: str, groups, args, out_lock: threading.Lock, problems: list[str]) -> list[str]:
    """`problems` (group exits) if any failed test of `groups` still fails or
    cannot be retried, plus why; [] if every one passed alone on retry."""
    modules = NEVER_RETRY_MODULES | oracle_modules(Path("crates"))
    plan, reason = retry_plan(groups, set(args.require_pass), args.retry_limit, modules)
    if reason:
        print(f"ci_runtime_tests: no retry: {reason}", flush=True)
        return problems + [f"no retry: {reason}"]
    flaky, still = [], []
    deadline = time.monotonic() + args.retry_budget
    for name, scope in plan:
        attempt = None
        for k in range(1, args.retry_failed + 1):
            left = min(args.retry_timeout, deadline - time.monotonic())
            if left <= 0:
                print(f"ci_runtime_tests: retry budget of {args.retry_budget:.0f} s used up; {name} not retried", flush=True)
                break
            if retry_alone(cargo, name, scope, left, out_lock):
                attempt = k
                break
        if attempt is None:
            still.append(f"{name}: failed again on {args.retry_failed} retry(s)")
        else:
            flaky.append((name, attempt))
    if flaky:
        record_flaky(flaky, args.flaky_json, args.shard)
    return problems + still if still else []


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
    parser.add_argument(
        "--shard", type=parse_shard, default=(1, 1), metavar="I/N",
        help="run share I of N of the ottto-service lib tests; share 1 also runs every other target",
    )
    parser.add_argument(
        "--require-pass", action="append", default=[], metavar="TEST",
        help="exact test name that must print `test <name> ... ok` (repeatable)",
    )
    parser.add_argument(
        "--retry-failed", type=int, default=0, metavar="N",
        help="re-run each failed test alone up to N times; needs --no-fail-fast",
    )
    parser.add_argument("--retry-limit", type=int, default=3, help="retry nothing when more tests failed")
    parser.add_argument("--retry-timeout", type=float, default=180, help="seconds per retry before it is killed")
    parser.add_argument(
        "--retry-budget", type=float, default=480,
        help="seconds for all retries together, so they fit the job timeout",
    )
    parser.add_argument("--flaky-json", metavar="PATH", help="write tests that passed on retry here (only if any)")
    args = parser.parse_args()
    if args.retry_failed and not args.no_fail_fast:
        parser.error("--retry-failed needs --no-fail-fast, or later test binaries never run")

    cargo = os.environ.get("CARGO", "cargo")
    try:
        built = subprocess.run(
            [cargo, "test", "--workspace", "--locked", "--no-run", "--message-format=json-render-diagnostics"],
            check=True, stdout=subprocess.PIPE, text=True, errors="replace",
        )
        binaries = test_binaries(built.stdout)
        serial_fns = serial_test_functions(SERVICE_SRC)
        lib_tests = listed_tests(
            capture([cargo, "test", "-p", "ottto-service", "--lib", "--locked", "--", "--list", "--format", "terse"])
        )
        # Doc-test names contain spaces, so they cannot clash with a lib test name.
        all_tests = listed_tests(
            capture([cargo, "test", "--workspace", "--locked", "--tests", "--", "--list", "--format", "terse"])
        )
        serial_all = serial_group(lib_tests, serial_fns)
        serial = shard_of(serial_all, args.shard)
        serial_set = set(serial_all)
        main_all = [name for name in lib_tests if name not in serial_set]
        mine = shard_of(main_all, args.shard)
        if not mine:
            raise SetupError(f"shard {args.shard[0]}/{args.shard[1]} owns no lib test")
        first = args.shard[0] == 1
        # Share 1 runs the whole workspace minus every lib test it does not own;
        # the other shares run only their own lib tests.
        skipped = [name for name in lib_tests if name not in set(mine)] if first else []
        require_unique(skipped, all_tests)
    except (SetupError, subprocess.CalledProcessError) as error:
        print(f"ci_runtime_tests: {error}", file=sys.stderr)
        return 2
    print(
        f"ci_runtime_tests: shard {args.shard[0]}/{args.shard[1]}: {len(serial)} of {len(serial_all)} #[serial] "
        f"and {len(mine)} of {len(main_all)} other ottto-service lib tests; "
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
    skips = [arg for name in skipped for arg in ("--skip", name)]
    scope = ["--workspace"] if first else ["-p", "ottto-service", "--lib"]
    main_run = start(
        "main group",
        [cargo, "test", *scope, "--locked", *(["--no-fail-fast"] if args.no_fail_fast else []), "--",
         "--nocapture", f"--test-threads={args.threads}", "--exact", *skips, *([] if first else mine)],
        out_lock,
        last_output,
    )

    problems = wait_groups(
        [("main group", main_run), ("serial group", serial_run)], last_output, args.idle_limit
    )
    # A killed group has no summary; the kill is the only problem to report.
    killed = {label for label in ("main group", "serial group")
              if any(problem.startswith(f"{label}: killed") for problem in problems)}
    if args.retry_failed and problems and not killed:
        # The serial group, and the main group of shares after 1, ran SERVICE_LIB only.
        problems = retry_failures(
            cargo,
            [(main_run[2], binaries.get if first else lambda _binary: SERVICE_LIB),
             (serial_run[2], lambda _binary: SERVICE_LIB)],
            args,
            out_lock,
            problems,
        )
    if "serial group" not in killed:
        problems += check_counts(
            "serial group", libtest_log.lib_summary(serial_run[2], None), len(serial), len(lib_tests) - len(serial)
        )
    main_summary = libtest_log.lib_summary(main_run[2], "ottto_service")
    # A fail-fast main group can stop before the lib target when an earlier one fails.
    if "main group" not in killed and (main_summary is not None or main_run[0].returncode == 0):
        problems += check_counts("main group", main_summary, len(mine), len(lib_tests) - len(mine))
    problems += require_passed(args.require_pass, main_run[2] + serial_run[2])
    for problem in problems:
        print(f"ci_runtime_tests: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
