#!/usr/bin/env python3
"""Offline regressions for mac_batch.py: local git repos and a fake gh.

Nothing here reaches GitHub. The fake gh refuses `workflow run` unless a test
opts in, and even then only records the call.
"""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).with_name("mac_batch.py").resolve()
spec = importlib.util.spec_from_file_location("mac_batch", str(SCRIPT))
mb = importlib.util.module_from_spec(spec)
sys.modules["mac_batch"] = mb  # dataclasses resolve annotations via sys.modules
spec.loader.exec_module(mb)

GREEN = [{"name": "Rust tests (Linux)", "conclusion": "SUCCESS"},
         {"name": "Rust format (Linux)", "conclusion": "SUCCESS"}]

RUST_BASE = '''pub fn plain() -> u32 {
    1
}

#[cfg(target_os = "macos")]
pub fn native() -> u32 {
    let s = "{ not a brace";
    2
}

impl crate::heap_layout_bound::HeapLayoutBound for Thing {
    fn heap_bound(&self) -> Option<()> {
        None
    }
}

fn unexecuted() -> bool {
    !crate::heap_layout_bound::layout_supported()
}

#[cfg(test)]
mod tests {
    #[test]
    fn portable() {
        let raw = r#"{"a": {"b": 1}}"#;
        let c = '{';
        assert_eq!(raw.len(), 15);
        let _ = c;
    }

    #[test]
    #[cfg_attr(not(target_os = "macos"), ignore = "needs macOS heap layout")]
    fn ignored_off_mac() {
        assert_eq!(1, 1);
    }

    #[test]
    fn early_return() {
        if unexecuted() {
            return;
        }
        assert_eq!(2, 2);
    }
}
'''


def bump(text, needle, replacement):
    assert needle in text, needle
    return text.replace(needle, replacement, 1)


class FakeRunner(mb.Runner):
    def __init__(self, cwd, prs, gate_rc=0, allow_dispatch=False, run=None, job_log=""):
        super().__init__(cwd)
        self.prs = prs
        self.gate_rc = gate_rc
        self.allow_dispatch = allow_dispatch
        self.run_view = run
        self.job_log = job_log
        self.gh_calls = []
        self.gate_calls = []

    def gh(self, *args, check=True):
        self.gh_calls.append(args)
        if args[:2] == ("workflow", "run"):
            if not self.allow_dispatch:
                raise AssertionError(f"test tried to dispatch: {args}")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[:2] == ("pr", "view"):
            return subprocess.CompletedProcess(args, 0, json.dumps(self.prs[int(args[2])]), "")
        if args[:2] == ("run", "list"):
            return subprocess.CompletedProcess(args, 0, json.dumps([{"databaseId": 7, "url": "u"}]), "")
        if args[:2] == ("run", "view"):
            out = self.job_log if "--log" in args else json.dumps(self.run_view)
            return subprocess.CompletedProcess(args, 0, out, "")
        raise AssertionError(f"unexpected gh call {args}")

    def gate(self, path):
        self.gate_calls.append(path)
        return subprocess.CompletedProcess(["bash", path], self.gate_rc, "gate says hi\n", "")


class Repo:
    def __init__(self, root):
        self.origin = root / "origin.git"
        self.work = root / "work"
        self.git_in(root, "init", "-q", "--bare", "-b", "main", str(self.origin))
        self.git_in(root, "init", "-q", "-b", "main", str(self.work))
        self.git("remote", "add", "origin", str(self.origin))
        (self.work / "src").mkdir()
        self.write("a.txt", "one\ntwo\nthree\nfour\nfive\n")
        self.write("src/lib.rs", RUST_BASE)
        self.commit("base")
        self.git("push", "-q", "origin", "main")
        self.base = self.rev("main")

    @staticmethod
    def git_in(cwd, *args):
        return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                              cwd=str(cwd), check=True, capture_output=True, text=True).stdout

    def git(self, *args):
        return self.git_in(self.work, *args)

    def write(self, path, text):
        (self.work / path).write_text(text)

    def read(self, path):
        return (self.work / path).read_text()

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)

    def rev(self, ref):
        return self.git("rev-parse", ref).strip()

    def branch(self, name, edits):
        self.git("checkout", "-q", "-b", name, self.base)
        for path, (needle, replacement) in edits.items():
            self.write(path, bump(self.read(path), needle, replacement))
        self.commit(name)
        self.git("push", "-q", "origin", name)
        self.git("checkout", "-q", "main")
        return self.rev(name)


def pr(number, head, branch, checks=GREEN, **extra):
    data = {"number": number, "state": "OPEN", "headRefOid": head, "headRefName": branch,
            "baseRefName": "main", "isCrossRepository": False, "statusCheckRollup": checks}
    data.update(extra)
    return data


class MacBatchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Repo(Path(tmp.name))
        r = self.repo
        self.heads = {
            1: r.branch("b1", {"a.txt": ("one\n", "ONE\n")}),
            2: r.branch("b2", {"a.txt": ("one\n", "uno\n")}),
            3: r.branch("b3", {"src/lib.rs": ("assert_eq!(1, 1);", "assert_eq!(1, 1, \"mac\");")}),
            4: r.branch("b4", {"a.txt": ("five\n", "FIVE\n")}),
        }
        self.prs = {n: pr(n, h, f"b{n}") for n, h in self.heads.items()}

    def run_main(self, argv, **kw):
        runner = FakeRunner(str(self.repo.work), self.prs, **kw)
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
                mock.patch.object(mb.time, "sleep", lambda _s: None):
            rc = mb.main(argv, runner)
        return rc, out.getvalue() + err.getvalue(), runner

    def remote_batches(self):
        return self.repo.git("ls-remote", "origin", "refs/heads/mac-batch/*").strip()

    def test_plan_builds_integration_commit_with_trailers_and_pushes_nothing(self):
        rc, out, runner = self.run_main(["plan", "3", "1"])
        self.assertEqual(rc, 0, out)
        commit = next(l.split(": ")[1] for l in out.splitlines() if l.startswith("integration commit"))
        msg = self.repo.git("log", "-1", "--format=%B", commit)
        base, members = mb.parse_trailers(msg)
        self.assertEqual(base, self.repo.base)
        self.assertEqual(members, [(1, self.heads[1]), (3, self.heads[3])])
        self.assertIn("ONE", self.repo.git("show", f"{commit}:a.txt"))
        self.assertIn('"mac"', self.repo.git("show", f"{commit}:src/lib.rs"))
        self.assertIn("member #3 b3", out)
        self.assertIn("MAC-NEEDED", out)
        self.assertEqual(self.remote_batches(), "")
        self.assertFalse([c for c in runner.gh_calls if c[:2] == ("workflow", "run")])
        self.assertEqual(runner.gate_calls, [])

    def test_plan_names_the_conflicting_pair(self):
        rc, out, _ = self.run_main(["plan", "1", "2", "3"])
        self.assertEqual(rc, mb.EXIT_REFUSED)
        self.assertIn("#1 and #2 conflict: a.txt", out)
        self.assertNotIn("integration commit", out)

    def test_dispatch_pushes_nothing_without_a_gate_ok(self):
        rc, out, runner = self.run_main(["dispatch", "--dry-run", "--gate", "/nonexistent", "1", "4"])
        self.assertEqual(rc, 0, out)
        self.assertIn("dry run", out)
        self.assertEqual(runner.gate_calls, [])
        with mock.patch.dict(os.environ, {"OTTTO_MAC_DISPATCH_GATE": ""}):
            rc, out, _ = self.run_main(["dispatch", "1", "4"])
        self.assertEqual(rc, mb.EXIT_REFUSED)
        self.assertIn("no Mac dispatch gate", out)
        with tempfile.NamedTemporaryFile(suffix=".sh") as gate:
            rc, out, runner = self.run_main(["dispatch", "--gate", gate.name, "1", "4"], gate_rc=1)
            self.assertEqual(rc, mb.EXIT_WAIT, out)
            self.assertEqual(runner.gate_calls, [gate.name])
            rc, out, _ = self.run_main(["dispatch", "--gate", gate.name, "1", "4"], gate_rc=3)
            self.assertEqual(rc, mb.EXIT_STALE, out)
        self.assertEqual(self.remote_batches(), "")

    def test_gate_ok_pushes_branch_and_calls_fake_dispatch_once(self):
        with tempfile.NamedTemporaryFile(suffix=".sh") as gate:
            rc, out, runner = self.run_main(["dispatch", "--gate", gate.name, "1", "4"], allow_dispatch=True)
        self.assertEqual(rc, 0, out)
        dispatches = [c for c in runner.gh_calls if c[:2] == ("workflow", "run")]
        self.assertEqual(len(dispatches), 1)
        branch = dispatches[0][dispatches[0].index("--ref") + 1]
        self.assertTrue(branch.startswith("mac-batch/") and branch.endswith("-1-4"), branch)
        self.assertIn(f"refs/heads/{branch}", self.remote_batches())
        # The pushed branch is now live: a second batch with #1 is refused.
        rc, out, _ = self.run_main(["plan", "1", "3"])
        self.assertEqual(rc, mb.EXIT_REFUSED)
        self.assertIn("already in live batch", out)

    def test_linux_first_and_fork_refusals(self):
        self.prs[1] = pr(1, self.heads[1], "b1", checks=GREEN[:1])
        rc, out, _ = self.run_main(["plan", "1", "4"])
        self.assertEqual(rc, mb.EXIT_REFUSED)
        self.assertIn("Rust format (Linux)=MISSING", out)
        self.prs[1] = pr(1, self.heads[1], "b1", isCrossRepository=True)
        rc, out, _ = self.run_main(["plan", "1", "4"])
        self.assertIn("fork", out)
        rc, out, _ = self.run_main(["plan", "1"])
        self.assertIn("at least two", out)

    def test_rust_items_ignore_braces_in_literals(self):
        items = {(it.kind, it.name): it for it in mb.rust_items(RUST_BASE)}
        self.assertTrue(items[("fn", "portable")].is_test)
        self.assertEqual(items[("mod", "tests")].end, RUST_BASE.count("\n"))
        native = items[("fn", "native")]
        self.assertTrue(mb._macos_cfg(native.attrs))
        self.assertEqual(native.end - native.decl, 3)
        self.assertFalse(mb._macos_cfg('#[cfg(not(target_os = "macos"))]'))
        self.assertFalse(mb._macos_cfg('#[cfg(any(target_os = "macos", target_os = "linux"))]'))
        self.assertTrue(mb._macos_cfg('#[cfg(all(test, target_os = "macos"))]'))
        self.assertEqual(mb.probe_fns(list(items.values())), {"unexecuted"})

    def test_detect_classifies_each_gate(self):
        r = mb.Runner(str(self.repo.work))
        cases = {
            "plain": ("    1\n}", "    10\n}", "LINUX-ENOUGH", set()),
            "native": ("    2\n}", "    20\n}", "MAC-NEEDED", set()),
            "impl": ("        None\n", "        Some(())\n", "MAC-NEEDED", set()),
            "ignored": ("assert_eq!(1, 1);", "assert_eq!(1, 2 - 1);", "MAC-NEEDED", {"ignored_off_mac"}),
            "early": ("assert_eq!(2, 2);", "assert_eq!(2, 1 + 1);", "MAC-NEEDED", {"early_return"}),
            "portable": ("assert_eq!(raw.len(), 15);", "assert_eq!(raw.len(), 15, \"x\");", "LINUX-ENOUGH", set()),
        }
        for name, (needle, repl, verdict, tests) in cases.items():
            with self.subTest(name):
                head = self.repo.branch(f"d-{name}", {"src/lib.rs": (needle, repl)})
                det = mb.detect_change(r, mb.member_change(r, self.repo.base, head))
                self.assertEqual(det.verdict, verdict, det.findings)
                self.assertEqual({fn for _, fn in det.mac_tests}, tests)

    def test_changed_lines_mark_pure_deletions(self):
        diff = "+++ b/x.rs\n@@ -3,2 +2,0 @@\n+++ b/y.rs\n@@ -1 +1 @@\n"
        self.assertEqual(mb.changed_new_lines(diff), {"x.rs": {2, 3}, "y.rs": {1}})

    def test_parse_log_and_ok_by_name(self):
        p = "Rust contracts\tRuntime tests\t2026-10-30T11:47:19.0555110Z "
        text = "\n".join(p + l for l in [
            "     Running unittests src/lib.rs (target/debug/deps/ottto_service-e314f6552e5362fc)",
            "test snapshots::tests::early_return ... ok",
            "test snapshots::tests::ignored_off_mac ... ignored, needs macOS heap layout",
            "thread 'snapshots::tests::boom' (73278) panicked at crates/ottto-service/src/snapshots.rs:12:5:",
            "test snapshots::tests::boom ... FAILED",
            "error: test failed, to rerun pass `-p ottto-service --lib`",
        ])
        log = mb.parse_log(text)
        self.assertEqual(log.failed, ["snapshots::tests::boom"])
        self.assertEqual(log.panics["snapshots::tests::boom"], {"crates/ottto-service/src/snapshots.rs"})
        self.assertEqual(log.failed_binaries, ["-p ottto-service --lib"])
        seen, missing = mb.ok_by_name(log, {("f.rs", "early_return"), ("f.rs", "ignored_off_mac"), ("f.rs", "gone")})
        self.assertEqual(seen, ["snapshots::tests::early_return ... ok"])
        self.assertEqual(len(missing), 2)

    def test_report_verdicts(self):
        # #3 changes the macOS-only test ignored_off_mac; #4 touches a.txt only.
        rc, out, _ = self.run_main(["plan", "3", "4"])
        self.assertEqual(rc, 0, out)
        commit = next(l.split(": ")[1] for l in out.splitlines() if l.startswith("integration commit"))
        branch = "mac-batch/t-3-4"
        self.repo.git("push", "-q", "origin", f"{commit}:refs/heads/{branch}")
        moved = self.repo.branch("b4-moved", {"a.txt": ("two\n", "TWO\n")})
        tests = [{"name": "Runtime tests", "conclusion": "success"}]
        red_tests = [{"name": "Runtime tests", "conclusion": "failure"}]
        red_fmt = [{"name": "Rust format", "conclusion": "failure"}]
        mac_ok = "test tests::ignored_off_mac ... ok"
        mac_red = "test tests::ignored_off_mac ... FAILED"
        cases = [
            # name, job conclusion, steps, log, #4 head, verdicts, exit code
            ("green", "success", tests, mac_ok, self.heads[4], ("CLEARED", "CLEARED"), 0),
            ("own test failed", "failure", red_tests, mac_red, self.heads[4], ("SUSPECT", "CLEARED"), 4),
            ("mac test did not run", "success", tests, "", self.heads[4], ("NO-EVIDENCE", "CLEARED"), 5),
            ("failed before tests", "failure", red_fmt, "", self.heads[4], ("NO-EVIDENCE", "NO-EVIDENCE"), 5),
            ("head moved", "success", tests, mac_ok, moved, ("CLEARED", "STALE"), 5),
        ]
        for name, conclusion, steps, log, head4, verdicts, code in cases:
            with self.subTest(name):
                self.prs[4] = pr(4, head4, "b4")
                run = {"status": "completed", "conclusion": conclusion, "headSha": commit, "headBranch": branch,
                       "event": "workflow_dispatch", "url": "u",
                       "jobs": [{"name": mb.MAC_JOB, "conclusion": conclusion, "databaseId": 9, "steps": steps}]}
                rc, out, _ = self.run_main(["report", "--run", "5"], run=run, job_log=log)
                self.assertEqual(rc, code, out)
                for number, verdict in zip((3, 4), verdicts):
                    self.assertIn(f"#{number} {verdict} (", out)

    def test_report_merge_queue_train(self):
        # A queued train PR: members come from its "train: merge #<n>" commits.
        r = self.repo
        r.git("checkout", "-q", "-b", "train", r.base)
        for n in (3, 4):
            r.git("merge", "-q", "--no-ff", "-m", f"train: merge #{n} b{n}", f"b{n}")
        r.git("push", "-q", "origin", "train")
        tree = r.git("rev-parse", "train^{tree}").strip()
        squash = r.git("commit-tree", tree, "-p", r.base, "-m", "train (#9)").strip()
        branch = f"gh-readonly-queue/main/pr-9-{r.base}"
        r.git("push", "-q", "origin", f"{squash}:refs/heads/{branch}")
        r.git("checkout", "-q", "main")
        self.prs[9] = pr(9, r.rev("train"), "train")
        run = {"status": "completed", "conclusion": "failure", "headSha": squash, "headBranch": branch,
               "event": "merge_group", "url": "u",
               "jobs": [{"name": mb.MAC_JOB, "conclusion": "failure", "databaseId": 9,
                         "steps": [{"name": "Runtime tests", "conclusion": "failure"}]}]}
        rc, out, _ = self.run_main(["report", "--run", "5"], run=run,
                                   job_log="test tests::ignored_off_mac ... FAILED")
        self.assertEqual(rc, 4, out)
        self.assertIn("#3 SUSPECT (", out)
        self.assertIn("#4 CLEARED (", out)

    def test_attribution_tiers(self):
        r = mb.Runner(str(self.repo.work))
        changes = {
            3: mb.member_change(r, self.repo.base, self.heads[3]),
            4: mb.member_change(r, self.repo.base, self.heads[4]),
        }
        fns = {n: mb.detect_change(r, ch).changed_fns for n, ch in changes.items()}
        log = mb.parse_log("test tests::ignored_off_mac ... FAILED\ntest tests::portable ... FAILED\n")
        ats = {at.test: at for at in mb.attribute(r, self.heads[3], log, changes, fns)}
        self.assertEqual(ats["tests::ignored_off_mac"].top, ("changes-test", [3]))
        self.assertEqual(ats["tests::portable"].top, ("touches-test-file", [3]))


if __name__ == "__main__":
    unittest.main()
