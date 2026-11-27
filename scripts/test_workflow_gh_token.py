#!/usr/bin/env python3
"""Workflow gh token policy: every workflow step that runs gh names its token.

A step that calls gh, directly in its run script or through a scripts/ file it runs (and
the scripts/ files that file sources), must set GH_TOKEN from an expression (step, job or
workflow env). Without it gh falls back to whatever login the runner's account has, so a
step can pass on one runner and fail on a runner whose account has no login.

The stable release workflow also gives gh an empty config folder in its first step, before
any step that calls gh, so a missing GH_TOKEN fails the same way on every runner.

Every workflow is parsed with each YAML parser present (see test_workflow_runner_policy).
Synthetic fixtures prove each rule fails closed.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_workflow_runner_policy as policy  # noqa: E402

ROOT = policy.ROOT
STABLE = policy.STABLE
GH_SUBCOMMANDS = ("api|attestation|auth|cache|gist|issue|label|pr|release|repo|run|search|"
                  "secret|variable|workflow")
# A gh invocation on a non-comment shell line: gh at a command position, not inside a
# string such as a printed verification command.
SHELL_GH = re.compile(r"(?:^|[\s;|&(!])gh\s+(?:%s)\b" % GH_SUBCOMMANDS)
# A gh argv in Python or Ruby: ["gh", ...] or ("gh", ...).
ARGV_GH = re.compile(r"""[\[(,]\s*["']gh["']\s*,""")
SCRIPT_REF = re.compile(r"(?:^|[\s\"'(=])(?:\./)?scripts/([A-Za-z0-9_.-]+\.(?:sh|py))\b")
SOURCED = re.compile(r"""^\s*(?:source|\.)\s+["']?\$\{?SCRIPT_DIR\}?/([A-Za-z0-9_.-]+)["']?""")
TOKEN_VALUE = re.compile(r"^\$\{\{\s*(?:github\.token|secrets\.[A-Za-z0-9_]+)\s*\}\}$")


def calls_gh(text):
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue
        if SHELL_GH.search(line) or ARGV_GH.search(line):
            return True
    return False


def script_calls_gh(name, read_script, seen=None):
    """True when scripts/<name>, or a scripts/ file it sources, calls gh."""
    seen = set() if seen is None else seen
    if name in seen:
        return False
    seen.add(name)
    text = read_script(name)
    if text is None:
        return False
    if calls_gh(text):
        return True
    return any(script_calls_gh(match.group(1), read_script, seen)
               for match in map(SOURCED.match, text.splitlines()) if match)


def step_calls_gh(run, read_script):
    if calls_gh(run):
        return True
    return any(script_calls_gh(name, read_script) for name in SCRIPT_REF.findall(run))


def has_token(*envs):
    for env in envs:
        if isinstance(env, dict) and "GH_TOKEN" in env:
            return bool(TOKEN_VALUE.match(str(env["GH_TOKEN"]).strip()))
    return False


def isolates_gh(step):
    run = step.get("run") if isinstance(step, dict) else None
    return isinstance(run, str) and "GH_CONFIG_DIR=" in run and "GITHUB_ENV" in run


def policy_problems(docs, read_script):
    problems = []
    for path, doc in sorted(docs.items()):
        if not isinstance(doc, dict):
            continue
        jobs = doc.get("jobs") or {}
        for job_name, job in jobs.items() if isinstance(jobs, dict) else ():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps") or []
            for index, step in enumerate(steps):
                run = step.get("run") if isinstance(step, dict) else None
                if not isinstance(run, str) or not step_calls_gh(run, read_script):
                    continue
                label = "%s:%s step %d (%s)" % (path, job_name, index + 1, step.get("name", "unnamed"))
                if not has_token(step.get("env"), job.get("env"), doc.get("env")):
                    problems.append("%s calls gh without GH_TOKEN from github.token or a secret" % label)
                if path == STABLE and not any(isolates_gh(earlier) for earlier in steps[:index]):
                    problems.append("%s calls gh before the step that empties gh's config folder" % label)
    return problems


def repository_reader(root):
    def read(name):
        path = os.path.join(root, "scripts", name)
        if not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return read


ISOLATE = ("      - name: Isolate gh\n"
           "        run: |\n"
           "          mkdir -m 700 \"$RUNNER_TEMP/gh-config\"\n"
           "          echo \"GH_CONFIG_DIR=$RUNNER_TEMP/gh-config\" >> \"$GITHUB_ENV\"\n")
TOKEN_ENV = "        env:\n          GH_TOKEN: ${{ github.token }}\n"


def workflow(steps, job_env=""):
    return ("on: workflow_dispatch\njobs:\n  build:\n    runs-on: ubuntu-24.04\n" + job_env +
            "    steps:\n" + steps)


def step(name, run, env=""):
    return "      - name: %s\n%s        run: %s\n" % (name, env, run)


SCRIPTS = {
    "calls_gh.sh": "#!/usr/bin/env bash\nset -euo pipefail\nif ! gh attestation verify \"$1\" --repo x; then exit 1; fi\n",
    "prints_gh.sh": "#!/usr/bin/env bash\n# gh attestation verify is printed for humans only\ncmd=\"gh attestation verify ./x -R y\"\necho \"$cmd\"\n",
    "sources_gh.sh": "#!/usr/bin/env bash\nsource \"$SCRIPT_DIR/calls_gh.sh\"\n",
    "argv_gh.py": "import subprocess\nsubprocess.run([\"gh\", \"api\", \"repos/x\"], check=True)\n",
    "wrapper.sh": "#!/usr/bin/env bash\n\"$@\"\n",
}


def fixture_cases():
    other = ".github/workflows/fixture.yml"
    return [
        ("no gh", {other: workflow(step("plain", "echo hi"))}, None),
        ("direct gh without token", {other: workflow(step("api", "gh api repos/x"))}, "without GH_TOKEN"),
        ("direct gh with step token", {other: workflow(step("api", "gh api repos/x", TOKEN_ENV))}, None),
        ("direct gh with job token",
         {other: workflow(step("api", "gh api repos/x"), "    env:\n      GH_TOKEN: ${{ github.token }}\n")}, None),
        ("token from a secret",
         {other: workflow(step("api", "gh api repos/x", "        env:\n          GH_TOKEN: ${{ secrets.FIXTURE }}\n"))},
         None),
        ("token that is a literal",
         {other: workflow(step("api", "gh api repos/x", "        env:\n          GH_TOKEN: fixture\n"))},
         "without GH_TOKEN"),
        ("gh in a comment only", {other: workflow(step("note", "'# gh api repos/x'"))}, None),
        ("gh through a wrapped script",
         {other: workflow(step("bind", "scripts/wrapper.sh \"bind\" scripts/calls_gh.sh x"))}, "without GH_TOKEN"),
        ("gh through a wrapped script with token",
         {other: workflow(step("bind", "scripts/wrapper.sh \"bind\" scripts/calls_gh.sh x", TOKEN_ENV))}, None),
        ("gh only printed by a script", {other: workflow(step("print", "scripts/prints_gh.sh"))}, None),
        ("gh in a sourced script", {other: workflow(step("source", "scripts/sources_gh.sh"))}, "without GH_TOKEN"),
        ("gh argv in Python", {other: workflow(step("py", "python3 -I scripts/argv_gh.py"))}, "without GH_TOKEN"),
        ("stable: gh after the isolation step",
         {STABLE: workflow(ISOLATE + step("api", "gh api repos/x", TOKEN_ENV))}, None),
        ("stable: gh without the isolation step",
         {STABLE: workflow(step("api", "gh api repos/x", TOKEN_ENV))}, "before the step that empties"),
        ("stable: gh before the isolation step",
         {STABLE: workflow(step("api", "gh api repos/x", TOKEN_ENV) + ISOLATE)}, "before the step that empties"),
    ]


def check(load_yaml):
    failures = []
    read_fixture = SCRIPTS.get
    for name, texts, expected in fixture_cases():
        try:
            docs = {path: load_yaml(text) for path, text in texts.items()}
        except policy.PolicyError as error:
            failures.append("fixture %r: %s" % (name, error))
            continue
        problems = policy_problems(docs, read_fixture)
        if expected is None and problems:
            failures.append("fixture %r: unexpected problems %s" % (name, problems))
        elif expected is not None and not any(expected in problem for problem in problems):
            failures.append("fixture %r: expected %r, got %s" % (name, expected, problems))
    docs = policy.repository_docs(ROOT, load_yaml)
    read_repo = repository_reader(ROOT)
    failures += policy_problems(docs, read_repo)
    # The policy has something to protect: the stable workflow calls gh through the
    # attestation binder, and the binder calls gh.
    stable_steps = (docs.get(STABLE, {}).get("jobs", {}).get("build-sign-notarize", {}).get("steps") or [])
    if not any(isinstance(s, dict) and isinstance(s.get("run"), str) and
               step_calls_gh(s["run"], read_repo) for s in stable_steps):
        failures.append("%s: no step calls gh any more; update this check" % STABLE)
    return failures, len(docs)


def main():
    try:
        parsers = policy.loaders()
        results = [(name,) + check(load) for name, load in parsers]
    except policy.PolicyError as error:
        print("workflow gh token policy: " + str(error), file=sys.stderr)
        return 1
    failures = ["%s: %s" % (name, failure) for name, problems, _count in results for failure in problems]
    if failures:
        for failure in failures:
            print("workflow gh token policy: " + failure, file=sys.stderr)
        return 1
    names = ", ".join(name for name, _problems, _count in results)
    print("workflow gh token policy: ok (%d workflows; parsers: %s)" % (results[0][2], names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
