#!/usr/bin/env python3
"""Workflow runner policy: the release signing runners never serve pull request or merge
queue events.

Every workflow under .github/workflows is parsed as YAML (PyYAML when installed, else Ruby's
standard YAML library) and checked:

- No job in a workflow triggered by pull_request, pull_request_target or merge_group may run
  on the release labels (ottto-signing-mac, ottto-release-bootstrap) or read the stable
  runner variable (vars.OTTTO_MACOS_STABLE_RUNNER_LABELS): not as a literal label, not in a
  list or group/labels form, not as an expression default, not through the job's matrix, and
  not through a local reusable workflow it calls. Labels and expressions are compared
  case-insensitively, as GitHub matches them. Such a job's runs-on and matrix also read no
  repository variable or event payload, whose value could name those labels.
- The stable release workflow's trigger set is exactly workflow_dispatch.

Synthetic workflow fixtures prove each rule fails closed.
"""

import json
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WORKFLOWS = ".github/workflows"
STABLE = WORKFLOWS + "/macos-stable-release.yml"
RELEASE_LABELS = ("ottto-signing-mac", "ottto-release-bootstrap")
RUNNER_VARIABLE = "ottto_macos_stable_runner_labels"
GUARDED_EVENTS = {"pull_request", "pull_request_target", "merge_group"}
# Expression sources whose value a workflow file does not fix.
OPEN_SOURCES = ("vars.", "github.event")


class PolicyError(Exception):
    pass


def load_yaml(text):
    try:
        import yaml
    except ImportError:
        yaml = None
    if yaml is not None:
        return yaml.safe_load(text)
    ruby = shutil.which("ruby")
    if ruby is None:
        raise PolicyError("no YAML parser: install PyYAML or Ruby")
    result = subprocess.run([ruby, "-ryaml", "-rjson", "-e", "print JSON.generate(YAML.safe_load(STDIN.read))"],
                            input=text.encode("utf-8"), capture_output=True, check=False)
    if result.returncode != 0:
        raise PolicyError("YAML parse failed: " + result.stderr.decode("utf-8", "replace").strip())
    return json.loads(result.stdout)


def triggers(doc):
    """The workflow's event names. YAML 1.1 reads a bare `on` key as true."""
    if not isinstance(doc, dict):
        raise PolicyError("workflow is not a mapping")
    keys = [key for key in ("on", True, "true") if key in doc]
    if len(keys) != 1:
        raise PolicyError("workflow needs exactly one `on` key")
    value = doc[keys[0]]
    if isinstance(value, str):
        return {value}
    if isinstance(value, (list, dict)) and value and all(isinstance(item, str) for item in value):
        return set(value)
    raise PolicyError("unreadable `on` value")


def strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)


def job_problems(docs, path, name, job, chain=()):
    """Problems for one job of a guarded workflow (and the jobs of local workflows it calls)."""
    where = " -> ".join(chain + ("%s:%s" % (path, name),))
    if not isinstance(job, dict):
        return ["%s: job is not a mapping" % where]
    problems = []
    for field in ("runs-on", "strategy"):
        for text in strings(job.get(field)):
            lowered = text.lower()
            for label in RELEASE_LABELS:
                if label in lowered:
                    problems.append("%s: %s names the release label %s" % (where, field, label))
            if RUNNER_VARIABLE in lowered:
                problems.append("%s: %s reads the stable runner variable" % (where, field))
            elif "${{" in text and any(source in lowered for source in OPEN_SOURCES):
                problems.append("%s: %s reads a repository variable or event payload" % (where, field))
    uses = job.get("uses")
    if isinstance(uses, str) and uses.startswith("./"):
        target = uses[2:].split("@", 1)[0]
        called = docs.get(target)
        if any(step.split(":", 1)[0] == target for step in chain + ("%s:%s" % (path, name),)):
            problems.append("%s: reusable workflow cycle" % where)
        elif not isinstance(called, dict) or not isinstance(called.get("jobs"), dict):
            problems.append("%s: calls a local workflow this check cannot read: %s" % (where, target))
        else:
            for called_name, called_job in called["jobs"].items():
                problems += job_problems(docs, target, called_name, called_job, chain + ("%s:%s" % (path, name),))
    return problems


def policy_problems(docs):
    """docs: {".github/workflows/<file>": parsed workflow}."""
    problems = []
    for path in sorted(docs):
        doc = docs[path]
        try:
            events = triggers(doc)
        except PolicyError as error:
            problems.append("%s: %s" % (path, error))
            continue
        if path == STABLE and events != {"workflow_dispatch"}:
            problems.append("%s: the stable release workflow must trigger on workflow_dispatch only" % path)
        if not events & GUARDED_EVENTS:
            continue
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            problems.append("%s: no jobs mapping" % path)
            continue
        for name, job in jobs.items():
            problems += job_problems(docs, path, name, job)
    if STABLE not in docs:
        problems.append("%s: the stable release workflow is missing" % STABLE)
    return problems


def repository_docs(root):
    docs = {}
    folder = os.path.join(root, WORKFLOWS)
    for name in sorted(os.listdir(folder)):
        if name.endswith((".yml", ".yaml")):
            with open(os.path.join(folder, name), encoding="utf-8") as handle:
                docs[WORKFLOWS + "/" + name] = load_yaml(handle.read())
    return docs


STABLE_FIXTURE = """
name: stable
on:
  workflow_dispatch:
    inputs:
      version:
        type: string
jobs:
  build:
    runs-on: ${{ fromJSON(vars.OTTTO_MACOS_STABLE_RUNNER_LABELS || '["self-hosted","ottto-signing-mac","ottto-release-bootstrap"]') }}
    steps:
      - run: echo ok
"""


def fixture_cases():
    """(name, {path: yaml text}, expected problem fragment or None for clean)."""
    def pr(on, job):
        return "name: fixture\non: %s\njobs:\n  check:\n%s    steps:\n      - run: echo ok\n" % (on, job)

    other = WORKFLOWS + "/fixture.yml"
    return [
        ("clean", {other: pr("pull_request", "    runs-on: ubuntu-24.04\n")}, None),
        ("dispatch-only workflow may use the labels",
         {other: pr("workflow_dispatch", "    runs-on: [self-hosted, ottto-signing-mac]\n")}, None),
        ("literal label", {other: pr("pull_request", "    runs-on: [self-hosted, ottto-signing-mac]\n")},
         "names the release label ottto-signing-mac"),
        ("string label, list trigger",
         {other: pr("[push, merge_group]", "    runs-on: ottto-release-bootstrap\n")},
         "names the release label ottto-release-bootstrap"),
        ("expression default",
         {other: pr("pull_request_target", "    runs-on: ${{ fromJSON(vars.OTHER || "
                    "'[\"self-hosted\",\"ottto-release-bootstrap\"]') }}\n")},
         "names the release label ottto-release-bootstrap"),
        ("runner variable",
         {other: pr("{merge_group: {}}", "    runs-on: ${{ fromJSON(vars.OTTTO_MACOS_STABLE_RUNNER_LABELS) }}\n")},
         "reads the stable runner variable"),
        ("runner variable, other case",
         {other: pr("pull_request", "    runs-on: ${{ fromJSON(VARS.ottto_macos_stable_runner_labels) }}\n")},
         "reads the stable runner variable"),
        ("group labels, other case",
         {other: pr("pull_request", "    runs-on:\n      group: fixture\n      labels: [OTTTO-Signing-Mac]\n")},
         "names the release label ottto-signing-mac"),
        ("matrix",
         {other: pr("pull_request", "    strategy:\n      matrix:\n        runner: [ubuntu-24.04, ottto-signing-mac]\n"
                                    "    runs-on: ${{ matrix.runner }}\n")},
         "strategy names the release label ottto-signing-mac"),
        ("other repository variable",
         {other: pr("pull_request", "    runs-on: ${{ vars.FIXTURE_RUNNER }}\n")},
         "reads a repository variable or event payload"),
        ("event payload",
         {other: pr("pull_request", "    runs-on: ${{ github.event.pull_request.title }}\n")},
         "reads a repository variable or event payload"),
        ("quoted on key",
         {other: '"on": pull_request\njobs:\n  check:\n    runs-on: [ottto-signing-mac]\n'},
         "names the release label ottto-signing-mac"),
        ("calls the stable workflow",
         {other: "on: pull_request\njobs:\n  call:\n    uses: ./" + STABLE + "\n", STABLE: STABLE_FIXTURE},
         "names the release label"),
        ("calls an unknown local workflow",
         {other: "on: pull_request\njobs:\n  call:\n    uses: ./" + WORKFLOWS + "/absent.yml\n"},
         "cannot read"),
        ("stable workflow with another trigger",
         {STABLE: STABLE_FIXTURE.replace("on:\n", "on:\n  push:\n    tags: ['v*']\n", 1)},
         "workflow_dispatch only"),
        ("stable workflow on pull requests",
         {STABLE: STABLE_FIXTURE.replace("on:\n", "on:\n  pull_request:\n", 1)},
         "workflow_dispatch only"),
    ]


def main():
    failures = []
    for name, texts, expected in fixture_cases():
        docs = {path: load_yaml(text) for path, text in texts.items()}
        docs.setdefault(STABLE, load_yaml(STABLE_FIXTURE))
        problems = policy_problems(docs)
        if expected is None and problems:
            failures.append("fixture %r: unexpected problems %s" % (name, problems))
        elif expected is not None and not any(expected in problem for problem in problems):
            failures.append("fixture %r: expected %r, got %s" % (name, expected, problems))
    docs = repository_docs(ROOT)
    problems = policy_problems(docs)
    failures += problems
    # The policy has something to protect: the stable workflow names the release labels.
    stable_runs_on = " ".join(strings(docs.get(STABLE, {}).get("jobs", {}).get("build-sign-notarize", {})
                                      .get("runs-on"))).lower()
    if not all(label in stable_runs_on for label in RELEASE_LABELS):
        failures.append("%s: the signing job no longer names the release labels; update this check" % STABLE)
    if failures:
        for failure in failures:
            print("workflow runner policy: " + failure, file=sys.stderr)
        return 1
    print("workflow runner policy tests passed (%d workflows)" % len(docs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
