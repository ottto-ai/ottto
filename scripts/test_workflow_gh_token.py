#!/usr/bin/env python3
"""Stable release gh policy: every gh call in the release job goes through the job-token shim.

The guarantee is at run time: scripts/macos_release_gh_isolation.sh, run as an unconditional
step right after checkout, puts a gh shim first on PATH that refuses to run unless GH_TOKEN
is non-empty and forces GH_HOST=github.com and an empty GH_CONFIG_DIR, whatever form the
call takes (tested by scripts/test_macos_release_gh_isolation.sh). This check keeps
.github/workflows/macos-stable-release.yml wired to it; other workflows are out of scope:

- The isolation step is named ISOLATION, has only `name` and `run` (no `if`, `env`,
  `shell`, `continue-on-error`), runs exactly the helper, and only the runner path check
  and checkout come before it.
- From the first step through the last gh step, no step and no job or workflow env sets
  GH_CONFIG_DIR, GH_HOST, PATH or GITHUB_PATH; no step run script, and no script a step
  reaches, names GITHUB_PATH, GH_CONFIG_DIR or GH_HOST; and no script a gh step reaches
  changes PATH.
- Each GH_STEPS step, and any other step found to call gh, sets GH_TOKEN to exactly
  ${{ github.token }} in its own env; no job or workflow env sets GH_TOKEN; and neither the
  step nor a script it reaches clears GH_TOKEN (env -u, unset, an empty assignment).
- No step and no script the workflow reaches runs gh by a path: that skips the shim.
- Each GH_STEPS step is still found to call gh, and dropping or emptying its token in
  memory is caught (mutation self-test on the real workflow).

Finding a gh call is a heuristic over the supported forms: gh (bare or quoted) at a shell
command position, also after exec/command/env/xargs or assignments; a shell variable or
array assigned gh; and a Python or Ruby process call (run, system, popen, spawn, exec,
capture...) or argv assignment whose first word is gh. Comments are skipped and line
continuations joined. Scripts are followed recursively through scripts/<name>,
$SCRIPT_DIR/<name> and $HERE/<name> references (not inside prose strings, which hold a space)
and Python imports of scripts/ modules. The runtime shim, not this heuristic, is what stops
a call without the token.

The real workflow is parsed with each YAML parser present (see test_workflow_runner_policy);
synthetic fixtures prove each rule fails closed and display-only text passes.
"""

import copy
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import test_workflow_runner_policy as policy  # noqa: E402

ROOT = policy.ROOT
STABLE = policy.STABLE
JOB = "build-sign-notarize"
ISOLATION = "Isolate gh from runner logins"
HELPER_NAME = "macos_release_gh_isolation.sh"
HELPER = "scripts/" + HELPER_NAME
PATH_CHECK = "Check neutral runner paths"
GH_STEPS = (
    "Verify release source",
    "Bind verified attestation metadata",
    "Verify final attestations and manifest binding",
    "Mirror stable build to GitHub Release (verification only)",
)
PROTECTED = ("GH_CONFIG_DIR", "GH_HOST", "PATH", "GITHUB_PATH")
TOKEN = re.compile(r"^\$\{\{\s*github\.token\s*\}\}$")

# gh at a shell command position: a line start or a separator, then keywords and
# prefixes (exec, command, env with its options, xargs...) and assignments.
SHELL_CALL = re.compile(
    r"(?:^|[;&|({!`]|\$\()\s*"
    r"(?:(?:then|do|else|elif|if|while|until|time|exec|command|builtin|nohup|xargs|sudo|eval|!)\s+)*"
    r"(?:env(?:\s+-[-\w]+(?:[ =]\w+)?)*\s+)?"
    r"(?:[A-Za-z_]\w*=\S*\s+)*"
    r"(?:\"gh\"|'gh'|gh)(?=$|[\s;|&)`\\])", re.M)
# A shell variable or array holding gh: cli=gh, local cli="gh", cmd=(gh api ...).
GH_VARIABLE = re.compile(r"(?<![\w$])[A-Za-z_]\w*\s*=\s*\(?\s*(?:\"gh\"|'gh'|gh)(?=$|[\s;)])", re.M)
# A Python or Ruby process call whose argv or command string starts with gh.
PROCESS_CALL = re.compile(
    r"\b(?:run|call|check_call|check_output|Popen|popen\w*|system|spawn\w*|exec\w*|capture\w*|"
    r"getoutput|getstatusoutput)(?:\s*\(\s*|\s+)(?:[\[(]\s*)?[\"']gh(?:[\"']|\s)")
# An argv list or tuple assigned with gh first: cmd = ["gh", ...].
ARGV_ASSIGN = re.compile(r"=\s*[\[(]\s*[\"']gh[\"']\s*,")
GH_CALLS = (SHELL_CALL, GH_VARIABLE, PROCESS_CALL, ARGV_ASSIGN)

# gh by a path (absolute, ~, ./ or from a variable): it skips the shim on PATH.
PATH_GH = re.compile(
    r"(?<![\w.:/-])(?:~|\.{1,2}|\$\{?\w+\}?|\$\([^()\n]*\))?(?:/[\w.@+-]+)*/gh(?=$|[\s\"'`;|&),\]\\])", re.M)
CLEARS_TOKEN = re.compile(
    r"\benv\b[^\n;|&]*?\s(?:-u\s*|--unset[= ]?)GH_TOKEN\b"
    r"|\benv\s+(?:-[-\w]+\s+)*-(?:i|-ignore-environment)\b"
    r"|\bunset\s+(?:-v\s+)?(?:\w+\s+)*GH_TOKEN\b"
    r"|(?<![\w$])(?:export\s+)?GH_TOKEN=(?=$|[\s;)&|]|\"\"|'')"
    r"|\bos\.(?:environ\.pop|unsetenv)\s*\(\s*[\"']GH_TOKEN[\"']"
    r"|\bdel\s+os\.environ\s*\[\s*[\"']GH_TOKEN[\"']"
    r"|\bENV\.delete\s*\(\s*[\"']GH_TOKEN[\"']"
    r"|[\"']GH_TOKEN[\"']\s*(?:\]\s*=|:)\s*(?:None|nil|\"\"|'')", re.M)
# A change to what the isolation set: in a step's own script, or a script a gh step runs.
OVERRIDE = re.compile(
    r"\bGITHUB_PATH\b"
    r"|(?<![\w$])(?:GH_CONFIG_DIR|GH_HOST|PATH)\+?="
    r"|\b(?:unset|-u)\s+(?:-v\s+)?(?:GH_CONFIG_DIR|GH_HOST|PATH)\b"
    r"|[\"'](?:GH_CONFIG_DIR|GH_HOST|PATH)[\"']\s*(?:\]\s*=(?!=)|:)", re.M)
# Any script a step before the last gh step runs has no business with these names.
SCRIPT_OVERRIDE = re.compile(r"\b(?:GITHUB_PATH|GH_CONFIG_DIR|GH_HOST)\b")

SCRIPT_REF = re.compile(
    r"(?:(?<![\w.-])scripts/|\$\{?(?:SCRIPT_DIR|HERE)\}?/)((?:[\w-]+/)*[\w.-]+\.(?:sh|bash|py|rb))(?![\w.-])")
IMPORT = re.compile(r"^\s*(?:from\s+(\w+)\s+import\b|import\s+(\w+)\s*$)", re.M)
QUOTED = re.compile(r"\"(?:[^\"\\\n]|\\.)*\"|'[^'\n]*'")


def strip_comment(line):
    """The line without a # comment: a # at a word start, outside quotes."""
    quote = None
    for index, char in enumerate(line):
        if quote:
            if char == quote and (quote != '"' or line[index - 1] != "\\"):
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "#" and (index == 0 or line[index - 1].isspace() or line[index - 1] in ";|&("):
            return line[:index]
    return line


def code_of(text):
    """Comment-free text with line continuations joined."""
    return re.sub(r"\\\n", " ", "\n".join(strip_comment(line) for line in text.splitlines()))


def calls_gh(code):
    return any(pattern.search(code) for pattern in GH_CALLS)


def refs(code):
    """scripts/ file names the code names, outside prose strings, and modules it imports."""
    text = QUOTED.sub(lambda match: '""' if re.search(r"\s", match.group(0)) else match.group(0), code)
    names = set(SCRIPT_REF.findall(text))
    names.update((first or second) + ".py" for first, second in IMPORT.findall(code))
    return names


class Scripts:
    def __init__(self, read_script):
        self.read_script = read_script
        self.codes = {}

    def code(self, name):
        if name not in self.codes:
            text = self.read_script(name)
            self.codes[name] = None if text is None else code_of(text)
        return self.codes[name]

    def reachable(self, code):
        """{name: code} for each scripts/ file the code reaches, recursively; not the helper,
        whose own test checks its contract."""
        found = {}
        pending = sorted(refs(code))
        while pending:
            name = pending.pop()
            if name in found or name == HELPER_NAME:
                continue
            script = self.code(name)
            if script is None:
                continue
            found[name] = script
            pending.extend(sorted(refs(script)))
        return found


def env_of(value):
    return value if isinstance(value, dict) else {}


def step_code(step):
    return "\n".join(code_of(step[key]) for key in ("run", "shell") if isinstance(step.get(key), str))


def is_checkout(step):
    return isinstance(step.get("uses"), str) and step["uses"].startswith("actions/checkout@")


def policy_problems(doc, read_script, gh_steps=GH_STEPS):
    if not isinstance(doc, dict):
        return ["the workflow is not a mapping"]
    jobs = doc.get("jobs")
    job = jobs.get(JOB) if isinstance(jobs, dict) else None
    if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
        return ["no %s job with steps" % JOB]
    if len(jobs) != 1:
        return ["the workflow has jobs other than %s; extend this check to them" % JOB]
    steps = [step if isinstance(step, dict) else {} for step in job["steps"]]
    problems = []
    for scope, env in (("workflow", doc.get("env")), ("job", job.get("env"))):
        for key in sorted(env_of(env)):
            if key == "GH_TOKEN":
                problems.append("%s env sets GH_TOKEN: set it only on the steps that call gh" % scope)
            elif key in PROTECTED:
                problems.append("%s env sets %s, which the gh isolation owns" % (scope, key))

    scripts = Scripts(read_script)
    labels, codes, reached, gh_indexes = [], [], [], []
    for index, step in enumerate(steps):
        labels.append("step %d (%s)" % (index + 1, step.get("name", "unnamed")))
        codes.append(step_code(step))
        reached.append(scripts.reachable(codes[-1]))
        if calls_gh(codes[-1]) or any(calls_gh(code) for code in reached[-1].values()):
            gh_indexes.append(index)
    names = [step.get("name") for step in steps]

    # The isolation step: one, plain, exactly the helper, after only the path check and checkout.
    isolation = [index for index, name in enumerate(names) if name == ISOLATION]
    if len(isolation) != 1:
        problems.append("the job needs exactly one %r step" % ISOLATION)
    else:
        index = isolation[0]
        extra = sorted(set(steps[index]) - {"name", "run"})
        if extra:
            problems.append("%s must be unconditional and plain; remove: %s" % (labels[index], ", ".join(extra)))
        run = steps[index].get("run")
        if not isinstance(run, str) or run.strip() != HELPER:
            problems.append("%s must run exactly %s" % (labels[index], HELPER))
        for earlier in range(index):
            plain_check = names[earlier] == PATH_CHECK and "uses" not in steps[earlier] and \
                not reached[earlier] and earlier not in gh_indexes
            if not (plain_check or is_checkout(steps[earlier])):
                problems.append("%s runs before %s: only the runner path check and checkout may"
                                % (labels[earlier], ISOLATION))

    # gh steps: the job token on the step itself, never cleared.
    for name in gh_steps:
        if name not in names:
            problems.append("the %r step is missing; update GH_STEPS" % name)
    for index, step in enumerate(steps):
        named = names[index] in gh_steps
        if named and index not in gh_indexes:
            problems.append("%s no longer calls gh as far as this check can see; update GH_STEPS or the detection"
                            % labels[index])
        if not (named or index in gh_indexes):
            continue
        token = env_of(step.get("env")).get("GH_TOKEN")
        if not (isinstance(token, str) and TOKEN.match(token.strip())):
            problems.append("%s calls gh but does not set GH_TOKEN: ${{ github.token }} in its own env" % labels[index])
        clearing = (["its run script"] if CLEARS_TOKEN.search(codes[index]) else []) + \
            ["scripts/" + name for name, code in sorted(reached[index].items()) if CLEARS_TOKEN.search(code)]
        if clearing:
            problems.append("%s clears GH_TOKEN before gh runs (%s)" % (labels[index], ", ".join(clearing)))

    # Nothing before or at the last gh step changes what the isolation set.
    last = max([index for index, name in enumerate(names) if name in gh_steps] + gh_indexes + [-1])
    for index in range(last + 1):
        if isolation and index == isolation[0]:
            continue
        for key in sorted(set(env_of(steps[index].get("env"))) & set(PROTECTED)):
            problems.append("%s sets %s, which the gh isolation owns" % (labels[index], key))
        if OVERRIDE.search(codes[index]):
            problems.append("%s changes PATH, GITHUB_PATH, GH_CONFIG_DIR or GH_HOST" % labels[index])
        for name, code in sorted(reached[index].items()):
            if SCRIPT_OVERRIDE.search(code) or (index in gh_indexes and OVERRIDE.search(code)):
                problems.append("%s changes PATH, GITHUB_PATH, GH_CONFIG_DIR or GH_HOST through scripts/%s"
                                % (labels[index], name))

    # gh by a path skips the shim, in any step.
    for index in range(len(steps)):
        where = (["its run script"] if PATH_GH.search(codes[index]) else []) + \
            ["scripts/" + name for name, code in sorted(reached[index].items()) if PATH_GH.search(code)]
        if where:
            problems.append("%s runs gh by a path, which skips the isolation shim (%s)"
                            % (labels[index], ", ".join(where)))
    return problems


def repository_reader(root):
    folder = os.path.realpath(os.path.join(root, "scripts"))

    def read(name):
        path = os.path.realpath(os.path.join(folder, name))
        if not path.startswith(folder + os.sep) or not os.path.isfile(path):
            return None
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read()
    return read


# Fixtures: the job is built as data, so each case states one shape.
CALL = "Call gh"
TOKEN_ENV = {"GH_TOKEN": "${{ github.token }}"}


def gh_step(run, env=None, name=CALL):
    step = {"name": name, "env": dict(TOKEN_ENV if env is None else env), "run": run}
    if not step["env"]:
        del step["env"]
    return step


def other(run, name="Other"):
    return {"name": name, "run": run}


def isolation_step(**extra):
    step = {"name": ISOLATION, "run": HELPER}
    step.update(extra)
    return step


def fixture(*steps, isolation=None, job_env=None, workflow_env=None):
    head = [{"name": PATH_CHECK, "run": "echo ok"}, {"name": "Checkout", "uses": "actions/checkout@" + "0" * 40}]
    if isolation is not False:
        head.append(isolation or isolation_step())
    job = {"runs-on": "ubuntu-24.04", "steps": head + list(steps)}
    if job_env:
        job["env"] = job_env
    doc = {"on": "workflow_dispatch", "jobs": {JOB: job}}
    if workflow_env:
        doc["env"] = workflow_env
    return doc


SCRIPTS = {
    "calls_gh.sh": "#!/usr/bin/env bash\nset -euo pipefail\nif ! gh attestation verify \"$1\"; then exit 1; fi\n",
    "wrapper.sh": "#!/usr/bin/env bash\nSCRIPT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
                  "\"$SCRIPT_DIR/calls_gh.sh\" \"$@\"\n",
    "root_source.sh": "#!/usr/bin/env bash\nROOT=\"$(cd \"$(dirname \"$0\")/..\" && pwd)\"\n"
                      "source \"$ROOT/scripts/calls_gh.sh\"\n",
    "runs_ruby.sh": "#!/usr/bin/env bash\nruby \"$SCRIPT_DIR/command_string.rb\"\n",
    "argv_multiline.py": "import subprocess\nsubprocess.run(\n    [\n        \"gh\",\n        \"api\",\n"
                         "        \"repos/x\",\n    ],\n    check=True,\n)\n",
    "command_string.py": "import os\nos.system(\"gh api repos/x\")\n",
    "command_string.rb": "system(\"gh api repos/x\")\n",
    "backticks.rb": "out = `gh api repos/x`\nputs out\n",
    "imports_gh.py": "from gh_module import call\ncall()\n",
    "gh_module.py": "import subprocess\n\ndef call():\n    cmd = [\"gh\", \"api\", \"repos/x\"]\n"
                    "    subprocess.run(cmd, check=True)\n",
    "prints_argv.py": "print([\"gh\", \"api\", \"repos/x\"])\nprint(\"gh api repos/x\")\n",
    "prints_gh.sh": "#!/usr/bin/env bash\n# gh attestation verify is printed for humans only\n"
                    "echo \"To verify, run gh attestation verify ./example\"\ncmd=\"gh attestation verify ./x\"\n"
                    "echo \"$cmd\"\n",
    "unsets_token.sh": "#!/usr/bin/env bash\nunset GH_TOKEN\ngh api repos/x\n",
    "empties_token.py": "import os, subprocess\nos.environ.pop(\"GH_TOKEN\")\nsubprocess.run([\"gh\", \"api\"])\n",
    "path_gh.sh": "#!/usr/bin/env bash\n\"$HOMEBREW_PREFIX/bin/gh\" api repos/x\n",
    "path_gh.py": "import subprocess\nsubprocess.run([\"/opt/homebrew/bin/gh\", \"api\"], check=True)\n",
    "writes_path.sh": "#!/usr/bin/env bash\necho \"/tmp/other-bin\" >> \"$GITHUB_PATH\"\n",
    "account_config.sh": "#!/usr/bin/env bash\nprintf 'GH_CONFIG_DIR=%s\\n' \"$HOME/.config\" >> \"$GITHUB_ENV\"\n",
    "sets_path.sh": "#!/usr/bin/env bash\nexport PATH=\"/usr/local/bin:$PATH\"\ngh api repos/x\n",
}


def fixture_cases():
    """(name, workflow doc, expected problem fragment or None for clean)."""
    call = gh_step("gh api repos/x")
    missing = "(Other) calls gh but does not set GH_TOKEN"
    return [
        ("clean", fixture(call), None),
        # The isolation step.
        ("no isolation step", fixture(call, isolation=False), "exactly one"),
        ("skipped isolation step", fixture(call, isolation=isolation_step(**{"if": False})), "unconditional"),
        ("isolation that may fail", fixture(call, isolation=isolation_step(**{"continue-on-error": True})),
         "unconditional"),
        ("isolation in a comment only", fixture(call, isolation=isolation_step(run="# " + HELPER + "\necho ok")),
         "must run exactly"),
        ("isolation then the account config",
         fixture(call, isolation=isolation_step(run=HELPER + "\necho \"GH_CONFIG_DIR=$HOME/.config\" >> \"$GITHUB_ENV\"")),
         "must run exactly"),
        ("gh before the isolation step",
         {"on": "workflow_dispatch", "jobs": {JOB: {"steps": [call, isolation_step()]}}},
         "(Call gh) runs before"),
        ("a script before the isolation step",
         {"on": "workflow_dispatch", "jobs": {JOB: {"steps": [other("scripts/prints_gh.sh", "Early"),
                                                              isolation_step(), call]}}},
         "(Early) runs before"),
        ("PATH in a later step's env", fixture({"name": "Build", "env": {"PATH": "/usr/bin"}, "run": "make"}, call),
         "sets PATH"),
        ("GH_HOST in a later step's env", fixture({"name": "Build", "env": {"GH_HOST": "ghe.example"}, "run": "make"},
                                                  call), "sets GH_HOST"),
        ("GITHUB_PATH write", fixture(other("echo /tmp/bin >> \"$GITHUB_PATH\""), call), "changes PATH"),
        ("GH_CONFIG_DIR export", fixture(other("export GH_CONFIG_DIR=\"$HOME/.config\"\nmake"), call),
         "changes PATH"),
        ("GITHUB_PATH write in a script", fixture(other("scripts/writes_path.sh"), call), "through scripts/writes_path.sh"),
        ("account config through GITHUB_ENV in a script", fixture(other("scripts/account_config.sh"), call),
         "through scripts/account_config.sh"),
        ("PATH change in a script a gh step runs", fixture(gh_step("scripts/sets_path.sh")),
         "through scripts/sets_path.sh"),
        ("job env GH_CONFIG_DIR", fixture(call, job_env={"GH_CONFIG_DIR": "/tmp/x"}), "job env sets GH_CONFIG_DIR"),
        ("PATH after the last gh step", fixture(call, {"name": "Late", "env": {"PATH": "/usr/bin"}, "run": "make"}),
         None),
        # The token.
        ("named gh step without a token", fixture(gh_step("gh api repos/x", env={})),
         "(Call gh) calls gh but does not set GH_TOKEN"),
        ("literal token", fixture(gh_step("gh api repos/x", env={"GH_TOKEN": "fixture"})),
         "(Call gh) calls gh but does not set GH_TOKEN"),
        ("token from a secret", fixture(gh_step("gh api repos/x", env={"GH_TOKEN": "${{ secrets.FIXTURE }}"})),
         "(Call gh) calls gh but does not set GH_TOKEN"),
        ("workflow-level token only", fixture(gh_step("gh api repos/x", env={}), workflow_env=dict(TOKEN_ENV)),
         "workflow env sets GH_TOKEN"),
        ("empty step token over a job token",
         fixture(gh_step("gh api repos/x", env={"GH_TOKEN": ""}), job_env=dict(TOKEN_ENV)),
         "(Call gh) calls gh but does not set GH_TOKEN"),
        ("env -u in the step", fixture(gh_step("env -u GH_TOKEN gh api repos/x")), "clears GH_TOKEN"),
        ("empty assignment in the step", fixture(gh_step("GH_TOKEN= gh api repos/x")), "clears GH_TOKEN"),
        ("unset in a script", fixture(gh_step("scripts/unsets_token.sh")), "before gh runs (scripts/unsets_token.sh)"),
        ("pop in a Python script", fixture(gh_step("python3 scripts/empties_token.py")), "clears GH_TOKEN"),
        ("token through a shell option", fixture(dict(gh_step("gh api repos/x"), shell="env -u GH_TOKEN bash {0}")),
         "clears GH_TOKEN"),
        # Call forms the check must find: a step without a token that uses one is flagged.
        ("variable", fixture(call, other("cli=gh; \"$cli\" api repos/x")), missing),
        ("quoted executable", fixture(call, other("\"gh\" api repos/x")), missing),
        ("line continuation", fixture(call, other("gh \\\n  attestation verify ./x")), missing),
        ("any subcommand", fixture(call, other("gh codespace list")), missing),
        ("after command", fixture(call, other("command gh api repos/x")), missing),
        ("after &&", fixture(call, other("true && gh api repos/x")), missing),
        ("command substitution", fixture(call, other("out=\"$(gh api repos/x)\"")), missing),
        ("multiline Python argv", fixture(call, other("python3 -I scripts/argv_multiline.py")), missing),
        ("Python command string", fixture(call, other("python3 scripts/command_string.py")), missing),
        ("Ruby command string", fixture(call, other("ruby scripts/command_string.rb")), missing),
        ("Ruby backticks", fixture(call, other("ruby scripts/backticks.rb")), missing),
        ("wrapper running a child script", fixture(call, other("scripts/wrapper.sh x")), missing),
        ("$ROOT/scripts source", fixture(call, other("scripts/root_source.sh")), missing),
        ("Ruby script through $SCRIPT_DIR", fixture(call, other("scripts/runs_ruby.sh")), missing),
        ("Python import of a scripts module", fixture(call, other("python3 scripts/imports_gh.py")), missing),
        # Display-only text needs no token.
        ("printed instruction", fixture(call, other("echo \"To verify, run gh attestation verify ./example\"")), None),
        ("inline comment", fixture(call, other("echo ok # gh api repos/x")), None),
        ("commented script reference", fixture(call, other("# scripts/calls_gh.sh\necho ok")), None),
        ("script path in prose", fixture(call, other("echo \"See scripts/calls_gh.sh for the binder.\"")), None),
        ("printed argv", fixture(call, other("python3 scripts/prints_argv.py")), None),
        ("script that prints gh", fixture(call, other("scripts/prints_gh.sh")), None),
        ("URL ending in gh", fixture(call, other("echo https://cli.github.com/manual/gh")), None),
        # gh by a path skips the shim.
        ("absolute path in a step", fixture(call, other("/opt/homebrew/bin/gh api repos/x")), "by a path"),
        ("variable path in a script", fixture(call, other("scripts/path_gh.sh")), "isolation shim (scripts/path_gh.sh)"),
        ("absolute argv in Python", fixture(call, other("python3 scripts/path_gh.py")), "isolation shim (scripts/path_gh.py)"),
        ("named step that stops calling gh", fixture(gh_step("echo none")), "no longer calls gh"),
    ]


def find_step(doc, name):
    return next(step for step in doc["jobs"][JOB]["steps"] if step.get("name") == name)


def mutations():
    """(name, change to the real workflow, expected problem fragment)."""
    cases = []
    for name in GH_STEPS:
        message = "(%s) calls gh but does not set GH_TOKEN" % name
        cases.append(("drop GH_TOKEN from %r" % name,
                      lambda doc, name=name: find_step(doc, name)["env"].pop("GH_TOKEN"), message))
        cases.append(("empty GH_TOKEN on %r" % name,
                      lambda doc, name=name: find_step(doc, name)["env"].update(GH_TOKEN=""), message))
    cases += [
        ("skip the isolation step", lambda doc: find_step(doc, ISOLATION).update({"if": False}), "unconditional"),
        ("remove the isolation step",
         lambda doc: doc["jobs"][JOB]["steps"].remove(find_step(doc, ISOLATION)), "exactly one"),
        ("PATH on the release source step",
         lambda doc: find_step(doc, GH_STEPS[0])["env"].update(PATH="/usr/bin"), "sets PATH"),
    ]
    return cases


def expect(failures, label, problems, expected):
    if expected is None and problems:
        failures.append("%s: unexpected problems %s" % (label, problems))
    elif expected is not None and not any(expected in problem for problem in problems):
        failures.append("%s: expected %r, got %s" % (label, expected, problems))


def check(load_yaml):
    failures = []
    cases = fixture_cases()
    for name, doc, expected in cases:
        expect(failures, "fixture %r" % name, policy_problems(doc, SCRIPTS.get, (CALL,)), expected)
    with open(os.path.join(ROOT, STABLE), encoding="utf-8") as handle:
        doc = load_yaml(handle.read())
    read_repo = repository_reader(ROOT)
    failures += ["%s: %s" % (STABLE, problem) for problem in policy_problems(doc, read_repo)]
    changes = mutations()
    for name, change, expected in changes:
        mutated = copy.deepcopy(doc)
        try:
            change(mutated)
        except (KeyError, StopIteration, AttributeError, TypeError, ValueError):
            failures.append("mutation %r: the workflow no longer has that shape; update this check" % name)
            continue
        expect(failures, "mutation %r" % name, policy_problems(mutated, read_repo), expected)
    return failures, len(cases), len(changes)


def main():
    try:
        parsers = policy.loaders()
        results = [(name,) + check(load) for name, load in parsers]
    except policy.PolicyError as error:
        print("stable release gh policy: " + str(error), file=sys.stderr)
        return 1
    failures = ["%s: %s" % (name, failure) for name, problems, _cases, _changes in results for failure in problems]
    if failures:
        for failure in failures:
            print("stable release gh policy: " + failure, file=sys.stderr)
        return 1
    print("stable release gh policy: ok (%d fixtures, %d mutations; parsers: %s)"
          % (results[0][2], results[0][3], ", ".join(name for name, _p, _c, _m in results)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
