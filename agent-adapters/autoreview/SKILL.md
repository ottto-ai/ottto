---
name: autoreview
description: Run a local fresh-context code review before handing off substantive Ottto PR changes, and verify accepted fixes. Does not replace Cargo, native, release or export checks.
---

# AutoReview

The implementing agent runs `scripts/autoreview` after relevant tests and before
PR handoff or merge. This is a local review command, not a background service or
GitHub enforcement. No mandatory model call for cosmetic, prose-only or purely
mechanical changes; record a concrete skip reason when closing them out.

Default to a committed branch diff against `origin/main`. Use one stable
`--change-id pr-123` for the PR, or the feature branch name before a PR exists.
Keep that identity through fixes, rebases and worktree moves. When switching to
a PR number, keep the earlier identity until this change is closed out so its
budget does not reset. Budgets live in the shared Git directory, outside export.

```bash
scripts/autoreview --change-id pr-123
scripts/autoreview --change-id pr-123 --decide
```

Standard review uses medium effort. Strict uses high effort for credentials,
privacy, account attribution, persisted formats, canonical bytes/hashes,
checkpoint/receipt/retry/recovery, lock and side-effect ordering, protocol trust,
and signing/install/update/release or dependency changes. The path classifier is
advisory: choose `--profile strict` for sensitive behavior regardless of filename.
Light review checks concrete documentation/operator contradictions.

Discovery examines the whole selected change for defects. After verifying and
fixing real findings, run affected tests and optionally one focused verification:

```bash
scripts/autoreview --change-id pr-123 --profile focused \
  --accepted-finding 'Describe the verified defect and its fix'
```

Focused review covers accepted fixes and direct regressions. Add `--sensitive-fix`
for credential, attribution, persistence, concurrency or other strict-risk fixes;
this keeps high effort while narrowing scope. Repeat `--accepted-finding` for
multiple fixes. Fix real defects before handoff; reject speculative findings
with a short source-backed reason. A rejected finding is a documented decision,
not a clean reviewer verdict; preserve the finding and reason in the PR report.

The default budget is **one discovery call plus one focused call per change
within 24 hours**, shared across standard/strict discovery and across worktrees.
Adding files, changing modes or rebasing does not reset it. Light has one call.
A materially changed design/risk can justify another deliberate call with
`--allow-budget-exceed --reason 'Explain the new review need'`. Exhaustion never
fulfills a required review or resolves a defect. Do not loop for nicer wording.

Codex is the default engine with explicit model `gpt-6.1-sol`. Prefer an available
opposite-provider reviewer for Codex-authored work, passing its configured exact
model with `--engine claude --model <model-id>`. Same-model fresh context is useful
but is not cross-model review. Explicit user model choices take precedence.
There is no automatic provider fallback, model escalation or panel. If a reviewer
is unavailable, record the limitation and relevant tests; do not claim review
passed. The helper records requested model/effort; resolved identity is reported
as unavailable when the CLI does not expose it.

Local review requires individually selected files, including new files:

```bash
scripts/autoreview --mode local --change-id task-recovery \
  --path crates/ottto-service/src/example.rs --path scripts/new_script.py
```

Do not include unrelated work, private transcripts, provider state, credentials
or local artifacts. Review tools inspect public source/dependency contracts only;
a read-only sandbox does not make private data safe to inspect. New files are
read only when explicitly selected. The helper refuses oversized bundles rather
than silently truncating them.

Optional manual release review compares the previous released source endpoint
to the intended source endpoint in a clean checkout at the intended SHA:

```bash
scripts/autoreview --mode release --base <previous-source-sha> \
  --head <intended-source-sha> --change-id release-1.2 --profile strict
```

This reviews source changes, not signing/notarization or installed behavior.
Existing release checks still apply. No release workflow automation is added.

Exit 0 means clean (or an explicitly labelled decision-only/skip operation);
exit 1 means findings; exit 2 means unavailable, invalid, stale or blocked review.
An incorrect verdict without findings is inconclusive and never cached as clean.
Only a genuine correct verdict with no findings gets an exact-change clean cache.
Cache keys cover content, endpoints, helper/prompt version and reviewer posture.
Do not use helper exit status alone as a successful-review receipt.

Record skips with `--skip-reason 'Concrete reason'`. Closeout reports identify the
review command/scope, model/effort, tests, accepted/declined findings and reasons,
and clean/skipped/unavailable/invalid outcome. Helper changes need an independent
review or the prior trusted helper; the candidate helper alone cannot certify itself.

Run `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_autoreview.py` for helper
regressions. During the first 10–20 substantive changes, use local run records to
assess useful findings, false positives, duration and unavailability; no additional
reporting system or CI model calls are required.

The structured schema/parser and CLI adapters derive from
[openclaw/agent-skills](https://github.com/openclaw/agent-skills), with the
[MIT notice](LICENSE) retained. The helper uses Python's standard library.
