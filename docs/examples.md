# Examples

These examples are safe for agents and support because they consume only JSON
output.

## First Status Check

```bash
ottto status --json
ottto account --json
ottto apps --json
```

Report daemon reachability, account state, app readiness, exit code, and next
action.

## Headless Setup

```bash
ottto setup --json --no-browser --no-wait
```

If the command exits `60`, show the returned `claim_url` or `claim_code` to the
user. Do not treat the nonzero exit as a corrupt response.

## Verify Claude Code

```bash
ottto apps status --app claude-code --json
ottto verify --app claude-code --json
ottto verify --repair --app claude-code --json
```

Plain verify is read-only and reports `config.fingerprint` plus any config
drift. Use `--repair` only when the JSON reports config drift; it repairs the
daemon-owned WriteConfig action and re-checks config before telemetry smoke.

## Repair Codex

```bash
ottto doctor --json
ottto verify --repair --app codex --json
ottto fix --app codex --json
ottto verify --app codex --json
```

Apply repair only through `ottto fix`. Do not patch `~/.codex/config.toml`
directly.

## Collect Local Diagnostics

```bash
ottto diagnostics collect --json
```

Summarize the redaction report and any recommended next action.

## Approved Diagnostics Upload

```bash
ottto diagnostics collect --upload \
  --approve-upload \
  --accept-retention-disclosure \
  --support-claim <claim> \
  --json
```

Use this only after the user approves upload and retention disclosure.

## Update Check

```bash
ottto update check --json
```

Report whether the update is a soft warning, hard block, current, or pending
manual action from the install owner.
