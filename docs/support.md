# Ottto Local Platform Support Runbook

Use this runbook for public-v1 support of the Ottto CLI, `ottto-service`,
install owners, setup, app verification, repair, diagnostics, update, uninstall,
connector manifests, and thin agent adapters.

This runbook is public-safe. Do not add private infrastructure details, account
identifiers, machine identifiers, raw command output, screenshots with local
paths, credentials, tokens, cookies, claim codes, setup-run tokens, setup keys,
raw prompts, raw model output, or private repository links.

## Triage

1. Identify the installed surface without parsing human text:

   ```bash
   ottto status --json
   ottto update check --json
   ```

2. Confirm setup and account state through browser-claim ownership:

   ```bash
   ottto setup --json --no-browser --no-wait
   ottto account --json
   ```

   Share the claim URL or code with the user when JSON returns
   `needs_user_action`. The CLI must not collect an Ottto password in the
   terminal.

3. Check app/source status with public app nouns:

   ```bash
   ottto apps detect --json
   ottto apps status --app codex --json
   ottto verify --app codex --json
   ```

4. Use `doctor` before repair, and respect repair authority metadata:

   ```bash
   ottto doctor --json
   ottto fix --app codex --json
   ```

   If JSON requires browser approval, do not edit local config directly. If a
   setup-safe action allows terminal approval, confirm that it is tied to an
   active setup-run binding before the user proceeds.

## Diagnostics

Collect local diagnostics first:

```bash
ottto diagnostics collect --json
```

Share only the command family, exit code, high-level status, support bundle
state, redaction summary, and next user action. Do not paste raw diagnostics
JSON into public issues or chat.

Upload diagnostics only after explicit user approval and retention disclosure
acceptance:

```bash
ottto diagnostics collect --upload \
  --approve-upload \
  --accept-retention-disclosure \
  --support-claim <claim> \
  --json
```

Support claims come from the product support channel. Do not ask users to paste
claims into public issues.

## Update And Rollback

Use the detected install owner from JSON status and the release manifest:

- Homebrew: `brew update && brew upgrade ottto`
- Hosted native installer: download and verify the signed native artifact
  advertised by the stable manifest.
- App bundle: update through the signed app path.

Do not self-overwrite owner-managed files. For rollback, follow the release
manifest rollback notes and verify checksums, signing/notarization state,
Gatekeeper assessment, and `ottto status --json` after the install owner
returns to the previous version.

## Escalation

- Security-sensitive reports go to `security@ottto.net`, not public issues.
- Account, billing, private organization, production backend, or support-claim
  problems go through the product support channel.
- Public issues are appropriate only for redacted, reproducible CLI,
  `ottto-service`, installer, public docs, connector SDK/testkit, source
  manifest, schema, or thin agent-adapter bugs.

## Do Not Collect

- Passwords, cookies, API keys, bearer tokens, setup-run tokens, setup keys,
  claim codes, support claims, or raw credentials.
- Raw prompts, raw model output, transcripts, customer data, local database
  files, private repository files, or provider account material.
- Absolute local filesystem paths, account identifiers, machine identifiers, or
  screenshots that reveal local paths or secrets.

## Public V1 Closeout

Before public-v1 closeout support is marked ready, verify that:

- public docs cover install, setup, privacy, diagnostics, troubleshooting,
  agent adapters, connector contribution, release verification, examples, and
  this support runbook;
- `SUPPORT.md` routes users to redacted public issues, product support,
  diagnostics, and security reporting;
- public release-candidate, stable clean-machine, production `/apps`, public
  cutover, private runtime pin, docs, source-card, and board handoff evidence
  gates are green;
- evidence records contain only redacted pass/fail facts and stable artifact
  references, not raw local output or identifiers.
