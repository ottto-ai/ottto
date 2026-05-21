# Diagnostics

Diagnostics help support understand local runtime state without exposing raw
local content.

## Local Collection

Collect a redacted diagnostics bundle locally:

```bash
ottto diagnostics collect --json
```

The response includes sectioned runtime, install, account, source, repair,
update, and security facts plus a redaction report.

## Approved Upload

Upload only when the user approves the upload and accepts the retention
disclosure. An active login or support claim is required:

```bash
ottto diagnostics collect --upload \
  --approve-upload \
  --accept-retention-disclosure \
  --support-claim <claim> \
  --json
```

If the user is already logged in, a support claim may not be needed. Follow the
JSON `upload_report` and next-action fields.

## What To Share

Share:

- command family;
- exit code;
- high-level status;
- support bundle id or uploaded state;
- next user action.

Do not share raw local paths, prompts, account ids, machine ids, credential
material, cookies, or command output.

## Common Diagnostics Flow

```bash
ottto status --json
ottto doctor --json
ottto diagnostics collect --json
```

If support requests an upload, rerun with the upload flags after the user has
approved the disclosure.
