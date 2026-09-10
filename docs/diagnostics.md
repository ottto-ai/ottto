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

Support claims are authorization material. They are sent only on the upload
request and must not appear in the returned JSON payload or uploaded bundle
content; the JSON report exposes only whether a support claim was provided.
Stable local identifiers, including machine ids, must appear only as redacted
placeholders such as `[machine_id]` in diagnostics output. Account, user,
organization, device, and installation identifiers must follow the same
redacted-placeholder rule.

## What To Share

Share:

- command family;
- exit code;
- high-level status;
- support bundle id or uploaded state;
- next user action.

Do not share raw local paths, prompts, account ids, machine ids, credential
material, cookies, or command output. Also keep raw user, organization, device,
and installation ids out of diagnostics summaries and support handoffs.

## Upload Receipts

An upload receipt is a local, bounded record of one snapshot batch attempt and
the backend acknowledgement, when one was returned. Use receipts to confirm
when a source uploaded, how many entities the backend accepted, and whether the
backend shed, rejected, or partially accepted a batch:

```bash
ottto receipts --limit 20
ottto receipts --json --since 2026-09-10T00:00:00Z --source codex
```

The daemon keeps at most 500 receipts. Source session ids are never stored:
each is replaced with a 12-hex SHA-256 prefix, and snapshot fingerprints are
limited to 12 hex characters. Request bodies, authorization headers, tokens,
and raw backend rejection details are not included. `device_label` and
`account_binding` use only the user-facing label and binding state already
shown by `ottto status`; raw device, account, user, and organization ids are
never stored. If `server_request_id` is present, provide it to support so the
local attempt can be correlated with the server request. Older backends may
omit the optional `X-Request-ID` header, in which case the field is `null`.

```json
{
  "schema": "ottto.upload_receipts.v1",
  "receipts": [
    {
      "uploaded_at": "2026-09-10T02:54:21Z",
      "outcome": "accepted",
      "http_status": 200,
      "server_request_id": "req-server-01HX",
      "retry_after_seconds": null,
      "source": "codex",
      "device_label": "Test Mac",
      "account_binding": "connected",
      "batch_item_count": 1,
      "accepted_count": 1,
      "accepted_entities": [
        {
          "source_session_id_hash": "7d96706e12ab",
          "snapshot_fingerprint_prefix": "abcdef012345",
          "occurrence_count": 1
        }
      ],
      "unchanged_entities": [],
      "conflict_entities": [],
      "rejected_entities": []
    }
  ],
  "ring_capacity": 500,
  "state_path_present": true
}
```

## Common Diagnostics Flow

```bash
ottto status --json
ottto receipts --json --limit 20
ottto doctor --json
ottto diagnostics collect --json
```

If support requests an upload, rerun with the upload flags after the user has
approved the disclosure.
