# Claude in-app authorization code

**Date:** 2026-09-09
**Scope:** Public local-control protocol and Claude provider supervisor

The public runtime now keeps the complete `claude auth login --claudeai`
ceremony inside the app. Browser success remains automatic. When the official
CLI emits its explicit `Paste code here if prompted` prompt, authenticated local
status changes from `waiting_for_provider` to `waiting_for_code`. Submission
changes it to `submitting_code`; the provider's exact `Invalid code. Please make
sure the full code was copied.` rejection yields typed `invalid_code` feedback.
The existing terminal `timed_out` outcome is the expired state.

## Protocol

- Command-scoped `protocol_version`: `25`
- Command: `claude_account_submit_auth_code`
- Fields: `schema_version: 1`, opaque exact `operation_id`, and `code`
- Capability: additive `auth_code_entry_supported: true`
- Phases added to `ClaudeBrowserAuthPhaseV1`: `waiting_for_code`,
  `submitting_code`
- Feedback added to `ClaudeBrowserAuthOperationV1`: optional
  `code_error: invalid_code`
- Response: the existing full `ClaudeAccountsStatusV1`; it never contains the
  submitted code or provider output

The command is accepted only from an already-authorized local client and only
while the same active operation is waiting for a code. Empty, multiline,
control-character, surrounding-whitespace, and over-2,048-byte values fail
before the operation changes state. A duplicate while submitting and any stale,
wrong, cancelled, completed, or timed-out operation fail closed.

## Privacy and process safety

The protocol models the value as `SecretString`: debug output is redacted and
the allocation is zeroized on drop. The daemon passes it once through an
in-memory bounded channel and anonymous pipe. The provider supervisor pipes and
drains stdout/stderr, retains only bounded rolling matchers for the exact prompt
and rejection sentence, emits only typed single-byte events, and never logs,
persists, uploads, echoes, or returns raw output. Provider stdin accepts only
the bounded line frame from the daemon.

The sentinels were verified against installed Claude Code 2.1.263. The scanner
ASCII-case-folds the full prompt literal, including its trailing ` >` delimiter,
and the complete `Invalid code. Please make sure the full code was copied.`
sentence. Nearby prose does not produce either typed event.

Existing exact-root descriptor pinning, operation/global/admission locks,
provider lifetime evidence, process-group termination, timeout handling, and
parent-EOF cancellation remain in force. If the daemon exits, anonymous control
and code pipes close; the supervisor terminates its provider child before the
root or ceremony can be released. Current operations never produce or expose a
Terminal fallback.
