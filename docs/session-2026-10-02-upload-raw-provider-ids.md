# Session 2026-10-02: upload raw provider account and organization ids

## Decision

Raw provider account ids and the selected organization/workspace ids are
identifiers, not passwords or access tokens. Agent status uploads now keep
them on the account block and on every plan observation, next to the existing
domain-separated hashes. Before this change `redacted_for_backend` and
`redact_plan_observation_for_backend` set both fields to null, so the backend
only ever saw the hashes and could not tell which identity role a 64-hex hash
came from.

## What changed

- `ottto-protocol`: both redaction functions pass `account_id` and
  `organization_id` through `safe_provider_identifier`. It trims the value and
  keeps it only when it is 1 to 128 ASCII letters, digits or `-` and also passes
  the shared backend-text guard. 128 matches the backend account schema, which
  rejects the whole snapshot above that length. Anything else is dropped, never
  rewritten.
- Still redacted, unchanged: account email, account labels, organization
  labels, credit-balance account labels, credentials, tokens, paths and
  diagnostics text.
- Tests: the privacy test now asserts that raw ids survive while email and
  labels do not, and a new test proves that email-shaped, path-shaped,
  URL-shaped, secret-shaped, whitespace, `|`-containing and over-long ids are
  dropped. The multi-slot Claude test now allows the raw ids only inside their
  own `account_id` / `organization_id` fields.
- Docs: `docs/privacy.md`, `README.md`, and the Claude Code and Codex source
  policies describe the new boundary.

## Roles on the wire

| Provider | `account_id` | `organization_id` | Hash kinds |
| --- | --- | --- | --- |
| Claude (`anthropic`) | provider account UUID (`oauthAccount.accountUuid`, Desktop account bucket, `claude auth status` account id) | selected organization UUID (current organization, or the only one for that account; omitted when ambiguous) | `account`, `organization` |
| Codex (`openai`) | ChatGPT user id (`chatgpt_user_id`, falling back to the ID token `sub`) | selected ChatGPT workspace id (`chatgpt_account_id`) | `account`, `workspace` |

Caveats checked while reading the producers:

- The Codex user id falls back to the OIDC `sub` claim when `chatgpt_user_id`
  is missing. `sub` values such as `google-oauth2|...` contain `|` and are
  dropped by the new check, so that rare case uploads only hashes, as before.
- The retired Codex default-organization id (`organizations[].id`) is used only
  for `superseded_organization_identifier_hash`; it never fills
  `organization_id`.
- Raw ids and hashes can come from different reads (for example the stored ID
  token versus the refreshed access token). A consumer that recomputes the hash
  from the raw id must compare it with the uploaded hash and ignore the pair on
  mismatch.

## Checks

- `cargo fmt --all --check`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test -p ottto-protocol` (65 passed)
- `cargo test -p ottto-service --lib -- agent_status:: snapshot_sync:: control::`
  (637 passed) and `-- snapshots::` (446 passed)
- `cargo test --manifest-path crates/Cargo.toml -p ottto-connector-testkit --test first_party_sources`
- `bash scripts/public_repo_export_check.sh`
