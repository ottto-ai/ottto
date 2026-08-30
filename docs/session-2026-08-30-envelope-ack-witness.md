# Semantic-envelope body-witness ACK compatibility

## Problem

Ottto 0.1.120 serializes every local session snapshot with a
`semantic_envelope` and identifies additive body witnesses internally with
versions `v9`-`v12`. The backend durably stores that envelope-domain witness,
then intentionally projects it onto the released public ACK vocabulary
`v3`-`v6`. The daemon incorrectly required the internal version in the public
response, so it rejected otherwise valid HTTP 200 responses and could not
advance its historical census cursor.

This was visible as all of the following at once:

- backend snapshot-batch flow outcome `success` with 50 accepted items;
- local upload progress retaining zero accepted body witnesses;
- daemon status reporting an unclassified local snapshot upload failure; and
- older lineage targets remaining behind the first historical census page.

## Fix

The uploader continues deriving its body-witness version from the envelope
domain it sends:

- tool-only evidence: `v9` / exclusive `v10`;
- context-curve evidence: `v11` / exclusive `v12`.

For ACK validation, the daemon now maps envelope `v9`-`v12` to the public
proof versions `v3`-`v6` before requiring an exact version and digest match.
Reserved non-proof versions `v7` and `v8` remain invalid. The Codex historical
replay revision advances to `codex_session_exclusive_usage:v7`, forcing one
fresh census so lineage newly recovered by the current parser is uploaded.

## Verification

- `cargo test -p ottto-service --lib context_curve_`
- `cargo test -p ottto-service --lib entity_ack`
- context-curve cross-language manifest regenerated and verified with envelope
  witness versions.

Live rollout is complete only after a stable daemon containing this change
advances the historical census and the target parent-child families render in
Sessions and Agent Families.
