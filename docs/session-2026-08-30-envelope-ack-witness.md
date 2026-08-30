# Semantic-envelope body-witness ACK compatibility

## Problem

Ottto 0.1.119 serializes every local session snapshot with a
`semantic_envelope`, but its resumable uploader still identified additive body
witnesses with the pre-envelope versions (`v3`-`v6`). The backend correctly
settled those same wire bodies in the envelope domain (`v9`-`v12`) and returned
that exact proof in the entity ACK. The daemon rejected the otherwise valid
HTTP 200 response because the witness version did not match, so its historical
census cursor could not advance even though the backend accepted the page.

This was visible as all of the following at once:

- backend snapshot-batch flow outcome `success` with 50 accepted items;
- local upload progress retaining zero accepted body witnesses;
- daemon status reporting an unclassified local snapshot upload failure; and
- older lineage targets remaining behind the first historical census page.

## Fix

The uploader now derives its body-witness version from the wire domain it
actually sends:

- tool-only evidence: `v9` / exclusive `v10`;
- context-curve evidence: `v11` / exclusive `v12`.

The digest projection stays unchanged; only the domain version advances. ACK
shape validation accepts both legacy `v3`-`v6` and envelope `v9`-`v12` proofs,
while context-curve settlement still requires the exact expected version and
digest. Reserved non-proof versions `v7` and `v8` remain invalid in this ACK
contract.

## Verification

- `cargo test -p ottto-service --lib context_curve_`
- `cargo test -p ottto-service --lib entity_ack`
- context-curve cross-language manifest regenerated and verified with envelope
  witness versions.

Live rollout is complete only after a stable daemon containing this change
advances the historical census and the target parent-child families render in
Sessions and Agent Families.
