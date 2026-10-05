# Account display status carrier

The local collector could acquire account email and workspace labels, but upload
redaction discarded them. The existing agent-status carrier now preserves
already-acquired account email and each plan observation's own account/workspace
display text, unmasked. Missing values remain missing; no root-account fallback,
slot reassignment, collection permission, provider call or historical copy is
introduced.

Only these display fields permit email. The field-specific safety check rejects
path/credential-shaped text, control characters and values beyond the existing
320-character account-email / 255-character label bounds, without rewriting
accepted text. Generic fields, diagnostics and credit-balance labels retain their
existing redaction. Provider ids/hashes and weak member identity rules are
unchanged. The backend continues its existing normalization, explicit-clear,
accepted-fact replay and SOURCE presentation behavior.

The synthetic display-carrier fixture covers distinct root and previous-slot
accounts, a weak-only current observation and a route without display acquisition.
Native serialization tests cover ownership, exact weak text, absence, boundaries,
idempotence, adversarial payloads and generic diagnostic email redaction. The
public privacy contract check now enforces the scoped status display policy.
The existing collector raw-id wire fixture now carries its own safe display
fields; degraded and mismatched-slot tests retain account isolation and diagnostic
redaction under the same contract. Absolute paths after label delimiters are
rejected as well as standalone paths.

A containing release and installed-to-SOURCE acceptance remain required. Verify
fresh accepted status display under the exact account/workspace pair, then its
existing account-card consumer. Receipts should record presence and scoped hashes,
never raw account email. No backend schema, sink, version rotation, backfill or
release operation belongs to this change.
