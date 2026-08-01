# Local snapshot audit v2

## Purpose

`ottto-service snapshot-audit` compares a local production scan with accepted
backend state without disclosing transcript paths, provider session ids, raw
snapshot fingerprints, titles, repository labels, or transcript content.

Audit v1 exposed one HMAC-blinded full semantic fingerprint. That fingerprint
includes both usage/lifecycle facts and optional upload-policy surfaces. A
policy-disabled audit therefore could not distinguish a real accounting
mismatch from an expected title, attribution, or artifact difference.

## V2 contract

`local_snapshot_audit:v2` keeps the full `semantic_key` as a diagnostic and adds:

- `component_contract_version`, currently `snapshot_semantic:v1`;
- `revision_contract_version`, currently `snapshot_revision:v1`;
- the exact content-free `upload_policy` booleans applied before output;
- `revision_key`, an HMAC-blinded identity for the local input revision,
  parser version, and scan-identity version;
- `policy_neutral_component_keys` for `usage_accounting`,
  `lifecycle_activity`, `latency`, and source-supported `context_posture`;
- `policy_sensitive_component_keys` for `display_identity`, `attribution`, and
  `artifacts`.
- a deduplicated, HMAC-blinded
  `legacy_policy_candidate_semantic_keys` set capped at 24 candidates, plus an
  explicit `legacy_revision_proof_available:false`.

Every key uses the private audit key, length-prefixed HMAC-SHA256 input, the v2
schema domain, and a purpose-specific domain. Component keys additionally bind
the semantic contract version and component name. The report never emits the
underlying SHA-256 component hash or revision material.

Every genuinely emitted normal snapshot now carries the same bounded
`semantic_envelope`: both contract versions, the five policy booleans, the
source-exact component hash set, the legacy client-authored revision hash, and
an additive server-reproducible `snapshot_revision:v2` witness. The v2 witness
uses RFC 8785 canonical JSON over an explicit field list: source/session,
parser and scan versions, opened/source-file witness, stable lifecycle and
provenance state, upload policy, and every post-policy component hash. It
excludes scan wall-clock, source-wide file count, fingerprints, and the semantic
envelope itself. The backend can therefore bind the envelope to the existing snapshot fingerprint
without reconstructing normalized payload fields. The compact envelope is
hard-capped at 2 KiB; the 60 Pi/Codex/Claude policy golden cases are 896–984
bytes. It contains no audit key, raw content, path, title, or provider session
id. Settled semantic no-ops still emit no snapshot and incur no wire cost.

`fixtures/snapshot-audit/semantic-envelope-golden.json` is the cross-language
fingerprint/revision oracle. It covers all 20 valid policy outcomes for each of
Pi, Codex, and Claude Code, including Unicode identity and null-bearing
component material. `v2-golden-keys.json` remains the HMAC-domain oracle; its
synthetic audit key is the first 32 bytes of `pi-session.jsonl`.

## Acceptance boundary

A guarded verifier may accept a local-to-backend semantic match when:

1. `revision_key` identifies the intended local revision;
2. every policy-neutral component supported by the source matches the backend's
   pre-enrichment component revision under `snapshot_semantic:v1`;
3. policy-sensitive components are compared only when the backend-recorded
   upload policy matches the report's policy.

The full `semantic_key` is not an acceptance gate across different policies.
Model/hour row counts remain diagnostic shape counters, not semantic equality
checks.

For a pre-envelope accepted head, the verifier may compare its blinded stored
fingerprint against the bounded legacy candidate set. That proves one exact
historically valid policy outcome, but revision proof remains unavailable.
The bridge is read-only: it never replays, uploads, repairs, or backfills a
legacy row.

Complete legacy candidates require the exact private session-attribution HMAC
key from the current activity hint. Pass its URL-safe no-pad encoding through a
private file with `--session-attribution-hmac-key-file`; it is used only in
zeroized process memory and never enters the audit report, envelope, state, or
private upload payload. The audit scans artifacts and attribution inputs before
applying its all-disabled output policy, so candidate enumeration covers every
valid historical policy outcome instead of attempting to reconstruct fields
after redaction. `--attribution-home` is optional and defaults to the current
home directory.

## Compatibility and rollout

The schema version changes intentionally. Private verifiers must explicitly
support v2 before a runtime containing this contract is used for guarded proof.
Audit state remains isolated under the existing marked `0700` directory with
`0600` files. The complete-candidate scanner uses
`local_snapshot_audit_state:v3` and rejects earlier state directories so a
prior artifact/attribution-incomplete scan index cannot silently suppress the
first report; use a fresh audit state directory for a complete proof scan.

Deploy backend envelope acceptance before releasing a public runtime containing
this wire field. Envelope persistence is atomic with a genuine accepted
semantic revision. A same-fingerprint request cannot backfill an old row, so
envelope-only traffic remains zero DML and never changes reconciliation or GOLD
routing.
