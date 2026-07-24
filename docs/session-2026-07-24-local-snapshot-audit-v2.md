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
- the exact content-free `upload_policy` booleans applied before output;
- `revision_key`, an HMAC-blinded identity for the local input revision,
  parser version, and scan-identity version;
- `policy_neutral_component_keys` for `usage_accounting`,
  `lifecycle_activity`, `latency`, and source-supported `context_posture`;
- `policy_sensitive_component_keys` for `display_identity`, `attribution`, and
  `artifacts`.

Every key uses the private audit key, length-prefixed HMAC-SHA256 input, the v2
schema domain, and a purpose-specific domain. Component keys additionally bind
the semantic contract version and component name. The report never emits the
underlying SHA-256 component hash or revision material.

`fixtures/snapshot-audit/v2-golden-keys.json` is the cross-language oracle for
private verifier implementations. Its synthetic audit key is defined without a
credential fixture as the first 32 bytes of `pi-session.jsonl`. The revision
vector replaces the scanner's metadata-sensitive source fingerprint with the
literal synthetic value `sha256:fixture-input`.

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

## Compatibility and rollout

The schema version changes intentionally. Private verifiers must explicitly
support v2 before a runtime containing this contract is used for guarded proof.
Audit state remains isolated under the existing marked `0700` directory with
`0600` files. V2 uses `local_snapshot_audit_state:v2` and rejects a v1 state
directory so a prior scan index cannot silently suppress the first v2 report;
use a fresh audit state directory for a complete proof scan.
