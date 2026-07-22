# Local semantic sync phase 1

Date: 2026-07-22

## Objective

Stop parser releases and observation-only metadata from turning unchanged local
sessions into historical replay or new snapshot work. Preserve first-install
bootstrap and real session updates.

## Design

- Parser build version remains wire provenance only.
- Historical replay has a separate explicit directive and revision. Default is
  `none`; a new machine still performs its initial bootstrap.
- Incremental scan identity uses transcript size, nanosecond mtime, a frozen
  scan derivation version, and a per-session title/state digest.
- Pre-cutover scan-index entries migrate without opening the transcript only
  when unchanged transcript stats and the reconstructed legacy source-wide
  sidecar identity prove nothing was missed. Unknown or changed legacy identity,
  entries that never produced a snapshot, and changed transcripts are parsed.
- Snapshot identity is a versioned hash over semantic components: usage,
  lifecycle/activity, latency, context posture, display identity, attribution,
  and artifacts.
- Collection time, parser build/source version, source-file fingerprint, and
  evidence-lineage fields are excluded from semantic equality.
- Selector evidence sources remain semantic because downstream logic uses them
  to distinguish observed values from configured defaults.
- Mutable current Codex config defaults remain available to live status display
  but are no longer backdated onto historical usage rows.
- A legacy Codex index with a config file in scope receives one conservative
  corrective reconciliation even when the current config yields no selector.
  The old index retained only file stats, so prior config content and affected
  session ids cannot be proven. This is a deliberate one-time correctness cost;
  after the index advances, config cannot select or rewrite history again.
- When a selected transcript parses to the same semantic fingerprint already in
  its local index entry, the index advances but the snapshot is not returned to
  the upload path.

## Correctness boundaries

- Token count, status, and last activity are useful candidate hints but are not
  sufficient equality proofs. Equality covers every backend-relevant semantic
  component.
- Transcript size or nanosecond mtime change always opens the file.
- Real usage, lifecycle, latency, title/state, context, attribution, or artifact
  changes alter semantic identity.
- Account-switch cutoff behavior is unchanged.
- Existing first-bootstrap behavior is unchanged; only parser-version-driven
  repeat walks are removed.

## Validation

- Backfill tests cover bootstrap, parser-version independence, explicit replay,
  state compatibility, delivery failure semantics, and account-switch cutoff.
- Snapshot tests cover legacy-index migration, same-second file edits,
  per-session sidecar isolation, semantic no-op suppression, observation/parser
  metadata stability, and real component changes.
- The complete snapshot unit-test group passes.

## Follow-up phases

- Make privacy/capability policy changes use targeted semantic reconciliation
  instead of policy-specific fresh indexes.
- Persist component revisions and an ACKed local outbox so upload retry and
  semantic equality are independent of scan-index lifecycle.
- Add backend set-based head lookup and conditional component writes as the
  second safety fuse.
- Add raw-local to backend/UI reconciliation fixtures and runtime counters for
  candidate, parsed, semantic-noop, uploaded, accepted, and materialized work.
