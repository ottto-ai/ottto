# Read-only historical candidate exporter (`h527_candidates:v1`)

`snapshots/h527_candidates.rs` turns one operator manifest of exactly 18 Claude sessions into a candidate packet for a separate, reviewed admission writer. It is a non-functional core: there is no runtime caller or CLI, and today every member is held without a body. It does not scan, parse, upload, call a provider or the backend, fetch an activity hint, or write scan index, upload progress, quarantine, status or ACK state. Its inputs are the production pipeline's own values, borrowed read-only: the post-policy upload set, `ClaudeUsageAuthorityDisposition` and `ScanIndex`.

## Packet

```
{contract_version:"h527_candidates:v1", operation_id, user_id, organization_id, device_id,
 machine_id, producer_revision, collector_version, scope_session_keys:[18],
 members:[{source_session_id, session_key_sha256, prior_refusal_body_witness,
           disposition:"held", reason, qualification_report_sha256,
           cross_session_conservation:"unknown"}]}
```

The top level is exactly the closed `CandidateBundle` that SESSION froze at commit `a1f87dd8a8aca2ae0140e29f6904aa9892fed69f`, which refuses any other key. The held fixture parses under that commit's `parse_candidate_bundle`.

- `session_key_sha256` is SHA-256 of the UTF-8 `session_key:v1` string: (`claude_code`, machine id, full source session id), with backslash doubled and pipe written as `\p`, joined by `|`. This matches the backend's `session_entity_key`, not the unit-separated storage locator. Tests pin four backend-computed vectors.
- Scope and member validation:
  - Scope ids must be lowercase canonical UUIDs.
  - `producer_revision` must be a 40-hex commit. The operator supplies it and the binary cannot prove it.
  - Every member must be a full Claude session id: a UUID, optionally with an `_agent-` suffix.
  - Each member's key must bind its id, and its refusal value must be 64 hex.
  - Members and keys must be distinct.
  - Anything else refuses the whole export.
- `collector_version` describes the build that actually ran the export, never the installed daemon's version. That build's executable SHA-256 (`producer_binary_sha256`), `producer_revision_source: "operator_supplied_unverified"` and `unresolved_fields: ["prior_refusal_body_witness"]` are written into every member's qualification report, so the packet binds them through each report SHA. Earlier drafts put them at the packet's top level, where the frozen bundle refuses them.
- `prior_refusal_body_witness` is opaque diagnostic metadata, copied and not verified. The daemon's additive upload body witness covers only additive evidence, so it does not identify a refused body. `unresolved_fields` keeps that gate explicit. A replacement, `prior_refusal_record_sha256`, would digest the destination-scoped tuple (destination namespace hash, snapshot fingerprint, body witness, reason, full source session id). SOURCE's Amendment 1 makes that tuple diagnostic only: there is no local-ledger drift gate at apply time. It is still not implemented, because no shared byte encoding with test vectors exists, and the exporter does not invent one.
- Each member has a content-free qualification report (RFC 8785, `h527_candidate_qualification:v1`) with local hold, census, fence and request-set facts, `local_checks_passed`, `global_conservation_evidence: "unavailable"` and `disclosed_residual_evidence: "exclusion_artifact_missing"`. Only the report's SHA travels in the packet; the report stays with the operator.

## Verdicts

Reasons are a closed set:

- eligible: `qualified_source_ownership`, `exact_exclusion`, `exact_previous_ack_membership`, `local_exclusion_disclosed_residual`
- held: `unknown_owner`, `incomplete_census`, `cap_overflow`, `creator_hold`, `missing_evidence`, `money_decrease`

Conservation states are `qualified`, `disclosed_residual` and `unknown`. An eligible `local_exclusion_disclosed_residual` member must carry `disclosed_residual`; every other eligible reason must carry `qualified`; `unknown` never qualifies. The exporter emits no eligible member.

No member is eligible today. Cross-session conservation has to cover the target set and every already-counted accepted session. That includes accepted bodies whose transcripts were deleted or left the census window. A complete local census cannot prove absence there, and no interface supplies qualified historical evidence. So conservation stays `unknown`, and no caller flag or report hash can change that.

Local checks still run, first failure wins:

1. If the session is account-deferred, the reason is `creator_hold`.
2. If it is in another authority quarantine, or has more than one upload item, the reason is `unknown_owner`.
3. If it has no upload item, the reason is `missing_evidence`.
4. If the local census is incomplete, invalid, missing coverage, or has unobserved family members, the reason is `incomplete_census`.
5. If the duplicate witness overflowed, either census fence tripped, or a page cap invalidation happened, the reason is `cap_overflow`.
6. If counted requests have no provider request ids, the reason is `missing_evidence`.
7. If a request hash is in the durable duplicate witness and the member's exact legacy exclusion does not remove it, the reason is `unknown_owner`.

A member that passes every local check is held as `missing_evidence` (the missing global conservation proof), with `local_checks_passed: true`. Session-exclusive proof is not required: a truthful unproven transcript body passes the local checks the same way a proven one does.

Items are never changed. Contract-5 rows can only come from the ordinary sync cycle's own fresh permit. The exporter neither forces nor fakes one, and a body built without that permit stays untagged.

## Disclosed residual basis

Ron chose a lean option: SOURCE may qualify a member under the named basis `local_exclusion_disclosed_residual:v1` instead of strict proof. That basis is a risk-reviewed qualification with an unbounded residual, not conservation proof. It needs a reviewed local exclusion artifact for the target, built over every local transcript including the other 17 targets. Nothing here produces that artifact, so every member stays held with `missing_evidence`, and Ron's product decision alone does not make any member eligible.

`local_exclusion_disclosure_json` writes one target's `LocalExclusionDisclosure` record, field for field as SESSION froze it:

```
{scope_session_keys_sha256, exclusion_artifact_sha256,
 local_exclusion_scope:"all_local_transcripts_including_other_17_targets:v1",
 identity_rule:"b2_counting_only_keep_root_owned_evidence:v1",
 excluded_request_count, excluded_token_counts:{8 counters},
 excluded_catalog_cost_usd:"<exact decimal>",
 copy_screen_status, copy_screen_artifact_sha256, copy_screen_not_run_reason,
 residual_statement:"<exact SESSION text>"}
```

- `scope_session_keys_sha256` is SESSION's `canonical_json_digest(sorted(scope_session_keys))`: SHA-256 of the compact JSON array of the 18 sorted keys. A test pins the value that SESSION's own function returns for the fixture scope.
- The identity rule is counting only. A shared request is counted once, in the session that keeps it, and no name, tag or kind moves. The keeping root tags a kept shared request only from its own request evidence; otherwise it stays untagged under its starting subscription.
- The eight token counters are always written, including zeros.
- `excluded_catalog_cost_usd` is the exclusion money estimated at catalog prices. It is a plain decimal string with no sign, exponent or leading zeros. It is never the server's canonical admitted money; the server prices admitted money and applies its floors independently.
- The copy screen is optional:
  - `not_run` needs a nonblank reason of at most 1024 characters and a null artifact.
  - `no_match` and `exclusions_applied` need a 64-hex artifact and a null reason.
  - Both nullable fields are always written.
- The exclusion totals come in as input from the exclusion artifact. This function only fixes the record's shape and validation. It never changes a packet member, and only SOURCE's reviewed certificate can name the basis.

Before any execution go, SI requires SOURCE's actual per-member preview to be reviewed. It shows, as counts and hashes only, which kept shared requests are tagged and which are untagged, along with the keeping root's own evidence. It must also show that B2 allocation changes zero names.

## Unqualified review artifact

`h527_unqualified_candidates:v1` is a separate local-only artifact. It lets SOURCE inspect the bytes a candidate would carry while proof is still unresolved.

```
{contract_version:"h527_unqualified_candidates:v1", local_only:true, admission_authority:"none",
 operation_id, user_id, organization_id, device_id, machine_id, producer_revision,
 producer_revision_source, producer_binary_sha256, collector_version, scope_session_keys:[18],
 qualification_gaps:[closed list],
 candidates:[{source_session_id, session_key_sha256, prior_refusal_body_witness,
              cross_session_conservation:"unknown", operator_packet_reason, local_checks_passed,
              body_status, unqualified_batch_request_json?, unqualified_batch_request_sha256?}]}
```

- Each member with exactly one upload item that the pipeline did not withhold carries `unqualified_batch_request_json`. That is the exact ordinary `SnapshotBatchRequest` serializer output for the unchanged item, after the ordinary batch validation. It also carries the SHA-256 of those bytes.
- Every other member gets `body_status` of `no_upload_item`, `pipeline_hold` or `ambiguous_upload_item`, and carries no body.
- The artifact has no `members` list, no disposition and no eligible value. Its field names differ from the operator packet's, so a strict reader of the operator packet rejects it, even if its contract tag is relabelled.
- It is neither an admission bundle nor a plan member, and it grants no upload permission. The server's own rejection belongs to the admission writer.
- `qualification_gaps` is a closed list:
  - `cross_session_conservation_evidence_unavailable`
  - `local_exclusion_artifact_missing`
  - `prior_refusal_record_codec_not_frozen`
  - `producer_revision_unverified`
  - `contract5_permit_provenance_unattested`

The operator packet for the same inputs still holds every member without a body.

Fixture `fixtures/h527-candidates/unqualified-redacted.v1.json` is the RFC 8785 form of the artifact for the same synthetic scenario. It has each body and body hash replaced by fixed placeholders, because tests compare the bodies against the ordinary serializer directly.

Fixture `fixtures/h527-candidates/disclosure-not-run.v1.json` is the exact disclosure record for the fixture scope, with a synthetic exclusion summary and a skipped screen. It validates under SESSION's frozen `LocalExclusionDisclosure`.

Fixture `fixtures/h527-candidates/held-mixed.v1.json` is the exact packet for a synthetic census covering every member-scoped hold class and the global hold. Tests drive real parser items from synthetic transcripts. Validation is hosted Public CI only; no local Cargo was run. A green CI does not make this core releasable.

## Offline producer (`h527-produce`, October 18)

`snapshots/h527_candidates/producer.rs` computes candidate bodies and exclusions from one explicit input bundle. It is reached only through the hidden operator subcommand:

```
ottto-service h527-produce --input <bundle.json> --out-dir <new private dir>
```

It changes no daemon, discovery, scan-index, upload or runtime path. It reads only the files the bundle names and writes only into a new `0700` output directory. It does not follow symlinks while walking peer roots. Each target `transcript_path` must already be canonical, so the parser and the unchanged-file checks read the same path.

Input `h527_producer_input:v1` (strict, unknown fields refused, at most 4 MiB):

```
{contract_version, scope:{operation_id,user_id,organization_id,device_id,machine_id,producer_revision},
 collected_at (RFC 3339), upload_policy:{5 booleans}, context_curve_enabled,
 targets:[18 x {source_session_id, session_key_sha256, prior_refusal_body_witness,
                transcript_path, b2_first_ack_order|null}],
 peer_roots:[{class: projects|slot|held|archive|quarantine|other, path}],
 bounds:{max_peer_files, max_peer_total_bytes, max_peer_file_bytes, max_line_bytes},
 catalog_prices?:{publication:{source,revision,sha256},
                  rates_usd_per_mtok:{"<model>|<context_bucket>":{input,output,cache_read,
                                       cache_creation_5m,cache_creation_1h}}}}
```

Steps:

1. Each target is parsed with the unchanged Claude parser. A target is held unless the parse is complete, it yields exactly one item, every counted request carries a native id, and totals equal the sum of its per-request usage. A held target's request ids still take part in step 3.
2. Every `.jsonl` file under the peer roots is streamed once. Native request ids are compared exactly, in memory, against all targets. A subagent transcript belongs to its path identity; any other file belongs to its first named session, as in the parser.
   - A fork-copied line is never counted in its own file, so it is not evidence that anyone counts the id. Each one is resolved after the whole census is read:
     - If the session it names is a target, or owns a scanned peer transcript, the copy is ignored and counted.
     - If the named source is absent, the copy is conservative peer evidence. It is disclosed as `inherited_from_absent_source`.
   - The census must include a `projects` root, and every target must lie under a scanned root; otherwise coverage is unknown.
   - These leave coverage unknown, and every target is then held without a body: a cap overflow, a file changed during the read, an unreadable file, a compressed transcript, an unparseable line carrying a request id key, an invalid fork marker, or a symlink leaving the roots.
   - A target's own replica (owned lines, not fork copies) that carries an id the target lacks is held as an unknown owner.
   - A target's own replica that repeats an id the target counts is not peer evidence. When other targets share that id, the share stays between targets, and B2 allocates it.
   - Bytes are charged as they are read, so a failed or growing file still spends the cumulative byte budget.
3. B2 counting allocation is fixed for the whole batch before any body or money exists:
   - An id seen in any peer is excluded from every target.
   - An id shared only by targets is kept by the lowest `b2_first_ack_order`, else by the smaller `session_key_sha256`.
   - The allocation digest is recorded. B2 is counting only; it is not ownership.
4. Each target is re-parsed with the same parser, dropping only the lines of its excluded ids. The producer then checks exactly: kept ids, per-request usage, item totals = original − excluded, and usage rows. It also checks that account evidence, titles, workspace and repository identity, and origin are unchanged. The ordinary daemon serializer writes the one-item body. Any mismatch holds the target.
5. A receipt is written for each kept shared request: the keeping root, `untagged`, and its starting subscription unchanged. The producer applies no Contract-5 permit. A body that carries request evidence is held as unsupported, and allocation-driven name changes must be zero.

Outputs (`0600`, created new):

- `artifact.json` (`h527_producer_diagnostic:v1`, `local_only`, `admission_authority: none`)
  - input and file manifest, coverage census, B2 allocation, per-target partitions and reconciliation
  - unqualified bodies and their hashes, SI receipts
  - qualification gaps, and the pipeline stages not reproduced
- `candidate-bundle.json`: the frozen operator packet. All 18 members are held with `missing_evidence` and carry no body fields. Each member's `qualification_report_sha256` binds its target report.
- `disclosures.json`: only when `catalog_prices` is supplied. These are `LocalExclusionDisclosure` records with the copy screen `not_run`. `excluded_catalog_cost_usd` is an exporter estimate at catalog prices, not canonical money. Rates are keyed by `model|context_bucket` only, so a request with any non-default pricing selector (fast mode, a non-standard service tier, batch, a region, or a cloud gateway) is `unpriced_dimension`. When prices are missing or a model or dimension is unpriced, there is no estimate; it is never shown as zero. Each record also carries `target_binding_sha256` = sha256(`session_key_sha256` + newline + `disclosure_sha256`), because the frozen record names only the batch scope.
- `summary.json`: content-free counts and hashes. It is written last, so a directory without it is an incomplete run.

Not reproduced, and disclosed in each artifact: Contract-5 local evidence and permit, account binding, desktop title metadata, attribution context, backfill cutoff, and cache-head identity. These bodies are therefore identity-less and untagged. If SOURCE or SI need pipeline-identical overlays, the dependency is the pre-upload phase of the sync pipeline, not this producer.

Tests: `producer/tests.rs` drives 18 synthetic targets and peer roots. They cover a peer exclusion, a B2 first-ACK keeper, a hash keeper, a held-root peer, a target replica, a fork child, a two-hop fork chain, a copy from an absent source, and a fast-mode request left unpriced. They check that each body equals the parse of a transcript with the excluded line physically removed. Further checks cover the receipt, the held packet, the estimate, determinism, refusing an existing output directory, and holds on a compressed peer, a census with no projects root, or a capped census. They also check that a failed read is charged to the byte budget.
