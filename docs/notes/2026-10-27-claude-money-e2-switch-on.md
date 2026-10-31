# Claude money E2 switch-on validation

PR C enables the E2 fold and advances the Claude upload body-witness revision
from 2 to 3, with maximum gated revision 3. The existing history-upgrade path
paces the one owed reread; completed revision-3 files owe no repeat pass.

## Legacy test pins

T8 records **51 gate-off pins**: 29 from its first round and 22 from its second.
The assertions stay intact. Each pin names the legacy rule and gate-on coverage.
The earlier C2 pin inventory is separate from these 51.

| Legacy rule | Pins | Named gate-on coverage |
| --- | ---: | --- |
| v1 reported-usage witness | 12 | `e2_pipeline_tags_the_final_root_and_agent_rows` |
| resolver conflict as dropped residue | 1 | `e2_malformed_literal_is_isolated_and_siblings_settle` |
| pre-E2 native comparison | 10 | `e2_late_identity_permit_reowes_revision_three_once_paced` |
| reported-body proof/delivery | 4 | `e2_pipeline_tags_the_final_root_and_agent_rows` |
| dark output bound | 1 | `x_out_t1_bounds_the_finished_claude_file` |
| reported-authority correction/demotion | 1 | `e2_body_of_previously_proven_family_is_not_a_demotion` |
| terminal authority hold/rearm and unchanged-body no-op | 12 | `persistent_structural_refusal_serves_due_authority_and_finishes_bounded_admission`, `e2_pipeline_quiet_otel_only_change_replaces_estimate_without_count_growth` |
| tombstone held until reported proof | 5 | `e2_returning_tombstoned_family_publishes_once_and_clears_its_tombstone` |
| markerless contract-5 tags | 4 | `e2_identity_markerless_desktop_keeps_d1_shape_and_recent_activity` |
| conflicting org markers with own telemetry login | 1 | `e2_identity_two_org_request_with_its_own_telemetry_login_goes_to_the_starting_account` |

Gate-on publication settles old authority records and returning tombstones on
the first E2 page. Proof corrections settle on the exact request-owned ACK.
The pre-flip correction test also checks one read per owed member and no quiet
re-offer. D4 replaces the broad finish cushion with itemized fold storage,
including the real overlap while `absorb_grains` clones held grains. The three
256-response worst shapes cover own hours, restored copies, and split markers.
The four cache-policy tests remain gate on with their assertions unchanged.

## Main integration

The branch merges main through `1e2de9201` before reapplying the flip. PR A
arrived as squash #781, so its squash tree supplies the content base when
reconciling duplicate changes. Both parents and their later behavior remain.

Main #794 preserves referenced ACKs through selected/partial index saves and
counts incomplete-census capacity stops. #795 shares file-set digest helpers.
#796 only refactors retry-carry predicates. #797 scopes the unchanged-proof
veto to held families while retaining their holds. #798 makes ctime a content
cross-check rather than a reread trigger and adds persisted ctime/birth fields:
`ScanIndexEntry` is 480 bytes. #799 adds reread diagnostics. #800 bounds
oversized retries and preserves recovery. #802 content-qualifies retained
Codex wake paths. #801 locks the state directory before state writes.

These main changes preserve the reasons for the 51 pins and the revision-3
adoption contract. No new pin or weaker assertion is part of the integration.

## Integration fixture updates

The original 51 T8 pins keep their reasons. Main #800 adds one more legacy
oracle, `oversized_blocking_hold_is_reoffered_once_per_six_hour_floor`, now
explicitly gate off because request-owned literals bypass its demotion hold.
Gate-on `oversized_request_owned_hold_is_reoffered_once_per_six_hour_floor`
uses the existing local-hold fixture and tests the same two six-hour recovery
floors, no early restart, held literal exclusion, and incomplete census.

The M-a fixture filler target changes from 212 to 210 permille per filler.
Its prior E2 headroom was about 300 bytes of X_out; longer CI paths exhausted
the 256 KiB prefix margin. The margin, exact two-victim/copy-only equality,
zero-budget tail conditions, and production resource budgets stay unchanged.
