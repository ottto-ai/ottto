# Original rearm regression oracles

Source pin: original #583 head `609ef1c3213466f625fd4710ab93b8ea2a75390c`; current base `bdd504a11fa5e919e29b5ae228bf34ca65bec344`; prior experiment `56bf257637cca3a66db9c7ab8b91ba576470a26f`.

Nine original test bodies are byte-identical at all three pins. Existing CI `38901455716` records their actual passing results with experimental reuse inactive. This candidate re-executes them under experimental restart/base-exit policy, with no eligible-family or negative certificate. That mode is fallback coverage, not eligible optimization coverage.

| Original oracle | Original function SHA-256 | Base/experiment body | Eligible reuse |
|---|---|---|---|
| `account_deferred_hold_lets_a_bounded_claude_traversal_converge` | `e378cd2d89475a9bb9d720a8209accc01aa1e435357580270be80ad8dc6b58d8` | Identical; existing base CI PASS | Unproved |
| `novel_import_recovers_after_owner_coverage_then_stops_reading` | `ac94f6874d0ba1c7b57797917656ddc62eb0a2b53480703fbfc9dc9ac78b1c8a` | Absent; ported body preserved, ignored pending driver | Unproved |
| `terminal_family_member_controls_keep_blocking_pruning_and_rebinding` | `f5ac8892474f33703dab2a6d2fd48bf9e12cf35705ee485f3c1884119c932933` | Identical; existing base CI PASS | Unproved |
| `terminal_family_never_committed_members_let_the_claude_census_complete` | `aae76481d79cbd315d3799fc1992c74acee1dc6c6b73d31574dec36f23b3eab8` | Identical; existing base CI PASS | Unproved |
| `claude_duplicate_fence_reopens_only_after_full_coverage` | `c0853a88e1613b7acbfbe3424251e58c2873a02c97532f59038ea197d1bf5dbf` | Identical; existing base CI PASS | Unproved |
| `claude_duplicate_across_pages_stays_refused_without_reparse_loop` | `3e89c864fa5b97ad11ad50ec566442ba4c51724183cab9ebe4b9086205c5cc6f` | Identical; existing base CI PASS | Unproved |
| `claude_explicit_fork_duplicate_owned_request_fails_posture_closed` | `1bdb9c28b6d1da2c32071675b02bb40cc3c36ffedb102f808543e88fdc272549` | Identical; existing base CI PASS | Unproved |
| `claude_future_quarantine_preserves_cross_page_duplicate_refusal` | `776d07550b441e5dd9ac77e748cccb67f87f4d45dca3aee4b7f2c2383acbf897` | Identical; existing base CI PASS | Unproved |
| `claude_pending_census_recovers_without_releasing_future_quarantine` | `c4689c6dadda698a35fd910eaea69e267cdc562b40b1fe8005832cc9c42e3961` | Identical; existing base CI PASS | Unproved |
| `claude_stable_owned_start_recovers_after_partial_conflict` | `ad84e9c2e120e3c9a14e48b98c1ce219089c9352598db8f2ef63ba9a9a46e0a1` | Identical; existing base CI PASS | Unproved |
| `member_change_after_unchanged_proof_fails_closed_until_family_reparse` | `549252233d1b8807fcc7134fc7156301febd99efe51b8c201829771f34ae0e18` | Absent; ported body preserved, ignored pending driver | Unproved |

## Two pending originals

The complete original bodies of `member_change_after_unchanged_proof_fails_closed_until_family_reparse` and `novel_import_recovers_after_owner_coverage_then_stops_reading` remain compiled but explicitly ignored. Their first optimized quiet-state requirements do not hold on base or uncertified experiment state. Nothing forces a negative certificate or manufactures the required starting state.

Separate characterization controls observe the real opposite base behavior: the stable terminal proof clears the parent revision, and the stable family still reads its three members. These controls do **not** count as the original oracles passing; their receipts say `BLOCKED_OPTIMIZED_PRELUDE`, `original_oracle_passed=false`, and `downstream_assertions_executed=false`. If an earlier or different invariant fails, the characterization fails normally.

The novel-import helper includes one independently evidenced fixture repair: an omitted empty duplicate map is only unwrapped in the copied-request branch; the novel branch still requires the map to be absent. Original oracle bodies and semantic assertions are unchanged. The port adapts the current optional correction-scan checkpoint argument and retry-record inspection API, and removes unused fixture fields/methods; it introduces no production behavior.

## Missing integration, not a weakened assertion

A full driver must retain the actual native scanner until current row qualification and any targeted native comparison finish, before constructing or offering B/C bodies. It must capture actual normal-Skip revision/scope certificates, freeze the retained old proof, respect all quarantine/demotion exclusions, and move rows through one authoritative fold. The current test-only rearm gate can demonstrate a qualified boundary, but does not perform that automatic classification/acquisition.

The component fixture uses seeded revision strings and no real candidate adoption/finalization, so its `armed` state is not itself a Q1 normal-Skip certificate. The pipeline fixture reaches real ACKed bodies but then requires an optimized quiet fixpoint before its import assertions. Activating the simple hook for either fixture without this driver would manufacture coverage.

No production activation, review/merge/release readiness, installed acceptance or resource benefit follows from this mapping.
