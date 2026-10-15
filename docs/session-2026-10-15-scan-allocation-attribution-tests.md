# Scan index and Claude evidence join allocation attribution tests

Two test-only measurements attribute allocator work in the local Claude scan
cycle to separate stages. They change no production code, persisted format,
workflow, dependency or allocator. Both use synthetic fixtures only.

## Method

Both tests use the existing test-only `retry_allocation_probe`. It counts the
requested and usable bytes and the allocation and deallocation events of the
current test thread inside one `measure` scope.

- **S6, scan index** (`snapshots/census_convergence_tests.rs`,
  `m2_s6_scan_index_load_clone_save_and_settlement_allocations`): a synthetic
  index with 32 and then 64 Claude family roots. Each root has two member
  files, 16 pending request occurrences and a retained usage witness. There
  are up to 1,024 duplicate-owner entries. The fixture is built and first
  saved outside every measured scope. The measured stages are:
  - `ScanIndex::load`
  - one clone, with both copies alive
  - the normal compare-and-swap `save`
  - the held-key settlement revert
  - a partial `committable_subset`
- **S7, Claude evidence join** (`snapshot_sync/census_convergence_pipeline_tests.rs`,
  `m2_s7_claude_evidence_join_decodes_every_witness_root_on_a_zero_parse_page`):
  16 and then 32 single-member families. Each has 16 requests with exactly
  paired API and trace telemetry rows. The test measures
  `apply_claude_local_evidence_to_scan_with_permit` in three runs:
  - a parsed control page with the emission permit denied
  - the same page with the permit allowed
  - after convergence, a page that parses no file, with the permit denied

  The join mutates its scan and index. So each run clones them inside the
  scope and reports the join phase above those clones separately.

Each stage writes one count-only JSON line to stderr through `std::io::Write`,
tagged `"receipt":"m2_allocation_attribution:v1"`. libtest captures only the
print macros, so these lines stay visible in an ordinary CI test log. They
contain only synthetic sizes, the stage name, byte counts and event counts.

## What the tests assert

- **Load parity**: load round-trips every persisted field.
- **Clone parity**: the clone equals its input.
- **Save**:
  - Save advances the generation by exactly one, and a stale generation is
    refused without touching the file.
  - The save scope's peak covers at least half a decoded copy and retains
    none. This is today's compare-and-swap check, which decodes the whole
    on-disk index. A header-only decode would change this assertion on
    purpose.
- **Held settlement**:
  - The revert peaks at least one full clone of the scanned index.
  - Held bodies are never current or accepted, and earlier accepted
    fingerprints stay accepted.
- **Partial subset**: only accepted bodies advance. Held and unaccepted keys
  keep their committed entry.
- **Join, control page**:
  - Measuring does not change the join's bodies, statistics or disposition.
  - Every family is reported usage with its request and token counts.
  - Without the permit, no contract-5 evidence is built.
  - With the permit, usage counts are unchanged.
- **Join, zero-parse page**: the page still requests and decodes the API and
  trace rows of every witness root (W×R rows each).
- **Scaling**: doubling the synthetic size grows the clone bytes (S6) and the
  zero-parse join allocations (S7) by between 1.5× and 2.5× (S6) or by at
  least 1.5× (S7). Fixed overhead makes the ratio inexact, so no per-unit cost
  is asserted.

## Limits

- The probe sees requested allocator calls only. It does not measure RSS,
  physical footprint, allocator retention or other threads. A pass is not
  evidence that nothing leaks.
- These are small synthetic fixtures. Do not extrapolate their values to a
  real index or corpus size.
- The tests characterize current behavior. No allocation path is fixed or
  optimized here.
- Not measured separately:
  - The duplicate-owner census block runs inside the reported-usage rebuild,
    so only the S7 join covers it.
  - The bounded `save_with_read_limit` path refuses an index this large at its
    shape cap.
