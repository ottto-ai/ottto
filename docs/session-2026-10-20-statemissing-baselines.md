# StateMissing characterization baselines

Test-only baselines for the mechanisms behind repeated Claude full reads. Each
`statemissing_baseline_*` test drives the real scan, fold and save path,
asserts today's behavior and passes on main. Each doc comment names the defect
and the expected post-fix behavior. The assertion that should flip after a fix
is marked `FLIPS` and isolated after the precondition checks, so a setup
failure cannot pass as the defect. No production code, hook, manifest or
lockfile changes. Proof, ACK, held and census gates are exercised unchanged; no
test forces a valid census.

1. **T1 proof-candidate re-arm** (`snapshot_sync/statemissing_baseline_pipeline_tests.rs`).
   An unchanged, proven Claude family on a census-complete, settled, unheld
   traversal is cleared at every healthy terminal. Hours 10 and 11 each reread
   all 3 family members, offer nothing, record 3 semantic no-ops and end with
   debt 3. Post-fix: 0 reads and debt 0 for an unchanged proof. The control
   (`snapshots/statemissing_baseline_fold_tests.rs`) changes the proof witness
   with a grown child page and still re-arms the earlier-page parent.
2. **T2 unrelated disappearance** (pipeline module). Deleting an unrelated
   session makes the window red (1 disappeared). The saved index keeps the
   traversal with retry attempt 1 at deadline 09:01 + 60 s and one pending
   family. The retry rereads the changed key once (1 semantic no-op). The
   unaffected member keeps its exact revision and entities and is never parsed.
   Post-fix: the retry rereads nothing already settled. The healthy control
   leaves no traversal or pending family and rereads nothing.
3. **T3 cross-source wipe** (`snapshots/statemissing_baseline_retention_tests.rs`).
   A retained Claude tail entry plus 4 retained 1,400-record fillers stay within
   the 32,505,856-byte state budget. A census-incomplete Codex file read
   unsampled, with no borrowed state and a zero copy budget, records one
   `ClearOtherActive` releasing 5 entries. The next Claude append then needs a
   full `StateMissing` read instead of a tail read. Post-fix: an unsampled
   active must not wipe other sources' retained state. The control without the
   Codex page reads only the tail. On an unsupported layout the positive prints
   `UNEXECUTED` and returns.
4. **T4 closed duplicate fence** (fold module). A complete traversal is not
   valid coverage. One transcript response without a `requestId`, or more
   pending occurrences than the cap (5 over 4), invalidates the family. Coverage
   counts it missing, the fence stays closed, and a full re-arm clears every
   revision with backoff attempts 1 and 2. Post-fix: an identity-invalid family
   must not replay full reads forever. The valid control reopens the fence at
   attempt 0.

Each test prints one count-only `STATEMISSING_BASELINE` stderr line, visible in
CI through `--nocapture`. T2 reread evidence is the pipeline's completed parse
list; that harness has no retained cache, so the reread is an unsampled parse,
not a recorded `Full(StateMissing)`. T3 mirrors the production scan step loop in
test code to count unsampled zero-budget steps. These tests are **UNRUN until
CI**. No local tests or builds were run for this patch.
