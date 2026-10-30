# Reusing a macOS contract pass in the merge queue

The merge queue keeps its `ALLGREEN` policy and required check names. Before
allocating a Mac, Public CI searches the latest 100 manual runs and 100 queue
runs of its own workflow for a successful Mac pass on the **complete same Git
tree**. A different commit SHA is allowed; a different file, mode, workflow,
fixture, manifest, script, or lockfile changes the tree and prevents reuse.

Proof must come from this repository's `ci.yml`, be no more than 24 hours old,
and contain a successful `Rust contracts` job on a GitHub-hosted `macos-15`
runner. Every existing Mac build/test step must have completed successfully.
The lookup verifies the candidate commit's tree through the Git API and pins
the workflow attempt when reading jobs. A skipped check or a Linux reuse
receipt cannot supply proof. Missing data, API failures, or lookup failure use
the full Mac job. Manual dispatch and the daily cache refresh always use Mac.

On a hit, the existing `Rust contracts` job runs on Ubuntu and reports a link
to the real Mac job and its tree in its summary. The other required checks run
normally. No additional status writer, artifact producer, or write permission
is needed. The lookup token has only contents/actions read access.

To improve hit rate, run branch Mac validation on a branch rebased onto the
current `main`, then enqueue that exact head. This only helps if the queue
produces the same tree: intervening merges and PRs ahead in the queue usually
change it. Avoid repeatedly rebasing and dispatching just to chase a hit;
that can consume more Mac time than it saves. Passing branch Mac with merely
"no Rust source changed on main" is insufficient evidence.

The 24-hour lifetime limits stale external-environment evidence; matching a
tree does not reproduce runner-image or network-service state. A Mac rerun is
still needed to investigate environment failures or flaky tests. A skipped
repeat proves the files previously passed; it is not an independent second
sample. Keep the daily Mac refresh. Future Mac test-step additions must also
update `MAC_STEPS` in `scripts/mac_contract_reuse.py`; the policy tests run in
the Linux workflow. Changing any repository file invalidates prior tree proof.

Rollback: revert this workflow/script change. `Rust contracts` then always
uses Mac for queue entries again; no ruleset change is required. Before
relying on live savings, inspect an owner-authorized queue miss and a queue hit
for the intended runner and proof link. Linux policy tests do not establish
live macOS or merge-queue behavior.
