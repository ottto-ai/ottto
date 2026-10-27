# Claude re-read diagnostic counters

The local resource carrier now distinguishes parsed-entry restoration from
actual nonempty-to-empty clears. Restoration keeps the existing conservative
save rule, separating prior empty/nonempty fingerprints and local held/sibling
keys, with a separate count for exact-incidence-only sibling rejection. The
owned-start, invalid account-witness, retry admission and authority normalization
sites retain their existing decisions and gain fixed local counts.

Claude collection scopes carry exact cache lifecycle events across cooperative
steps and worker moves. Existing process cache totals remain unchanged; sparse
page events identify the causing source, with count/byte capacity eviction
splits and failed destructive-hit reinsertion. Preparation/save intervals report
through the existing comparison decision stage, including when comparison is
disabled. Counts never enter wire/persisted models or authorize progress.

Tests cover source/thread/nested-scope isolation, resumed aggregation, sparse
encoding, saturation, real subset restoration and unchanged saved entries, plus
existing native pipeline/layout and resource budget contracts in CI. Validation
runs and exact head are recorded in the PR. No local Rust build/test/clippy,
installation, runtime collection, release or production action was performed.
