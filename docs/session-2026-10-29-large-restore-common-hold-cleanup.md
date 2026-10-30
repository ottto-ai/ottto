# Large-record restore common-hold cleanup fixture

Fresh-index cleanup has no membership for either record seeded by the
common-hold fixture. Codex may collect the known synthetic absent record and,
in the unmarked control, the known selected record too. The exact deletion
counter is therefore two for that control and one for its held/corrupt variants.
Cold Claude retains every unproved known predecessor, preserving strict
mutation custody, so its deletion counter remains zero.

The fixture now derives that exact count and separately asserts the selected
record's presence. Existing source-specific absent-record checks, unchanged
held bytes, strict mutation refusal counts, all guard precedence and no-body
assertions remain. This corrects a fixture expectation introduced during earlier
integration; production GC and guard behavior are unchanged. The sibling restore
branch already checks the same source-specific preservation rule without the
incorrect total-count assertion. Package all-targets Clippy compiles fixtures;
runtime execution remains owned by CI. No local Cargo tests were run.
