# Large-record restore Linux test-target Clippy repair

The unsupported-layout cache test now uses `expect_err` directly instead of
`err().expect`. The exact original Box pointer, refusal event and empty-cache
assertions remain unchanged. This is a test-only lint repair with no production,
persistence, custody, budget or admission change.

The expression originated in the lossless-cache prerequisite, carried by the
large-record restore chain; it was not introduced by the later main merge.
The test is compiled only outside macOS, so a Mac all-targets Clippy check does
not compile this Linux-specific assertion. Package Clippy validation uses pinned
1.95.0 with all targets, locked dependencies and warnings denied. Linux-specific
validation remains owned by Linux CI. No local Cargo tests were run.
