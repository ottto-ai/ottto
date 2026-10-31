# Advisory synthetic runner retirement

The development-only synthetic runner feature, command, integration tests,
and advisory Linux workflow are retired together. Default service builds keep
their existing collection clock, transcript roots, upload behavior and diagnostics.
Its loopback support is also removed: the benchmark that shared it was retired
in the prerequisite bundle. Scoped collection and diagnostic-capture support
remains test-only for the existing money and pipeline tests.

The independent cold-read money assertion is a prerequisite: all fifteen money
fields, including field presence, must match the cumulative result in the kept
`e2_pipeline_full_tail_unchanged_eviction_and_restart_are_cumulative` test.
Retirement must not merge until that additive port has merged and passed Linux
and normal macOS CI. The retirement PR itself runs Linux CI only.
