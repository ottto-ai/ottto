# Test fixtures

- `claude_released_copy_prefix.json` contains released (pre-dedupe) Claude copy-prefix bodies,
  accepted-share ledgers and the raised-cap held scan-index state. A throwaway test printed
  them once at main commit `f38649b7e`, the last main revision with the copy-prefix switch OFF
  path. The fixture replaces the corpus root with `<BASE>`. Keys name the consuming fixture in
  `snapshot_sync/claude_money_e2_pipeline_tests.rs`.
