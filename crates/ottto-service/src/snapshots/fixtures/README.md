# Test fixtures

- `claude_released_copy_prefix.json`: released (pre-dedupe) Claude copy-prefix bodies, #909 ledgers and
  the raised-cap held scan-index state, printed once by a throwaway test at main `f38649b7e` (the last
  main with the copy-prefix switch OFF path) in Linux CI run 41285148471; the corpus root is replaced by
  `<BASE>`. Keys name the consuming fixture in `snapshot_sync/claude_money_e2_pipeline_tests.rs`.
