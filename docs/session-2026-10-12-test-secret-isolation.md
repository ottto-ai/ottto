# Test credential-store isolation

Rust service tests could reach the host login Keychain whenever a fixture omitted
or removed `OTTTO_SECRET_FALLBACK_DIR`. A core dependency does not receive
`cfg(test)` merely because its caller is a test harness. Timeouts do not cancel
Security framework calls or dismiss their authorization dialogs.

The core `test-secret-store` feature is enabled through service and CLI
**dev-dependencies**, so ordinary runtime builds retain their credential-store
behavior. Core unit tests also use the boundary through `cfg(test)`. Test secret
stores use explicit fixture directories when supplied, otherwise a fresh private
process-local temporary directory. Removing environment overrides cannot enable
native Keychain access. Telemetry stores use the same boundary, including sweeps.
The feature is for synthetic tests only; do not enable it for installed binaries.

Regression coverage runs in a child process with both fixture overrides absent.
It verifies missing/saved/deleted control, setup and device secrets, plus telemetry
save/load/sweep, against temporary files. No live credentials are test fixtures.

Validation results are recorded in the pull request. The temporary directory
used by this regression is removed before the child exits. Other tests should
continue providing scoped fixture directories and cleaning them up.
