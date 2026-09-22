# Context curve component extraction

The snapshot collector's deterministic context-curve construction and
validation now live in `crates/ottto-service/src/snapshots/context_curve.rs`.
This is a mechanical module extraction: serialized fields, revision strings,
sampling, wire limits, caller behavior, and public type paths are unchanged.

Moved into the component:

- `ContextCurveCandidatePoint` and `ContextCurveCandidateBoundary`
- `SnapshotContextCurve`, `SnapshotContextCurvePoint`,
  `SnapshotContextCurveBoundary`, and `SnapshotContextCurveModelWindow`
- curve size, retention, contract, and sampling constants
- `build_context_curve`, `unavailable_context_curve`,
  `mark_context_curve_retention`, `canonical_context_curve_timestamp`,
  `safe_context_curve_model`, and `context_curve_revision_is_safe`
- `compact_context_curve_model_windows`,
  `prune_one_context_curve_fill_point`, and `validate_context_curve`

Provider parsing, Claude and Codex ownership decisions, source revision
selection, persisted scan checkpoints, replay policy, snapshot finalization,
and uploader eligibility remain in `snapshots.rs`. The parent module re-exports
the existing public curve types and crate-visible contract constant from one
definition.

Focused validation:

```bash
cargo test -p ottto-service context_curve --lib
cargo fmt --check
bash scripts/public_repo_export_check.sh --require-no-rewrites
bash scripts/public_repo_manifest_check.sh
bash scripts/public_repo_contract_check.sh
bash scripts/public_repo_secret_scan.sh
```

The release-profile comparison uses synthetic fixtures only and does not start
a daemon, contact a provider, or upload data. It covers unchanged polling, new
and duplicate usage, same-size model/hour correction, workspace invalidation,
truncation, retry-deadline completion, bounded large files, source file/line
limits, and a 5,000-file metadata population.
