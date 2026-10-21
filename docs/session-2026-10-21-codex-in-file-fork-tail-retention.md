# Codex in-file forks keep their retained tail reduction

The sampled native tail cache admits a Codex reduction only through
`sampled_scan::compatible_reduction`. Before this change any fork was refused,
so a long subagent or forked session was fully re-read on every append. The
predicate now also admits a fork whose ownership boundary was decided from the
file's own header fields:

- `subagent_history_start_ordinal` → `Ordinal { start }`, with or without
  `forked_from_id`;
- a non-null `history_base` → `AllLocal`;
- a legacy subagent after its trigger turn → `AllLocal`.

The admitted fork must not be a provider-created thread or a sidecar-ambiguous
file (`codex_created_thread_native_only`), and must not have read a parent
ledger (`codex_parent_ledger_consulted`). The existing conjuncts are unchanged:
an observed priority-witness map and complete usage accounting. Non-fork files
keep today's rule (no fork, no header parent, no sidecar parent). Excluded:

- `NativeCreatedThread`, with or without a trusted parent;
- an ordinary fork whose `AllLocal` boundary came from a parent ledger;
- `AwaitingLegacyTrigger`, `AwaitingParentPrefix`, `AmbiguousFork` and
  `Undetermined` (accounting is incomplete there anyway).

A sidecar parent edge does not block a lifted fork. The Codex reduction scope
already folds in the file's family position through
`path_reduction_fingerprint`, so a family change forces a full read
(`ScopeChanged`).

The lift applies wherever `compatible_reduction` gates retention, including
cursor sealed-prefix retention (`sampled_jsonl::retain_sealed_prefix`): a lifted
fork's cursor-certified prefix is now retained and tailed as well.

No cache budget, cap, admission proof, persisted state, counter, wire field or
runtime path changes. Usage boundaries and arithmetic are unchanged: a retained
copy continues the same accumulator a full parse would build.

## Tests

- `sampled_native_in_file_codex_forks_continue_tail_with_full_parse_parity`:
  four fork shapes are retained on the first read, continue as `Tail` across two
  appends, and match a fresh full parse at every step.
- `sampled_native_legacy_subagent_with_sidecar_parent_retains_until_family_changes`:
  a bound sidecar parent still retains and tails; a newly recorded grandparent
  changes the scope and forces `Full(ScopeChanged)`, with parity.
- `codex_lineage_lift_keeps_created_ledger_and_pre_trigger_forks_unretained`:
  a parented created thread (complete accounting) and a ledger-resolved
  `AllLocal` fork (complete accounting) stay incompatible, and a pre-trigger
  legacy subagent stays incompatible. Single-field controls show which conjunct
  excludes each.
- `sampled_native_retained_ordinal_fork_with_an_ordinal_break_is_held_not_retained`:
  a retained `Ordinal` fork followed by an ordinal gap or a backward step
  tails, publishes nothing (parity with a full parse), drops the retained copy,
  and the next change is `Full(StateMissing)` with parity.
- `lifted_ordinal_fork_retains_sealed_prefix_then_tails_with_full_parity`
  (cursor tests): a paged `Ordinal` fork keeps its certified sealed prefix,
  tails one append from it, and matches an unpaged full read.
- The existing parentless created-thread retention test keeps its assertions;
  only its comment was corrected.

The sampled-native test helpers `native_parser` and `acquire` gained
metadata- and scope-taking variants; existing callers are unchanged.

CI ran these tests on the PR head (see the PR body for the receipt). No local
builds or tests were run for this patch.
